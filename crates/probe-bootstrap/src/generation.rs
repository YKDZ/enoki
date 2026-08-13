use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(test)]
use std::{os::unix::ffi::OsStrExt, path::Path};

pub const DELEGATION_GENERATION_STATE_ROOT: &str = "/var/lib/enoki-probe-bootstrap";

const TRUST_DIRECTORY: &str = "trust";
const GENERATION_FILE: &str = "delegation-generation";
const LOCK_FILE: &str = ".delegation-generation.lock";
const MAX_CANONICAL_GENERATION_BYTES: u64 = 21;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Eq, PartialEq)]
pub enum GenerationStateError {
    InvalidCandidate,
    InsecureState,
    Io,
    Malformed,
    NotRoot,
    Rollback,
}

/// An exclusive lease over the installed Host's delegation generation.
///
/// The lock remains held after [`Self::persist_before_mutation`] and is only
/// released when this value is dropped, so callers keep the lease through the
/// complete activation attempt.
pub struct DelegationGenerationLease {
    candidate: u64,
    current: u64,
    _lock: File,
    #[allow(dead_code)]
    state_directory: File,
    trust_directory: File,
}

impl DelegationGenerationLease {
    pub fn current(&self) -> u64 {
        self.current
    }

    pub fn candidate(&self) -> u64 {
        self.candidate
    }

    #[allow(dead_code)]
    pub(crate) fn state_directory(&self) -> &File {
        &self.state_directory
    }

    /// Atomically advances the rollback floor before any installation state
    /// is mutated. Equal generations need no rewrite and remain accepted.
    pub fn persist_before_mutation(&mut self) -> Result<(), GenerationStateError> {
        if self.candidate < self.current {
            return Err(GenerationStateError::Rollback);
        }
        if self.candidate == self.current {
            return Ok(());
        }

        persist_generation(&self.trust_directory, self.candidate)?;
        self.current = self.candidate;
        Ok(())
    }
}

/// Acquires the production generation-state lease at its one compiled path.
pub fn acquire_delegation_generation(
    candidate: u64,
) -> Result<DelegationGenerationLease, GenerationStateError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(GenerationStateError::NotRoot);
    }
    if candidate == 0 {
        return Err(GenerationStateError::InvalidCandidate);
    }
    let state_directory = ensure_production_state_root()?;
    acquire_delegation_generation_from_directory(state_directory, 0, candidate)
}

#[cfg(test)]
fn acquire_delegation_generation_in(
    state_root: &Path,
    expected_uid: u32,
    candidate: u64,
) -> Result<DelegationGenerationLease, GenerationStateError> {
    if candidate == 0 {
        return Err(GenerationStateError::InvalidCandidate);
    }

    let state_directory = ensure_state_root(state_root, expected_uid)?;
    acquire_delegation_generation_from_directory(state_directory, expected_uid, candidate)
}

fn acquire_delegation_generation_from_directory(
    state_directory: File,
    expected_uid: u32,
    candidate: u64,
) -> Result<DelegationGenerationLease, GenerationStateError> {
    let trust_directory =
        ensure_directory_at(state_directory.as_raw_fd(), TRUST_DIRECTORY, expected_uid)?;
    let lock = open_lock_file(&trust_directory, expected_uid)?;
    lock_exclusive(&lock)?;

    // Read only after taking the lock. A concurrent activation therefore sees
    // the generation persisted by the preceding complete lease holder.
    let current = read_generation(&trust_directory, expected_uid)?;
    if candidate < current {
        return Err(GenerationStateError::Rollback);
    }

    Ok(DelegationGenerationLease {
        candidate,
        current,
        _lock: lock,
        state_directory,
        trust_directory,
    })
}

fn ensure_production_state_root() -> Result<File, GenerationStateError> {
    let root_name = c_string(b"/")?;
    let root = open_directory(root_name.as_ptr())?;
    validate_file(&root, 0, libc::S_IFDIR, 0o755)?;
    let var = open_existing_directory_at(root.as_raw_fd(), "var", 0, 0o755)?;
    let lib = open_existing_directory_at(var.as_raw_fd(), "lib", 0, 0o755)?;
    ensure_directory_at(lib.as_raw_fd(), "enoki-probe-bootstrap", 0)
}

fn open_existing_directory_at(
    parent: RawFd,
    name: &str,
    expected_uid: u32,
    expected_mode: libc::mode_t,
) -> Result<File, GenerationStateError> {
    let name = c_string(name.as_bytes())?;
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let directory = file_from_descriptor(descriptor)?;
    validate_file(&directory, expected_uid, libc::S_IFDIR, expected_mode)?;
    Ok(directory)
}

#[cfg(all(test, feature = "activator"))]
pub(crate) fn acquire_delegation_generation_for_test(
    state_root: &Path,
    candidate: u64,
) -> Result<DelegationGenerationLease, GenerationStateError> {
    acquire_delegation_generation_in(state_root, unsafe { libc::geteuid() }, candidate)
}

#[cfg(test)]
fn ensure_state_root(state_root: &Path, expected_uid: u32) -> Result<File, GenerationStateError> {
    let path = c_string(state_root.as_os_str().as_bytes())?;
    let created = unsafe { libc::mkdir(path.as_ptr(), 0o700) } == 0;
    if !created {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(GenerationStateError::Io);
        }
    }
    let file = open_directory(path.as_ptr())?;
    if created {
        set_mode(&file, 0o700)?;
    }
    validate_file(&file, expected_uid, libc::S_IFDIR, 0o700)?;
    if created {
        sync_parent_directory(state_root)?;
    }
    Ok(file)
}

fn ensure_directory_at(
    parent: RawFd,
    name: &str,
    expected_uid: u32,
) -> Result<File, GenerationStateError> {
    let name = c_string(name.as_bytes())?;
    let created = unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) } == 0;
    if !created {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(GenerationStateError::Io);
        }
    }
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let file = file_from_descriptor(descriptor)?;
    if created {
        set_mode(&file, 0o700)?;
    }
    validate_file(&file, expected_uid, libc::S_IFDIR, 0o700)?;
    if created {
        // Make the new directory entry durable before it can contain the
        // rollback floor.
        sync_descriptor(parent)?;
    }
    Ok(file)
}

fn open_directory(path: *const libc::c_char) -> Result<File, GenerationStateError> {
    let descriptor = unsafe {
        libc::open(
            path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

fn open_lock_file(directory: &File, expected_uid: u32) -> Result<File, GenerationStateError> {
    let name = c_string(LOCK_FILE.as_bytes())?;
    let (descriptor, created) = open_exclusive_or_existing(
        directory.as_raw_fd(),
        &name,
        libc::O_RDWR | libc::O_NONBLOCK,
    )?;
    let file = file_from_descriptor(descriptor)?;
    if created {
        set_mode(&file, 0o600)?;
    }
    validate_file(&file, expected_uid, libc::S_IFREG, 0o600)?;
    Ok(file)
}

fn open_exclusive_or_existing(
    directory: RawFd,
    name: &CString,
    access: libc::c_int,
) -> Result<(RawFd, bool), GenerationStateError> {
    let common = access | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let created = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            common | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    };
    if created >= 0 {
        return Ok((created, true));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EEXIST) {
        return Err(open_error(error));
    }
    let existing = unsafe { libc::openat(directory, name.as_ptr(), common) };
    if existing < 0 {
        return Err(open_error(std::io::Error::last_os_error()));
    }
    Ok((existing, false))
}

fn lock_exclusive(file: &File) -> Result<(), GenerationStateError> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(GenerationStateError::Io);
    }
    Ok(())
}

fn read_generation(directory: &File, expected_uid: u32) -> Result<u64, GenerationStateError> {
    let name = c_string(GENERATION_FILE.as_bytes())?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(0)
        } else {
            Err(open_error(error))
        };
    }
    let mut file = file_from_descriptor(descriptor)?;
    validate_file(&file, expected_uid, libc::S_IFREG, 0o600)?;
    let length = file.metadata().map_err(|_| GenerationStateError::Io)?.len();
    if length == 0 || length > MAX_CANONICAL_GENERATION_BYTES {
        return Err(GenerationStateError::Malformed);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| GenerationStateError::Io)?;
    parse_generation(&bytes)
}

fn parse_generation(bytes: &[u8]) -> Result<u64, GenerationStateError> {
    if !bytes.ends_with(b"\n") {
        return Err(GenerationStateError::Malformed);
    }
    let digits = &bytes[..bytes.len() - 1];
    if digits.is_empty()
        || !digits.iter().all(u8::is_ascii_digit)
        || (digits.len() > 1 && digits[0] == b'0')
    {
        return Err(GenerationStateError::Malformed);
    }
    let text = std::str::from_utf8(digits).map_err(|_| GenerationStateError::Malformed)?;
    text.parse().map_err(|_| GenerationStateError::Malformed)
}

fn persist_generation(directory: &File, generation: u64) -> Result<(), GenerationStateError> {
    let (temporary, mut file) = create_temporary_generation_file(directory)?;
    let final_name = c_string(GENERATION_FILE.as_bytes())?;
    let result = (|| {
        set_mode(&file, 0o600)?;
        file.write_all(format!("{generation}\n").as_bytes())
            .map_err(|_| GenerationStateError::Io)?;
        file.sync_all().map_err(|_| GenerationStateError::Io)?;
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                final_name.as_ptr(),
            )
        } != 0
        {
            return Err(GenerationStateError::Io);
        }
        directory.sync_all().map_err(|_| GenerationStateError::Io)?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}

fn create_temporary_generation_file(
    directory: &File,
) -> Result<(CString, File), GenerationStateError> {
    // A crash can leave a same-PID temporary name behind. Try a bounded set
    // of exclusive names; exhaustion fails closed without touching state.
    for _ in 0..32 {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary_name = format!(
            ".delegation-generation.tmp-{}-{sequence}",
            std::process::id()
        );
        let temporary = c_string(temporary_name.as_bytes())?;
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor >= 0 {
            return Ok((temporary, file_from_descriptor(descriptor)?));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(open_error(error));
        }
    }
    Err(GenerationStateError::Io)
}

#[cfg(test)]
fn sync_parent_directory(path: &Path) -> Result<(), GenerationStateError> {
    let parent = path.parent().ok_or(GenerationStateError::InsecureState)?;
    let parent = c_string(parent.as_os_str().as_bytes())?;
    let directory = open_directory(parent.as_ptr())?;
    directory.sync_all().map_err(|_| GenerationStateError::Io)
}

fn sync_descriptor(descriptor: RawFd) -> Result<(), GenerationStateError> {
    if unsafe { libc::fsync(descriptor) } != 0 {
        return Err(GenerationStateError::Io);
    }
    Ok(())
}

fn validate_file(
    file: &File,
    expected_uid: u32,
    expected_type: libc::mode_t,
    expected_mode: libc::mode_t,
) -> Result<(), GenerationStateError> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(GenerationStateError::Io);
    }
    let status = unsafe { status.assume_init() };
    if status.st_uid != expected_uid
        || status.st_mode & libc::S_IFMT != expected_type
        || status.st_mode & 0o7777 != expected_mode
    {
        return Err(GenerationStateError::InsecureState);
    }
    Ok(())
}

fn set_mode(file: &File, mode: libc::mode_t) -> Result<(), GenerationStateError> {
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(GenerationStateError::Io);
    }
    Ok(())
}

fn file_from_descriptor(descriptor: RawFd) -> Result<File, GenerationStateError> {
    if descriptor < 0 {
        return Err(open_error(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_error(error: std::io::Error) -> GenerationStateError {
    match error.raw_os_error() {
        Some(libc::ELOOP) | Some(libc::ENOTDIR) => GenerationStateError::InsecureState,
        _ => GenerationStateError::Io,
    }
}

fn c_string(bytes: &[u8]) -> Result<CString, GenerationStateError> {
    CString::new(bytes).map_err(|_| GenerationStateError::InsecureState)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        sync::{Arc, Barrier},
        thread,
    };
    use tempfile::tempdir;

    fn owner() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn acquire_at(
        root: &Path,
        candidate: u64,
    ) -> Result<DelegationGenerationLease, GenerationStateError> {
        acquire_delegation_generation_in(root, owner(), candidate)
    }

    #[test]
    fn missing_state_starts_at_zero_and_persists_before_mutation() {
        let temporary = tempdir().expect("temporary directory");
        let state_root = temporary.path().join("bootstrap-state");

        let mut lease = acquire_at(&state_root, 4).expect("generation lease");
        assert_eq!(lease.current(), 0);
        assert_eq!(lease.candidate(), 4);
        lease
            .persist_before_mutation()
            .expect("persist generation before mutation");
        assert_eq!(lease.current(), 4);
        drop(lease);

        assert_eq!(
            fs::read_to_string(state_root.join("trust/delegation-generation"))
                .expect("generation state"),
            "4\n"
        );
        assert_eq!(mode(&state_root), 0o700);
        assert_eq!(mode(&state_root.join("trust")), 0o700);
        assert_eq!(mode(&state_root.join("trust/delegation-generation")), 0o600);
    }

    #[test]
    fn accepts_the_same_generation_and_rejects_a_rollback() {
        let temporary = tempdir().expect("temporary directory");
        let state_root = temporary.path().join("bootstrap-state");
        let mut first = acquire_at(&state_root, 7).expect("first lease");
        first.persist_before_mutation().expect("persist first");
        drop(first);

        let mut same = acquire_at(&state_root, 7).expect("same generation");
        same.persist_before_mutation().expect("same accepted");
        drop(same);
        assert!(matches!(
            acquire_at(&state_root, 6),
            Err(GenerationStateError::Rollback)
        ));
    }

    #[test]
    fn malformed_symlinked_or_insecure_state_fails_closed() {
        for contents in ["", "01\n", "1", "-1\n", " 1\n", "18446744073709551616\n"] {
            let temporary = tempdir().expect("temporary directory");
            let state_root = prepared_root(temporary.path());
            fs::write(state_root.join("trust/delegation-generation"), contents)
                .expect("state fixture");
            fs::set_permissions(
                state_root.join("trust/delegation-generation"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("state mode");
            assert!(matches!(
                acquire_at(&state_root, 2),
                Err(GenerationStateError::Malformed)
            ));
        }

        let temporary = tempdir().expect("temporary directory");
        let state_root = prepared_root(temporary.path());
        symlink(
            temporary.path().join("outside"),
            state_root.join("trust/delegation-generation"),
        )
        .expect("state symlink");
        assert!(matches!(
            acquire_at(&state_root, 2),
            Err(GenerationStateError::InsecureState)
        ));

        let temporary = tempdir().expect("temporary directory");
        let state_root = prepared_root(temporary.path());
        fs::set_permissions(state_root.join("trust"), fs::Permissions::from_mode(0o755))
            .expect("insecure trust mode");
        assert!(matches!(
            acquire_at(&state_root, 2),
            Err(GenerationStateError::InsecureState)
        ));

        let temporary = tempdir().expect("temporary directory");
        let state_root = prepared_root(temporary.path());
        assert!(matches!(
            acquire_delegation_generation_in(&state_root, owner().wrapping_add(1), 2),
            Err(GenerationStateError::InsecureState)
        ));

        let temporary = tempdir().expect("temporary directory");
        let state_root = temporary.path().join("bootstrap-state");
        symlink(temporary.path().join("outside"), &state_root).expect("root symlink");
        assert!(matches!(
            acquire_at(&state_root, 2),
            Err(GenerationStateError::InsecureState)
        ));

        let temporary = tempdir().expect("temporary directory");
        let state_root = temporary.path().join("bootstrap-state");
        fs::create_dir(&state_root).expect("state root");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
            .expect("state root mode");
        symlink(temporary.path().join("outside"), state_root.join("trust")).expect("trust symlink");
        assert!(matches!(
            acquire_at(&state_root, 2),
            Err(GenerationStateError::InsecureState)
        ));

        let temporary = tempdir().expect("temporary directory");
        let state_root = prepared_root(temporary.path());
        fs::write(state_root.join("trust/delegation-generation"), "1\n").expect("state fixture");
        fs::set_permissions(
            state_root.join("trust/delegation-generation"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("insecure state mode");
        assert!(matches!(
            acquire_at(&state_root, 2),
            Err(GenerationStateError::InsecureState)
        ));
    }

    #[test]
    fn stale_partial_temporary_file_is_never_accepted_as_state() {
        let temporary = tempdir().expect("temporary directory");
        let state_root = prepared_root(temporary.path());
        fs::write(
            state_root.join("trust/.delegation-generation.tmp-crashed"),
            "999\n",
        )
        .expect("partial fixture");

        let mut lease = acquire_at(&state_root, 3).expect("generation lease");
        assert_eq!(lease.current(), 0);
        lease.persist_before_mutation().expect("persist generation");
        drop(lease);
        assert_eq!(
            fs::read_to_string(state_root.join("trust/delegation-generation"))
                .expect("generation state"),
            "3\n"
        );
    }

    #[test]
    fn atomic_persist_replaces_a_racing_symlink_without_following_it() {
        let temporary = tempdir().expect("temporary directory");
        let outside = temporary.path().join("outside");
        fs::write(&outside, "unchanged\n").expect("outside fixture");
        let state_root = temporary.path().join("bootstrap-state");
        let mut lease = acquire_at(&state_root, 5).expect("generation lease");
        symlink(&outside, state_root.join("trust/delegation-generation")).expect("racing symlink");

        lease.persist_before_mutation().expect("atomic persist");
        drop(lease);

        assert_eq!(fs::read_to_string(outside).expect("outside"), "unchanged\n");
        let state = state_root.join("trust/delegation-generation");
        assert!(
            fs::symlink_metadata(&state)
                .expect("state")
                .file_type()
                .is_file()
        );
        assert_eq!(fs::read_to_string(state).expect("state"), "5\n");
    }

    #[test]
    fn lease_lock_is_held_until_drop_across_processes() {
        let temporary = tempdir().expect("temporary directory");
        let state_root = temporary.path().join("bootstrap-state");
        let first = acquire_at(&state_root, 1).expect("first lease");
        let mut pipe_descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_descriptors.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // Do not keep the parent's inherited description alive in the
            // child; the new acquisition below must contend independently.
            unsafe {
                libc::close(first._lock.as_raw_fd());
            }
            unsafe {
                libc::close(pipe_descriptors[0]);
            }
            let outcome = acquire_at(&state_root, 1);
            let byte = if outcome.is_ok() { b'1' } else { b'0' };
            unsafe {
                libc::write(pipe_descriptors[1], (&byte as *const u8).cast(), 1);
                libc::_exit(0);
            }
        }

        unsafe {
            libc::close(pipe_descriptors[1]);
        }
        let flags = unsafe { libc::fcntl(pipe_descriptors[0], libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(pipe_descriptors[0], libc::F_SETFL, flags | libc::O_NONBLOCK,) },
            0
        );
        let mut byte = 0_u8;
        assert_eq!(
            unsafe { libc::read(pipe_descriptors[0], (&mut byte as *mut u8).cast(), 1) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );

        drop(first);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(
            unsafe { libc::read(pipe_descriptors[0], (&mut byte as *mut u8).cast(), 1) },
            1
        );
        unsafe {
            libc::close(pipe_descriptors[0]);
        }
        assert_eq!(byte, b'1');
    }

    #[test]
    fn concurrent_leases_serialize_and_leave_the_highest_generation() {
        let temporary = tempdir().expect("temporary directory");
        let state_root = Arc::new(temporary.path().join("bootstrap-state"));
        let start = Arc::new(Barrier::new(9));
        let mut workers = Vec::new();
        for candidate in 1..=8_u64 {
            let state_root = Arc::clone(&state_root);
            let start = Arc::clone(&start);
            workers.push(thread::spawn(move || {
                start.wait();
                match acquire_at(&state_root, candidate) {
                    Ok(mut lease) => lease.persist_before_mutation(),
                    Err(GenerationStateError::Rollback) => Ok(()),
                    Err(error) => Err(error),
                }
            }));
        }
        start.wait();
        for worker in workers {
            worker
                .join()
                .expect("worker panicked")
                .expect("worker result");
        }
        let lease = acquire_at(&state_root, 8).expect("final generation");
        assert_eq!(lease.current(), 8);
    }

    #[test]
    fn zero_is_not_a_valid_candidate_generation() {
        let temporary = tempdir().expect("temporary directory");
        assert!(matches!(
            acquire_at(&temporary.path().join("bootstrap-state"), 0),
            Err(GenerationStateError::InvalidCandidate)
        ));
    }

    #[test]
    fn production_entry_rejects_zero_before_touching_state() {
        if unsafe { libc::geteuid() } == 0 {
            assert!(matches!(
                acquire_delegation_generation(0),
                Err(GenerationStateError::InvalidCandidate)
            ));
        }
    }

    #[test]
    fn production_entry_rejects_a_non_root_process() {
        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                acquire_delegation_generation(1),
                Err(GenerationStateError::NotRoot)
            ));
            return;
        }

        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let rejected = unsafe { libc::setgid(65_534) } == 0
                && unsafe { libc::setuid(65_534) } == 0
                && matches!(
                    acquire_delegation_generation(1),
                    Err(GenerationStateError::NotRoot)
                );
            unsafe { libc::_exit(if rejected { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    fn prepared_root(parent: &Path) -> std::path::PathBuf {
        let root = parent.join("bootstrap-state");
        fs::create_dir(&root).expect("state root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("state root mode");
        fs::create_dir(root.join("trust")).expect("trust directory");
        fs::set_permissions(root.join("trust"), fs::Permissions::from_mode(0o700))
            .expect("trust mode");
        root
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }
}
