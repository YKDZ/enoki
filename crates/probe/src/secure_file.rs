use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Creates a no-follow temporary sibling through held directory file descriptors,
/// writes and fsyncs it, then atomically renames it into place with `renameat`.
/// No managed path component is ever resolved through a pathname after it has
/// been checked, so a concurrent directory replacement cannot redirect a write.
pub fn atomic_write(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    atomic_write_with_before_rename(path, contents, mode, owner, || Ok(()))
}

fn atomic_write_with_before_rename(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
    before_rename: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let (parent, target) = open_parent(path, true)?;
    verify_private_directory(parent.raw())?;
    reject_target_symlink(parent.raw(), &target)?;

    let temporary = temporary_name(&target)?;
    let temporary_fd = open_new_file(parent.raw(), &temporary, mode)?;
    let mut file = unsafe { File::from_raw_fd(temporary_fd) };
    let write_result = (|| {
        set_file_attributes(file.as_raw_fd(), mode, owner)?;
        file.write_all(contents)?;
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = unlink_at(parent.raw(), &temporary);
        return Err(error);
    }

    before_rename()?;

    if unsafe {
        libc::renameat(
            parent.raw(),
            temporary.as_ptr(),
            parent.raw(),
            target.as_ptr(),
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        let _ = unlink_at(parent.raw(), &temporary);
        return Err(error);
    }
    sync_directory(parent.raw())?;
    verify_file_at(parent.raw(), &target, mode, owner)
}

/// Creates or opens a managed directory through held directory FDs, then applies
/// and verifies its exact permissions and owner.
pub fn ensure_directory(path: &Path, mode: u32, owner: Option<(u32, u32)>) -> io::Result<()> {
    let directory = open_directory(path, true)?;
    set_file_attributes(directory.raw(), mode, owner)?;
    // Persist both the directory inode attributes and the parent entry.  The
    // held descriptors keep this durability boundary independent of a later
    // pathname replacement.
    sync_directory(directory.raw())?;
    let (parent, _) = open_parent(path, false)?;
    sync_directory(parent.raw())?;
    verify_directory(directory.raw(), mode, owner)
}

/// Returns whether a managed target exists after traversing every extant parent
/// through no-follow directory FDs. A symlink in the parent chain is an error.
pub fn managed_path_exists(path: &Path) -> io::Result<bool> {
    let (parent, target) = match open_parent(path, false) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    match stat_at(parent.raw(), &target) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Reads an existing managed regular file through held no-follow directory FDs.
/// This is for the registration handoff, which preserves installer-owned fields
/// before atomically replacing the bootstrap identity.
pub fn read_regular_file(path: &Path) -> io::Result<Vec<u8>> {
    let (parent, target) = open_parent(path, false)?;
    verify_private_directory(parent.raw())?;
    let fd = unsafe {
        libc::openat(
            parent.raw(),
            target.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    if file_type(stat_fd(file.as_raw_fd())?.st_mode) != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed target must be a regular non-symlink file",
        ));
    }
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

fn open_parent(path: &Path, create: bool) -> io::Result<(DirectoryFd, CString)> {
    let components = absolute_components(path)?;
    let (target, parents) = components.split_last().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed path has no target name",
        )
    })?;
    let mut directory = DirectoryFd::root()?;
    for component in parents {
        directory = directory.open_child(component, create)?;
    }
    Ok((directory, component_name(target)?))
}

fn open_directory(path: &Path, create: bool) -> io::Result<DirectoryFd> {
    let mut directory = DirectoryFd::root()?;
    for component in absolute_components(path)? {
        directory = directory.open_child(component, create)?;
    }
    Ok(directory)
}

fn absolute_components(path: &Path) -> io::Result<Vec<&OsStr>> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed path must be a non-root absolute path",
        ));
    }

    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "managed path contains an unsafe component",
                ));
            }
        }
    }
    Ok(components)
}

struct DirectoryFd(RawFd);

impl DirectoryFd {
    fn root() -> io::Result<Self> {
        let root = CString::new("/").expect("root has no NUL");
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(fd))
        }
    }

    fn open_child(self, child: &OsStr, create: bool) -> io::Result<Self> {
        let name = component_name(child)?;
        let fd = open_directory_at(self.raw(), &name);
        if fd >= 0 {
            return Ok(Self(fd));
        }
        let error = io::Error::last_os_error();
        if !create || error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
        if unsafe { libc::mkdirat(self.raw(), name.as_ptr(), 0o755) } != 0 {
            let mkdir_error = io::Error::last_os_error();
            if mkdir_error.kind() != io::ErrorKind::AlreadyExists {
                return Err(mkdir_error);
            }
        }
        // A successful mkdirat changes the parent directory.  Make that
        // namespace entry durable before continuing to configure the child.
        sync_directory(self.raw())?;
        let fd = open_directory_at(self.raw(), &name);
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(fd))
        }
    }

    fn raw(&self) -> RawFd {
        self.0
    }
}

impl Drop for DirectoryFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

fn component_name(component: &OsStr) -> io::Result<CString> {
    let bytes = component.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed path component is unsafe",
        ));
    }
    CString::new(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed path component contains a NUL byte",
        )
    })
}

fn open_directory_at(parent: RawFd, name: &CString) -> RawFd {
    unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    }
}

fn reject_target_symlink(parent: RawFd, name: &CString) -> io::Result<()> {
    match stat_at(parent, name) {
        Ok(stat) if file_type(stat.st_mode) == libc::S_IFLNK => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed target must not be a symlink",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn open_new_file(parent: RawFd, name: &CString, mode: u32) -> io::Result<RawFd> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn temporary_name(target: &CString) -> io::Result<CString> {
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    CString::new(format!(
        ".{}-enoki-write-{}-{sequence}",
        target.to_string_lossy(),
        std::process::id(),
    ))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "temporary name is unsafe"))
}

fn unlink_at(parent: RawFd, name: &CString) -> io::Result<()> {
    if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn sync_directory(directory: RawFd) -> io::Result<()> {
    if unsafe { libc::fsync(directory) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_file_attributes(fd: RawFd, mode: u32, owner: Option<(u32, u32)>) -> io::Result<()> {
    if unsafe { libc::fchmod(fd, mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if let Some((uid, gid)) = owner
        && unsafe { libc::fchown(fd, uid, gid) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn verify_private_directory(fd: RawFd) -> io::Result<()> {
    let stat = stat_fd(fd)?;
    if file_type(stat.st_mode) != libc::S_IFDIR || stat.st_mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed parent must be a private directory",
        ));
    }
    Ok(())
}

fn verify_directory(fd: RawFd, mode: u32, owner: Option<(u32, u32)>) -> io::Result<()> {
    let stat = stat_fd(fd)?;
    if file_type(stat.st_mode) != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed target must be a directory",
        ));
    }
    verify_mode_and_owner(&stat, mode, owner)
}

fn verify_file_at(
    parent: RawFd,
    name: &CString,
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    let stat = stat_at(parent, name)?;
    if file_type(stat.st_mode) != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed target must be a regular non-symlink file",
        ));
    }
    verify_mode_and_owner(&stat, mode, owner)
}

fn verify_mode_and_owner(
    stat: &libc::stat,
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    if stat.st_mode & 0o777 != mode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed target mode does not match its required mode",
        ));
    }
    if let Some((uid, gid)) = owner
        && (stat.st_uid != uid || stat.st_gid != gid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed target owner does not match its required owner",
        ));
    }
    Ok(())
}

fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(stat)
    }
}

fn stat_at(parent: RawFd, name: &CString) -> io::Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(stat)
    }
}

fn file_type(mode: libc::mode_t) -> libc::mode_t {
    mode & libc::S_IFMT
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };

    #[test]
    fn atomic_write_rejects_a_dangling_target_symlink_without_following_it() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let target = temporary.path().join("managed/config.toml");
        let outside = temporary.path().join("outside.toml");
        fs::create_dir(target.parent().expect("parent")).expect("managed parent");
        symlink(&outside, &target).expect("dangling target symlink");

        let error =
            atomic_write(&target, b"new", 0o600, None).expect_err("dangling target is rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.exists());
    }

    #[test]
    fn atomic_write_keeps_using_its_held_parent_fd_if_the_path_is_replaced() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let managed = temporary.path().join("managed");
        let original = temporary.path().join("managed-original");
        let outside = temporary.path().join("outside");
        fs::create_dir(&managed).expect("managed directory");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
            .expect("private managed directory");
        fs::create_dir(&outside).expect("outside directory");
        let target = managed.join("probe-bootstrap.toml");

        atomic_write_with_before_rename(&target, b"identity", 0o600, None, || {
            fs::rename(&managed, &original)?;
            symlink(&outside, &managed)?;
            Ok(())
        })
        .expect("write through held parent fd");

        assert_eq!(
            fs::read_to_string(original.join("probe-bootstrap.toml")).expect("original target"),
            "identity",
        );
        assert!(!outside.join("probe-bootstrap.toml").exists());
    }

    #[test]
    fn service_identity_can_atomically_replace_its_bootstrap_from_a_private_owned_directory() {
        if unsafe { libc::geteuid() } != 0 {
            // A real privilege-drop assertion requires a root test runner; the
            // production boundary is still covered whenever that privilege is
            // available (as in the release Host harness).
            return;
        }
        let nobody = CString::new("nobody").expect("account name");
        let account = unsafe { libc::getpwnam(nobody.as_ptr()) };
        assert!(!account.is_null(), "nobody account is available");
        let uid = unsafe { (*account).pw_uid };
        let gid = unsafe { (*account).pw_gid };
        let temporary = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))
            .expect("service can traverse test root");
        let state = temporary.path().join("state");
        let identity = state.join("identity");
        let bootstrap = identity.join("probe-bootstrap.toml");
        ensure_directory(&state, 0o750, Some((uid, gid))).expect("service state");
        ensure_directory(&identity, 0o700, Some((uid, gid))).expect("identity directory");
        atomic_write(&bootstrap, b"before", 0o600, Some((uid, gid))).expect("initial bootstrap");

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork succeeds");
        if child == 0 {
            let result = unsafe { libc::setgid(gid) };
            if result != 0 || unsafe { libc::setuid(uid) } != 0 {
                unsafe { libc::_exit(1) };
            }
            let exit = atomic_write(&bootstrap, b"after", 0o600, Some((uid, gid)))
                .map(|_| 0)
                .unwrap_or(2);
            unsafe { libc::_exit(exit) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(fs::read(&bootstrap).expect("replaced bootstrap"), b"after");
        let metadata = fs::metadata(&identity).expect("identity metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.gid(), gid);
    }
}
