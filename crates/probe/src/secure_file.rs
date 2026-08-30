use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
};

const SYSTEMD_PROBE_CREDENTIAL_DIRECTORY: &str = "/run/credentials/enoki-probe.service";
const SYSTEMD_REGISTRATION_CREDENTIAL_NAME: &str = "registration-attempt";
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;

#[cfg(test)]
use std::{
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(test)]
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
    let _ = open_parent(path, true)?;
    enoki_probe_bootstrap::secure_file::atomic_write(path, contents, mode, owner)
}

#[cfg(test)]
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

pub fn remove_regular_file(path: &Path, mode: u32, owner: Option<(u32, u32)>) -> io::Result<()> {
    let (parent, target) = open_parent(path, false)?;
    verify_private_directory(parent.raw())?;
    verify_file_at(parent.raw(), &target, mode, owner)?;
    unlink_at(parent.raw(), &target)?;
    sync_directory(parent.raw())
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

/// 读取私有持久化注册尝试材料，并通过持有的目录文件描述符校验其所有者、模式、大小、
/// 普通文件类型与单硬链接保管约束。
pub fn read_private_regular_file(
    path: &Path,
    mode: u32,
    owner: (u32, u32),
    maximum_bytes: usize,
) -> io::Result<Vec<u8>> {
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
    let stat = stat_fd(file.as_raw_fd())?;
    if file_type(stat.st_mode) != libc::S_IFREG
        || stat.st_mode & 0o777 != mode
        || stat.st_uid != owner.0
        || stat.st_gid != owner.1
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as usize > maximum_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed private file attributes do not match",
        ));
    }
    let mut contents = Vec::with_capacity(stat.st_size as usize);
    Read::by_ref(&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut contents)?;
    if contents.len() > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed private file is too large",
        ));
    }
    Ok(contents)
}

/// Rejects any unresolved atomic-write sibling for the managed target while
/// holding its verified parent directory. A prior publisher may have crashed
/// before rename; callers must not guess whether those bytes can be discarded.
pub fn reject_atomic_write_residue(path: &Path) -> io::Result<()> {
    let (parent, target) = open_parent(path, false)?;
    verify_private_directory(parent.raw())?;
    let duplicate = unsafe { libc::fcntl(parent.raw(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    let mut prefix = Vec::with_capacity(target.as_bytes().len() + 14);
    prefix.push(b'.');
    prefix.extend_from_slice(target.as_bytes());
    prefix.extend_from_slice(b"-enoki-write-");
    let result = loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            break if error.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(error)
            };
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes().starts_with(&prefix) {
            break Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unresolved registration capsule atomic-write residue",
            ));
        }
    };
    if unsafe { libc::closedir(directory) } != 0 && result.is_ok() {
        return Err(io::Error::last_os_error());
    }
    result
}

/// 读取大小受限的一次性 systemd 凭据。该凭据可归 root 或 DynamicUser
/// 服务身份所有，但必须是组用户与其他用户均无权限的单硬链接普通文件。
pub fn read_bounded_private_credential(path: &Path, maximum_bytes: usize) -> io::Result<Vec<u8>> {
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
    let stat = stat_fd(file.as_raw_fd())?;
    let service_owner = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
    if file_type(stat.st_mode) != libc::S_IFREG
        || stat.st_mode & 0o077 != 0
        || !matches!(stat.st_mode & 0o700, 0o400 | 0o600)
        || ((stat.st_uid, stat.st_gid) != (0, 0) && (stat.st_uid, stat.st_gid) != service_owner)
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as usize > maximum_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registration credential attributes do not match",
        ));
    }
    let mut contents = Vec::with_capacity(stat.st_size as usize);
    Read::by_ref(&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut contents)?;
    (contents.len() <= maximum_bytes)
        .then_some(contents)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "registration credential is too large",
            )
        })
}

/// 读取 Replacement registration 的一次性交付材料。有 systemd credential 环境时，
/// 只接受 canonical Probe service 的固定凭据；其他调用继续使用持久 root-private capsule
/// 的原有校验规则。
pub fn read_registration_attempt_credential_bytes(
    path: &Path,
    maximum_bytes: usize,
) -> io::Result<Vec<u8>> {
    let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
        return read_bounded_private_credential(path, maximum_bytes);
    };
    let directory = Path::new(&directory);
    let expected_directory = Path::new(SYSTEMD_PROBE_CREDENTIAL_DIRECTORY);
    let expected_path = expected_directory.join(SYSTEMD_REGISTRATION_CREDENTIAL_NAME);
    if directory != expected_directory || path != expected_path {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registration credential path does not match systemd delivery",
        ));
    }
    read_systemd_registration_credential(path, maximum_bytes)
}

fn read_systemd_registration_credential(path: &Path, maximum_bytes: usize) -> io::Result<Vec<u8>> {
    let (parent, target) = open_parent(path, false)?;
    let directory = stat_fd(parent.raw())?;
    if file_type(directory.st_mode) != libc::S_IFDIR
        || directory.st_mode & 0o777 != 0o550
        || directory.st_uid != 0
        || directory.st_gid != 0
        || directory.st_nlink != 2
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "systemd registration credential directory attributes do not match",
        ));
    }
    let filesystem = statfs_fd(parent.raw())?;
    let mount = statvfs_fd(parent.raw())?;
    let required_flags = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    if filesystem.f_type != TMPFS_MAGIC || mount.f_flag & required_flags != required_flags {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "systemd registration credential mount attributes do not match",
        ));
    }
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
    let stat = stat_fd(file.as_raw_fd())?;
    if file_type(stat.st_mode) != libc::S_IFREG
        || stat.st_mode & 0o777 != 0o440
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as usize > maximum_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "systemd registration credential attributes do not match",
        ));
    }
    let mut contents = Vec::with_capacity(stat.st_size as usize);
    Read::by_ref(&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut contents)?;
    (contents.len() <= maximum_bytes)
        .then_some(contents)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "registration credential is too large",
            )
        })
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

fn statfs_fd(fd: RawFd) -> io::Result<libc::statfs> {
    let mut stat = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::fstatfs(fd, &mut stat) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(stat)
    }
}

fn statvfs_fd(fd: RawFd) -> io::Result<libc::statvfs> {
    let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::fstatvfs(fd, &mut stat) } != 0 {
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
        process::Command,
    };

    const SYSTEMD_CREDENTIAL_CHILD: &str = "ENOKI_TEST_SYSTEMD_CREDENTIAL_CHILD";
    const SYSTEMD_CREDENTIAL_DIRECTORY: &str = "/run/credentials/enoki-probe.service";
    const SYSTEMD_CREDENTIAL_PATH: &str =
        "/run/credentials/enoki-probe.service/registration-attempt";

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

    #[test]
    fn systemd_delivered_registration_credential_is_exact_and_fail_closed() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let status = Command::new("unshare")
            .args([
                "--mount",
                std::env::current_exe()
                    .expect("current test executable")
                    .to_str()
                    .expect("UTF-8 test executable"),
                "--exact",
                "secure_file::tests::systemd_delivered_registration_credential_child",
                "--nocapture",
            ])
            .env(SYSTEMD_CREDENTIAL_CHILD, "1")
            .status()
            .expect("run credential contract in an isolated mount namespace");
        assert!(status.success(), "credential contract child succeeds");
    }

    #[test]
    fn systemd_delivered_registration_credential_child() {
        if std::env::var_os(SYSTEMD_CREDENTIAL_CHILD).is_none() {
            return;
        }

        for tamper in [
            "none",
            "directory-owner",
            "directory-mode",
            "file-owner",
            "file-mode",
            "hardlink",
            "symlink",
            "path",
            "writable-mount",
        ] {
            mount_systemd_credential(tamper);
            unsafe {
                std::env::set_var("CREDENTIALS_DIRECTORY", SYSTEMD_CREDENTIAL_DIRECTORY);
            }
            let path = if tamper == "path" {
                Path::new(SYSTEMD_CREDENTIAL_DIRECTORY).join("other-attempt")
            } else {
                Path::new(SYSTEMD_CREDENTIAL_PATH).to_path_buf()
            };
            let result = read_registration_attempt_credential_bytes(&path, 1024);
            if tamper == "none" {
                assert_eq!(result.expect("canonical systemd credential"), b"canonical");
            } else {
                assert!(result.is_err(), "tamper {tamper} must fail closed");
            }
            unsafe {
                std::env::remove_var("CREDENTIALS_DIRECTORY");
            }
            assert_eq!(
                unsafe {
                    libc::umount2(
                        CString::new(SYSTEMD_CREDENTIAL_DIRECTORY).unwrap().as_ptr(),
                        libc::MNT_DETACH,
                    )
                },
                0,
                "credential tmpfs unmounts",
            );
        }
        fs::remove_dir(SYSTEMD_CREDENTIAL_DIRECTORY).expect("remove credential mountpoint");
    }

    fn mount_systemd_credential(tamper: &str) {
        fs::create_dir_all(SYSTEMD_CREDENTIAL_DIRECTORY).expect("credential mountpoint");
        let source = CString::new("tmpfs").unwrap();
        let target = CString::new(SYSTEMD_CREDENTIAL_DIRECTORY).unwrap();
        let kind = CString::new("tmpfs").unwrap();
        let data = CString::new("size=1m,mode=0550").unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    kind.as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSYMFOLLOW,
                    data.as_ptr().cast(),
                )
            },
            0,
            "credential tmpfs mounts",
        );
        let path = Path::new(SYSTEMD_CREDENTIAL_PATH);
        fs::write(path, b"canonical").expect("credential contents");
        fs::set_permissions(path, fs::Permissions::from_mode(0o440)).expect("credential mode");
        match tamper {
            "directory-owner" => assert_eq!(unsafe { libc::chown(target.as_ptr(), 1, 1) }, 0),
            "directory-mode" => fs::set_permissions(
                SYSTEMD_CREDENTIAL_DIRECTORY,
                fs::Permissions::from_mode(0o750),
            )
            .expect("tampered directory mode"),
            "file-owner" => {
                let path = CString::new(SYSTEMD_CREDENTIAL_PATH).unwrap();
                assert_eq!(unsafe { libc::chown(path.as_ptr(), 1, 1) }, 0);
            }
            "file-mode" => fs::set_permissions(path, fs::Permissions::from_mode(0o400))
                .expect("tampered credential mode"),
            "hardlink" => fs::hard_link(path, path.with_file_name("registration-copy"))
                .expect("tampered hard link"),
            "symlink" => {
                fs::rename(path, path.with_file_name("registration-referent"))
                    .expect("move credential referent");
                symlink("registration-referent", path).expect("tampered credential symlink");
            }
            "none" | "path" | "writable-mount" => {}
            _ => unreachable!(),
        }
        if tamper != "writable-mount" {
            assert_eq!(
                unsafe {
                    libc::mount(
                        std::ptr::null(),
                        target.as_ptr(),
                        std::ptr::null(),
                        libc::MS_REMOUNT
                            | libc::MS_RDONLY
                            | libc::MS_NOSUID
                            | libc::MS_NODEV
                            | libc::MS_NOEXEC
                            | libc::MS_NOSYMFOLLOW,
                        std::ptr::null(),
                    )
                },
                0,
                "credential tmpfs becomes read-only",
            );
        }
    }
}
