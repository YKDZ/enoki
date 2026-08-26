use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const SYSTEMD_PROBE_STATE_DIRECTORY: &str = "/var/lib/enoki-probe";

/// 通过持有的目录 descriptor 发布文件；检查后不再按 pathname 解析受管父目录。
pub fn atomic_write(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    let (parent, target) = open_parent(path)
        .map_err(|error| io::Error::new(error.kind(), format!("受管父目录打开失败: {error}")))?;
    atomic_write_at(&parent, &target, path, contents, mode, owner)
}

/// 在 systemd `DynamicUser` 管理的固定 Probe state directory 中原子替换 bootstrap config。
/// 只有 root 保管的 canonical `private/<同名>` StateDirectory 链接会被解析；取得 state
/// directory descriptor 后，identity 与目标仍禁止跟随符号链接。
pub fn atomic_write_systemd_probe_bootstrap_config(contents: &[u8]) -> io::Result<()> {
    atomic_write_systemd_probe_bootstrap_config_at(
        Path::new(SYSTEMD_PROBE_STATE_DIRECTORY),
        contents,
    )
}

fn atomic_write_systemd_probe_bootstrap_config_at(
    state_directory: &Path,
    contents: &[u8],
) -> io::Result<()> {
    let (identity, service_owner) = open_systemd_probe_identity_directory(state_directory)?;
    let target = CString::new("probe-bootstrap.toml").expect("固定文件名不含 NUL");
    let path = state_directory.join("identity/probe-bootstrap.toml");
    atomic_write_at(
        &identity,
        &target,
        &path,
        contents,
        0o600,
        Some(service_owner),
    )
}

/// 读取 systemd `DynamicUser` 管理的固定 Probe bootstrap config；StateDirectory
/// 保管链与目标文件属性必须和原子写入接口完全一致。
pub fn read_systemd_probe_bootstrap_config() -> io::Result<Vec<u8>> {
    read_systemd_probe_bootstrap_config_at(Path::new(SYSTEMD_PROBE_STATE_DIRECTORY))
}

fn read_systemd_probe_bootstrap_config_at(state_directory: &Path) -> io::Result<Vec<u8>> {
    let (identity, service_owner) = open_systemd_probe_identity_directory(state_directory)?;
    let target = CString::new("probe-bootstrap.toml").expect("固定文件名不含 NUL");
    let fd = unsafe {
        libc::openat(
            identity.raw(),
            target.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let stat = stat_fd(file.as_raw_fd())?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o777 != 0o600
        || stat.st_uid != service_owner.0
        || stat.st_gid != service_owner.1
        || stat.st_nlink != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Probe bootstrap config 保管属性不匹配",
        ));
    }
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

fn open_systemd_probe_identity_directory(
    state_directory: &Path,
) -> io::Result<(DirectoryFd, (u32, u32))> {
    let service_owner = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
    let projection = open_systemd_probe_state_projection(
        state_directory,
        (0, 0),
        Some(service_owner),
        SystemdProbeStateView::ServiceConfig,
    )?;
    Ok((projection.identity, service_owner))
}

/// root finalizer 对 canonical systemd `StateDirectory` 投影的唯一受信视图。
/// public link、private parent、state 与 identity 均在持有 descriptor 后才返回。
pub(crate) struct SystemdProbeStateProjection {
    state: DirectoryFd,
    identity: DirectoryFd,
    owner: (u32, u32),
}

#[derive(Clone, Copy)]
pub(crate) enum SystemdProbeDirectory {
    State,
    Identity,
}

#[derive(Clone, Copy)]
pub(crate) struct HeldDirectoryFacts {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
}

impl SystemdProbeStateProjection {
    pub(crate) fn owner(&self) -> (u32, u32) {
        self.owner
    }

    pub(crate) fn facts(&self, directory: SystemdProbeDirectory) -> io::Result<HeldDirectoryFacts> {
        let stat = stat_fd(self.directory(directory).raw())?;
        Ok(HeldDirectoryFacts {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode & 0o7777,
        })
    }

    pub(crate) fn read_file(
        &self,
        directory: SystemdProbeDirectory,
        name: &OsStr,
    ) -> io::Result<Vec<u8>> {
        let name = component_name(name)?;
        let fd = unsafe {
            libc::openat(
                self.directory(directory).raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let stat = stat_fd(file.as_raw_fd())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_mode & 0o777 != 0o600
            || stat.st_uid != self.owner.0
            || stat.st_gid != self.owner.1
            || stat.st_nlink != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "systemd StateDirectory 文件保管属性不匹配",
            ));
        }
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Ok(contents)
    }

    pub(crate) fn remove_file(
        &self,
        directory: SystemdProbeDirectory,
        name: &OsStr,
    ) -> io::Result<()> {
        let directory = self.directory(directory);
        let name = component_name(name)?;
        unlink_at(directory.raw(), &name)?;
        sync_directory(directory.raw())
    }

    pub(crate) fn write_probe_bootstrap_config(
        &self,
        path: &Path,
        contents: &[u8],
    ) -> io::Result<()> {
        let target = CString::new("probe-bootstrap.toml").expect("固定文件名不含 NUL");
        atomic_write_at(
            &self.identity,
            &target,
            path,
            contents,
            0o600,
            Some(self.owner),
        )
    }

    fn directory(&self, directory: SystemdProbeDirectory) -> &DirectoryFd {
        match directory {
            SystemdProbeDirectory::State => &self.state,
            SystemdProbeDirectory::Identity => &self.identity,
        }
    }
}

pub(crate) fn open_systemd_probe_state_projection_for_finalization(
    state_directory: &Path,
    authority_owner: (u32, u32),
) -> io::Result<SystemdProbeStateProjection> {
    if (unsafe { libc::geteuid() }, unsafe { libc::getegid() }) != authority_owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "systemd StateDirectory finalizer authority 不匹配",
        ));
    }
    open_systemd_probe_state_projection(
        state_directory,
        authority_owner,
        None,
        SystemdProbeStateView::HostJournal,
    )
}

#[derive(Clone, Copy)]
enum SystemdProbeStateView {
    HostJournal,
    ServiceConfig,
}

impl SystemdProbeStateView {
    fn private_parent_contract(self) -> (u32, u64) {
        match self {
            Self::HostJournal => (0o700, 1),
            Self::ServiceConfig => (0o755, 2),
        }
    }
}

fn atomic_write_at(
    parent: &DirectoryFd,
    target: &CString,
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    verify_private_directory(parent.raw())
        .map_err(|error| io::Error::new(error.kind(), format!("受管父目录复验失败: {error}")))?;
    reject_target_symlink(parent.raw(), target)
        .map_err(|error| io::Error::new(error.kind(), format!("受管目标复验失败: {error}")))?;
    let temporary = temporary_name(target)?;
    let fd = unsafe {
        libc::openat(
            parent.raw(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("暂存文件打开失败: {error}"),
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let staged = (|| {
        if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if let Some((uid, gid)) = owner
            && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        file.write_all(contents)?;
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = staged {
        let _ = unlink_at(parent.raw(), &temporary);
        return Err(io::Error::new(
            error.kind(),
            format!("暂存文件写入失败: {error}"),
        ));
    }
    secure_file_effect_crash(path, "before-rename");
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
    sync_directory(parent.raw())
        .map_err(|error| io::Error::new(error.kind(), format!("受管父目录同步失败: {error}")))?;
    verify_file(parent.raw(), target, mode, owner)
        .map_err(|error| io::Error::new(error.kind(), format!("发布文件复验失败: {error}")))?;
    secure_file_effect_crash(path, "after-rename");
    Ok(())
}

fn open_systemd_probe_state_projection(
    path: &Path,
    authority_owner: (u32, u32),
    expected_service_owner: Option<(u32, u32)>,
    view: SystemdProbeStateView,
) -> io::Result<SystemdProbeStateProjection> {
    let (public_parent, public_name) = open_parent(path)?;
    verify_owned_directory(public_parent.raw(), 0o755, authority_owner, 1)?;
    let public = stat_at(public_parent.raw(), &public_name)?;
    if public.st_mode & libc::S_IFMT != libc::S_IFLNK
        || public.st_mode & 0o777 != 0o777
        || public.st_uid != authority_owner.0
        || public.st_gid != authority_owner.1
        || public.st_nlink != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "systemd StateDirectory 链接保管属性不匹配",
        ));
    }
    let private = public_parent.open_child(OsStr::new("private"))?;
    let (private_mode, private_minimum_links) = view.private_parent_contract();
    verify_owned_directory(
        private.raw(),
        private_mode,
        authority_owner,
        private_minimum_links,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("systemd private state parent 保管属性不匹配: {error}"),
        )
    })?;
    let expected_target = format!("private/{}", public_name.to_string_lossy());
    if read_link_at(public_parent.raw(), &public_name)?.as_slice() != expected_target.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "systemd StateDirectory 链接目标不匹配",
        ));
    }
    let state = private.open_child(OsStr::from_bytes(public_name.to_bytes()))?;
    let state_stat = stat_fd(state.raw())?;
    let service_owner = (state_stat.st_uid, state_stat.st_gid);
    if expected_service_owner.is_some_and(|expected| expected != service_owner) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "systemd StateDirectory service owner 不匹配",
        ));
    }
    verify_owned_directory(state.raw(), 0o750, service_owner, 2)?;
    let identity = state.open_child(OsStr::new("identity"))?;
    verify_owned_directory(identity.raw(), 0o700, service_owner, 2)?;
    let followed = stat_following_at(public_parent.raw(), &public_name)?;
    let opened = stat_fd(state.raw())?;
    if followed.st_dev != opened.st_dev || followed.st_ino != opened.st_ino {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "systemd StateDirectory 在打开期间发生变化",
        ));
    }
    Ok(SystemdProbeStateProjection {
        state,
        identity,
        owner: service_owner,
    })
}

#[cfg(feature = "deterministic-test-seams")]
fn secure_file_effect_crash(path: &Path, point: &str) {
    if std::env::var_os("ENOKI_TEST_SECURE_FILE_PATH").as_deref() == Some(path.as_os_str())
        && std::env::var("ENOKI_TEST_SECURE_FILE_CRASH_POINT").as_deref() == Ok(point)
    {
        std::process::abort();
    }
}

#[cfg(not(feature = "deterministic-test-seams"))]
fn secure_file_effect_crash(_path: &Path, _point: &str) {}

/// 通过持有的禁止跟随符号链接目录描述符，删除指定的 root 私有普通文件，
/// 并对命名空间更新执行 fsync。
pub fn remove_private_regular_file(path: &Path, mode: u32, owner: (u32, u32)) -> io::Result<()> {
    let (parent, target) = open_parent(path)?;
    verify_private_directory(parent.raw())?;
    verify_file(parent.raw(), &target, mode, Some(owner))?;
    secure_file_effect_crash(path, "before-unlink");
    unlink_at(parent.raw(), &target)?;
    sync_directory(parent.raw())?;
    secure_file_effect_crash(path, "after-unlink");
    Ok(())
}

pub(crate) fn retire_replacement_atomic_write_residue(
    path: &Path,
    mode: u32,
    owner: (u32, u32),
) -> io::Result<()> {
    let (parent, target) = open_parent(path)?;
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
    let mut removed = false;
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
        if !is_atomic_write_residue(name.to_bytes(), target.as_bytes()) {
            continue;
        }
        let metadata = stat_at(parent.raw(), name)?;
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || metadata.st_mode & 0o777 != mode
            || metadata.st_uid != owner.0
            || metadata.st_gid != owner.1
            || metadata.st_nlink != 1
        {
            break Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "atomic write residue attributes do not match",
            ));
        }
        unlink_at(parent.raw(), name)?;
        removed = true;
    };
    if unsafe { libc::closedir(directory) } != 0 && result.is_ok() {
        return Err(io::Error::last_os_error());
    }
    result?;
    if removed {
        sync_directory(parent.raw())?;
    }
    Ok(())
}

fn is_atomic_write_residue(name: &[u8], target: &[u8]) -> bool {
    let mut prefix = Vec::with_capacity(target.len() + 14);
    prefix.push(b'.');
    prefix.extend_from_slice(target);
    prefix.extend_from_slice(b"-enoki-write-");
    let Some(suffix) = name.strip_prefix(prefix.as_slice()) else {
        return false;
    };
    let Some(separator) = suffix.iter().position(|byte| *byte == b'-') else {
        return false;
    };
    let (process, sequence) = (&suffix[..separator], &suffix[separator + 1..]);
    !process.is_empty()
        && process.iter().all(u8::is_ascii_digit)
        && !sequence.is_empty()
        && sequence.iter().all(u8::is_ascii_digit)
}

fn open_parent(path: &Path) -> io::Result<(DirectoryFd, CString)> {
    let components = absolute_components(path)?;
    let (target, parents) = components
        .split_last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "受管路径缺少文件名"))?;
    let mut directory = DirectoryFd::root()?;
    for component in parents {
        directory = directory.open_child(component).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("目录分量 {:?} 打开失败: {error}", component),
            )
        })?;
    }
    Ok((directory, component_name(target)?))
}

fn absolute_components(path: &Path) -> io::Result<Vec<&OsStr>> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "受管路径必须是非根绝对路径",
        ));
    }
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(name) => Some(Ok(name)),
            _ => Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "受管路径包含不安全分量",
            ))),
        })
        .collect()
}

struct DirectoryFd(OwnedFd);

impl DirectoryFd {
    fn root() -> io::Result<Self> {
        let root = CString::new("/").expect("固定根路径不含 NUL");
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        (fd >= 0)
            .then(|| Self(unsafe { OwnedFd::from_raw_fd(fd) }))
            .ok_or_else(io::Error::last_os_error)
    }

    fn open_child(&self, child: &OsStr) -> io::Result<Self> {
        let name = component_name(child)?;
        let fd = unsafe {
            libc::openat(
                self.raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        (fd >= 0)
            .then(|| Self(unsafe { OwnedFd::from_raw_fd(fd) }))
            .ok_or_else(io::Error::last_os_error)
    }

    fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

fn component_name(component: &OsStr) -> io::Result<CString> {
    let bytes = component.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "受管路径分量不安全",
        ));
    }
    CString::new(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "受管路径包含 NUL"))
}

fn reject_target_symlink(parent: RawFd, target: &CString) -> io::Result<()> {
    match stat_at(parent, target) {
        Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFLNK => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "受管目标不得是符号链接",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn temporary_name(target: &CString) -> io::Result<CString> {
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    CString::new(format!(
        ".{}-enoki-write-{}-{sequence}",
        target.to_string_lossy(),
        std::process::id()
    ))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "临时文件名不安全"))
}

fn verify_private_directory(fd: RawFd) -> io::Result<()> {
    let stat = stat_fd(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR || stat.st_mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "受管父目录不安全",
        ));
    }
    Ok(())
}

fn verify_owned_directory(
    fd: RawFd,
    mode: u32,
    owner: (u32, u32),
    minimum_links: u64,
) -> io::Result<()> {
    let stat = stat_fd(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_mode & 0o777 != mode
        || stat.st_uid != owner.0
        || stat.st_gid != owner.1
        || stat.st_nlink < minimum_links
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "受管目录保管属性不匹配",
        ));
    }
    Ok(())
}

fn verify_file(
    parent: RawFd,
    target: &CString,
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    let stat = stat_at(parent, target)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o777 != mode
        || stat.st_nlink != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "受管文件属性不匹配",
        ));
    }
    if let Some((uid, gid)) = owner
        && (stat.st_uid != uid || stat.st_gid != gid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "受管文件 owner 不匹配",
        ));
    }
    Ok(())
}

fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } == 0 {
        Ok(stat)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn stat_at(parent: RawFd, target: &CStr) -> io::Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent,
            target.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        Ok(stat)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn stat_following_at(parent: RawFd, target: &CStr) -> io::Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, target.as_ptr(), &mut stat, 0) } == 0 {
        Ok(stat)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn read_link_at(parent: RawFd, target: &CStr) -> io::Result<Vec<u8>> {
    let mut bytes = [0_u8; 4096];
    let length = unsafe {
        libc::readlinkat(
            parent,
            target.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "链接长度无效"))?;
    if length == bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "systemd StateDirectory 链接目标过长",
        ));
    }
    Ok(bytes[..length].to_vec())
}

fn unlink_at(parent: RawFd, target: &CStr) -> io::Result<()> {
    if unsafe { libc::unlinkat(parent, target.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn sync_directory(fd: RawFd) -> io::Result<()> {
    if unsafe { libc::fsync(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, fs::symlink},
    };

    use tempfile::{TempDir, tempdir};

    use super::{
        atomic_write, atomic_write_systemd_probe_bootstrap_config_at,
        open_systemd_probe_state_projection_for_finalization,
        read_systemd_probe_bootstrap_config_at,
    };

    struct SystemdStateLayout {
        _root: TempDir,
        identity: std::path::PathBuf,
        private: std::path::PathBuf,
        private_state: std::path::PathBuf,
        public: std::path::PathBuf,
        public_parent: std::path::PathBuf,
        target: std::path::PathBuf,
    }

    fn systemd_state_layout(private_mode: u32) -> SystemdStateLayout {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let public_parent = root.path().join("var/lib");
        let private = public_parent.join("private");
        let private_state = private.join("enoki-probe");
        let identity = private_state.join("identity");
        fs::create_dir_all(&identity).unwrap();
        fs::set_permissions(&public_parent, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(private_mode)).unwrap();
        fs::set_permissions(&private_state, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o700)).unwrap();
        let public = public_parent.join("enoki-probe");
        symlink("private/enoki-probe", &public).unwrap();
        let target = identity.join("probe-bootstrap.toml");
        fs::write(&target, b"before").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        SystemdStateLayout {
            _root: root,
            identity,
            private,
            private_state,
            public,
            public_parent,
            target,
        }
    }

    #[test]
    fn atomic_write_rejects_a_symlink_target_without_touching_its_referent() {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let referent = root.path().join("referent");
        fs::write(&referent, "原值".as_bytes()).unwrap();
        let target = root.path().join("commit.json");
        symlink(&referent, &target).unwrap();

        assert!(atomic_write(&target, "新值".as_bytes(), 0o600, None).is_err());
        assert_eq!(fs::read(referent).unwrap(), "原值".as_bytes());
        assert!(
            fs::symlink_metadata(target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn atomic_write_publishes_a_private_file_and_leaves_no_candidate() {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.path().join("commit.json");

        atomic_write(&target, "事实".as_bytes(), 0o600, None).unwrap();

        assert_eq!(fs::read(&target).unwrap(), "事实".as_bytes());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn systemd_state_writer_atomically_replaces_identity_through_the_canonical_link() {
        let layout = systemd_state_layout(0o755);

        assert_eq!(
            read_systemd_probe_bootstrap_config_at(&layout.public).unwrap(),
            b"before"
        );
        assert!(
            atomic_write(
                &layout.public.join("identity/probe-bootstrap.toml"),
                b"generic",
                0o600,
                None,
            )
            .is_err(),
            "generic writer must continue rejecting parent symlinks"
        );
        atomic_write_systemd_probe_bootstrap_config_at(&layout.public, b"after").unwrap();

        assert_eq!(fs::read(&layout.target).unwrap(), b"after");
        assert!(
            fs::symlink_metadata(&layout.public)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(&layout.public).unwrap(),
            std::path::Path::new("private/enoki-probe")
        );
        assert_eq!(fs::read_dir(&layout.identity).unwrap().count(), 1);
    }

    #[test]
    fn systemd_state_writer_rejects_tampered_custody_without_writing() {
        for tamper in [
            "public-parent",
            "private-parent",
            "state",
            "link-target",
            "destination-link",
        ] {
            let layout = systemd_state_layout(0o755);
            match tamper {
                "public-parent" => {
                    fs::set_permissions(&layout.public_parent, fs::Permissions::from_mode(0o777))
                        .unwrap()
                }
                "private-parent" => {
                    fs::set_permissions(&layout.private, fs::Permissions::from_mode(0o777)).unwrap()
                }
                "state" => fs::set_permissions(
                    layout.target.parent().unwrap().parent().unwrap(),
                    fs::Permissions::from_mode(0o770),
                )
                .unwrap(),
                "link-target" => {
                    fs::remove_file(&layout.public).unwrap();
                    symlink("private/../private/enoki-probe", &layout.public).unwrap();
                }
                "destination-link" => {
                    let referent = layout.private.join("enoki-probe-referent");
                    fs::rename(&layout.private_state, &referent).unwrap();
                    symlink("enoki-probe-referent", &layout.private_state).unwrap();
                }
                _ => unreachable!(),
            }

            assert!(
                atomic_write_systemd_probe_bootstrap_config_at(&layout.public, b"after").is_err(),
                "tamper {tamper} must fail closed"
            );
            assert_eq!(fs::read(&layout.target).unwrap(), b"before");
        }
    }

    #[test]
    fn systemd_state_views_require_their_exact_private_parent_contract() {
        let service_view = systemd_state_layout(0o755);
        assert!(read_systemd_probe_bootstrap_config_at(&service_view.public).is_ok());
        assert!(
            open_systemd_probe_state_projection_for_finalization(
                &service_view.public,
                (unsafe { libc::geteuid() }, unsafe { libc::getegid() }),
            )
            .is_err(),
            "host journal view must reject the service namespace projection"
        );

        let host_view = systemd_state_layout(0o700);
        assert!(read_systemd_probe_bootstrap_config_at(&host_view.public).is_err());
        assert!(
            open_systemd_probe_state_projection_for_finalization(
                &host_view.public,
                (unsafe { libc::geteuid() }, unsafe { libc::getegid() }),
            )
            .is_ok(),
            "host journal view accepts only the root-private host projection"
        );
    }
}
