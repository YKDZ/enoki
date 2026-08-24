use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// 通过持有的目录 descriptor 发布文件；检查后不再按 pathname 解析受管父目录。
pub fn atomic_write(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    let (parent, target) = open_parent(path)
        .map_err(|error| io::Error::new(error.kind(), format!("受管父目录打开失败: {error}")))?;
    verify_private_directory(parent.raw())
        .map_err(|error| io::Error::new(error.kind(), format!("受管父目录复验失败: {error}")))?;
    reject_target_symlink(parent.raw(), &target)
        .map_err(|error| io::Error::new(error.kind(), format!("受管目标复验失败: {error}")))?;
    let temporary = temporary_name(&target)?;
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
    verify_file(parent.raw(), &target, mode, owner)
        .map_err(|error| io::Error::new(error.kind(), format!("发布文件复验失败: {error}")))
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

fn verify_file(
    parent: RawFd,
    target: &CString,
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    let stat = stat_at(parent, target)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_mode & 0o777 != mode {
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

fn stat_at(parent: RawFd, target: &CString) -> io::Result<libc::stat> {
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

fn unlink_at(parent: RawFd, target: &CString) -> io::Result<()> {
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

    use tempfile::tempdir;

    use super::atomic_write;

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
}
