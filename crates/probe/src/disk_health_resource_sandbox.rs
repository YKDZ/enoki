//! Disk Health Resource Provider 的构建期固定文件系统边界。

use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;
pub const SMARTCTL_CANDIDATES: &[&str] = &["/usr/sbin/smartctl", "/usr/bin/smartctl"];
const FIXED_RUNTIME_READ_ROOTS: &[&str] = &["/lib", "/lib64", "/usr/lib", "/dev"];

#[derive(Debug)]
pub struct DiskHealthResourceSandboxError;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

pub fn enforce_disk_health_resource_read_allowlist() -> Result<(), DiskHealthResourceSandboxError> {
    if landlock_abi()? < 1 {
        return Err(DiskHealthResourceSandboxError);
    }
    let attr = RulesetAttr {
        handled_access_fs: ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR,
    };
    // SAFETY: attr 是固定大小的 ABI 1 ruleset 描述。
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            std::mem::size_of::<RulesetAttr>(),
            0,
        )
    };
    if ruleset < 0 {
        return Err(DiskHealthResourceSandboxError);
    }
    // SAFETY: 非负 syscall 结果是当前进程拥有的 descriptor。
    let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset as i32) };
    for path in FIXED_RUNTIME_READ_ROOTS {
        if Path::new(path).exists() {
            add_path_rule(&ruleset, path, ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR)?;
        }
    }
    for path in SMARTCTL_CANDIDATES {
        if Path::new(path).exists() {
            add_path_rule(&ruleset, path, ACCESS_FS_READ_FILE)?;
        }
    }
    for path in ["/etc/ld.so.cache", "/var/local/emhttp/disks.ini"] {
        if Path::new(path).exists() {
            add_path_rule(&ruleset, path, ACCESS_FS_READ_FILE)?;
        }
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS 没有指针参数且不可逆。
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(DiskHealthResourceSandboxError);
    }
    // SAFETY: ruleset 是有效 descriptor，flags 必须为零。
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } != 0 {
        return Err(DiskHealthResourceSandboxError);
    }
    Ok(())
}

fn landlock_abi() -> Result<i32, DiskHealthResourceSandboxError> {
    // SAFETY: VERSION 查询按 ABI 使用空 attr 和零 size。
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0,
            CREATE_RULESET_VERSION,
        )
    };
    i32::try_from(version)
        .ok()
        .filter(|version| *version >= 1)
        .ok_or(DiskHealthResourceSandboxError)
}

fn add_path_rule(
    ruleset: &OwnedFd,
    path: &str,
    access: u64,
) -> Result<(), DiskHealthResourceSandboxError> {
    let path = CString::new(path).map_err(|_| DiskHealthResourceSandboxError)?;
    // SAFETY: path 以 NUL 结尾，O_PATH 只取得对象身份。
    let parent = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent < 0 {
        return Err(DiskHealthResourceSandboxError);
    }
    // SAFETY: 非负 open 结果是当前进程拥有的 descriptor。
    let parent = unsafe { OwnedFd::from_raw_fd(parent) };
    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: attr 是 packed ABI 1 PATH_BENEATH 规则描述。
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &raw const attr,
            0,
        )
    };
    (result == 0)
        .then_some(())
        .ok_or(DiskHealthResourceSandboxError)
}

#[cfg(test)]
mod tests {
    use super::{FIXED_RUNTIME_READ_ROOTS, SMARTCTL_CANDIDATES};

    #[test]
    fn command_and_runtime_read_roots_are_build_fixed() {
        assert_eq!(
            SMARTCTL_CANDIDATES,
            &["/usr/sbin/smartctl", "/usr/bin/smartctl"]
        );
        assert_eq!(
            FIXED_RUNTIME_READ_ROOTS,
            &["/lib", "/lib64", "/usr/lib", "/dev"]
        );
    }
}
