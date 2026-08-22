//! System State Resource Provider 的内核级只读白名单。
//!
//! systemd 负责进程、网络与 capability 边界；Landlock 在固定请求认证后
//! 进一步把文件读取限制到构建期封闭的 system-state/Host Profile 事实集合。

use std::{
    ffi::CString,
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;

#[derive(Debug)]
pub struct SystemStateResourceSandboxError;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

pub fn enforce_system_state_resource_read_allowlist() -> Result<(), SystemStateResourceSandboxError>
{
    if landlock_abi()? < 1 {
        return Err(SystemStateResourceSandboxError);
    }
    let attr = RulesetAttr {
        handled_access_fs: ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR,
    };
    // SAFETY: attr 是固定大小、ABI 1 的 ruleset 描述。
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            std::mem::size_of::<RulesetAttr>(),
            0,
        )
    };
    if ruleset < 0 {
        return Err(SystemStateResourceSandboxError);
    }
    // SAFETY: 非负 syscall 结果是当前进程拥有的 descriptor。
    let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset as i32) };

    for path in [
        "/etc/os-release",
        "/usr/lib/os-release",
        "/proc/stat",
        "/proc/loadavg",
        "/proc/meminfo",
        "/proc/uptime",
        "/proc/cpuinfo",
        "/proc/self/mounts",
        "/proc/sys/kernel/hostname",
        "/proc/sys/kernel/osrelease",
    ] {
        add_path_rule(&ruleset, path, ACCESS_FS_READ_FILE)?;
    }
    add_path_rule(
        &ruleset,
        "/sys/devices/system/cpu",
        ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR,
    )?;
    add_path_rule(&ruleset, "/proc", ACCESS_FS_READ_DIR)?;
    for entry in fs::read_dir("/proc")
        .map_err(|_| SystemStateResourceSandboxError)?
        .flatten()
    {
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        {
            let status = entry.path().join("status");
            if status.exists() {
                // 进程可在枚举和加规则之间退出；这不应破坏同一次固定 pull。
                let _ = add_path_rule(
                    &ruleset,
                    status.to_str().ok_or(SystemStateResourceSandboxError)?,
                    ACCESS_FS_READ_FILE,
                );
            }
        }
    }

    // SAFETY: PR_SET_NO_NEW_PRIVS 没有指针参数且不可逆。
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(SystemStateResourceSandboxError);
    }
    // SAFETY: ruleset 是有效 descriptor，flags 必须为零。
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } != 0 {
        return Err(SystemStateResourceSandboxError);
    }
    Ok(())
}

fn landlock_abi() -> Result<i32, SystemStateResourceSandboxError> {
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
        .ok_or(SystemStateResourceSandboxError)
}

fn add_path_rule(
    ruleset: &OwnedFd,
    path: &str,
    access: u64,
) -> Result<(), SystemStateResourceSandboxError> {
    let path = CString::new(path).map_err(|_| SystemStateResourceSandboxError)?;
    // SAFETY: path 以 NUL 结尾；O_PATH 仅取得对象身份。
    let parent = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent < 0 {
        return Err(SystemStateResourceSandboxError);
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
        .ok_or(SystemStateResourceSandboxError)
}
