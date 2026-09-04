use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use enoki_probe_bootstrap::{
    handoff::Enrollment,
    lifecycle::{LifecycleRequest, LifecycleResponse},
};

fn replacement_request() -> LifecycleRequest {
    let enrollment = Enrollment::from_install_input(
        "https://hub.example",
        br#"{"hubOrigin":"https://hub.example","enrollmentToken":"enk_enroll_test","replacementMigration":{"enrollmentId":"enr_0123456789abcdef","expectedProbeId":"probe_old_01","sourceProbeSha256":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"sourceProbeVersion":"1.2.2","targetAssetSetDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","targetHostId":"7","targetProbeVersion":"1.2.3"},"schemaVersion":1}"#,
    )
    .expect("固定 Replacement enrollment 有效");
    LifecycleRequest::replacement_migration(
        &enrollment,
        &format!("sha256:{}", "a".repeat(64)),
        "x86_64-unknown-linux-gnu",
        &"b".repeat(64),
        "1.2.3",
    )
    .expect("固定 Replacement request 有效")
}

struct CreatedStableLock {
    _file: File,
    path: PathBuf,
}

impl Drop for CreatedStableLock {
    fn drop(&mut self) {
        // 仅移除本测试 create_new 成功且仍由 pathname 指向的 exact inode。
        let held = self._file.metadata().ok();
        let current = fs::symlink_metadata(&self.path).ok();
        if held.is_some_and(|held| {
            current
                .is_some_and(|current| held.dev() == current.dev() && held.ino() == current.ino())
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_test_stable_lock() -> Option<CreatedStableLock> {
    let path = PathBuf::from("/run/lock/enoki-probe-lifecycle.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .ok()?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .expect("固定 stable mode");
    assert_eq!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) },
        0,
        "测试 parent 必须持有 stable OFD",
    );
    Some(CreatedStableLock { _file: file, path })
}

fn add_inherited_ofd_range_lock(stable: &CreatedStableLock) {
    let range = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 1,
        l_pid: 0,
    };
    assert_eq!(
        unsafe { libc::fcntl(stable._file.as_raw_fd(), libc::F_OFD_SETLK, &range) },
        0,
        "测试在同一 inherited OFD 上添加额外内核 lock record",
    );
}

fn sealed_companion_binary() -> File {
    let name = CString::new("enoki-probe-lifecycle-companion").expect("fixed memfd name");
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    assert!(fd >= 0, "创建 sealed executable memfd");
    let mut file = unsafe { File::from_raw_fd(fd) };
    let bytes = fs::read(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"))
        .expect("读取真实 Companion bytes");
    file.write_all(&bytes).expect("复制真实 Companion bytes");
    file.sync_all().expect("sync sealed bytes");
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) }, seals);
    file
}

fn malformed_marker_runtime_output() -> Vec<u8> {
    let executable = CString::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"))
        .expect("Companion executable path has no NUL");
    let argument = CString::new("record-runtime-failure").expect("fixed argv has no NUL");
    let malformed_marker =
        CString::new("ENOKI_LIFECYCLE_LEASE_FD").expect("fixed malformed env entry has no NUL");
    let mut pipe = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork real Companion process");
    if child == 0 {
        unsafe {
            libc::close(pipe[0]);
            if libc::dup2(pipe[1], libc::STDOUT_FILENO) != libc::STDOUT_FILENO {
                libc::_exit(127);
            }
            libc::close(pipe[1]);
            let null = CString::new("/dev/null").expect("fixed null path");
            let stdin = libc::open(null.as_ptr(), libc::O_RDONLY);
            if stdin < 0 || libc::dup2(stdin, libc::STDIN_FILENO) != libc::STDIN_FILENO {
                libc::_exit(127);
            }
            let mut argv = [executable.as_ptr(), argument.as_ptr(), std::ptr::null()];
            let mut environment = [malformed_marker.as_ptr(), std::ptr::null()];
            libc::execve(
                executable.as_ptr(),
                argv.as_mut_ptr(),
                environment.as_mut_ptr(),
            );
            libc::_exit(127);
        }
    }
    unsafe { libc::close(pipe[1]) };
    let mut output = Vec::new();
    unsafe { File::from_raw_fd(pipe[0]) }
        .read_to_end(&mut output)
        .expect("read real Companion stdout");
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) != 0);
    output
}

#[test]
fn general_replacement_without_an_inherited_marker_is_rejected_before_coordinator() {
    let request = replacement_request();
    let mut child = Command::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"))
        .env_remove("ENOKI_LIFECYCLE_LEASE_FD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("启动真实 Companion binary");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(&request.encode().expect("canonical request"))
        .expect("写入 request");
    let output = child.wait_with_output().expect("等待 Companion binary");

    assert!(!output.status.success(), "拒绝必须以失败退出");
    assert_eq!(
        LifecycleResponse::decode(&output.stdout),
        Ok(LifecycleResponse::failed("lifecycle.invalid_authority")),
    );
}

#[test]
fn upgrade_mode_with_an_invalid_inherited_marker_rejects_before_mode_rejection() {
    let request = replacement_request();
    let mut child = Command::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"))
        .arg("--upgrade")
        .env("ENOKI_LIFECYCLE_LEASE_FD", "9")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("启动真实 Companion binary");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(&request.encode().expect("canonical request"))
        .expect("写入 request");
    let output = child.wait_with_output().expect("等待 Companion binary");

    assert!(!output.status.success(), "无效来源必须以失败退出");
    assert_eq!(
        LifecycleResponse::decode(&output.stdout),
        Ok(LifecycleResponse::failed("lifecycle.invalid_authority")),
    );
}

#[test]
fn invalid_marker_precedes_runtime_mode_without_running_the_runtime_action() {
    let output = Command::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"))
        .arg("record-runtime-failure")
        .env("ENOKI_LIFECYCLE_LEASE_FD", "not-fd9")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("启动真实 Companion binary");

    assert!(!output.status.success(), "无效来源必须以失败退出");
    assert_eq!(
        LifecycleResponse::decode(&output.stdout),
        Ok(LifecycleResponse::failed("lifecycle.invalid_authority")),
    );
}

#[test]
fn malformed_present_marker_precedes_runtime_mode() {
    assert_eq!(
        LifecycleResponse::decode(&malformed_marker_runtime_output()),
        Ok(LifecycleResponse::failed("lifecycle.invalid_authority")),
    );
}

#[test]
fn invalid_marker_precedes_empty_resume() {
    let output = Command::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"))
        .env("ENOKI_LIFECYCLE_LEASE_FD", "not-fd9")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("启动真实 Companion binary");

    assert_eq!(
        LifecycleResponse::decode(&output.stdout),
        Ok(LifecycleResponse::failed("lifecycle.invalid_authority")),
    );
}

#[test]
fn invalid_marker_precedes_socket_peer_input() {
    let (mut peer, child_socket) = UnixStream::pair().expect("创建真实 Unix socket peer");
    let socket_fd = child_socket.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"));
    command
        .env("ENOKI_LIFECYCLE_LEASE_FD", "not-fd9")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(socket_fd, libc::STDIN_FILENO) != libc::STDIN_FILENO {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().expect("启动真实 Companion binary");
    peer.write_all(b"unread socket request")
        .expect("写 socket peer");
    drop(peer);
    let output = child.wait_with_output().expect("等待 Companion binary");

    assert_eq!(
        LifecycleResponse::decode(&output.stdout),
        Ok(LifecycleResponse::failed("lifecycle.invalid_authority")),
    );
}

#[test]
fn valid_adopted_fd9_reaches_the_private_replacement_branch() {
    assert!(
        !Path::new("/etc/enoki/probe-install.toml").exists(),
        "真实 process oracle 拒绝在已安装宿主上运行"
    );
    let Some(stable) = create_test_stable_lock() else {
        return;
    };
    let stable_fd = stable._file.as_raw_fd();
    let sealed = sealed_companion_binary();
    let request = replacement_request();
    let mut command = Command::new(format!("/proc/self/fd/{}", sealed.as_raw_fd()));
    command
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("ENOKI_LIFECYCLE_LEASE_FD", "9")
        .env_remove("ENOKI_TEST_REPLACEMENT_PRODUCTION_ROOT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if stable_fd == 9 {
                let flags = libc::fcntl(9, libc::F_GETFD);
                if flags < 0 || libc::fcntl(9, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup3(stable_fd, 9, 0) != 9 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .expect("启动 sealed-child 等价的真实 binary");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(&request.encode().expect("canonical request"))
        .expect("写入 exact Replacement request");
    let output = child.wait_with_output().expect("等待 child EOF/exit");

    assert_eq!(
        LifecycleResponse::decode(&output.stdout),
        Ok(LifecycleResponse::failed(
            "lifecycle.replacement_commit_failed"
        )),
        "fd9 已经通过 source admission；只有 private Replacement coordinator 才会读取缺失 commit custody",
    );
}

#[test]
fn adopted_fd9_with_malformed_request_is_invalid_authority() {
    let Some(stable) = create_test_stable_lock() else {
        return;
    };
    let stable_fd = stable._file.as_raw_fd();
    let sealed = sealed_companion_binary();
    let mut command = Command::new(format!("/proc/self/fd/{}", sealed.as_raw_fd()));
    command
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("ENOKI_LIFECYCLE_LEASE_FD", "9")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::dup3(stable_fd, 9, 0) != 9 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("启动 sealed Companion binary");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(b"not a lifecycle request")
        .expect("写入 malformed request");
    let output = child.wait_with_output().expect("等待 child EOF/exit");

    assert!(!output.status.success());
    assert_eq!(
        LifecycleResponse::decode(&output.stdout),
        Ok(LifecycleResponse::failed("lifecycle.invalid_authority")),
    );
}

#[test]
fn adopted_fd9_with_an_extra_kernel_lock_record_is_invalid_authority() {
    let Some(stable) = create_test_stable_lock() else {
        return;
    };
    add_inherited_ofd_range_lock(&stable);
    let stable_fd = stable._file.as_raw_fd();
    let sealed = sealed_companion_binary();
    let request = replacement_request();
    let mut command = Command::new(format!("/proc/self/fd/{}", sealed.as_raw_fd()));
    command
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("ENOKI_LIFECYCLE_LEASE_FD", "9")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::dup3(stable_fd, 9, 0) != 9 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("启动 sealed Companion binary");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(&request.encode().expect("canonical request"))
        .expect("写入 exact Replacement request");
    let output = child.wait_with_output().expect("等待 child EOF/exit");

    assert!(!output.status.success());
    assert_eq!(
        LifecycleResponse::decode(&output.stdout),
        Ok(LifecycleResponse::failed("lifecycle.invalid_authority")),
    );
}

#[test]
fn markerless_upgrade_replacement_is_not_enabled() {
    let request = replacement_request();
    let mut child = Command::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"))
        .arg("--upgrade")
        .env_remove("ENOKI_LIFECYCLE_LEASE_FD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("启动真实 Companion binary");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(&request.encode().expect("canonical request"))
        .expect("写入 request");
    let output = child.wait_with_output().expect("等待 Companion binary");

    assert!(!output.status.success());
    assert_eq!(
        LifecycleResponse::decode(&output.stdout),
        Ok(LifecycleResponse::not_enabled()),
    );
}
