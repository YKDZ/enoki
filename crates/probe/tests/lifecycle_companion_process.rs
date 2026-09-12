use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
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

const UNINSTALL_DIAGNOSTIC_CASE: &str = "ENOKI_TEST_UNINSTALL_DIAGNOSTIC_CASE";
const UNINSTALL_DIAGNOSTIC_SECRET: &str = "formal241-secret-sentinel";

fn schema_five_metadata() -> String {
    [
        "schema_version = 5",
        "hub_url = \"https://hub.example\"",
        "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
        "install_path = \"/usr/local/bin/enoki-probe\"",
        "observation_runtime_path = \"/usr/local/bin/enoki-observation-runtime\"",
        "cpu_provider_path = \"/usr/local/bin/enoki-cpu-resource-provider\"",
        "disk_health_provider_path = \"/usr/local/bin/enoki-disk-health-resource-provider\"",
        "lifecycle_companion_path = \"/usr/local/bin/enoki-probe-lifecycle-companion\"",
        "probe_ipc_group = \"enoki-probe-ipc\"",
        "probe_ipc_group_ownership = \"!enoki-bootstrap-dddddddddddddddddddddddddddddddd\"",
        "observation_ipc_group = \"enoki-observation-ipc\"",
        "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
        "state_dir = \"/var/lib/enoki-probe\"",
        "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
        "install_state_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
        "target_manifest_sha256 = \"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"",
        "bundle_version = \"1.2.3\"",
        "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"",
        "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
        "bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\"",
        "service_name = \"enoki-probe\"",
        "service_user = \"enoki-probe\"",
        "service_group = \"enoki-probe\"",
        "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
        "observation_runtime_service_unit_path = \"/etc/systemd/system/enoki-observation-runtime.service\"",
        "observation_runtime_socket_unit_path = \"/etc/systemd/system/enoki-observation-runtime.socket\"",
        "cpu_provider_service_unit_path = \"/etc/systemd/system/enoki-cpu-resource-provider@.service\"",
        "cpu_provider_socket_unit_path = \"/etc/systemd/system/enoki-cpu-resource-provider.socket\"",
        "disk_health_provider_service_unit_path = \"/etc/systemd/system/enoki-disk-health-resource-provider@.service\"",
        "disk_health_provider_socket_unit_path = \"/etc/systemd/system/enoki-disk-health-resource-provider.socket\"",
        "lifecycle_companion_service_unit_path = \"/etc/systemd/system/enoki-probe-lifecycle-companion@.service\"",
        "lifecycle_companion_socket_unit_path = \"/etc/systemd/system/enoki-probe-lifecycle-companion.socket\"",
        "collector_helper_sudoers_path = \"/etc/sudoers.d/enoki-probe-collector-helpers\"",
        "lifecycle_upgrade_service_unit_path = \"/etc/systemd/system/enoki-probe-lifecycle-upgrade@.service\"",
        "lifecycle_upgrade_socket_unit_path = \"/etc/systemd/system/enoki-probe-lifecycle-upgrade.socket\"",
        "lifecycle_authority_install_key = \"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"",
    ]
    .join("\n")
}

fn create_uninstall_process_fixture(root: &Path) -> (String, String, String) {
    let metadata_contents = schema_five_metadata();
    let identity_contents = [
        "hub_url = \"https://hub.example\"",
        "probe_id = \"probe_01\"",
        "probe_private_key_pem = \"formal241-fixture-key\"",
        "",
    ]
    .join("\n");
    let capsule_contents = format!("request = \"{UNINSTALL_DIAGNOSTIC_SECRET}");
    let identity = root.join("var/lib/enoki-probe/identity/probe-bootstrap.toml");
    fs::create_dir_all(identity.parent().expect("identity parent")).expect("identity parent");
    fs::write(&identity, &identity_contents).expect("identity config");
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).expect("identity mode");
    let metadata = root.join("etc/enoki/probe-install.toml");
    fs::create_dir_all(metadata.parent().expect("metadata parent")).expect("metadata parent");
    fs::write(&metadata, &metadata_contents).expect("schema five metadata");
    fs::set_permissions(&metadata, fs::Permissions::from_mode(0o600)).expect("metadata mode");
    let capsule = root.join("etc/enoki/probe-uninstall.capsule");
    fs::write(&capsule, &capsule_contents).expect("malformed uninstall capsule");
    fs::set_permissions(&capsule, fs::Permissions::from_mode(0o600)).expect("capsule mode");
    fs::create_dir_all(root.join("run/lock")).expect("isolated run lock");

    (metadata_contents, identity_contents, capsule_contents)
}

fn bind_mount(source: &Path, target: &str) {
    let source = CString::new(source.as_os_str().as_bytes()).expect("source path has no NUL");
    let target = CString::new(target).expect("target path has no NUL");
    assert_eq!(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        0,
        "bind mount the isolated Companion fixture"
    );
}

fn enter_uninstall_process_namespace(root: &Path) {
    assert_eq!(
        unsafe { libc::unshare(libc::CLONE_NEWNS) },
        0,
        "unshare mount namespace"
    );
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0,
        "make test mounts private"
    );
    bind_mount(&root.join("etc"), "/etc");
    bind_mount(&root.join("var"), "/var");
    bind_mount(&root.join("run/lock"), "/run/lock");
}

fn run_uninstall_process_child(case: &str) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().expect("current test process"));
    command
        .args(["--exact", "uninstall_failure_process_child", "--nocapture"])
        .env(UNINSTALL_DIAGNOSTIC_CASE, case)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
        .spawn()
        .expect("start isolated Companion test child")
        .wait_with_output()
        .expect("collect isolated Companion test child")
}

#[test]
fn uninstall_failure_process_child() {
    let Ok(case) = std::env::var(UNINSTALL_DIAGNOSTIC_CASE) else {
        return;
    };
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "namespace fixture requires root"
    );
    let temporary = tempfile::tempdir().expect("isolated production root");
    let (metadata_contents, identity_contents, capsule_contents) =
        create_uninstall_process_fixture(temporary.path());
    enter_uninstall_process_namespace(temporary.path());
    let (mut peer, child_socket) = UnixStream::pair().expect("real UnixStream peer");
    let socket_fd = child_socket.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"));
    command
        .env_remove("ENOKI_LIFECYCLE_LEASE_FD")
        .env_remove("ENOKI_TEST_REPLACEMENT_PRODUCTION_ROOT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if case == "stderr-full" {
            Stdio::from(
                OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .expect("open deterministic failing stderr"),
            )
        } else {
            Stdio::piped()
        });
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(socket_fd, libc::STDIN_FILENO) != libc::STDIN_FILENO {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().expect("start real Companion binary");
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_42",
        UNINSTALL_DIAGNOSTIC_SECRET,
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("fixed Uninstall request");
    peer.write_all(&request.encode().expect("canonical request"))
        .expect("send real Uninstall request");
    drop(peer);
    let output = child
        .wait_with_output()
        .expect("wait for real Companion binary");
    let expected = LifecycleResponse::failed("probe_uninstall_metadata_invalid").encode();
    assert_eq!(
        output.stdout, expected,
        "stdout remains the original terminal response bytes",
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "Companion exits with failure"
    );
    if case == "stderr-piped" {
        let stderr = String::from_utf8(output.stderr).expect("diagnostic stderr is UTF-8");
        assert_eq!(
            stderr,
            "enoki.lifecycle.diagnostic role=companion phase=uninstall_failure outcome=failed operation=uninstall step=resume_decision code=probe_uninstall_metadata_invalid reason=uninstall capsule is malformed\n",
        );
        assert!(!stderr.contains(UNINSTALL_DIAGNOSTIC_SECRET));
        assert!(!stderr.contains("formal241-fixture-key"));
        assert!(!stderr.contains("probe-uninstall.capsule"));
    }
    assert_eq!(
        fs::read(temporary.path().join("etc/enoki/probe-install.toml")).expect("metadata remains"),
        metadata_contents.as_bytes(),
    );
    assert_eq!(
        fs::read(
            temporary
                .path()
                .join("var/lib/enoki-probe/identity/probe-bootstrap.toml")
        )
        .expect("identity remains"),
        identity_contents.as_bytes(),
    );
    assert_eq!(
        fs::read(temporary.path().join("etc/enoki/probe-uninstall.capsule"))
            .expect("capsule remains"),
        capsule_contents.as_bytes(),
    );
}

#[test]
fn uninstall_failure_process_keeps_stdout_when_stderr_fails() {
    let output = run_uninstall_process_child("stderr-full");

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn uninstall_failure_process_keeps_protocol_and_diagnostic_separate() {
    let output = run_uninstall_process_child("stderr-piped");

    assert!(output.status.success(), "{output:?}");
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
    let mut stdin = tempfile::tempfile().expect("创建 preloaded stdin");
    stdin
        .write_all(&request.encode().expect("canonical request"))
        .expect("预载 request");
    stdin.rewind().expect("rewind preloaded stdin");

    let output = Command::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"))
        .arg("--upgrade")
        .env("ENOKI_LIFECYCLE_LEASE_FD", "9")
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("启动并等待真实 Companion binary");

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
