use std::{
    io::Write,
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
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
