use std::{
    io::{Read, Write},
    net::Shutdown,
    os::fd::OwnedFd,
    os::unix::net::UnixStream,
    process::{Command, Stdio},
};

use enoki_probe_bootstrap::{
    install::fixed_execution_role_units,
    lifecycle::{LifecycleRequest, LifecycleResponse, LifecycleResultStatus},
};

#[test]
fn failed_repair_response_decodes_with_installed_companion_descriptors() {
    let service_unit = String::from_utf8(
        fixed_execution_role_units()
            .into_iter()
            .find(|(profile, _)| *profile == "lifecycle-companion-v3")
            .expect("the installed bundle declares the lifecycle companion")
            .1,
    )
    .expect("the generated service unit is UTF-8");
    assert_eq!(
        unit_property(&service_unit, "StandardInput"),
        Some("socket")
    );
    assert_eq!(
        unit_property(&service_unit, "StandardOutput"),
        Some("socket")
    );
    assert_eq!(
        unit_property(&service_unit, "StandardError"),
        Some("journal")
    );

    // systemd 的 StandardError 默认继承 StandardOutput；测试据此复现安装 unit 的真实描述符关系。
    let standard_error = unit_property(&service_unit, "StandardError").unwrap_or("inherit");
    let (mut caller, companion_socket) = UnixStream::pair().expect("socket pair");
    let companion_stdin = companion_socket.try_clone().expect("stdin socket");
    let stderr = match standard_error {
        "inherit" => Stdio::from(OwnedFd::from(
            companion_socket.try_clone().expect("stderr socket"),
        )),
        "journal" => Stdio::piped(),
        other => panic!("unsupported generated StandardError setting: {other}"),
    };
    let child = Command::new(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"))
        .stdin(Stdio::from(OwnedFd::from(companion_stdin)))
        .stdout(Stdio::from(OwnedFd::from(companion_socket)))
        .stderr(stderr)
        .spawn()
        .expect("the lifecycle companion starts");

    let request = LifecycleRequest::local_repair(
        "probe_01",
        &"a".repeat(64),
        &"b".repeat(64),
        "1.2.3",
        1000,
        1000,
    )
    .expect("the public constructor creates a valid local repair request");
    caller
        .write_all(&request.encode().expect("the request encodes"))
        .expect("the companion receives the request");
    caller
        .shutdown(Shutdown::Write)
        .expect("the request stream ends");

    let mut response_bytes = Vec::new();
    caller
        .read_to_end(&mut response_bytes)
        .expect("the companion response is readable");
    let output = child.wait_with_output().expect("the companion exits");

    let response = LifecycleResponse::decode(&response_bytes)
        .expect("diagnostics do not contaminate the typed response frame");
    assert_eq!(response.status(), LifecycleResultStatus::Failed);
    assert_eq!(output.status.code(), Some(1));
}

fn unit_property<'a>(unit: &'a str, property: &str) -> Option<&'a str> {
    let prefix = format!("{property}=");
    unit.lines().find_map(|line| line.strip_prefix(&prefix))
}
