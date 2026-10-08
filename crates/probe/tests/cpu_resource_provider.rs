use std::{
    io::Write,
    process::{Command, Stdio},
};

const CPU_PULL: &[u8] = b"enoki.cpu-counters.v1\n";

#[test]
fn cpu_provider_rejects_the_fixed_pull_when_stdin_is_a_direct_pipe() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enoki-cpu-resource-provider"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("CPU Provider starts");
    child
        .stdin
        .take()
        .expect("Provider stdin")
        .write_all(CPU_PULL)
        .expect("fixed request writes");
    let output = child.wait_with_output().expect("Provider exits");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn cpu_provider_rejects_every_non_fixed_request_without_a_result() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enoki-cpu-resource-provider"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("CPU Provider starts");
    child
        .stdin
        .take()
        .expect("Provider stdin")
        .write_all(b"enoki.cpu-counters.v1 /etc/shadow\n")
        .expect("hostile request writes");
    let output = child.wait_with_output().expect("Provider exits");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
