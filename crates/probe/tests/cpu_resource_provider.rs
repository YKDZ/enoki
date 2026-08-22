use std::{
    io::Write,
    process::{Command, Stdio},
};

const CPU_PULL: &[u8] = b"enoki.cpu-counters.v1\n";

#[test]
fn cpu_provider_serves_only_the_fixed_pull_once_and_exits() {
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

    assert!(output.status.success());
    let result_len = u32::from_be_bytes(output.stdout[..4].try_into().expect("length prefix"));
    assert_eq!(result_len as usize, output.stdout.len() - 4);
    let typed = &output.stdout[4..];
    let count = u16::from_be_bytes(typed[..2].try_into().expect("record count"));
    assert!(count > 0);
    let name_len = typed[2] as usize;
    assert_eq!(&typed[3..3 + name_len], b"cpu");
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
