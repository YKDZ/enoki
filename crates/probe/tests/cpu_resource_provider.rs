use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

const CPU_PULL: &[u8] = b"enoki.cpu-counters.v1\n";

#[test]
fn cpu_provider_rejects_a_direct_pipe_before_reading_any_request() {
    // 生产入口在读任何 payload 前就拒绝非 socket stdin，父写入成功不是该边界
    // 的要求；先等子进程退出再写，复现 CI 观察到的 EPIPE 而非竞态伪失败。
    for request in [CPU_PULL, b"enoki.cpu-counters.v1 /etc/shadow\n"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_enoki-cpu-resource-provider"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("CPU Provider starts");
        let mut stdin = child.stdin.take().expect("Provider stdin");
        let mut stdout = child.stdout.take().expect("Provider stdout");
        let status = child.wait().expect("Provider exits");
        let write_error = stdin
            .write_all(request)
            .expect_err("direct pipe writes fail once the Provider has exited");
        let mut output = Vec::new();
        stdout
            .read_to_end(&mut output)
            .expect("Provider stdout drains");

        assert_eq!(write_error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(!status.success());
        assert!(output.is_empty());
    }
}
