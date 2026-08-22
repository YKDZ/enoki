//! 仅由固定 systemd socket 启动的 Observation Runtime。

use std::{os::fd::FromRawFd, os::unix::net::UnixListener, process::ExitCode};

use enoki_probe::observation_runtime::{
    CPU_PROVIDER_SOCKET, ObservationRuntimeServer, UnixCpuCountersProvider,
    validate_systemd_listener_fd,
};

fn main() -> ExitCode {
    match inherited_listener().and_then(|listener| {
        ObservationRuntimeServer::new(UnixCpuCountersProvider::new(CPU_PROVIDER_SOCKET))
            .serve_fixed_probe_listener(&listener)
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

fn inherited_listener() -> std::io::Result<UnixListener> {
    let listen_pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_default();
    let listen_fds = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_default();
    validate_systemd_listener_fd(3, listen_pid, listen_fds)?;
    // SAFETY: 进程尚未启动线程；清除 activation 环境避免子进程继承并误认 FD。
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }
    // SAFETY: systemd 在 exec 时把固定 Unix listener 的 FD 3 独占转交给进程。
    Ok(unsafe { UnixListener::from_raw_fd(3) })
}
