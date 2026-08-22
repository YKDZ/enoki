//! 仅由固定 systemd socket 启动的 Observation Runtime。

use std::{os::fd::FromRawFd, os::unix::net::UnixListener, process::ExitCode};

use enoki_probe::observation_runtime::{
    CPU_PROVIDER_SOCKET, ObservationRuntimeServer, UnixCpuCountersProvider,
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
    if std::env::var_os("LISTEN_FDS").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "one systemd listener is required",
        ));
    }
    // SAFETY: systemd 在 exec 时把固定 Unix listener 的 FD 3 独占转交给进程。
    Ok(unsafe { UnixListener::from_raw_fd(3) })
}
