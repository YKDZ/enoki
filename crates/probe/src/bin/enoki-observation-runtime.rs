//! 仅由固定 systemd socket 启动的 Observation Runtime。

use std::{
    io,
    os::fd::FromRawFd,
    os::unix::net::{UnixDatagram, UnixListener},
    path::PathBuf,
    process::ExitCode,
};

use enoki_probe::observation_runtime::{
    CPU_PROVIDER_SOCKET, DISK_HEALTH_PROVIDER_SOCKET, ObservationRuntimeProgressNotifier,
    ObservationRuntimeServer, UnixDiskHealthProvider, UnixSystemStateProvider,
    validate_systemd_listener_fd,
};

fn main() -> ExitCode {
    match inherited_listener().and_then(|listener| {
        let mut progress = SystemdRuntimeProgressNotifier::from_environment()?;
        ObservationRuntimeServer::with_disk_health_provider(
            UnixSystemStateProvider::new(CPU_PROVIDER_SOCKET),
            UnixDiskHealthProvider::new(DISK_HEALTH_PROVIDER_SOCKET),
        )
        .serve_fixed_probe_listener_with_progress(&listener, &mut progress)
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

struct SystemdRuntimeProgressNotifier {
    socket_path: Option<PathBuf>,
}

impl SystemdRuntimeProgressNotifier {
    fn from_environment() -> io::Result<Self> {
        let socket_path = match std::env::var_os("NOTIFY_SOCKET") {
            None => None,
            Some(value) => {
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "NOTIFY_SOCKET 必须是绝对路径",
                    ));
                }
                Some(path)
            }
        };
        Ok(Self { socket_path })
    }

    fn send(&self, state: &[u8]) -> io::Result<()> {
        let Some(socket_path) = &self.socket_path else {
            return Ok(());
        };
        UnixDatagram::unbound()?.send_to(state, socket_path)?;
        Ok(())
    }
}

impl ObservationRuntimeProgressNotifier for SystemdRuntimeProgressNotifier {
    fn notify_ready(&mut self) -> io::Result<()> {
        self.send(b"READY=1")
    }

    fn notify_progress(&mut self) -> io::Result<()> {
        self.send(b"WATCHDOG=1")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_notifier_sends_only_the_fixed_systemd_states() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("notification receiver");
        let mut notifier = SystemdRuntimeProgressNotifier {
            socket_path: Some(socket_path),
        };

        notifier.notify_ready().expect("ready notification");
        notifier.notify_progress().expect("watchdog notification");

        let mut message = [0_u8; 32];
        let ready_length = receiver.recv(&mut message).expect("ready state");
        assert_eq!(&message[..ready_length], b"READY=1");
        let watchdog_length = receiver.recv(&mut message).expect("watchdog state");
        assert_eq!(&message[..watchdog_length], b"WATCHDOG=1");
    }
}
