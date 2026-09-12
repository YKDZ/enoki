use super::InstallError;
use std::{
    io::Read,
    os::fd::AsRawFd,
    os::unix::process::CommandExt,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_STDOUT: u64 = 4097;

pub(super) struct BoundedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0
}

fn drain_pipe(pipe: &mut impl Read, bytes: &mut Vec<u8>) -> Result<bool, ()> {
    let mut chunk = [0_u8; 512];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(read) => {
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.len() as u64 >= MAX_STDOUT {
                    return Err(());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Err(()),
        }
    }
}

/// 在单步与事务总 deadline 内运行固定主机命令。超时返回前必须终止并回收子进程，
/// stdout 上限独立于命令时限。
pub(super) fn run_bounded(
    program: &str,
    arguments: &[&str],
    error: InstallError,
    total_deadline: Instant,
    step_budget: Duration,
) -> Result<BoundedOutput, InstallError> {
    let deadline = std::cmp::min(total_deadline, Instant::now() + step_budget);
    if Instant::now() >= deadline {
        return Err(error);
    }
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // 固定主机命令仍可能 fork；每一步使用独立进程组，使超时清理在回收前关闭继承管道。
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut child = command.spawn().map_err(|_| error.clone())?;
    let mut stdout = child.stdout.take().ok_or_else(|| error.clone())?;
    let mut stderr = child.stderr.take().ok_or_else(|| error.clone())?;
    if !set_nonblocking(stdout.as_raw_fd()) || !set_nonblocking(stderr.as_raw_fd()) {
        let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        drop(stdout);
        drop(stderr);
        let _ = child.wait();
        return Err(error);
    }
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_closed = false;
    let mut stderr_closed = false;
    let mut child_status = None;
    loop {
        if !stdout_closed {
            match drain_pipe(&mut stdout, &mut stdout_bytes) {
                Ok(closed) => stdout_closed = closed,
                Err(()) => {
                    let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                    let _ = child.kill();
                    drop(stdout);
                    drop(stderr);
                    let _ = child.wait();
                    return Err(error);
                }
            }
        }
        if !stderr_closed {
            match drain_pipe(&mut stderr, &mut stderr_bytes) {
                Ok(closed) => stderr_closed = closed,
                Err(()) => {
                    let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                    let _ = child.kill();
                    drop(stdout);
                    drop(stderr);
                    let _ = child.wait();
                    return Err(error);
                }
            }
        }
        if stdout_bytes.len() as u64 >= MAX_STDOUT
            || stderr_bytes.len() as u64 >= MAX_STDOUT
            || Instant::now() >= deadline
        {
            let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            drop(stdout);
            drop(stderr);
            let _ = child.wait();
            return Err(error);
        }
        if child_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => child_status = Some(status),
                Ok(None) => {}
                Err(_) => {
                    let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                    let _ = child.kill();
                    drop(stdout);
                    drop(stderr);
                    let _ = child.wait();
                    return Err(error);
                }
            }
        }
        if let Some(status) = child_status
            && stdout_closed
            && stderr_closed
        {
            return Ok(BoundedOutput {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timed_out_command_is_killed_and_reaped_within_the_step_budget() {
        let started = Instant::now();
        assert_eq!(
            run_bounded(
                "/bin/sh",
                &["-c", "sleep 10"],
                InstallError::Systemd,
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(30),
            )
            .map(|_| ()),
            Err(InstallError::Systemd)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn transaction_deadline_preempts_a_longer_step_budget() {
        let started = Instant::now();
        assert!(
            run_bounded(
                "/bin/sh",
                &["-c", "sleep 10"],
                InstallError::Account,
                Instant::now() + Duration::from_millis(30),
                Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn inherited_stdout_after_command_exit_remains_bounded_by_the_deadline() {
        let started = Instant::now();
        assert_eq!(
            run_bounded(
                "/bin/sh",
                &["-c", "sleep 10 &"],
                InstallError::Systemd,
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(50),
            )
            .map(|_| ()),
            Err(InstallError::Systemd)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn stderr_flood_is_drained_and_terminated_within_the_step_budget() {
        let started = Instant::now();
        assert_eq!(
            run_bounded(
                "/bin/sh",
                &["-c", "yes blocked >&2"],
                InstallError::Systemd,
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(50),
            )
            .map(|_| ()),
            Err(InstallError::Systemd)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
