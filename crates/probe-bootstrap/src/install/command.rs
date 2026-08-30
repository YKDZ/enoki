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
        .stderr(Stdio::null());
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
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
    {
        let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        let _ = child.wait();
        return Err(error);
    }
    let mut bytes = Vec::new();
    let mut child_status = None;
    loop {
        let mut chunk = [0_u8; 512];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) if child_status.is_some() => {
                    return Ok(BoundedOutput {
                        status: child_status.expect("status was checked"),
                        stdout: bytes,
                    });
                }
                Ok(0) => break,
                Ok(read) => {
                    bytes.extend_from_slice(&chunk[..read]);
                    if bytes.len() as u64 >= MAX_STDOUT {
                        child_status = None;
                        break;
                    }
                }
                Err(read_error) if read_error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    child_status = None;
                    break;
                }
            }
        }
        if bytes.len() as u64 >= MAX_STDOUT || Instant::now() >= deadline {
            let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.kill();
            drop(stdout);
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
                    let _ = child.wait();
                    return Err(error);
                }
            }
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
}
