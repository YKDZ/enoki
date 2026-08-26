//! The separately compiled root-only Bootstrap role.
use std::{
    fs::File,
    io,
    os::{fd::FromRawFd, unix::net::UnixStream},
    process::ExitCode,
};

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--render-observation-integration-v1") {
        use std::io::Write;
        return match std::io::stdout()
            .lock()
            .write_all(&enoki_probe_bootstrap::install::render_observation_integration_v1())
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    let result = if std::env::args().nth(1).as_deref() == Some("--fd-handoff") {
        // SAFETY: acquirer transfers sole ownership of the private socket on
        // fd 1 and the sealed executable receipt on fd 0 across sudo/exec.
        let mut receipt = unsafe { File::from_raw_fd(libc::STDIN_FILENO) };
        let mut input = unsafe { UnixStream::from_raw_fd(libc::STDOUT_FILENO) };
        enoki_probe_bootstrap::activation::activate_from_socket(&mut input, &mut receipt)
    } else {
        enoki_probe_bootstrap::activation::activate_from_stdin(&mut io::stdin().lock())
    };
    match result {
        Ok(verified) => match verified.activate_fixed_current_probe() {
            Ok(()) => ExitCode::SUCCESS,
            Err(enoki_probe_bootstrap::activation::ActivationError::Install(error)) => {
                eprintln!("Probe Bootstrap activation failed ({})", error.diagnostic());
                ExitCode::from(error.exit_code())
            }
            Err(_) => {
                eprintln!("Probe Bootstrap activation failed");
                ExitCode::from(1)
            }
        },
        Err(enoki_probe_bootstrap::activation::ActivationError::NotRoot) => {
            eprintln!("Probe Bootstrap activation must run as root");
            ExitCode::from(2)
        }
        Err(_) => {
            eprintln!("Probe Bootstrap activation failed");
            ExitCode::from(1)
        }
    }
}
