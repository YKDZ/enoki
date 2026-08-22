//! The separately compiled unprivileged Bootstrap role.
use std::{io, process::ExitCode};

fn main() -> ExitCode {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Probe Bootstrap acquisition must run as a non-root user");
        return ExitCode::from(2);
    }
    match enoki_probe_bootstrap::acquisition::acquire_and_activate_from_environment(
        &mut io::stdin().lock(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        // Deliberately never include the environment-provided enrollment token.
        Err(_) => {
            eprintln!("Probe Bootstrap acquisition failed");
            ExitCode::from(1)
        }
    }
}
