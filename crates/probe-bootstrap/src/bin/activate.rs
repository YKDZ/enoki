//! The separately compiled root-only Bootstrap role.
use std::{io, process::ExitCode};

fn main() -> ExitCode {
    match enoki_probe_bootstrap::activation::activate_from_stdin(&mut io::stdin().lock()) {
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
