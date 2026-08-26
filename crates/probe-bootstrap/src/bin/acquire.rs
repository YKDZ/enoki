//! The separately compiled unprivileged Bootstrap role.
use std::{io, io::Read, io::Write, process::ExitCode};

fn main() -> ExitCode {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Probe Bootstrap acquisition must run as a non-root user");
        return ExitCode::from(2);
    }
    let repair_exchange = std::env::args().nth(1).as_deref() == Some("--repair-authorize");
    let result = if repair_exchange {
        let mut request = Vec::new();
        match io::stdin()
            .lock()
            .take(8 * 1024 + 1)
            .read_to_end(&mut request)
        {
            Ok(_) => {
                enoki_probe_bootstrap::acquisition::acquire_probe_repair_authority_once(&request)
                    .and_then(|response| {
                        io::stdout().lock().write_all(&response).map_err(|_| {
                            enoki_probe_bootstrap::acquisition::AcquisitionFailure::Local
                        })
                    })
            }
            Err(_) => Err(enoki_probe_bootstrap::acquisition::AcquisitionFailure::Local),
        }
    } else {
        enoki_probe_bootstrap::acquisition::acquire_and_activate_from_environment(
            &mut io::stdin().lock(),
        )
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // Deliberately never include the environment-provided enrollment token.
        Err(enoki_probe_bootstrap::acquisition::AcquisitionFailure::ManualReinstallRequired) => {
            eprintln!("Probe Repair requires manual reinstall");
            ExitCode::from(3)
        }
        Err(_) => {
            eprintln!("Probe Bootstrap acquisition failed");
            ExitCode::from(1)
        }
    }
}
