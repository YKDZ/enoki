use enoki_probe::{
    cli::{ProbeCommand, parse_probe_command, render_probe_output},
    local_lifecycle::{
        LOCAL_LIFECYCLE_COMPLETE_MARKER, confirm_probe_local_install_failure,
        format_probe_local_lifecycle_failure, probe_local_install_input_from_environment,
        run_probe_local_install,
    },
    registration::{HttpRegistrationTransport, ProbeRegistrationInput, register_probe},
    runtime::{
        ProbeRunInput, probe_run_exit_status, run_loop_control_from_environment,
        run_probe_with_loop_control,
    },
    upgrader::{
        HttpProbeUpgraderValidationTransport, ProbeUninstallerRunInput, ProbeUpgraderRunInput,
        format_probe_upgrader_result, run_local_probe_uninstall, run_probe_repair,
        run_probe_uninstaller, run_probe_upgrader,
    },
};
use std::io::Read;

fn main() {
    let command = parse_probe_command(std::env::args());

    match command {
        ProbeCommand::Help => {
            print!("{}", render_probe_output(ProbeCommand::Help));
        }
        ProbeCommand::Version => {
            print!("{}", render_probe_output(ProbeCommand::Version));
        }
        ProbeCommand::InternalLocalLifecycle { candidate_binary } => {
            let input = match probe_local_install_input_from_environment(candidate_binary) {
                Ok(input) => input,
                Err(error) => {
                    eprintln!("Probe Local Lifecycle failed: {error}");
                    std::process::exit(1);
                }
            };
            match run_probe_local_install(&input) {
                Ok(()) => println!("{LOCAL_LIFECYCLE_COMPLETE_MARKER}"),
                Err(error) => {
                    let failure = format_probe_local_lifecycle_failure(&error);
                    match confirm_probe_local_install_failure(&input, &error) {
                        Ok(()) => eprintln!("{failure}"),
                        Err(confirmation) => eprintln!("{failure}; {confirmation}"),
                    }
                    std::process::exit(1);
                }
            }
        }
        ProbeCommand::InternalUpgrader {
            bootstrap_config_path,
        } => {
            let mut stdin = String::new();
            if let Err(error) = std::io::stdin().read_to_string(&mut stdin) {
                eprintln!("Probe Upgrader failed: {error}");
                std::process::exit(1);
            }
            let mut transport = HttpProbeUpgraderValidationTransport;
            match run_probe_upgrader(
                ProbeUpgraderRunInput {
                    bootstrap_config_path,
                },
                &stdin,
                &mut transport,
            ) {
                Ok(result) => {
                    println!("{}", format_probe_upgrader_result(&result));
                }
                Err(error) => {
                    eprintln!("Probe Upgrader failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        ProbeCommand::InternalUninstaller {
            bootstrap_config_path,
        } => {
            let mut stdin = String::new();
            if let Err(error) = std::io::stdin().read_to_string(&mut stdin) {
                eprintln!("Probe Uninstaller failed: {error}");
                std::process::exit(1);
            }
            let mut transport = HttpProbeUpgraderValidationTransport;
            match run_probe_uninstaller(
                ProbeUninstallerRunInput {
                    bootstrap_config_path,
                },
                &stdin,
                &mut transport,
            ) {
                Ok(result) => {
                    println!("{}", format_probe_upgrader_result(&result));
                }
                Err(error) => {
                    eprintln!("Probe Uninstaller failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        ProbeCommand::Uninstall => match run_local_probe_uninstall() {
            Ok(()) => println!("Local Probe Uninstall completed."),
            Err(error) => {
                eprintln!(
                    "Local Probe Uninstall failed: code={} message={error}",
                    error.code()
                );
                std::process::exit(1);
            }
        },
        ProbeCommand::Repair => {
            let mut transport = HttpProbeUpgraderValidationTransport;
            match run_probe_repair(&mut transport) {
                Ok(result) => println!(
                    "Probe Repair succeeded: probe={} version={}",
                    result.probe_id, result.repaired_version
                ),
                Err(error) => {
                    eprintln!("Probe Repair failed: code={} message={error}", error.code());
                    std::process::exit(1);
                }
            }
        }
        ProbeCommand::Rejected { code } => {
            eprintln!("Probe command rejected: code={code}");
            std::process::exit(2);
        }
        ProbeCommand::Register {
            bootstrap_config_path,
            enrollment_token,
            hub_url,
        } => {
            let mut transport = HttpRegistrationTransport;
            match register_probe(
                ProbeRegistrationInput {
                    bootstrap_config_path,
                    enrollment_token,
                    hub_url,
                },
                &mut transport,
            ) {
                Ok(outcome) => {
                    println!(
                        "Registered Probe {} and stored local bootstrap config.",
                        outcome.probe_id
                    );
                }
                Err(error) => {
                    eprintln!("Probe registration failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        ProbeCommand::Run {
            bootstrap_config_path,
        } => {
            let mut transport = HttpRegistrationTransport;
            let loop_control =
                match run_loop_control_from_environment(|name| std::env::var(name).ok()) {
                    Ok(loop_control) => loop_control,
                    Err(error) => {
                        eprintln!("Probe run failed: {error}");
                        std::process::exit(1);
                    }
                };
            let mut sleeper = enoki_probe::runtime::ThreadProbeRuntimeSleeper;
            if let Err(error) = run_probe_with_loop_control(
                ProbeRunInput {
                    bootstrap_config_path: bootstrap_config_path.clone(),
                },
                &mut transport,
                &mut sleeper,
                loop_control,
            ) {
                eprintln!("Probe run failed: {error}");
                std::process::exit(probe_run_exit_status(&error));
            }

            print!(
                "{}",
                render_probe_output(ProbeCommand::Run {
                    bootstrap_config_path
                })
            );
        }
    }
}
