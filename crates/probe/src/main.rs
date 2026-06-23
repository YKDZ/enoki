use enoki_probe::{
    cli::{ProbeCommand, parse_probe_command, render_probe_output},
    metrics::{collect_disk_health_metrics_with_smartctl, format_disk_health_metrics_json},
    privileged_runtime::PrivilegedCollectorId,
    registration::{HttpRegistrationTransport, ProbeRegistrationInput, register_probe},
    runtime::{ProbeRunInput, run_loop_control_from_environment, run_probe_with_loop_control},
    upgrader::{
        HttpProbeUpgraderValidationTransport, ProbeUninstallerRunInput, ProbeUpgraderRunInput,
        format_probe_upgrader_result, run_probe_uninstaller, run_probe_upgrader,
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
        ProbeCommand::InternalPrivilegedCollector { collector_id } => {
            if collector_id == PrivilegedCollectorId::DiskHealthSmartctl {
                match collect_disk_health_metrics_with_smartctl() {
                    Ok(metrics) => {
                        println!("{}", format_disk_health_metrics_json(&metrics));
                    }
                    Err(error) => {
                        eprintln!("Privileged Collector failed: {error:?}");
                        std::process::exit(1);
                    }
                }
                return;
            }

            eprintln!(
                "Privileged Collector failed: no compiled entrypoint linked for {collector_id:?}"
            );
            std::process::exit(1);
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
                std::process::exit(1);
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
