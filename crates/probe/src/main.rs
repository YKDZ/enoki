use enoki_probe::{
    cli::{ProbeCommand, parse_probe_command, render_probe_output, render_probe_repair_failure},
    registration::{HttpRegistrationTransport, ProbeRegistrationInput, register_probe},
    runtime::{
        ProbeRunInput, probe_run_exit_status, run_loop_control_from_environment,
        run_probe_with_loop_control,
    },
};

fn main() {
    let command = parse_probe_command(std::env::args());

    match command {
        ProbeCommand::Help => {
            print!("{}", render_probe_output(ProbeCommand::Help));
        }
        ProbeCommand::Version => {
            print!("{}", render_probe_output(ProbeCommand::Version));
        }
        ProbeCommand::Uninstall => match enoki_probe::runtime::request_local_probe_uninstall() {
            Ok(()) => println!("Probe uninstall completed."),
            Err(code) => {
                eprintln!("Probe uninstall failed: code={code}.");
                std::process::exit(1);
            }
        },
        ProbeCommand::Repair => match enoki_probe::runtime::request_local_probe_repair() {
            Ok(()) => println!("Probe repair completed."),
            Err(code) => {
                eprint!("{}", render_probe_repair_failure(code));
                std::process::exit(1);
            }
        },
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
