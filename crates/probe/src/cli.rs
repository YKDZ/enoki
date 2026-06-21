use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeCommand {
    Help,
    Register {
        bootstrap_config_path: PathBuf,
        enrollment_token: String,
        hub_url: String,
    },
    Run {
        bootstrap_config_path: PathBuf,
    },
    Version,
}

pub fn parse_probe_command(args: impl IntoIterator<Item = String>) -> ProbeCommand {
    let mut args = args.into_iter();
    let _binary = args.next();

    match args.next().as_deref() {
        Some("register") => parse_register_command(args),
        Some("run") => parse_run_command(args),
        Some("--version" | "-V") => ProbeCommand::Version,
        _ => ProbeCommand::Help,
    }
}

fn parse_register_command(mut args: impl Iterator<Item = String>) -> ProbeCommand {
    let mut bootstrap_config_path = None;
    let mut enrollment_token = None;
    let mut hub_url = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                bootstrap_config_path = args.next().map(PathBuf::from);
            }
            "--enrollment-token" => {
                enrollment_token = args.next();
            }
            "--hub-url" => {
                hub_url = args.next();
            }
            _ => return ProbeCommand::Help,
        }
    }

    match (bootstrap_config_path, enrollment_token, hub_url) {
        (Some(bootstrap_config_path), Some(enrollment_token), Some(hub_url)) => {
            ProbeCommand::Register {
                bootstrap_config_path,
                enrollment_token,
                hub_url,
            }
        }
        _ => ProbeCommand::Help,
    }
}

fn parse_run_command(mut args: impl Iterator<Item = String>) -> ProbeCommand {
    let mut bootstrap_config_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                bootstrap_config_path = args.next().map(PathBuf::from);
            }
            _ => return ProbeCommand::Help,
        }
    }

    match bootstrap_config_path {
        Some(bootstrap_config_path) => ProbeCommand::Run {
            bootstrap_config_path,
        },
        None => ProbeCommand::Help,
    }
}

#[must_use]
pub fn render_probe_output(command: ProbeCommand) -> String {
    match command {
        ProbeCommand::Help => concat!(
            "Enoki Probe\n",
            "\n",
            "A lightweight host-side process that reports Host ",
            "observations to the Hub over outbound HTTPS.\n",
            "\n",
            "Usage:\n",
            "  enoki-probe --help\n",
            "  enoki-probe --version\n",
            "  enoki-probe register --hub-url <url> ",
            "--enrollment-token <token> --config <path>\n",
            "  enoki-probe run --config <path>\n",
        )
        .to_string(),
        ProbeCommand::Register { .. } => {
            "Probe registration performs network I/O and cannot be rendered.\n".to_string()
        }
        ProbeCommand::Run { .. } => {
            "Probe runtime loop reports Host observations to the Hub.\n".to_string()
        }
        ProbeCommand::Version => format!("enoki-probe {}\n", crate::version::probe_version()),
    }
}
