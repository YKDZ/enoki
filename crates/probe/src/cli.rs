use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeCommand {
    Help,
    InternalLocalLifecycle {
        candidate_binary: PathBuf,
    },
    InternalUpgrader {
        bootstrap_config_path: PathBuf,
    },
    InternalUninstaller {
        bootstrap_config_path: PathBuf,
    },
    Uninstall,
    Repair,
    Rejected {
        code: &'static str,
    },
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
        Some("local-install") => parse_internal_local_lifecycle_command(args),
        Some("internal-uninstaller") => parse_internal_uninstaller_command(args),
        Some("uninstall") => {
            if args.next().is_none() {
                ProbeCommand::Uninstall
            } else {
                ProbeCommand::Help
            }
        }
        Some("internal-upgrader") => parse_internal_upgrader_command(args),
        Some("repair") => {
            if args.next().is_none() {
                ProbeCommand::Repair
            } else {
                ProbeCommand::Rejected {
                    code: "probe_repair_arguments_forbidden",
                }
            }
        }
        Some("register") => parse_register_command(args),
        Some("run") => parse_run_command(args),
        Some("--version" | "-V") => ProbeCommand::Version,
        _ => ProbeCommand::Help,
    }
}

fn parse_internal_local_lifecycle_command(mut args: impl Iterator<Item = String>) -> ProbeCommand {
    match (args.next().as_deref(), args.next()) {
        (Some("--candidate"), Some(candidate_binary)) if args.next().is_none() => {
            ProbeCommand::InternalLocalLifecycle {
                candidate_binary: PathBuf::from(candidate_binary),
            }
        }
        _ => ProbeCommand::Help,
    }
}

fn parse_internal_uninstaller_command(mut args: impl Iterator<Item = String>) -> ProbeCommand {
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
        Some(bootstrap_config_path) => ProbeCommand::InternalUninstaller {
            bootstrap_config_path,
        },
        None => ProbeCommand::Help,
    }
}

fn parse_internal_upgrader_command(mut args: impl Iterator<Item = String>) -> ProbeCommand {
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
        Some(bootstrap_config_path) => ProbeCommand::InternalUpgrader {
            bootstrap_config_path,
        },
        None => ProbeCommand::Help,
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
            "  sudo enoki-probe repair\n",
            "  sudo enoki-probe uninstall\n",
            "  enoki-probe run --config <path>\n",
        )
        .to_string(),
        ProbeCommand::InternalLocalLifecycle { .. } => {
            "Probe Local Lifecycle performs typed fresh installation and readiness verification.\n"
                .to_string()
        }
        ProbeCommand::InternalUpgrader { .. } => {
            "Probe Upgrader performs privileged Probe Upgrade execution.\n".to_string()
        }
        ProbeCommand::InternalUninstaller { .. } => {
            "Probe Uninstaller performs privileged Probe uninstall execution.\n".to_string()
        }
        ProbeCommand::Uninstall => {
            "Local Probe Uninstall removes this machine's local Probe installation without contacting the Hub.\n".to_string()
        }
        ProbeCommand::Repair => {
            "Probe Repair reinstalls from the bound Hub using the existing Probe Identity.\n"
                .to_string()
        }
        ProbeCommand::Rejected { code } => format!("Probe command rejected: code={code}\n"),
        ProbeCommand::Register { .. } => {
            "Probe registration performs network I/O and cannot be rendered.\n".to_string()
        }
        ProbeCommand::Run { .. } => {
            "Probe runtime loop reports Host observations to the Hub.\n".to_string()
        }
        ProbeCommand::Version => format!("enoki-probe {}\n", crate::version::probe_version()),
    }
}
