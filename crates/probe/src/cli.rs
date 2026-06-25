use std::path::PathBuf;

use crate::local_privilege_boundary::{
    PrivilegedCollectorHelperId, compiled_privileged_collector_helper_spec,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeCommand {
    Help,
    InternalPrivilegedCollectorHelper {
        helper_id: PrivilegedCollectorHelperId,
    },
    InternalRenderCollectorHelperSudoers {
        service_user: String,
        probe_binary: PathBuf,
    },
    InternalUpgrader {
        bootstrap_config_path: PathBuf,
    },
    InternalUninstaller {
        bootstrap_config_path: PathBuf,
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
        Some("internal-privileged-collector-helper") => {
            parse_internal_privileged_collector_helper_command(args)
        }
        Some("internal-render-collector-helper-sudoers") => {
            parse_internal_render_collector_helper_sudoers_command(args)
        }
        Some("internal-uninstaller") => parse_internal_uninstaller_command(args),
        Some("internal-upgrader") => parse_internal_upgrader_command(args),
        Some("register") => parse_register_command(args),
        Some("run") => parse_run_command(args),
        Some("--version" | "-V") => ProbeCommand::Version,
        _ => ProbeCommand::Help,
    }
}

fn parse_internal_privileged_collector_helper_command(
    mut args: impl Iterator<Item = String>,
) -> ProbeCommand {
    let mut helper_id = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--helper" => {
                if helper_id.is_some() {
                    return ProbeCommand::Help;
                }
                let Some(value) = args.next() else {
                    return ProbeCommand::Help;
                };
                let Some(parsed_helper_id) = PrivilegedCollectorHelperId::from_internal_arg(&value)
                else {
                    return ProbeCommand::Help;
                };
                let Some(spec) = compiled_privileged_collector_helper_spec(parsed_helper_id) else {
                    return ProbeCommand::Help;
                };
                helper_id = Some(spec.id);
            }
            _ => return ProbeCommand::Help,
        }
    }

    match helper_id {
        Some(helper_id) => ProbeCommand::InternalPrivilegedCollectorHelper { helper_id },
        None => ProbeCommand::Help,
    }
}

fn parse_internal_render_collector_helper_sudoers_command(
    mut args: impl Iterator<Item = String>,
) -> ProbeCommand {
    let mut service_user = None;
    let mut probe_binary = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--service-user" => {
                if service_user.is_some() {
                    return ProbeCommand::Help;
                }
                service_user = args.next();
            }
            "--probe-binary" => {
                if probe_binary.is_some() {
                    return ProbeCommand::Help;
                }
                probe_binary = args.next().map(PathBuf::from);
            }
            _ => return ProbeCommand::Help,
        }
    }

    match (service_user, probe_binary) {
        (Some(service_user), Some(probe_binary)) => {
            ProbeCommand::InternalRenderCollectorHelperSudoers {
                service_user,
                probe_binary,
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
            "  enoki-probe run --config <path>\n",
        )
        .to_string(),
        ProbeCommand::InternalPrivilegedCollectorHelper { .. } => {
            "Privileged Collector Helper executes a compiled helper entrypoint.\n".to_string()
        }
        ProbeCommand::InternalRenderCollectorHelperSudoers { .. } => {
            "Privileged Collector Helper sudoers rendering uses compiled helper declarations.\n"
                .to_string()
        }
        ProbeCommand::InternalUpgrader { .. } => {
            "Probe Upgrader performs privileged Probe Upgrade execution.\n".to_string()
        }
        ProbeCommand::InternalUninstaller { .. } => {
            "Probe Uninstaller performs privileged Probe uninstall execution.\n".to_string()
        }
        ProbeCommand::Register { .. } => {
            "Probe registration performs network I/O and cannot be rendered.\n".to_string()
        }
        ProbeCommand::Run { .. } => {
            "Probe runtime loop reports Host observations to the Hub.\n".to_string()
        }
        ProbeCommand::Version => format!("enoki-probe {}\n", crate::version::probe_version()),
    }
}
