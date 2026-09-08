use super::{
    CleanupCommandOutput, ProbeUpgraderRunError, remove_fixed_ipc_group_with_accounts,
    run_cleanup_command, verify_systemd_service_absent_with, verify_systemd_service_stopped_with,
};

fn successful_output(stdout: &str) -> CleanupCommandOutput {
    CleanupCommandOutput {
        code: Some(0),
        stderr: String::new(),
        stdout: stdout.to_owned(),
        successful: true,
    }
}

#[test]
fn absence_verification_accepts_empty_match_for_fixed_instance_glob() {
    for service_name in [
        "enoki-cpu-resource-provider@*.service",
        "enoki-disk-health-resource-provider@*.service",
        "enoki-probe-lifecycle-upgrade@*.service",
    ] {
        let mut run = |program: &str, args: &[&str]| {
            assert_eq!(program, "systemctl");
            assert_eq!(args[0], "show");
            Ok(successful_output(""))
        };

        assert!(verify_systemd_service_absent_with(service_name, &mut run).is_ok());
    }
}

#[test]
fn absence_verification_keeps_exact_unit_and_not_found_semantics() {
    let mut exact_empty = |_: &str, _: &[&str]| Ok(successful_output(""));
    let error = verify_systemd_service_absent_with("enoki-probe.service", &mut exact_empty)
        .expect_err("an exact unit with an empty LoadState is ambiguous");
    assert_eq!(error.code(), "probe_uninstall_service_residue");

    let mut exact_not_found = |_: &str, _: &[&str]| Ok(successful_output("not-found\n"));
    assert!(
        verify_systemd_service_absent_with("enoki-probe.service", &mut exact_not_found).is_ok()
    );
}

#[test]
fn absence_verification_rejects_matching_or_ambiguous_instance_results() {
    for stdout in ["loaded\n", "not-found\nnot-found\n"] {
        let mut run = |_: &str, _: &[&str]| Ok(successful_output(stdout));
        let error =
            verify_systemd_service_absent_with("enoki-cpu-resource-provider@*.service", &mut run)
                .expect_err("a matching or ambiguous result must remain residue");
        assert_eq!(error.code(), "probe_uninstall_service_residue");
    }
}

#[test]
fn absence_verification_rejects_query_failure_and_io_failure() {
    let mut nonzero = |_: &str, _: &[&str]| {
        Ok(CleanupCommandOutput {
            code: Some(1),
            stderr: "query failed".to_owned(),
            stdout: String::new(),
            successful: false,
        })
    };
    let error =
        verify_systemd_service_absent_with("enoki-cpu-resource-provider@*.service", &mut nonzero)
            .expect_err("a non-zero query must fail closed");
    assert_eq!(error.code(), "probe_uninstall_service_verification_failed");

    let mut io_failure = |_: &str, _: &[&str]| Err(std::io::Error::other("systemctl unavailable"));
    let error = verify_systemd_service_absent_with(
        "enoki-cpu-resource-provider@*.service",
        &mut io_failure,
    )
    .expect_err("an I/O failure must fail closed");
    assert_eq!(error.code(), "probe_uninstall_service_verification_failed");
}

#[test]
fn stopped_service_verification_requires_manager_loaded_process_and_killmode_facts() {
    let mut run = |program: &str, args: &[&str]| {
        assert_eq!(program, "systemctl");
        assert_eq!(args[0], "show");
        assert_eq!(args[1], "-p");
        assert_eq!(args[3], "--value");
        assert_eq!(args[4], "enoki-probe.service");
        let value = match args[2] {
            "LoadState" => "loaded\n",
            "ActiveState" => "inactive\n",
            "SubState" => "dead\n",
            "Job" => "\n",
            "MainPID" | "ControlPID" => "0\n",
            "KillMode" => "control-group\n",
            property => panic!("unexpected systemd property {property}"),
        };
        Ok(successful_output(value))
    };

    assert!(verify_systemd_service_stopped_with("enoki-probe.service", &mut run).is_ok());

    let mut live_pid = |_: &str, args: &[&str]| {
        let value = match args[2] {
            "LoadState" => "loaded\n",
            "ActiveState" => "inactive\n",
            "SubState" => "dead\n",
            "Job" => "\n",
            "MainPID" => "42\n",
            "ControlPID" => "0\n",
            "KillMode" => "control-group\n",
            property => panic!("unexpected systemd property {property}"),
        };
        Ok(successful_output(value))
    };
    let error = verify_systemd_service_stopped_with("enoki-probe.service", &mut live_pid)
        .expect_err("a stopped role cannot retain a manager PID");
    assert_eq!(error.code(), "probe_uninstall_service_residue");
}

#[test]
fn stopped_service_verification_accepts_not_found_reentry_and_checks_every_instance() {
    let mut missing = |_: &str, args: &[&str]| {
        let value = match args[2] {
            "LoadState" => "not-found\n",
            property => panic!("unexpected property after not-found: {property}"),
        };
        Ok(successful_output(value))
    };
    assert!(verify_systemd_service_stopped_with("enoki-probe.service", &mut missing).is_ok());

    let mut two_stopped_instances = |_: &str, args: &[&str]| {
        let value = match args[2] {
            "LoadState" => "loaded\nloaded\n",
            "ActiveState" => "inactive\ninactive\n",
            "SubState" => "dead\ndead\n",
            "Job" => "\n\n",
            "MainPID" | "ControlPID" => "0\n0\n",
            "KillMode" => "control-group\ncontrol-group\n",
            property => panic!("unexpected systemd property {property}"),
        };
        Ok(successful_output(value))
    };
    assert!(
        verify_systemd_service_stopped_with(
            "enoki-cpu-resource-provider@*.service",
            &mut two_stopped_instances,
        )
        .is_ok()
    );

    let mut mismatched_instances = |_: &str, args: &[&str]| {
        let value = match args[2] {
            "LoadState" => "loaded\nloaded\n",
            "ActiveState" => "inactive\n",
            "SubState" => "dead\ndead\n",
            "Job" => "\n\n",
            "MainPID" | "ControlPID" => "0\n0\n",
            "KillMode" => "control-group\ncontrol-group\n",
            property => panic!("unexpected systemd property {property}"),
        };
        Ok(successful_output(value))
    };
    let error = verify_systemd_service_stopped_with(
        "enoki-cpu-resource-provider@*.service",
        &mut mismatched_instances,
    )
    .expect_err("each instance needs a complete stopped-state fact set");
    assert_eq!(error.code(), "probe_uninstall_service_residue");
}

#[test]
fn stopped_instance_verification_keeps_empty_jobs_from_the_production_command_conversion() {
    let mut run = |_: &str, args: &[&str]| {
        let text = match args[2] {
            "LoadState" => "loaded\nloaded\n",
            "ActiveState" => "inactive\ninactive\n",
            "SubState" => "dead\ndead\n",
            "Job" => "\n\n",
            "MainPID" | "ControlPID" => "0\n0\n",
            "KillMode" => "control-group\ncontrol-group\n",
            property => panic!("unexpected systemd property {property}"),
        };
        run_cleanup_command("printf", &[text])
    };

    assert!(
        verify_systemd_service_stopped_with("enoki-cpu-resource-provider@*.service", &mut run,)
            .is_ok()
    );
}

#[test]
fn fixed_ipc_group_removal_preflights_complete_harmless_records_before_groupdel() {
    let group = "enoki-observation-ipc";
    let group_record = "enoki-observation-ipc:x:4242:";
    let harmless_shadow =
        "enoki-observation-ipc:!enoki-bootstrap-0123456789abcdef0123456789abcdef::";
    let passwd = "root:x:0:0:root:/root:/bin/bash\n";

    let mut unsafe_reads = || {
        Ok((
            group_record.to_owned(),
            "enoki-observation-ipc:!not-a-production-marker::".to_owned(),
            passwd.to_owned(),
        ))
    };
    let mut unsafe_calls = Vec::new();
    let mut unsafe_run = |program: &str, args: &[&str]| {
        unsafe_calls.push(format!("{program} {}", args.join(" ")));
        if program == "getent" {
            Ok(successful_output(group_record))
        } else {
            Ok(successful_output(""))
        }
    };
    assert!(
        remove_fixed_ipc_group_with_accounts(group, None, &mut unsafe_reads, &mut unsafe_run)
            .is_err()
    );
    assert!(!unsafe_calls.iter().any(|call| call.starts_with("groupdel")));

    let mut harmless_reads = || {
        Ok((
            group_record.to_owned(),
            harmless_shadow.to_owned(),
            passwd.to_owned(),
        ))
    };
    let mut harmless_calls = Vec::new();
    let mut harmless_run = |program: &str, args: &[&str]| {
        harmless_calls.push(format!("{program} {}", args.join(" ")));
        if program == "getent" {
            Ok(successful_output(group_record))
        } else {
            Ok(CleanupCommandOutput {
                code: Some(30),
                stderr: "read-only filesystem".to_owned(),
                stdout: String::new(),
                successful: false,
            })
        }
    };
    assert!(
        remove_fixed_ipc_group_with_accounts(group, None, &mut harmless_reads, &mut harmless_run,)
            .is_ok()
    );
    assert_eq!(
        harmless_calls
            .iter()
            .filter(|call| call.starts_with("groupdel"))
            .count(),
        1
    );

    let mut duplicate_reads = || {
        Ok((
            format!("{group_record}\n{group_record}"),
            harmless_shadow.to_owned(),
            passwd.to_owned(),
        ))
    };
    let mut duplicate_calls = Vec::new();
    let mut duplicate_run = |program: &str, args: &[&str]| {
        duplicate_calls.push(format!("{program} {}", args.join(" ")));
        Ok(CleanupCommandOutput {
            code: Some(2),
            stderr: String::new(),
            stdout: String::new(),
            successful: false,
        })
    };
    let error =
        remove_fixed_ipc_group_with_accounts(group, None, &mut duplicate_reads, &mut duplicate_run)
            .expect_err(
                "duplicate local record must block deletion even when keyed NSS is not found",
            );
    assert!(matches!(
        error,
        ProbeUpgraderRunError::UninstallCleanupFailure { .. }
    ));
    assert!(
        !duplicate_calls
            .iter()
            .any(|call| call.starts_with("groupdel"))
    );
}
