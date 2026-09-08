use super::{
    CleanupCommandOutput, verify_systemd_service_absent_with, verify_systemd_service_stopped_with,
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
