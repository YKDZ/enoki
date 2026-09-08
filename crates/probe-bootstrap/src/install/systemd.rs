use super::*;

const ROLLBACK_STOP_UNITS: &[&str] = &[
    "enoki-observation-runtime-failure.service",
    "enoki-observation-runtime.socket",
    "enoki-cpu-resource-provider.socket",
    "enoki-disk-health-resource-provider.socket",
    "enoki-probe-lifecycle-companion.socket",
    "enoki-probe-lifecycle-upgrade.socket",
    "enoki-probe.service",
    "enoki-observation-runtime.service",
    "enoki-cpu-resource-provider@*.service",
    "enoki-disk-health-resource-provider@*.service",
    "enoki-probe-lifecycle-companion@*.service",
    "enoki-probe-lifecycle-upgrade@*.service",
];
const ROLLBACK_VERIFY_UNITS: &[&str] = &[
    "enoki-observation-runtime-failure.service",
    "enoki-probe.service",
    "enoki-observation-runtime.service",
    "enoki-observation-runtime.socket",
    "enoki-cpu-resource-provider.socket",
    "enoki-cpu-resource-provider@*.service",
    "enoki-disk-health-resource-provider.socket",
    "enoki-disk-health-resource-provider@*.service",
    "enoki-probe-lifecycle-companion.socket",
    "enoki-probe-lifecycle-companion@*.service",
    "enoki-probe-lifecycle-upgrade.socket",
    "enoki-probe-lifecycle-upgrade@*.service",
];
const ROLLBACK_RESET_UNITS: &[&str] = &[
    "enoki-observation-runtime-failure.service",
    "enoki-observation-runtime.socket",
    "enoki-cpu-resource-provider.socket",
    "enoki-disk-health-resource-provider.socket",
    "enoki-probe-lifecycle-companion.socket",
    "enoki-probe-lifecycle-upgrade.socket",
    "enoki-probe.service",
    "enoki-observation-runtime.service",
    "enoki-cpu-resource-provider@*.service",
    "enoki-disk-health-resource-provider@*.service",
    "enoki-probe-lifecycle-companion@*.service",
    "enoki-probe-lifecycle-upgrade@*.service",
];
const REPLACEMENT_REGISTRATION_CREDENTIAL: &str =
    "/run/credentials/enoki-probe.service/registration-attempt";

fn canonical_restart_deadline(now: Instant, _install_deadline: Option<Instant>) -> Instant {
    // canonical convergence 是安装事务完成后的独立有界步骤；install deadline 可能已被
    // response/config crash 恢复耗尽，不能阻止固定 canonical restart 被实际提交。
    now + Duration::from_secs(60)
}

fn attempt_all_fixed_units(
    units: &[&str],
    mut attempt: impl FnMut(&str) -> Result<(), InstallError>,
) -> Result<(), InstallError> {
    let mut first_error = None;
    for unit in units {
        if let Err(error) = attempt(unit)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn rollback_unit_is_absent(state: &str) -> bool {
    matches!(state.trim(), "inactive" | "unknown")
}
/// 生产 systemd adapter 不接收动态数据，所有 unit 名称和路径均为编译期常量。
#[derive(Default)]
pub struct SystemSystemd {
    command_deadline: Option<Instant>,
    preserve_live_companion: Option<LiveCompanionFamily>,
}

#[derive(Clone, Copy)]
enum LiveCompanionFamily {
    General,
    Upgrade,
}

impl SystemSystemd {
    pub fn for_live_general_companion() -> Self {
        Self {
            command_deadline: None,
            preserve_live_companion: Some(LiveCompanionFamily::General),
        }
    }

    pub fn for_live_upgrade() -> Self {
        Self {
            command_deadline: None,
            preserve_live_companion: Some(LiveCompanionFamily::Upgrade),
        }
    }

    fn preserves_live_companion_stop_or_verify_unit(&self, unit: &str) -> bool {
        match self.preserve_live_companion {
            Some(LiveCompanionFamily::General) => is_live_general_companion_unit(unit),
            Some(LiveCompanionFamily::Upgrade) => is_live_upgrade_companion_unit(unit),
            None => false,
        }
    }

    fn preserves_live_upgrade_reset_unit(&self, unit: &str) -> bool {
        matches!(
            self.preserve_live_companion,
            Some(LiveCompanionFamily::Upgrade)
        ) && is_live_upgrade_companion_unit(unit)
    }
}

fn is_live_general_companion_unit(unit: &str) -> bool {
    unit == "enoki-probe-lifecycle-companion@*.service"
}

fn is_live_upgrade_companion_unit(unit: &str) -> bool {
    matches!(
        unit,
        "enoki-probe-lifecycle-upgrade.socket" | "enoki-probe-lifecycle-upgrade@*.service"
    )
}

fn require_absent_from_load_state(loaded: &command::BoundedOutput) -> Result<(), InstallError> {
    if !loaded.status.success() || single_systemd_value(&loaded.stdout)? != "not-found" {
        return Err(InstallError::ExistingResidue);
    }
    Ok(())
}

fn fixed_unit_is_instance_glob(unit: &str) -> bool {
    matches!(
        unit,
        "enoki-cpu-resource-provider@*.service"
            | "enoki-disk-health-resource-provider@*.service"
            | "enoki-probe-lifecycle-companion@*.service"
            | "enoki-probe-lifecycle-upgrade@*.service"
    )
}

fn require_fixed_unit_absent(
    unit: &str,
    loaded: &command::BoundedOutput,
) -> Result<(), InstallError> {
    if fixed_unit_is_instance_glob(unit) && loaded.status.success() && loaded.stdout.is_empty() {
        return Ok(());
    }
    require_absent_from_load_state(loaded)
}

fn require_rollback_unit_absent(
    unit: &str,
    output: &command::BoundedOutput,
) -> Result<(), InstallError> {
    // systemd 255 对没有任何实例匹配的已知 instance glob 返回 status=4 且没有 stdout。
    // 这只说明该编译期 fixed glob 已收敛；普通 unit 的同样输出仍必须 fail closed。
    if fixed_unit_is_instance_glob(unit)
        && output.status.code() == Some(4)
        && output.stdout.is_empty()
    {
        return Ok(());
    }
    let state = std::str::from_utf8(&output.stdout).map_err(|_| InstallError::Systemd)?;
    if state.lines().count() != 1 || !state.lines().all(rollback_unit_is_absent) {
        return Err(InstallError::Systemd);
    }
    Ok(())
}

impl SystemdPort for SystemSystemd {
    fn set_command_deadline(&mut self, deadline: Instant) {
        self.command_deadline = Some(deadline);
    }
    fn require_absent(&mut self) -> Result<(), InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        for unit in ROLLBACK_VERIFY_UNITS {
            let loaded = run_bounded(
                "/usr/bin/systemctl",
                &["show", "--property=LoadState", "--value", unit],
                InstallError::Systemd,
                deadline,
                COMMAND_STEP_BUDGET,
            )?;
            require_fixed_unit_absent(unit, &loaded)?;
        }
        Ok(())
    }
    fn daemon_reload(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["daemon-reload"],
            InstallError::Systemd,
            self.command_deadline
                .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET),
        )
    }
    fn enable(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["enable", "enoki-probe.service"],
            InstallError::Systemd,
            self.command_deadline
                .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET),
        )
    }
    fn start(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["start", "--no-block", "enoki-probe.service"],
            InstallError::Systemd,
            self.command_deadline
                .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET),
        )
    }
    fn restart_canonical(&mut self) -> Result<(), InstallError> {
        let deadline = canonical_restart_deadline(Instant::now(), self.command_deadline);
        require_success(
            "/usr/bin/systemctl",
            &["restart", "enoki-probe.service"],
            InstallError::Systemd,
            deadline,
        )?;
        loop {
            let active = require_success(
                "/usr/bin/systemctl",
                &["is-active", "--quiet", "enoki-probe.service"],
                InstallError::Systemd,
                deadline,
            )
            .is_ok();
            let credential_absent = match fs::symlink_metadata(REPLACEMENT_REGISTRATION_CREDENTIAL)
            {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Ok(_) => false,
                Err(_) => return Err(InstallError::ExistingResidue),
            };
            if active && credential_absent {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(InstallError::Systemd);
            }
            thread::sleep(Duration::from_millis(250));
        }
    }
    fn wait_local_activated(&mut self) -> Result<(), InstallError> {
        let local_deadline = Instant::now() + Duration::from_secs(60);
        let deadline = std::cmp::min(
            local_deadline,
            self.command_deadline.unwrap_or(local_deadline),
        );
        loop {
            if require_success(
                "/usr/bin/systemctl",
                &["is-active", "--quiet", "enoki-probe.service"],
                InstallError::Systemd,
                deadline,
            )
            .is_ok()
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(InstallError::Systemd);
            }
            thread::sleep(Duration::from_millis(250));
        }
    }
    fn stop(&mut self) -> Result<(), InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        // 先关闭激活 socket，阻止回滚期间产生新进程，再收敛所有固定角色。
        let mut first_error = attempt_all_fixed_units(ROLLBACK_STOP_UNITS, |unit| {
            if self.preserves_live_companion_stop_or_verify_unit(unit) {
                return Ok(());
            }
            require_success(
                "/usr/bin/systemctl",
                &["stop", unit],
                InstallError::Systemd,
                deadline,
            )
        })
        .err();
        if let Err(error) = attempt_all_fixed_units(ROLLBACK_RESET_UNITS, |unit| {
            if self.preserves_live_upgrade_reset_unit(unit) {
                return Ok(());
            }
            require_success(
                "/usr/bin/systemctl",
                &["reset-failed", unit],
                InstallError::Systemd,
                deadline,
            )
        }) && first_error.is_none()
        {
            first_error = Some(error);
        }
        if let Err(error) = attempt_all_fixed_units(ROLLBACK_VERIFY_UNITS, |unit| {
            if self.preserves_live_companion_stop_or_verify_unit(unit) {
                return Ok(());
            }
            let output = run_bounded(
                "/usr/bin/systemctl",
                &["is-active", unit],
                InstallError::Systemd,
                deadline,
                COMMAND_STEP_BUDGET,
            )?;
            require_rollback_unit_absent(unit, &output)
        }) && first_error.is_none()
        {
            first_error = Some(error);
        }
        first_error.map_or(Ok(()), Err)
    }
    fn disable(&mut self) -> Result<(), InstallError> {
        require_success(
            "/usr/bin/systemctl",
            &["disable", "enoki-probe.service"],
            InstallError::Systemd,
            self.command_deadline
                .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InstallError, ROLLBACK_RESET_UNITS, ROLLBACK_STOP_UNITS, ROLLBACK_VERIFY_UNITS,
        SystemSystemd, attempt_all_fixed_units, canonical_restart_deadline, command,
        fixed_unit_is_instance_glob, require_absent_from_load_state, require_fixed_unit_absent,
        require_rollback_unit_absent, rollback_unit_is_absent,
    };
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};

    #[test]
    fn systemd_249_missing_unit_is_absent_when_load_state_is_not_found() {
        let loaded = command::BoundedOutput {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"not-found\n".to_vec(),
        };

        assert_eq!(require_absent_from_load_state(&loaded), Ok(()));
    }

    #[test]
    fn loaded_unit_is_existing_residue() {
        let loaded = command::BoundedOutput {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"loaded\n".to_vec(),
        };

        assert_eq!(
            require_absent_from_load_state(&loaded),
            Err(InstallError::ExistingResidue)
        );
    }

    #[test]
    fn failed_load_state_query_fails_closed() {
        let loaded = command::BoundedOutput {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: b"not-found\n".to_vec(),
        };

        assert_eq!(
            require_absent_from_load_state(&loaded),
            Err(InstallError::ExistingResidue)
        );
    }

    #[test]
    fn ambiguous_load_state_output_fails_closed() {
        for stdout in [b"".as_slice(), b"not-found\nloaded\n", b"not-found\r\n"] {
            let loaded = command::BoundedOutput {
                status: std::process::ExitStatus::from_raw(0),
                stdout: stdout.to_vec(),
            };

            assert_eq!(
                require_absent_from_load_state(&loaded),
                Err(InstallError::Systemd)
            );
        }
    }

    #[test]
    fn fresh_absence_accepts_only_an_empty_fixed_instance_set() {
        let empty = command::BoundedOutput {
            status: std::process::ExitStatus::from_raw(0),
            stdout: Vec::new(),
        };
        assert!(fixed_unit_is_instance_glob(
            "enoki-probe-lifecycle-companion@*.service"
        ));
        assert!(
            require_fixed_unit_absent("enoki-probe-lifecycle-companion@*.service", &empty).is_ok()
        );
        assert_eq!(
            require_fixed_unit_absent("enoki-probe.service", &empty),
            Err(InstallError::Systemd)
        );
    }

    #[test]
    fn fixed_provider_glob_empty_systemd_255_is_active_result_is_absent() {
        let empty_no_match = command::BoundedOutput {
            status: std::process::ExitStatus::from_raw(4 << 8),
            stdout: Vec::new(),
        };

        for unit in [
            "enoki-cpu-resource-provider@*.service",
            "enoki-disk-health-resource-provider@*.service",
        ] {
            assert_eq!(require_rollback_unit_absent(unit, &empty_no_match), Ok(()));
        }
    }

    #[test]
    fn rollback_verify_rejects_empty_non_glob_and_non_absent_output() {
        let empty_no_match = command::BoundedOutput {
            status: std::process::ExitStatus::from_raw(4 << 8),
            stdout: Vec::new(),
        };
        assert_eq!(
            require_rollback_unit_absent("enoki-probe.service", &empty_no_match),
            Err(InstallError::Systemd)
        );
        let empty_command_failure = command::BoundedOutput {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
        };
        assert_eq!(
            require_rollback_unit_absent(
                "enoki-cpu-resource-provider@*.service",
                &empty_command_failure
            ),
            Err(InstallError::Systemd)
        );

        for stdout in [b"active\n".as_slice(), b"failed\n", b"inactive\nactive\n"] {
            let output = command::BoundedOutput {
                status: std::process::ExitStatus::from_raw(3 << 8),
                stdout: stdout.to_vec(),
            };
            assert_eq!(
                require_rollback_unit_absent("enoki-cpu-resource-provider@*.service", &output),
                Err(InstallError::Systemd)
            );
        }
    }

    #[test]
    fn canonical_restart_gets_a_new_bounded_deadline_after_install_deadline() {
        let now = Instant::now();
        let expired_install_deadline = now - Duration::from_secs(1);

        let deadline = canonical_restart_deadline(now, Some(expired_install_deadline));

        assert_eq!(deadline.duration_since(now), Duration::from_secs(60));
    }

    #[test]
    fn live_upgrade_preserves_only_its_fixed_recovery_socket_and_instance() {
        let systemd = SystemSystemd::for_live_upgrade();

        assert!(
            systemd.preserves_live_companion_stop_or_verify_unit(
                "enoki-probe-lifecycle-upgrade.socket"
            )
        );
        assert!(systemd.preserves_live_companion_stop_or_verify_unit(
            "enoki-probe-lifecycle-upgrade@*.service"
        ));
        assert!(!systemd.preserves_live_companion_stop_or_verify_unit("enoki-probe.service"));
        assert!(!systemd.preserves_live_companion_stop_or_verify_unit(
            "enoki-probe-lifecycle-companion.socket"
        ));
        assert!(systemd.preserves_live_upgrade_reset_unit("enoki-probe-lifecycle-upgrade.socket"));
    }

    #[test]
    fn live_general_companion_preserves_its_instance_but_not_its_activation_socket() {
        let systemd = SystemSystemd::for_live_general_companion();

        assert!(systemd.preserves_live_companion_stop_or_verify_unit(
            "enoki-probe-lifecycle-companion@*.service"
        ));
        assert!(!systemd.preserves_live_companion_stop_or_verify_unit(
            "enoki-probe-lifecycle-companion.socket"
        ));
        assert!(!systemd.preserves_live_companion_stop_or_verify_unit(
            "enoki-probe-lifecycle-upgrade@*.service"
        ));
        assert!(!systemd.preserves_live_companion_stop_or_verify_unit("enoki-probe.service"));
        assert!(
            !systemd.preserves_live_upgrade_reset_unit("enoki-probe-lifecycle-companion@*.service")
        );
        assert_eq!(
            ROLLBACK_STOP_UNITS
                .iter()
                .copied()
                .filter(|unit| !systemd.preserves_live_companion_stop_or_verify_unit(unit))
                .collect::<Vec<_>>(),
            [
                "enoki-observation-runtime-failure.service",
                "enoki-observation-runtime.socket",
                "enoki-cpu-resource-provider.socket",
                "enoki-disk-health-resource-provider.socket",
                "enoki-probe-lifecycle-companion.socket",
                "enoki-probe-lifecycle-upgrade.socket",
                "enoki-probe.service",
                "enoki-observation-runtime.service",
                "enoki-cpu-resource-provider@*.service",
                "enoki-disk-health-resource-provider@*.service",
                "enoki-probe-lifecycle-upgrade@*.service",
            ]
        );
    }

    #[test]
    fn rollback_attempts_every_fixed_role_after_one_stop_failure() {
        let mut calls = Vec::new();
        let error = attempt_all_fixed_units(ROLLBACK_STOP_UNITS, |unit| {
            calls.push(unit.to_owned());
            (unit != "enoki-cpu-resource-provider.socket")
                .then_some(())
                .ok_or(InstallError::Systemd)
        })
        .expect_err("一次停止失败仍应返回关闭失败");

        assert_eq!(error, InstallError::Systemd);
        assert_eq!(calls, ROLLBACK_STOP_UNITS);
        assert!(calls.contains(&"enoki-disk-health-resource-provider.socket".to_owned()));
        assert!(calls.contains(&"enoki-disk-health-resource-provider@*.service".to_owned()));
        assert!(ROLLBACK_VERIFY_UNITS.contains(&"enoki-disk-health-resource-provider.socket"));
        assert!(ROLLBACK_VERIFY_UNITS.contains(&"enoki-disk-health-resource-provider@*.service"));
    }

    #[test]
    fn rollback_resets_every_fixed_role_in_order_and_rejects_failed_as_absent() {
        let mut calls = Vec::new();
        let error = attempt_all_fixed_units(ROLLBACK_RESET_UNITS, |unit| {
            calls.push(unit.to_owned());
            (unit != "enoki-observation-runtime.socket")
                .then_some(())
                .ok_or(InstallError::Systemd)
        })
        .expect_err("一次 reset 失败仍应返回失败");

        assert_eq!(error, InstallError::Systemd);
        assert_eq!(calls, ROLLBACK_RESET_UNITS);
        assert_eq!(
            &calls[1..4],
            [
                "enoki-observation-runtime.socket",
                "enoki-cpu-resource-provider.socket",
                "enoki-disk-health-resource-provider.socket",
            ]
        );
        assert!(rollback_unit_is_absent("inactive\n"));
        assert!(rollback_unit_is_absent("unknown\n"));
        assert!(!rollback_unit_is_absent("failed\n"));
        assert!(!rollback_unit_is_absent("active\n"));
    }
}
