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
    preserve_live_upgrade_companion: bool,
}
impl SystemSystemd {
    pub fn for_live_upgrade() -> Self {
        Self {
            command_deadline: None,
            preserve_live_upgrade_companion: true,
        }
    }
}

fn is_live_upgrade_companion_unit(unit: &str) -> bool {
    matches!(
        unit,
        "enoki-probe-lifecycle-upgrade.socket" | "enoki-probe-lifecycle-upgrade@*.service"
    )
}
impl SystemdPort for SystemSystemd {
    fn set_command_deadline(&mut self, deadline: Instant) {
        self.command_deadline = Some(deadline);
    }
    fn require_absent(&mut self) -> Result<(), InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        let enabled = run_bounded(
            "/usr/bin/systemctl",
            &["is-enabled", "--full", "--no-pager", "enoki-probe.service"],
            InstallError::Systemd,
            deadline,
            COMMAND_STEP_BUDGET,
        )?;
        let enabled_value = single_systemd_value(&enabled.stdout)?;
        if enabled_value != "not-found" || !matches!(enabled.status.code(), Some(1) | Some(4)) {
            return Err(InstallError::ExistingResidue);
        }
        let loaded = run_bounded(
            "/usr/bin/systemctl",
            &[
                "show",
                "--property=LoadState",
                "--value",
                "enoki-probe.service",
            ],
            InstallError::Systemd,
            deadline,
            COMMAND_STEP_BUDGET,
        )?;
        if !loaded.status.success() || single_systemd_value(&loaded.stdout)? != "not-found" {
            return Err(InstallError::ExistingResidue);
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
            if self.preserve_live_upgrade_companion && is_live_upgrade_companion_unit(unit) {
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
            if self.preserve_live_upgrade_companion && is_live_upgrade_companion_unit(unit) {
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
            if self.preserve_live_upgrade_companion && is_live_upgrade_companion_unit(unit) {
                return Ok(());
            }
            let output = run_bounded(
                "/usr/bin/systemctl",
                &["is-active", unit],
                InstallError::Systemd,
                deadline,
                COMMAND_STEP_BUDGET,
            )?;
            let state = String::from_utf8(output.stdout).map_err(|_| InstallError::Systemd)?;
            if state.lines().count() != 1 || !state.lines().all(rollback_unit_is_absent) {
                return Err(InstallError::Systemd);
            }
            Ok(())
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
        attempt_all_fixed_units, is_live_upgrade_companion_unit, rollback_unit_is_absent,
    };

    #[test]
    fn live_upgrade_preserves_only_its_fixed_recovery_socket_and_instance() {
        assert!(is_live_upgrade_companion_unit(
            "enoki-probe-lifecycle-upgrade.socket"
        ));
        assert!(is_live_upgrade_companion_unit(
            "enoki-probe-lifecycle-upgrade@*.service"
        ));
        assert!(!is_live_upgrade_companion_unit("enoki-probe.service"));
        assert!(!is_live_upgrade_companion_unit(
            "enoki-probe-lifecycle-companion.socket"
        ));
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
