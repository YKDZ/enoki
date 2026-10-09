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

/// 缺失 unit 探测对固定 systemctl CLI 输出的判定结果。
enum AbsenceProbeDecision {
    /// 双支持平台 (systemd 249/255) 一致的真缺失形态，可继续安装。
    Absent,
    /// v249 的 disabled/masked 与缺失共享空 stdout + 码 1 形态；不是结论，
    /// 必须由权威 `show LoadState` 确认后才能放行。
    ExistingCandidate,
    /// 已加载/禁用/屏蔽等既有 unit 或不受支持的组合，必须拒绝。
    Existing,
    /// manager 故障或不可解析输出；不得当作缺失。
    ManagerFault,
}

/// `systemctl is-enabled` 对 enoki-probe.service 的 stdout/退出码形态判定：
/// v255 缺失打印 `not-found`（退出码 1/4）；v249 缺失与已加载 disabled/masked
/// 都打印空 stdout 且退出码 1，故空 stdout 只是待 `show` 权威确认的候选，
/// 本身从不构成缺失结论。其它码（如 v255 manager 未运行的空 stdout+4）为故障。
fn classify_is_enabled_absence_probe(stdout: &[u8], code: Option<i32>) -> AbsenceProbeDecision {
    match systemd_probe_value(stdout) {
        Some("not-found") => match code {
            Some(1) | Some(4) => AbsenceProbeDecision::Absent,
            _ => AbsenceProbeDecision::Existing,
        },
        Some("") => match code {
            Some(1) => AbsenceProbeDecision::ExistingCandidate,
            _ => AbsenceProbeDecision::ManagerFault,
        },
        Some(_) => AbsenceProbeDecision::Existing,
        None => AbsenceProbeDecision::ManagerFault,
    }
}

/// `systemctl show --property=LoadState --value` 是两版本一致的权威确认：
/// 缺失必须精确为 `not-found` 且退出码 0；沿用 `single_systemd_value` 的既有
/// 输出资格规则（空/多行/非 UTF-8 一律视为 manager 故障，不得放行安装）。
fn classify_load_state_absence_probe(stdout: &[u8], success: bool) -> AbsenceProbeDecision {
    let value = match single_systemd_value(stdout) {
        Ok(value) => value,
        Err(_) => return AbsenceProbeDecision::ManagerFault,
    };
    if !success {
        return AbsenceProbeDecision::Existing;
    }
    if value == "not-found" {
        AbsenceProbeDecision::Absent
    } else {
        AbsenceProbeDecision::Existing
    }
}

/// `is-enabled` 输出的单行资格判定：与 `single_systemd_value` 相同的换行规则，
/// 但空 stdout 是 v249 的合法可判定形态而非错误。
fn systemd_probe_value(bytes: &[u8]) -> Option<&str> {
    let value = std::str::from_utf8(bytes).ok()?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.contains(['\n', '\r']) {
        return None;
    }
    Some(value)
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

    fn preserves_live_companion_unit(&self, unit: &str) -> bool {
        match self.preserve_live_companion {
            Some(LiveCompanionFamily::General) => is_live_general_companion_unit(unit),
            Some(LiveCompanionFamily::Upgrade) => is_live_upgrade_companion_unit(unit),
            None => false,
        }
    }
}

fn is_live_general_companion_unit(unit: &str) -> bool {
    matches!(
        unit,
        "enoki-probe-lifecycle-companion.socket" | "enoki-probe-lifecycle-companion@*.service"
    )
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
        match classify_is_enabled_absence_probe(&enabled.stdout, enabled.status.code()) {
            AbsenceProbeDecision::Existing => return Err(InstallError::ExistingResidue),
            AbsenceProbeDecision::ManagerFault => return Err(InstallError::Systemd),
            AbsenceProbeDecision::Absent | AbsenceProbeDecision::ExistingCandidate => {}
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
        match classify_load_state_absence_probe(&loaded.stdout, loaded.status.success()) {
            AbsenceProbeDecision::Absent => Ok(()),
            AbsenceProbeDecision::Existing => Err(InstallError::ExistingResidue),
            AbsenceProbeDecision::ManagerFault | AbsenceProbeDecision::ExistingCandidate => {
                Err(InstallError::Systemd)
            }
        }
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
            if self.preserves_live_companion_unit(unit) {
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
            if self.preserves_live_companion_unit(unit) {
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
            if self.preserves_live_companion_unit(unit) {
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
        AbsenceProbeDecision, InstallError, ROLLBACK_RESET_UNITS, ROLLBACK_STOP_UNITS,
        ROLLBACK_VERIFY_UNITS, attempt_all_fixed_units, canonical_restart_deadline,
        classify_is_enabled_absence_probe, classify_load_state_absence_probe,
        is_live_general_companion_unit, is_live_upgrade_companion_unit, rollback_unit_is_absent,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn absence_probe_accepts_both_supported_systemd_absent_shapes() {
        // systemd 249 (Ubuntu 22.04)：缺失 unit 的 is-enabled 为空 stdout + 退出码 1，
        // 经 show LoadState=not-found 权威确认后才可继续安装。
        assert!(matches!(
            classify_is_enabled_absence_probe(b"", Some(1)),
            AbsenceProbeDecision::ExistingCandidate
        ));
        assert!(matches!(
            classify_load_state_absence_probe(b"not-found\n", true),
            AbsenceProbeDecision::Absent
        ));
        // systemd 255 (Ubuntu 24.04)：is-enabled 直接打印 not-found（退出码 1 或 4）。
        for code in [Some(1), Some(4)] {
            assert!(matches!(
                classify_is_enabled_absence_probe(b"not-found\n", code),
                AbsenceProbeDecision::Absent
            ));
        }
    }

    #[test]
    fn absence_probe_rejects_existing_units_including_v249_empty_shapes() {
        for (stdout, code) in [
            ("enabled\n", Some(0)),
            ("static\n", Some(1)),
            ("disabled\n", Some(1)),
            ("masked\n", Some(1)),
            // 异常退出码下的 not-found 不构成缺失。
            ("not-found\n", Some(0)),
        ] {
            assert!(
                matches!(
                    classify_is_enabled_absence_probe(stdout.as_bytes(), code),
                    AbsenceProbeDecision::Existing
                ),
                "已加载或不受支持形态必须拒绝: {stdout:?} {code:?}"
            );
        }
        // v249 缺失候选进入 show 后，loaded（含 masked/disabled）一律 ExistingResidue。
        for stdout in [b"loaded\n".as_slice(), b"loaded".as_slice()] {
            assert!(matches!(
                classify_load_state_absence_probe(stdout, true),
                AbsenceProbeDecision::Existing
            ));
        }
        assert!(matches!(
            classify_load_state_absence_probe(b"not-found\n", false),
            AbsenceProbeDecision::Existing
        ));
    }

    #[test]
    fn absence_probe_maps_manager_faults_to_systemd_not_absence() {
        // v255 manager 未运行：is-enabled 空 stdout + 退出码 4，不得视为缺失候选。
        assert!(matches!(
            classify_is_enabled_absence_probe(b"", Some(4)),
            AbsenceProbeDecision::ManagerFault
        ));
        assert!(matches!(
            classify_is_enabled_absence_probe(b"not-found\nnot-found\n", Some(1)),
            AbsenceProbeDecision::ManagerFault
        ));
        assert!(matches!(
            classify_is_enabled_absence_probe(&[0xff], Some(1)),
            AbsenceProbeDecision::ManagerFault
        ));
        // 权威确认命令自身无输出时不得放行安装。
        assert!(matches!(
            classify_load_state_absence_probe(b"", true),
            AbsenceProbeDecision::ManagerFault
        ));
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
    fn general_companion_preserves_only_its_own_fixed_socket_and_instance() {
        assert!(is_live_general_companion_unit(
            "enoki-probe-lifecycle-companion.socket"
        ));
        assert!(is_live_general_companion_unit(
            "enoki-probe-lifecycle-companion@*.service"
        ));
        assert!(!is_live_general_companion_unit("enoki-probe.service"));
        assert!(!is_live_general_companion_unit(
            "enoki-probe-lifecycle-upgrade.socket"
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
