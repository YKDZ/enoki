use super::*;
/// 生产 systemd adapter 不接收动态数据，所有 unit 名称和路径均为编译期常量。
#[derive(Default)]
pub struct SystemSystemd {
    command_deadline: Option<Instant>,
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
        // 先关闭两个激活 socket，阻止回滚期间产生新进程，再收敛所有固定角色。
        for unit in [
            "enoki-observation-runtime.socket",
            "enoki-cpu-resource-provider.socket",
            "enoki-probe.service",
            "enoki-observation-runtime.service",
            "enoki-cpu-resource-provider@*.service",
        ] {
            require_success(
                "/usr/bin/systemctl",
                &["stop", unit],
                InstallError::Systemd,
                deadline,
            )?;
        }
        require_success(
            "/usr/bin/systemctl",
            &[
                "reset-failed",
                "enoki-probe.service",
                "enoki-observation-runtime.service",
                "enoki-cpu-resource-provider@*.service",
            ],
            InstallError::Systemd,
            deadline,
        )?;
        for unit in [
            "enoki-probe.service",
            "enoki-observation-runtime.service",
            "enoki-observation-runtime.socket",
            "enoki-cpu-resource-provider.socket",
            "enoki-cpu-resource-provider@*.service",
        ] {
            let output = run_bounded(
                "/usr/bin/systemctl",
                &["is-active", unit],
                InstallError::Systemd,
                deadline,
                COMMAND_STEP_BUDGET,
            )?;
            let state = String::from_utf8(output.stdout).map_err(|_| InstallError::Systemd)?;
            if state.lines().any(|value| {
                matches!(
                    value.trim(),
                    "active" | "activating" | "reloading" | "deactivating"
                )
            }) {
                return Err(InstallError::Systemd);
            }
        }
        Ok(())
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
