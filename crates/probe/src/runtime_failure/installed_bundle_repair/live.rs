use std::{path::Path, process::Command, time::Duration};

use enoki_probe_bootstrap::{
    acquisition::{open_verified_probe_upgrade_stage, remove_verified_probe_upgrade_stage},
    install::{
        FixedInstallPaths, SystemSystemd, SystemdPort, VerifiedUpgradeComponents,
        inspect_installed_probe_for_upgrade, restore_installed_bundle_for_repair,
    },
};

use crate::secure_file::{atomic_write, ensure_directory, remove_regular_file};

use super::{
    InstalledBundleRepairDriveError, InstalledBundleRepairEffects, InstalledBundleRepairOutcome,
    ResumableInstalledBundleRepair, drive_installed_bundle_repair,
};

pub(crate) fn drive_live_installed_bundle_repair(
    session: ResumableInstalledBundleRepair,
) -> Result<InstalledBundleRepairOutcome, LiveInstalledBundleRepairError> {
    let mut effects = LiveInstalledBundleRepairEffects {
        systemd: SystemSystemd::for_live_upgrade(),
    };
    match drive_installed_bundle_repair(session, &mut effects) {
        Ok(outcome) => Ok(outcome),
        Err(InstalledBundleRepairDriveError::Effect(error)) => Err(error),
        Err(InstalledBundleRepairDriveError::RecoveryPending(code)) => {
            Err(LiveInstalledBundleRepairError::Contract(code))
        }
    }
}

#[derive(Debug)]
pub(crate) enum LiveInstalledBundleRepairError {
    ManualReinstallRequired,
    Contract(&'static str),
}

impl LiveInstalledBundleRepairError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::ManualReinstallRequired => "probe_manual_reinstall_required",
            Self::Contract(code) => code,
        }
    }
}

struct LiveInstalledBundleRepairEffects {
    systemd: SystemSystemd,
}

impl InstalledBundleRepairEffects for LiveInstalledBundleRepairEffects {
    type Error = LiveInstalledBundleRepairError;

    fn restore_bundle(
        &mut self,
        stage_receipt: &enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
        stage_owner_uid: u32,
        authority: &enoki_probe_bootstrap::lifecycle::InstalledBundleRepairAuthorityV1,
    ) -> Result<(), Self::Error> {
        let mut stage = open_verified_probe_upgrade_stage(stage_receipt, stage_owner_uid)
            .map_err(|_| LiveInstalledBundleRepairError::ManualReinstallRequired)?;
        let paths = FixedInstallPaths::production();
        let installed = inspect_installed_probe_for_upgrade(&paths)
            .map_err(|_| LiveInstalledBundleRepairError::ManualReinstallRequired)?;
        if installed.hub_origin != authority.hub_origin
            || installed.probe_id != authority.probe_id
            || installed.source_bundle_version != authority.bundle_version
            || installed.source_install_state_sha256 != authority.install_state_sha256
            || installed.source_manifest_sha256 != authority.manifest_sha256
            || stage.bundle.version != authority.bundle_version
            || stage.bundle.manifest_sha256 != authority.manifest_sha256
            || stage_receipt.target_manifest_sha256 != authority.manifest_sha256
            || stage_receipt.target_asset_set_digest != authority.target_asset_set_digest
        {
            return Err(LiveInstalledBundleRepairError::ManualReinstallRequired);
        }
        mask_runtime_validation_socket()?;
        remove_runtime_repair_validation_gate()?;
        self.systemd
            .daemon_reload()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        restore_installed_bundle_for_repair(
            VerifiedUpgradeComponents {
                probe: &mut stage.probe,
                observation_runtime: &mut stage.observation_runtime,
                system_state_provider: &mut stage.system_state_provider,
                disk_health_provider: &mut stage.disk_health_provider,
                lifecycle_companion: &mut stage.lifecycle_companion,
                bootstrap_acquirer: &mut stage.bootstrap_acquirer,
                bootstrap_activator: &mut stage.bootstrap_activator,
            },
            &stage.bundle,
            &installed,
            &paths,
            &mut self.systemd,
        )
        .map_err(|_| contract_failure("probe_repair_bundle_restore_failed"))
    }

    fn validate_temporary_runtime(&mut self) -> Result<(), Self::Error> {
        install_runtime_repair_validation_gate()?;
        self.systemd
            .daemon_reload()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        unmask_runtime_validation_socket()?;
        required_repair_systemctl(&["start", "enoki-observation-runtime.socket"])?;
        crate::observation_runtime::UnixObservationRuntimeClient::production()
            .request_finalized_window(Duration::from_secs(1), 0)
            .map(|_| ())
            .map_err(|_| contract_failure("probe_repair_runtime_validation_failed"))
    }

    fn activate_probe_on_canonical_gate(&mut self) -> Result<(), Self::Error> {
        restore_canonical_runtime_gate(&mut self.systemd)?;
        self.systemd
            .start()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        self.systemd
            .wait_local_activated()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))
    }

    fn validate_canonical_runtime(&mut self) -> Result<(), Self::Error> {
        required_repair_systemctl(&["reset-failed", "enoki-observation-runtime.service"])?;
        required_repair_systemctl(&["start", "enoki-observation-runtime.socket"])?;
        crate::observation_runtime::UnixObservationRuntimeClient::production()
            .request_finalized_window(Duration::from_secs(1), 0)
            .map(|_| ())
            .map_err(|_| contract_failure("probe_repair_canonical_runtime_validation_failed"))
    }

    fn recover_preboundary_reporting(&mut self) -> Result<(), Self::Error> {
        restore_canonical_runtime_gate(&mut self.systemd)?;
        self.systemd
            .start()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        self.systemd
            .wait_local_activated()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))
    }

    fn remove_stage(&mut self, operation_id: &str, owner_uid: u32) {
        let _ = remove_verified_probe_upgrade_stage(operation_id, owner_uid);
    }

    fn error_code<'a>(&self, error: &'a Self::Error) -> &'a str {
        error.code()
    }
}

const RUNTIME_REPAIR_RUN_DIR: &str = "/run/enoki-probe";
const RUNTIME_REPAIR_PERMIT: &str = "/run/enoki-probe/runtime-repair-permit";
const RUNTIME_REPAIR_DROP_IN_DIR: &str = "/run/systemd/system/enoki-observation-runtime.service.d";
const RUNTIME_REPAIR_DROP_IN: &str =
    "/run/systemd/system/enoki-observation-runtime.service.d/repair-validation.conf";

fn mask_runtime_validation_socket() -> Result<(), LiveInstalledBundleRepairError> {
    required_repair_systemctl(&[
        "stop",
        "enoki-probe.service",
        "enoki-observation-runtime.socket",
        "enoki-observation-runtime.service",
    ])?;
    required_repair_systemctl(&["mask", "--runtime", "enoki-observation-runtime.socket"])
}

fn install_runtime_repair_validation_gate() -> Result<(), LiveInstalledBundleRepairError> {
    ensure_directory(Path::new(RUNTIME_REPAIR_RUN_DIR), 0o700, Some((0, 0)))
        .map_err(|_| contract_failure("probe_repair_validation_gate_failed"))?;
    ensure_directory(Path::new(RUNTIME_REPAIR_DROP_IN_DIR), 0o700, Some((0, 0)))
        .map_err(|_| contract_failure("probe_repair_validation_gate_failed"))?;
    atomic_write(
        Path::new(RUNTIME_REPAIR_PERMIT),
        b"installed-bundle-repair\n",
        0o600,
        Some((0, 0)),
    )
    .map_err(|_| contract_failure("probe_repair_validation_gate_failed"))?;
    atomic_write(
        Path::new(RUNTIME_REPAIR_DROP_IN),
        b"[Unit]\nConditionPathExists=\nConditionPathExists=/run/enoki-probe/runtime-repair-permit\n",
        0o600,
        Some((0, 0)),
    )
    .map_err(|_| contract_failure("probe_repair_validation_gate_failed"))
}

fn remove_runtime_repair_validation_gate() -> Result<(), LiveInstalledBundleRepairError> {
    for path in [RUNTIME_REPAIR_DROP_IN, RUNTIME_REPAIR_PERMIT] {
        match remove_regular_file(Path::new(path), 0o600, Some((0, 0))) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(contract_failure("probe_repair_validation_gate_failed"));
            }
        }
    }
    Ok(())
}

fn restore_canonical_runtime_gate(
    systemd: &mut impl SystemdPort,
) -> Result<(), LiveInstalledBundleRepairError> {
    required_repair_systemctl(&["stop", "enoki-observation-runtime.service"])?;
    remove_runtime_repair_validation_gate()?;
    systemd
        .daemon_reload()
        .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
    unmask_runtime_validation_socket()
}

fn unmask_runtime_validation_socket() -> Result<(), LiveInstalledBundleRepairError> {
    required_repair_systemctl(&["unmask", "--runtime", "enoki-observation-runtime.socket"])
}

fn required_repair_systemctl(arguments: &[&str]) -> Result<(), LiveInstalledBundleRepairError> {
    let status = Command::new("/usr/bin/systemctl")
        .args(arguments)
        .status()
        .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| contract_failure("probe_repair_systemd_failed"))
}

fn contract_failure(code: &'static str) -> LiveInstalledBundleRepairError {
    LiveInstalledBundleRepairError::Contract(code)
}
