use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use enoki_probe_bootstrap::{
    acquisition::{
        VerifiedProbeUpgradeStage, VerifiedUpgradeStageReceipt, open_verified_probe_upgrade_stage,
        remove_verified_probe_upgrade_stage,
    },
    install::{
        FixedInstallPaths, InstalledBundleRepairBinding, InstalledUpgradeBinding, SystemSystemd,
        SystemdPort, VerifiedUpgradeComponents, cleanup_installed_bundle_repair,
        inspect_installed_probe_for_upgrade, restore_installed_bundle_for_repair,
        verify_installed_bundle_repair_complete,
    },
    lifecycle::InstalledBundleRepairAuthorityV1,
    verifier::VerifiedBundle,
};

use crate::secure_file::{atomic_write, ensure_directory, remove_regular_file};

use super::{
    InstalledBundleRepairDriveError, InstalledBundleRepairEffects, InstalledBundleRepairOutcome,
    ResumableInstalledBundleRepair, drive_installed_bundle_repair,
};

pub(crate) fn drive_live_installed_bundle_repair(
    session: ResumableInstalledBundleRepair,
) -> Result<InstalledBundleRepairOutcome, LiveInstalledBundleRepairError> {
    drive_live_installed_bundle_repair_with(session, LiveRepairContext::production())
}

fn drive_live_installed_bundle_repair_with<S, R, V, O, H>(
    session: ResumableInstalledBundleRepair,
    context: LiveRepairContext<S, R, V, O, H>,
) -> Result<InstalledBundleRepairOutcome, LiveInstalledBundleRepairError>
where
    S: SystemdPort,
    R: FixedRepairSystemdRunner,
    V: RuntimeValidator,
    O: RepairStageOpener,
    H: LiveRepairCrashHook,
{
    let mut effects = LiveInstalledBundleRepairEffects { context };
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

struct LiveRepairContext<S, R, V, O, H> {
    root: PathBuf,
    paths: FixedInstallPaths,
    systemd: S,
    runner: R,
    runtime: V,
    stages: O,
    crash: H,
}

impl
    LiveRepairContext<
        SystemSystemd,
        ProcessRepairSystemdRunner,
        UnixRuntimeValidator,
        ProductionStageOpener,
        NoLiveRepairCrash,
    >
{
    fn production() -> Self {
        Self {
            root: PathBuf::from("/"),
            paths: FixedInstallPaths::production(),
            systemd: SystemSystemd::for_live_general_companion(),
            runner: ProcessRepairSystemdRunner,
            runtime: UnixRuntimeValidator,
            stages: ProductionStageOpener,
            crash: NoLiveRepairCrash,
        }
    }
}

struct LiveInstalledBundleRepairEffects<S, R, V, O, H> {
    context: LiveRepairContext<S, R, V, O, H>,
}

impl<S, R, V, O, H> LiveInstalledBundleRepairEffects<S, R, V, O, H>
where
    S: SystemdPort,
    R: FixedRepairSystemdRunner,
    V: RuntimeValidator,
    O: RepairStageOpener,
    H: LiveRepairCrashHook,
{
    fn open_bound_stage(
        &mut self,
        receipt: &VerifiedUpgradeStageReceipt,
        owner_uid: u32,
        authority: &InstalledBundleRepairAuthorityV1,
    ) -> Result<
        (
            RepairStage,
            InstalledUpgradeBinding,
            InstalledBundleRepairBinding,
        ),
        LiveInstalledBundleRepairError,
    > {
        let stage = self.context.stages.open(receipt, owner_uid)?;
        let installed = inspect_installed_probe_for_upgrade(&self.context.paths)
            .map_err(|_| LiveInstalledBundleRepairError::ManualReinstallRequired)?;
        if installed.hub_origin != authority.hub_origin
            || installed.probe_id != authority.probe_id
            || installed.source_bundle_version != authority.bundle_version
            || installed.source_install_state_sha256 != authority.install_state_sha256
            || installed.source_manifest_sha256 != authority.manifest_sha256
            || stage.bundle.version != authority.bundle_version
            || stage.bundle.manifest_sha256 != authority.manifest_sha256
            || receipt.target_manifest_sha256 != authority.manifest_sha256
            || receipt.target_asset_set_digest != authority.target_asset_set_digest
        {
            return Err(LiveInstalledBundleRepairError::ManualReinstallRequired);
        }
        let binding =
            InstalledBundleRepairBinding::from_verified_stage(authority, receipt, owner_uid)
                .map_err(|_| LiveInstalledBundleRepairError::ManualReinstallRequired)?;
        Ok((stage, installed, binding))
    }
}

impl<S, R, V, O, H> InstalledBundleRepairEffects for LiveInstalledBundleRepairEffects<S, R, V, O, H>
where
    S: SystemdPort,
    R: FixedRepairSystemdRunner,
    V: RuntimeValidator,
    O: RepairStageOpener,
    H: LiveRepairCrashHook,
{
    type Error = LiveInstalledBundleRepairError;

    fn restore_bundle(
        &mut self,
        stage_receipt: &VerifiedUpgradeStageReceipt,
        stage_owner_uid: u32,
        authority: &InstalledBundleRepairAuthorityV1,
    ) -> Result<(), Self::Error> {
        let (mut stage, installed, binding) =
            self.open_bound_stage(stage_receipt, stage_owner_uid, authority)?;
        mask_runtime_validation_socket(&mut self.context.runner)?;
        remove_runtime_repair_validation_gate(&self.context.root)?;
        self.context
            .crash
            .after(LiveRepairEffect::RuntimeGateRemoved)?;
        self.context
            .systemd
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
            &binding,
            &self.context.paths,
            &mut self.context.systemd,
        )
        .map_err(|_| contract_failure("probe_repair_bundle_restore_failed"))
    }

    fn validate_temporary_runtime(&mut self) -> Result<(), Self::Error> {
        mask_runtime_validation_socket(&mut self.context.runner)?;
        remove_runtime_repair_validation_gate(&self.context.root)?;
        self.context
            .crash
            .after(LiveRepairEffect::RuntimeGateRemoved)?;
        self.context
            .systemd
            .daemon_reload()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        install_runtime_repair_validation_gate(&self.context.root, RuntimeValidation::Temporary)?;
        self.context
            .crash
            .after(LiveRepairEffect::TemporaryGateInstalled)?;
        self.context
            .systemd
            .daemon_reload()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        self.context
            .runner
            .run(RepairSystemdAction::UnmaskRuntimeSocket)?;
        self.context
            .runner
            .run(RepairSystemdAction::StartRuntimeSocket)?;
        self.context.runtime.validate(RuntimeValidation::Temporary)
    }

    fn normalize_canonical_runtime(&mut self) -> Result<(), Self::Error> {
        install_canonical_runtime_gate(
            &self.context.root,
            &mut self.context.systemd,
            &mut self.context.runner,
            &mut self.context.crash,
        )
    }

    fn activate_probe_on_canonical_gate(&mut self) -> Result<(), Self::Error> {
        self.normalize_canonical_runtime()?;
        self.context
            .systemd
            .start()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        self.context
            .systemd
            .wait_local_activated()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))
    }

    fn validate_canonical_runtime(&mut self) -> Result<(), Self::Error> {
        self.context
            .runner
            .run(RepairSystemdAction::ResetRuntimeFailed)?;
        self.context
            .runner
            .run(RepairSystemdAction::StartRuntimeSocket)?;
        self.context.runtime.validate(RuntimeValidation::Canonical)
    }

    fn activate_final_ordinary_probe(&mut self) -> Result<(), Self::Error> {
        mask_runtime_validation_socket(&mut self.context.runner)?;
        remove_runtime_repair_validation_gate(&self.context.root)?;
        self.context
            .systemd
            .daemon_reload()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        self.context
            .runner
            .run(RepairSystemdAction::UnmaskRuntimeSocket)?;
        self.context
            .runner
            .run(RepairSystemdAction::StartRuntimeSocket)?;
        self.context
            .systemd
            .start()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        self.context
            .systemd
            .wait_local_activated()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))
    }

    fn quiesce_status_published(&mut self) -> Result<(), Self::Error> {
        mask_canonical_runtime_socket(&mut self.context.runner)?;
        remove_runtime_repair_validation_gate(&self.context.root)?;
        self.context
            .crash
            .after(LiveRepairEffect::CanonicalGateRemoved)?;
        self.context
            .systemd
            .daemon_reload()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))
    }

    fn recover_preboundary_reporting(&mut self) -> Result<(), Self::Error> {
        mask_runtime_validation_socket(&mut self.context.runner)?;
        remove_runtime_repair_validation_gate(&self.context.root)?;
        self.context
            .systemd
            .daemon_reload()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        self.context
            .runner
            .run(RepairSystemdAction::UnmaskRuntimeSocket)?;
        self.context
            .runner
            .run(RepairSystemdAction::StartRuntimeSocket)?;
        self.context
            .systemd
            .start()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        self.context
            .systemd
            .wait_local_activated()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))
    }

    fn verify_bundle_restore_complete(
        &mut self,
        receipt: &VerifiedUpgradeStageReceipt,
        owner_uid: u32,
        authority: &InstalledBundleRepairAuthorityV1,
    ) -> Result<(), Self::Error> {
        let (stage, installed, binding) = self.open_bound_stage(receipt, owner_uid, authority)?;
        verify_installed_bundle_repair_complete(
            &stage.bundle,
            &installed,
            &binding,
            &self.context.paths,
        )
        .map_err(|_| contract_failure("probe_repair_bundle_verification_failed"))
    }

    fn retire_bundle_restore(
        &mut self,
        receipt: &VerifiedUpgradeStageReceipt,
        owner_uid: u32,
        authority: &InstalledBundleRepairAuthorityV1,
    ) -> Result<(), Self::Error> {
        let binding =
            InstalledBundleRepairBinding::from_verified_stage(authority, receipt, owner_uid)
                .map_err(|_| contract_failure("probe_repair_bundle_cleanup_failed"))?;
        self.context
            .crash
            .after(LiveRepairEffect::StatusPublishedBeforeRetirement)?;
        cleanup_installed_bundle_repair(&binding, &self.context.paths)
            .map_err(|_| contract_failure("probe_repair_bundle_cleanup_failed"))
    }

    fn remove_stage(&mut self, operation_id: &str, owner_uid: u32) -> Result<(), Self::Error> {
        self.context.stages.remove(operation_id, owner_uid)
    }

    fn after_intent_retirement(&mut self) -> Result<(), Self::Error> {
        self.context.crash.after(LiveRepairEffect::IntentRetired)
    }

    fn error_code<'a>(&self, error: &'a Self::Error) -> &'a str {
        error.code()
    }
}

struct RepairStage {
    probe: File,
    observation_runtime: File,
    system_state_provider: File,
    disk_health_provider: File,
    lifecycle_companion: File,
    bootstrap_acquirer: File,
    bootstrap_activator: File,
    bundle: VerifiedBundle,
}

impl From<VerifiedProbeUpgradeStage> for RepairStage {
    fn from(stage: VerifiedProbeUpgradeStage) -> Self {
        Self {
            probe: stage.probe,
            observation_runtime: stage.observation_runtime,
            system_state_provider: stage.system_state_provider,
            disk_health_provider: stage.disk_health_provider,
            lifecycle_companion: stage.lifecycle_companion,
            bootstrap_acquirer: stage.bootstrap_acquirer,
            bootstrap_activator: stage.bootstrap_activator,
            bundle: stage.bundle,
        }
    }
}

trait RepairStageOpener {
    fn open(
        &mut self,
        receipt: &VerifiedUpgradeStageReceipt,
        owner_uid: u32,
    ) -> Result<RepairStage, LiveInstalledBundleRepairError>;
    fn remove(
        &mut self,
        operation_id: &str,
        owner_uid: u32,
    ) -> Result<(), LiveInstalledBundleRepairError>;
}

struct ProductionStageOpener;

impl RepairStageOpener for ProductionStageOpener {
    fn open(
        &mut self,
        receipt: &VerifiedUpgradeStageReceipt,
        owner_uid: u32,
    ) -> Result<RepairStage, LiveInstalledBundleRepairError> {
        open_verified_probe_upgrade_stage(receipt, owner_uid)
            .map(RepairStage::from)
            .map_err(|_| LiveInstalledBundleRepairError::ManualReinstallRequired)
    }

    fn remove(
        &mut self,
        operation_id: &str,
        owner_uid: u32,
    ) -> Result<(), LiveInstalledBundleRepairError> {
        remove_verified_probe_upgrade_stage(operation_id, owner_uid)
            .map_err(|_| contract_failure("probe_repair_stage_cleanup_failed"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepairSystemdAction {
    StopRepairServices,
    MaskRuntimeSocket,
    ResetRuntimeFailed,
    StartRuntimeSocket,
    StopCanonicalRuntime,
    UnmaskRuntimeSocket,
}

trait FixedRepairSystemdRunner {
    fn run(&mut self, action: RepairSystemdAction) -> Result<(), LiveInstalledBundleRepairError>;
}

struct ProcessRepairSystemdRunner;

impl FixedRepairSystemdRunner for ProcessRepairSystemdRunner {
    fn run(&mut self, action: RepairSystemdAction) -> Result<(), LiveInstalledBundleRepairError> {
        let arguments: &[&str] = match action {
            RepairSystemdAction::StopRepairServices => &[
                "stop",
                "enoki-probe.service",
                "enoki-observation-runtime.socket",
                "enoki-observation-runtime.service",
            ],
            RepairSystemdAction::MaskRuntimeSocket => {
                &["mask", "--runtime", "enoki-observation-runtime.socket"]
            }
            RepairSystemdAction::ResetRuntimeFailed => {
                &["reset-failed", "enoki-observation-runtime.service"]
            }
            RepairSystemdAction::StartRuntimeSocket => {
                &["start", "enoki-observation-runtime.socket"]
            }
            RepairSystemdAction::StopCanonicalRuntime => &[
                "stop",
                "enoki-observation-runtime.socket",
                "enoki-observation-runtime.service",
            ],
            RepairSystemdAction::UnmaskRuntimeSocket => {
                &["unmask", "--runtime", "enoki-observation-runtime.socket"]
            }
        };
        let status = Command::new("/usr/bin/systemctl")
            .args(arguments)
            .status()
            .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| contract_failure("probe_repair_systemd_failed"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeValidation {
    Temporary,
    Canonical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveRepairEffect {
    RuntimeGateRemoved,
    TemporaryGateInstalled,
    CanonicalGateRemoved,
    StatusPublishedBeforeRetirement,
    IntentRetired,
}

trait LiveRepairCrashHook {
    fn after(&mut self, effect: LiveRepairEffect) -> Result<(), LiveInstalledBundleRepairError>;
}

struct NoLiveRepairCrash;

impl LiveRepairCrashHook for NoLiveRepairCrash {
    fn after(&mut self, _: LiveRepairEffect) -> Result<(), LiveInstalledBundleRepairError> {
        Ok(())
    }
}

trait RuntimeValidator {
    fn validate(
        &mut self,
        validation: RuntimeValidation,
    ) -> Result<(), LiveInstalledBundleRepairError>;
}

struct UnixRuntimeValidator;

impl RuntimeValidator for UnixRuntimeValidator {
    fn validate(
        &mut self,
        validation: RuntimeValidation,
    ) -> Result<(), LiveInstalledBundleRepairError> {
        validate_runtime_window(
            &crate::observation_runtime::UnixObservationRuntimeClient::production(),
            validation,
        )
    }
}

fn validate_runtime_window(
    client: &impl crate::observation_runtime::ObservationWindowClient,
    validation: RuntimeValidation,
) -> Result<(), LiveInstalledBundleRepairError> {
    client
        .request_finalized_window(Duration::from_secs(1), 1)
        .map(|_| ())
        .map_err(|_| match validation {
            RuntimeValidation::Temporary => {
                contract_failure("probe_repair_runtime_validation_failed")
            }
            RuntimeValidation::Canonical => {
                contract_failure("probe_repair_canonical_runtime_validation_failed")
            }
        })
}

const RUNTIME_REPAIR_RUN_DIR: &str = "/run/enoki-probe";
const RUNTIME_REPAIR_PERMIT: &str = "/run/enoki-probe/runtime-repair-permit";
const RUNTIME_REPAIR_DROP_IN_DIR: &str = "/run/systemd/system/enoki-observation-runtime.service.d";
const RUNTIME_REPAIR_DROP_IN: &str =
    "/run/systemd/system/enoki-observation-runtime.service.d/repair-validation.conf";
// 验证 gate 只授权 root 修复角色读取固定别名 metadata；撤销 permit 即撤销授权。
const VALIDATION_DROP_IN_TEMPORARY: &[u8] = b"[Unit]\nConditionPathExists=\nConditionPathExists=/run/enoki-probe/runtime-repair-permit\n[Service]\nEnvironment=ENOKI_RUNTIME_REPAIR_VALIDATION=1\nBindReadOnlyPaths=/run/enoki-probe/runtime-repair-permit:/run/enoki-runtime-repair-permit\n";
const VALIDATION_DROP_IN_CANONICAL: &[u8] = b"[Unit]\nConditionPathExists=\nConditionPathExists=!/var/lib/enoki-probe/runtime-failure/latch\nConditionPathExists=/run/enoki-probe/runtime-repair-permit\n[Service]\nEnvironment=ENOKI_RUNTIME_REPAIR_VALIDATION=1\nBindReadOnlyPaths=/run/enoki-probe/runtime-repair-permit:/run/enoki-runtime-repair-permit\n";

fn rooted(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn mask_runtime_validation_socket(
    runner: &mut impl FixedRepairSystemdRunner,
) -> Result<(), LiveInstalledBundleRepairError> {
    runner.run(RepairSystemdAction::StopRepairServices)?;
    runner.run(RepairSystemdAction::MaskRuntimeSocket)
}

fn mask_canonical_runtime_socket(
    runner: &mut impl FixedRepairSystemdRunner,
) -> Result<(), LiveInstalledBundleRepairError> {
    runner.run(RepairSystemdAction::StopCanonicalRuntime)?;
    runner.run(RepairSystemdAction::MaskRuntimeSocket)
}

fn install_runtime_repair_validation_gate(
    root: &Path,
    validation: RuntimeValidation,
) -> Result<(), LiveInstalledBundleRepairError> {
    let uid = unsafe { libc::geteuid() };
    ensure_directory(
        &rooted(root, RUNTIME_REPAIR_RUN_DIR),
        0o700,
        Some((uid, uid)),
    )
    .map_err(|_| contract_failure("probe_repair_validation_gate_failed"))?;
    ensure_directory(
        &rooted(root, RUNTIME_REPAIR_DROP_IN_DIR),
        0o700,
        Some((uid, uid)),
    )
    .map_err(|_| contract_failure("probe_repair_validation_gate_failed"))?;
    atomic_write(
        &rooted(root, RUNTIME_REPAIR_PERMIT),
        b"installed-bundle-repair\n",
        0o600,
        Some((uid, uid)),
    )
    .map_err(|_| contract_failure("probe_repair_validation_gate_failed"))?;
    let drop_in: &[u8] = match validation {
        RuntimeValidation::Temporary => VALIDATION_DROP_IN_TEMPORARY,
        RuntimeValidation::Canonical => VALIDATION_DROP_IN_CANONICAL,
    };
    atomic_write(
        &rooted(root, RUNTIME_REPAIR_DROP_IN),
        drop_in,
        0o600,
        Some((uid, uid)),
    )
    .map_err(|_| contract_failure("probe_repair_validation_gate_failed"))
}

fn remove_runtime_repair_validation_gate(
    root: &Path,
) -> Result<(), LiveInstalledBundleRepairError> {
    let uid = unsafe { libc::geteuid() };
    for path in [RUNTIME_REPAIR_DROP_IN, RUNTIME_REPAIR_PERMIT] {
        match remove_regular_file(&rooted(root, path), 0o600, Some((uid, uid))) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(contract_failure("probe_repair_validation_gate_failed")),
        }
    }
    Ok(())
}

fn install_canonical_runtime_gate(
    root: &Path,
    systemd: &mut impl SystemdPort,
    runner: &mut impl FixedRepairSystemdRunner,
    crash: &mut impl LiveRepairCrashHook,
) -> Result<(), LiveInstalledBundleRepairError> {
    runner.run(RepairSystemdAction::StopCanonicalRuntime)?;
    runner.run(RepairSystemdAction::MaskRuntimeSocket)?;
    remove_runtime_repair_validation_gate(root)?;
    crash.after(LiveRepairEffect::CanonicalGateRemoved)?;
    systemd
        .daemon_reload()
        .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
    install_runtime_repair_validation_gate(root, RuntimeValidation::Canonical)?;
    systemd
        .daemon_reload()
        .map_err(|_| contract_failure("probe_repair_systemd_failed"))?;
    runner.run(RepairSystemdAction::UnmaskRuntimeSocket)
}

fn contract_failure(code: &'static str) -> LiveInstalledBundleRepairError {
    LiveInstalledBundleRepairError::Contract(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use enoki_probe_bootstrap::install::{
        InstallError, InstalledBundleRepairCrashPoint, set_installed_bundle_repair_crash_for_test,
    };
    use std::{
        cell::RefCell,
        fs,
        os::unix::fs::PermissionsExt,
        panic::{AssertUnwindSafe, catch_unwind},
        rc::Rc,
    };

    use crate::runtime_failure::{
        InstalledBundleRepairProgress, RuntimeFailureSystemd,
        installed_bundle_failure_is_current_at, resume_installed_bundle_repair_at,
        tests::{repair_completion_fixture, repair_test_bundle},
    };

    struct TerminalRuntime;

    impl RuntimeFailureSystemd for TerminalRuntime {
        fn recorder_unit_show(&mut self) -> std::io::Result<String> {
            Err(std::io::Error::other("observation runtime active"))
        }

        fn runtime_unit_show(&mut self) -> std::io::Result<String> {
            Err(std::io::Error::other("observation runtime active"))
        }

        fn observe_monotonic_usec(&mut self) -> std::io::Result<u64> {
            Err(std::io::Error::other("observation runtime active"))
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FaultEvent {
        SystemdStop,
        SystemdReload,
        ProbeStart,
        ProbeWait,
        Runner(RepairSystemdAction),
        Runtime(RuntimeValidation),
        Gate(LiveRepairEffect),
        StageRetirement,
    }

    #[derive(Default)]
    struct FaultPlan {
        target: Option<(FaultEvent, usize)>,
        seen: usize,
        transcript: Vec<FaultEvent>,
    }

    impl FaultPlan {
        fn effect(&mut self, event: FaultEvent) {
            self.transcript.push(event);
            let Some((target, occurrence)) = self.target else {
                return;
            };
            if event != target {
                return;
            }
            self.seen += 1;
            if self.seen == occurrence {
                self.target = None;
                panic!("simulated abrupt process disappearance after {event:?}");
            }
        }
    }

    type SharedFault = Rc<RefCell<FaultPlan>>;

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct ObservableSystemState {
        services_stopped: bool,
        socket_masked: bool,
        socket_started: bool,
        runtime_stopped: bool,
        temporary_runtime_healthy: bool,
        canonical_runtime_healthy: bool,
        probe_started: bool,
        probe_active: bool,
        reload_generation: usize,
    }

    type SharedSystemState = Rc<RefCell<ObservableSystemState>>;

    #[derive(Clone)]
    struct TestSystemd {
        transcript: Rc<RefCell<Vec<&'static str>>>,
        fault: SharedFault,
        state: SharedSystemState,
    }

    impl SystemdPort for TestSystemd {
        fn require_absent(&mut self) -> Result<(), InstallError> {
            Ok(())
        }
        fn daemon_reload(&mut self) -> Result<(), InstallError> {
            self.transcript.borrow_mut().push("reload");
            self.state.borrow_mut().reload_generation += 1;
            self.fault.borrow_mut().effect(FaultEvent::SystemdReload);
            Ok(())
        }
        fn enable(&mut self) -> Result<(), InstallError> {
            Ok(())
        }
        fn start(&mut self) -> Result<(), InstallError> {
            self.transcript.borrow_mut().push("start-probe");
            let mut state = self.state.borrow_mut();
            assert!(
                !state.socket_masked,
                "Probe cannot start behind a masked gate"
            );
            state.services_stopped = false;
            state.probe_started = true;
            drop(state);
            self.fault.borrow_mut().effect(FaultEvent::ProbeStart);
            Ok(())
        }
        fn wait_local_activated(&mut self) -> Result<(), InstallError> {
            self.transcript.borrow_mut().push("probe-active");
            let mut state = self.state.borrow_mut();
            assert!(state.probe_started, "Probe activation requires Probe start");
            state.probe_active = true;
            drop(state);
            self.fault.borrow_mut().effect(FaultEvent::ProbeWait);
            Ok(())
        }
        fn stop(&mut self) -> Result<(), InstallError> {
            self.transcript.borrow_mut().push("stop");
            let mut state = self.state.borrow_mut();
            state.services_stopped = true;
            state.probe_started = false;
            state.probe_active = false;
            drop(state);
            self.fault.borrow_mut().effect(FaultEvent::SystemdStop);
            Ok(())
        }
        fn disable(&mut self) -> Result<(), InstallError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestRunner {
        transcript: Rc<RefCell<Vec<RepairSystemdAction>>>,
        fault: SharedFault,
        state: SharedSystemState,
    }

    impl FixedRepairSystemdRunner for TestRunner {
        fn run(
            &mut self,
            action: RepairSystemdAction,
        ) -> Result<(), LiveInstalledBundleRepairError> {
            self.transcript.borrow_mut().push(action);
            let mut state = self.state.borrow_mut();
            match action {
                RepairSystemdAction::StopRepairServices => {
                    state.services_stopped = true;
                    state.probe_started = false;
                    state.probe_active = false;
                    state.socket_started = false;
                    state.runtime_stopped = true;
                }
                RepairSystemdAction::MaskRuntimeSocket => {
                    assert!(
                        state.services_stopped || state.runtime_stopped,
                        "Runtime socket 只能在其服务已先停止后被 mask"
                    );
                    state.socket_masked = true;
                    state.socket_started = false;
                }
                RepairSystemdAction::ResetRuntimeFailed => {
                    assert!(state.probe_active);
                }
                RepairSystemdAction::StartRuntimeSocket => {
                    assert!(!state.socket_masked);
                    state.socket_started = true;
                    state.runtime_stopped = false;
                }
                RepairSystemdAction::StopCanonicalRuntime => {
                    state.runtime_stopped = true;
                    state.socket_started = false;
                }
                RepairSystemdAction::UnmaskRuntimeSocket => state.socket_masked = false,
            }
            drop(state);
            self.fault.borrow_mut().effect(FaultEvent::Runner(action));
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestRuntime {
        transcript: Rc<RefCell<Vec<RuntimeValidation>>>,
        fail_on: Rc<RefCell<Option<RuntimeValidation>>>,
        fault: SharedFault,
        state: SharedSystemState,
    }

    impl RuntimeValidator for TestRuntime {
        fn validate(
            &mut self,
            validation: RuntimeValidation,
        ) -> Result<(), LiveInstalledBundleRepairError> {
            self.transcript.borrow_mut().push(validation);
            {
                let state = self.state.borrow();
                assert!(
                    state.socket_started,
                    "Runtime validation requires its socket"
                );
                if validation == RuntimeValidation::Canonical {
                    assert!(state.probe_active);
                }
            }
            if *self.fail_on.borrow() == Some(validation) {
                return Err(match validation {
                    RuntimeValidation::Temporary => {
                        contract_failure("probe_repair_runtime_validation_failed")
                    }
                    RuntimeValidation::Canonical => {
                        contract_failure("probe_repair_canonical_runtime_validation_failed")
                    }
                });
            }
            {
                let mut state = self.state.borrow_mut();
                match validation {
                    RuntimeValidation::Temporary => state.temporary_runtime_healthy = true,
                    RuntimeValidation::Canonical => state.canonical_runtime_healthy = true,
                }
                drop(state);
            }
            // 验证窗口只有完整成功才可观测；崩溃注入发生在效果完成之后。
            self.fault
                .borrow_mut()
                .effect(FaultEvent::Runtime(validation));
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestCrash(SharedFault);

    impl LiveRepairCrashHook for TestCrash {
        fn after(
            &mut self,
            effect: LiveRepairEffect,
        ) -> Result<(), LiveInstalledBundleRepairError> {
            self.0.borrow_mut().effect(FaultEvent::Gate(effect));
            Ok(())
        }
    }

    struct TestStageOpener {
        directory: PathBuf,
        bundle: VerifiedBundle,
        removed: Rc<RefCell<usize>>,
        fault: SharedFault,
    }

    impl RepairStageOpener for TestStageOpener {
        fn open(
            &mut self,
            _: &VerifiedUpgradeStageReceipt,
            _: u32,
        ) -> Result<RepairStage, LiveInstalledBundleRepairError> {
            let open = |name: &str| {
                File::open(self.directory.join(name))
                    .map_err(|_| LiveInstalledBundleRepairError::ManualReinstallRequired)
            };
            Ok(RepairStage {
                probe: open("probe")?,
                observation_runtime: open("runtime")?,
                system_state_provider: open("provider")?,
                disk_health_provider: open("disk")?,
                lifecycle_companion: open("lifecycle")?,
                bootstrap_acquirer: open("acquirer")?,
                bootstrap_activator: open("activator")?,
                bundle: self.bundle.clone(),
            })
        }

        fn remove(&mut self, _: &str, _: u32) -> Result<(), LiveInstalledBundleRepairError> {
            if self.directory.exists() {
                fs::remove_dir_all(&self.directory)
                    .map_err(|_| contract_failure("probe_repair_stage_cleanup_failed"))?;
                *self.removed.borrow_mut() += 1;
            }
            self.fault.borrow_mut().effect(FaultEvent::StageRetirement);
            Ok(())
        }
    }

    struct LiveFixture {
        root: tempfile::TempDir,
        stage: PathBuf,
        systemd: TestSystemd,
        runner: TestRunner,
        runtime: TestRuntime,
        state: SharedSystemState,
        removed: Rc<RefCell<usize>>,
        fault: SharedFault,
    }

    impl LiveFixture {
        fn new() -> Self {
            Self::with_fault(None)
        }

        fn with_fault(target: Option<(FaultEvent, usize)>) -> Self {
            let (root, _) = repair_completion_fixture(InstalledBundleRepairProgress::Admitted, 91);
            for directory in [
                "usr/local/bin",
                "var/lib/enoki-probe-bootstrap",
                "etc/systemd/system",
                "run/systemd/system",
            ] {
                fs::create_dir_all(root.path().join(directory)).unwrap();
            }
            fs::set_permissions(
                root.path().join("var/lib/enoki-probe-bootstrap"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            for path in [
                "usr/local/bin/enoki-probe",
                "usr/local/bin/enoki-observation-runtime",
                "usr/local/bin/enoki-cpu-resource-provider",
                "usr/local/bin/enoki-disk-health-resource-provider",
                "usr/local/bin/enoki-probe-lifecycle-companion",
                "usr/local/bin/enoki-probe-bootstrap-acquire",
                "usr/local/bin/enoki-probe-bootstrap-activate",
            ] {
                write_mode(root.path().join(path), b"old", 0o755);
            }
            for path in [
                "etc/systemd/system/enoki-probe.service",
                "etc/systemd/system/enoki-observation-runtime.socket",
                "etc/systemd/system/enoki-cpu-resource-provider@.service",
                "etc/systemd/system/enoki-cpu-resource-provider.socket",
                "etc/systemd/system/enoki-disk-health-resource-provider@.service",
                "etc/systemd/system/enoki-disk-health-resource-provider.socket",
                "etc/systemd/system/enoki-probe-lifecycle-companion@.service",
                "etc/systemd/system/enoki-probe-lifecycle-companion.socket",
                "etc/systemd/system/enoki-probe-lifecycle-upgrade@.service",
                "etc/systemd/system/enoki-probe-lifecycle-upgrade.socket",
            ] {
                write_mode(root.path().join(path), b"old-unit", 0o644);
            }
            let stage = root.path().join("var/lib/enoki-probe/upgrade-stages/50");
            fs::create_dir_all(&stage).unwrap();
            for name in [
                "probe",
                "runtime",
                "provider",
                "disk",
                "lifecycle",
                "acquirer",
                "activator",
            ] {
                write_mode(stage.join(name), b"probe", 0o600);
            }
            let fault = Rc::new(RefCell::new(FaultPlan {
                target,
                seen: 0,
                transcript: Vec::new(),
            }));
            let state = Rc::new(RefCell::new(ObservableSystemState::default()));
            Self {
                root,
                stage,
                systemd: TestSystemd {
                    transcript: Rc::new(RefCell::new(Vec::new())),
                    fault: fault.clone(),
                    state: state.clone(),
                },
                runner: TestRunner {
                    transcript: Rc::new(RefCell::new(Vec::new())),
                    fault: fault.clone(),
                    state: state.clone(),
                },
                runtime: TestRuntime {
                    transcript: Rc::new(RefCell::new(Vec::new())),
                    fail_on: Rc::new(RefCell::new(None)),
                    fault: fault.clone(),
                    state: state.clone(),
                },
                state,
                removed: Rc::new(RefCell::new(0)),
                fault,
            }
        }

        fn context(
            &self,
        ) -> LiveRepairContext<TestSystemd, TestRunner, TestRuntime, TestStageOpener, TestCrash>
        {
            LiveRepairContext {
                root: self.root.path().to_owned(),
                paths: FixedInstallPaths::under_test_root(self.root.path()),
                systemd: self.systemd.clone(),
                runner: self.runner.clone(),
                runtime: self.runtime.clone(),
                stages: TestStageOpener {
                    directory: self.stage.clone(),
                    bundle: repair_test_bundle(),
                    removed: self.removed.clone(),
                    fault: self.fault.clone(),
                },
                crash: TestCrash(self.fault.clone()),
            }
        }

        fn resume(&self) -> ResumableInstalledBundleRepair {
            resume_installed_bundle_repair_at(self.root.path(), unsafe { libc::geteuid() })
                .unwrap()
                .unwrap()
        }
    }

    fn write_mode(path: PathBuf, bytes: &[u8], mode: u32) {
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn assert_converged(fixture: &LiveFixture, identity_before: &[u8]) {
        assert_eq!(
            fs::read(
                fixture
                    .root
                    .path()
                    .join("var/lib/enoki-probe/identity/probe-bootstrap.toml")
            )
            .unwrap(),
            identity_before,
            "Repair 必须保持同一 Probe Identity"
        );
        assert_eq!(*fixture.removed.borrow(), 1);
        assert!(
            !fixture
                .root
                .path()
                .join("var/lib/enoki-probe-bootstrap/installed-bundle-repair.json")
                .exists()
        );
        assert!(!fixture.stage.exists(), "verified stage must be retired");
        assert!(
            !fixture
                .root
                .path()
                .join("var/lib/enoki-probe/runtime-failure/repair-intent.json")
                .exists(),
            "repair intent must be retired"
        );
        for path in [RUNTIME_REPAIR_PERMIT, RUNTIME_REPAIR_DROP_IN] {
            assert!(
                !rooted(fixture.root.path(), path).exists(),
                "temporary Runtime gate residue: {path}"
            );
        }
        for directory in [
            "usr/local/bin",
            "etc/systemd/system",
            "etc/enoki",
            "var/lib/enoki-probe/identity",
        ] {
            for entry in fs::read_dir(fixture.root.path().join(directory)).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                assert!(!name.contains("enoki-repair"), "owned residue: {name}");
            }
        }
        let status = fs::read_to_string(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe/probe-operation-status.toml"),
        )
        .unwrap();
        assert_eq!(status.matches("status = \"succeeded\"").count(), 1);
        assert!(!status.contains("status = \"failed\""));
        let state = fixture.state.borrow();
        assert!(!state.services_stopped);
        assert!(!state.socket_masked);
        assert!(state.socket_started);
        assert!(!state.runtime_stopped);
        assert!(state.temporary_runtime_healthy);
        assert!(state.canonical_runtime_healthy);
        assert!(state.probe_started);
        assert!(state.probe_active);
        assert!(state.reload_generation >= 4);
    }

    fn assert_effect_state_after_crash(fixture: &LiveFixture, fault: (FaultEvent, usize)) {
        let state = fixture.state.borrow();
        match fault.0 {
            FaultEvent::SystemdStop => assert!(state.services_stopped),
            FaultEvent::SystemdReload => assert_eq!(state.reload_generation, fault.1),
            FaultEvent::ProbeStart => assert!(state.probe_started),
            FaultEvent::ProbeWait => assert!(state.probe_active),
            FaultEvent::Runner(action) => match action {
                RepairSystemdAction::StopRepairServices => assert!(state.services_stopped),
                RepairSystemdAction::MaskRuntimeSocket => assert!(state.socket_masked),
                RepairSystemdAction::ResetRuntimeFailed => assert!(state.probe_active),
                RepairSystemdAction::StartRuntimeSocket => assert!(state.socket_started),
                RepairSystemdAction::StopCanonicalRuntime => {
                    assert!(state.runtime_stopped);
                    assert!(!state.socket_started);
                }
                RepairSystemdAction::UnmaskRuntimeSocket => assert!(!state.socket_masked),
            },
            FaultEvent::Runtime(RuntimeValidation::Temporary) => {
                assert!(state.temporary_runtime_healthy)
            }
            FaultEvent::Runtime(RuntimeValidation::Canonical) => {
                assert!(state.canonical_runtime_healthy)
            }
            FaultEvent::Gate(_) | FaultEvent::StageRetirement => {}
        }
    }

    fn fixed_live_effect_order() -> [FaultEvent; 40] {
        [
            // restore_bundle：先停旧 Runtime 并撤销任何遗留验证 gate。
            FaultEvent::Runner(RepairSystemdAction::StopRepairServices),
            FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
            FaultEvent::Gate(LiveRepairEffect::RuntimeGateRemoved),
            FaultEvent::SystemdReload,
            FaultEvent::SystemdStop,
            FaultEvent::SystemdReload,
            // temporary 验证：重建同 intent 的 permit-only shape。
            FaultEvent::Runner(RepairSystemdAction::StopRepairServices),
            FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
            FaultEvent::Gate(LiveRepairEffect::RuntimeGateRemoved),
            FaultEvent::SystemdReload,
            FaultEvent::Gate(LiveRepairEffect::TemporaryGateInstalled),
            FaultEvent::SystemdReload,
            FaultEvent::Runner(RepairSystemdAction::UnmaskRuntimeSocket),
            FaultEvent::Runner(RepairSystemdAction::StartRuntimeSocket),
            FaultEvent::Runtime(RuntimeValidation::Temporary),
            // canonical-validation shape：!latch + permit，仅绕过尚未退休的 J。
            FaultEvent::Runner(RepairSystemdAction::StopCanonicalRuntime),
            FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
            FaultEvent::Gate(LiveRepairEffect::CanonicalGateRemoved),
            FaultEvent::SystemdReload,
            FaultEvent::SystemdReload,
            FaultEvent::Runner(RepairSystemdAction::UnmaskRuntimeSocket),
            FaultEvent::ProbeStart,
            FaultEvent::ProbeWait,
            FaultEvent::Runner(RepairSystemdAction::ResetRuntimeFailed),
            FaultEvent::Runner(RepairSystemdAction::StartRuntimeSocket),
            FaultEvent::Runtime(RuntimeValidation::Canonical),
            // 退休顺序：停 validation Runtime/socket -> 撤全 gate -> stage -> J -> 最终普通探针。
            FaultEvent::Runner(RepairSystemdAction::StopCanonicalRuntime),
            FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
            FaultEvent::Gate(LiveRepairEffect::CanonicalGateRemoved),
            FaultEvent::SystemdReload,
            FaultEvent::StageRetirement,
            FaultEvent::Gate(LiveRepairEffect::StatusPublishedBeforeRetirement),
            FaultEvent::Runner(RepairSystemdAction::StopRepairServices),
            FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
            FaultEvent::SystemdReload,
            FaultEvent::Runner(RepairSystemdAction::UnmaskRuntimeSocket),
            FaultEvent::Runner(RepairSystemdAction::StartRuntimeSocket),
            FaultEvent::ProbeStart,
            FaultEvent::ProbeWait,
            FaultEvent::Gate(LiveRepairEffect::IntentRetired),
        ]
    }

    fn assert_exact_crash_restart_transcript(fixture: &LiveFixture, fault: (FaultEvent, usize)) {
        let baseline = fixed_live_effect_order();
        let mut seen = 0;
        let cut = baseline
            .iter()
            .position(|event| {
                if *event == fault.0 {
                    seen += 1;
                }
                *event == fault.0 && seen == fault.1
            })
            .unwrap();
        let restart: Vec<FaultEvent> = match cut {
            0..=4 => baseline.to_vec(),
            5 => baseline[..4]
                .iter()
                .chain(&baseline[5..])
                .copied()
                .collect(),
            6..=14 => baseline[6..].to_vec(),
            15..=22 => baseline[15..].to_vec(),
            23..=25 => baseline[15..=20]
                .iter()
                .chain(&baseline[23..])
                .copied()
                .collect(),
            26..=38 => baseline[26..].to_vec(),
            _ => unreachable!(),
        };
        let expected = baseline[..=cut]
            .iter()
            .copied()
            .chain(restart)
            .collect::<Vec<_>>();
        assert_eq!(
            fixture.fault.borrow().transcript,
            expected,
            "abrupt crash must not run compensation and restart may replay only its persisted outer checkpoint"
        );
    }

    #[test]
    fn production_repair_driver_resumes_every_bootstrap_filesystem_receipt_window() {
        let mut points = vec![
            InstalledBundleRepairCrashPoint::JournalPublish,
            InstalledBundleRepairCrashPoint::Stop,
            InstalledBundleRepairCrashPoint::Reload,
            InstalledBundleRepairCrashPoint::Complete,
            InstalledBundleRepairCrashPoint::JournalCleanup,
        ];
        for index in 0..21 {
            points.extend([
                InstalledBundleRepairCrashPoint::Prepare(index),
                InstalledBundleRepairCrashPoint::Backup(index),
                InstalledBundleRepairCrashPoint::Publish(index),
                InstalledBundleRepairCrashPoint::Cleanup(index),
            ]);
        }
        assert_eq!(points.len(), 89);
        for point in points {
            let fixture = LiveFixture::new();
            let identity_before = fs::read(
                fixture
                    .root
                    .path()
                    .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
            )
            .unwrap();
            set_installed_bundle_repair_crash_for_test(point).unwrap();
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let _ = drive_live_installed_bundle_repair_with(
                        fixture.resume(),
                        fixture.context(),
                    );
                }))
                .is_err(),
                "{point:?} must abruptly disappear instead of returning an ordinary effect error"
            );
            let transcript = fixture.fault.borrow().transcript.clone();
            let baseline = fixed_live_effect_order();
            let expected_cut = match point {
                InstalledBundleRepairCrashPoint::JournalPublish
                | InstalledBundleRepairCrashPoint::Prepare(_)
                | InstalledBundleRepairCrashPoint::Backup(_) => 4,
                InstalledBundleRepairCrashPoint::Stop
                | InstalledBundleRepairCrashPoint::Publish(_) => 5,
                InstalledBundleRepairCrashPoint::Reload
                | InstalledBundleRepairCrashPoint::Cleanup(_)
                | InstalledBundleRepairCrashPoint::Complete => 6,
                InstalledBundleRepairCrashPoint::JournalCleanup => 32,
            };
            assert_eq!(
                transcript,
                baseline[..expected_cut],
                "{point:?} crash path must stop at the effect and must not run ordinary-error compensation"
            );
            let intent: serde_json::Value = serde_json::from_slice(
                &fs::read(
                    fixture
                        .root
                        .path()
                        .join("var/lib/enoki-probe/runtime-failure/repair-intent.json"),
                )
                .unwrap(),
            )
            .unwrap();
            let expected_progress = match point {
                InstalledBundleRepairCrashPoint::JournalCleanup => "status-published",
                _ => "admitted",
            };
            assert_eq!(intent["state"], expected_progress);
            assert_eq!(
                intent["lastErrorCode"],
                serde_json::Value::Null,
                "{point:?} crash path must not persist an ordinary failure"
            );
            let status_path = fixture
                .root
                .path()
                .join("var/lib/enoki-probe/probe-operation-status.toml");
            let status = match fs::read_to_string(status_path) {
                Ok(status) => status,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(error) => panic!("{point:?} status read failed: {error}"),
            };
            assert!(
                !status.contains("status = \"failed\""),
                "{point:?} crash path must not publish failed status"
            );
            let outcome =
                drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context())
                    .unwrap_or_else(|error| panic!("{point:?} resume failed: {error:?}"));
            assert_eq!(outcome.probe_id, "probe_01");
            assert_eq!(outcome.repaired_version, "1.2.3");
            assert_converged(&fixture, &identity_before);
        }
    }

    #[test]
    fn production_repair_driver_resumes_every_live_system_effect_window() {
        let faults = [
            (
                FaultEvent::Runner(RepairSystemdAction::StopRepairServices),
                1,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
                1,
            ),
            (FaultEvent::Gate(LiveRepairEffect::RuntimeGateRemoved), 1),
            (FaultEvent::SystemdReload, 1),
            (FaultEvent::SystemdStop, 1),
            (FaultEvent::SystemdReload, 2),
            (
                FaultEvent::Runner(RepairSystemdAction::StopRepairServices),
                2,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
                2,
            ),
            (FaultEvent::Gate(LiveRepairEffect::RuntimeGateRemoved), 2),
            (FaultEvent::SystemdReload, 3),
            (
                FaultEvent::Gate(LiveRepairEffect::TemporaryGateInstalled),
                1,
            ),
            (FaultEvent::SystemdReload, 4),
            (
                FaultEvent::Runner(RepairSystemdAction::UnmaskRuntimeSocket),
                1,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::StartRuntimeSocket),
                1,
            ),
            (FaultEvent::Runtime(RuntimeValidation::Temporary), 1),
            (
                FaultEvent::Runner(RepairSystemdAction::StopCanonicalRuntime),
                1,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
                3,
            ),
            (FaultEvent::Gate(LiveRepairEffect::CanonicalGateRemoved), 1),
            (FaultEvent::SystemdReload, 5),
            (FaultEvent::SystemdReload, 6),
            (
                FaultEvent::Runner(RepairSystemdAction::UnmaskRuntimeSocket),
                2,
            ),
            (FaultEvent::ProbeStart, 1),
            (FaultEvent::ProbeWait, 1),
            (
                FaultEvent::Runner(RepairSystemdAction::ResetRuntimeFailed),
                1,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::StartRuntimeSocket),
                2,
            ),
            (FaultEvent::Runtime(RuntimeValidation::Canonical), 1),
            (
                FaultEvent::Runner(RepairSystemdAction::StopCanonicalRuntime),
                2,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
                4,
            ),
            (FaultEvent::Gate(LiveRepairEffect::CanonicalGateRemoved), 2),
            (FaultEvent::SystemdReload, 7),
            (FaultEvent::StageRetirement, 1),
            (
                FaultEvent::Gate(LiveRepairEffect::StatusPublishedBeforeRetirement),
                1,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::StopRepairServices),
                3,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
                5,
            ),
            (FaultEvent::SystemdReload, 8),
            (
                FaultEvent::Runner(RepairSystemdAction::UnmaskRuntimeSocket),
                3,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::StartRuntimeSocket),
                3,
            ),
            (FaultEvent::ProbeStart, 2),
            (FaultEvent::ProbeWait, 2),
        ];
        for fault in faults {
            let fixture = LiveFixture::with_fault(Some(fault));
            let identity_before = fs::read(
                fixture
                    .root
                    .path()
                    .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
            )
            .unwrap();
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let _ = drive_live_installed_bundle_repair_with(
                        fixture.resume(),
                        fixture.context(),
                    );
                }))
                .is_err(),
                "effect-after fault must disappear abruptly rather than return an ordinary error"
            );
            assert!(
                fixture.fault.borrow().target.is_none(),
                "typed fault 未命中: {fault:?}"
            );
            assert_eq!(fixture.fault.borrow().seen, fault.1);
            assert_eq!(
                fixture.fault.borrow().transcript.last(),
                Some(&fault.0),
                "the selected observable effect must complete before abrupt disappearance"
            );
            match fault.0 {
                FaultEvent::Gate(LiveRepairEffect::TemporaryGateInstalled) => {
                    assert!(rooted(fixture.root.path(), RUNTIME_REPAIR_PERMIT).exists());
                    assert!(rooted(fixture.root.path(), RUNTIME_REPAIR_DROP_IN).exists());
                }
                FaultEvent::Gate(LiveRepairEffect::RuntimeGateRemoved)
                | FaultEvent::Gate(LiveRepairEffect::CanonicalGateRemoved) => {
                    assert!(!rooted(fixture.root.path(), RUNTIME_REPAIR_PERMIT).exists());
                    assert!(!rooted(fixture.root.path(), RUNTIME_REPAIR_DROP_IN).exists());
                }
                _ => {}
            }
            assert_effect_state_after_crash(&fixture, fault);
            let outcome =
                drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context())
                    .unwrap_or_else(|error| panic!("{fault:?} resume failed: {error:?}"));
            assert_eq!(outcome.probe_id, "probe_01");
            assert_eq!(outcome.repaired_version, "1.2.3");
            assert_converged(&fixture, &identity_before);
            assert_exact_crash_restart_transcript(&fixture, fault);
        }
    }

    #[test]
    fn production_repair_driver_retains_exact_custody_across_the_status_window() {
        let fault = (
            FaultEvent::Gate(LiveRepairEffect::StatusPublishedBeforeRetirement),
            1,
        );
        let fixture = LiveFixture::with_fault(Some(fault));
        let identity_before = fs::read(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        )
        .unwrap();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ =
                    drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context());
            }))
            .is_err()
        );
        assert!(fixture.fault.borrow().target.is_none());
        assert!(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe-bootstrap/installed-bundle-repair.json")
                .exists(),
            "succeeded status 与 custody retirement 之间中断时必须保留 complete journal"
        );
        let status = fs::read_to_string(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe/probe-operation-status.toml"),
        )
        .unwrap();
        assert_eq!(status.matches("status = \"succeeded\"").count(), 1);

        let installed_probe = fixture.root.path().join("usr/local/bin/enoki-probe");
        let metadata = fs::metadata(&installed_probe).unwrap();
        let original = fs::read(&installed_probe).unwrap();
        let tampered = vec![b'x'; original.len()];
        assert_ne!(tampered, original);
        fs::write(&installed_probe, tampered).unwrap();
        fs::set_permissions(&installed_probe, metadata.permissions()).unwrap();

        assert!(
            drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()).is_err(),
            "StatusPublished recovery must re-verify the journal's exact destination fingerprints"
        );
        assert!(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe-bootstrap/installed-bundle-repair.json")
                .exists(),
            "payload mismatch must retain transaction custody"
        );
        assert!(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe/runtime-failure/repair-intent.json")
                .exists(),
            "payload mismatch must retain StatusPublished intent"
        );
        assert_eq!(
            fs::read_to_string(
                fixture
                    .root
                    .path()
                    .join("var/lib/enoki-probe/probe-operation-status.toml")
            )
            .unwrap()
            .matches("status = \"succeeded\"")
            .count(),
            1
        );
        assert_eq!(
            fs::read(
                fixture
                    .root
                    .path()
                    .join("var/lib/enoki-probe/identity/probe-bootstrap.toml")
            )
            .unwrap(),
            identity_before
        );
    }

    #[test]
    fn production_repair_driver_retries_stage_retirement_before_removing_intent() {
        let fault = (FaultEvent::StageRetirement, 1);
        let fixture = LiveFixture::with_fault(Some(fault));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ =
                    drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context());
            }))
            .is_err()
        );
        assert!(fixture.fault.borrow().target.is_none());
        assert!(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe/runtime-failure/repair-intent.json")
                .exists(),
            "stage retirement 失败必须保留 StatusPublished intent 作为 resume authority"
        );

        let outcome =
            drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()).unwrap();
        assert_eq!(outcome.probe_id, "probe_01");
        assert_eq!(
            *fixture.removed.borrow(),
            1,
            "effect-after crash 后重试不得产生第二次 stage unlink"
        );
        assert!(
            !fixture
                .root
                .path()
                .join("var/lib/enoki-probe/runtime-failure/repair-intent.json")
                .exists()
        );
    }

    #[test]
    fn fresh_recovery_detector_stays_terminal_after_real_intent_unlink() {
        let fixture =
            LiveFixture::with_fault(Some((FaultEvent::Gate(LiveRepairEffect::IntentRetired), 1)));
        let identity_before = fs::read(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        )
        .unwrap();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ =
                    drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context());
            }))
            .is_err()
        );
        assert!(
            resume_installed_bundle_repair_at(fixture.root.path(), unsafe { libc::geteuid() })
                .unwrap()
                .is_none(),
            "fresh process must observe the real intent unlink"
        );
        assert!(
            !installed_bundle_failure_is_current_at(
                fixture.root.path(),
                unsafe { libc::geteuid() },
                &mut TerminalRuntime,
            ),
            "without intent or epoch, a fresh process must not re-enter Installed Bundle Repair"
        );
        assert_eq!(fixture.fault.borrow().transcript, fixed_live_effect_order());
        assert_converged(&fixture, &identity_before);
    }

    fn identity_of(fixture: &LiveFixture) -> Vec<u8> {
        fs::read(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        )
        .unwrap()
    }

    fn drive_until_crash(fixture: &LiveFixture) {
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ =
                    drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context());
            }))
            .is_err(),
            "effect-after 切点必须让进程突然消失而不是返回普通错误"
        );
    }

    #[test]
    fn a_stale_validation_gate_is_normalized_before_the_temporary_shape_is_rebuilt() {
        let fixture = LiveFixture::new();
        let identity_before = identity_of(&fixture);
        install_runtime_repair_validation_gate(fixture.root.path(), RuntimeValidation::Canonical)
            .unwrap();

        let outcome =
            drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()).unwrap();

        assert_eq!(outcome.probe_id, "probe_01");
        assert_eq!(
            fixture.fault.borrow().transcript[6..11].to_vec(),
            [
                FaultEvent::Runner(RepairSystemdAction::StopRepairServices),
                FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
                FaultEvent::Gate(LiveRepairEffect::RuntimeGateRemoved),
                FaultEvent::SystemdReload,
                FaultEvent::Gate(LiveRepairEffect::TemporaryGateInstalled),
            ],
            "临时验证前必须先撤销漂移的旧 gate，再按同一 intent 重建 temporary shape"
        );
        assert_eq!(
            fixture.fault.borrow().transcript,
            fixed_live_effect_order().to_vec()
        );
        assert_converged(&fixture, &identity_before);
    }

    #[test]
    fn forward_only_resume_repairs_a_drifted_gate_before_the_canonical_window() {
        let fault = (
            FaultEvent::Runner(RepairSystemdAction::ResetRuntimeFailed),
            1,
        );
        let fixture = LiveFixture::with_fault(Some(fault));
        let identity_before = identity_of(&fixture);
        drive_until_crash(&fixture);

        // 已持久化到 ProbeActive 后，验证 gate 漂移到缺少 !latch 负条件的 temporary shape。
        install_runtime_repair_validation_gate(fixture.root.path(), RuntimeValidation::Temporary)
            .unwrap();
        assert_eq!(
            fs::read(rooted(fixture.root.path(), RUNTIME_REPAIR_DROP_IN)).unwrap(),
            VALIDATION_DROP_IN_TEMPORARY
        );

        let outcome =
            drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()).unwrap();

        assert_eq!(outcome.probe_id, "probe_01");
        assert_converged(&fixture, &identity_before);
        assert_exact_crash_restart_transcript(&fixture, fault);
    }

    struct InertWindowSleeper;

    impl crate::observation_runtime::ObservationRuntimeSleeper for InertWindowSleeper {
        fn sleep(&mut self, _duration: Duration) {}
    }

    struct ValidationWindowProvider;

    impl crate::observation_runtime::SystemStateProvider for ValidationWindowProvider {
        fn pull_system_state(
            &mut self,
            _request: crate::observation_runtime::SystemStatePullRequest,
        ) -> Result<
            crate::observation_runtime::SystemStateResourceResult,
            crate::observation_runtime::SystemStateResourceAcquisitionFailure,
        > {
            use crate::observation_runtime::SystemStateResourceAcquisitionFailure::Malformed;

            let counters = crate::metrics::parse_linux_proc_stat_cpu_counters(
                "cpu  100 0 0 900 0 0 0 0 0 0\ncpu0 100 0 0 900 0 0 0 0 0 0\n",
            )
            .ok_or(Malformed)?;
            crate::observation_runtime::SystemStateResourceResult::from_records(counters)
                .map(|result| {
                    result.with_system_state(
                        Some(crate::metrics::LoadMetrics {
                            one: 1.0,
                            five: 0.5,
                            fifteen: 0.25,
                        }),
                        Some(crate::metrics::MemoryMetrics {
                            cache_bytes: 512,
                            swap_total_bytes: 1_024,
                            swap_used_bytes: 256,
                            total_bytes: 8_192,
                            used_bytes: 4_096,
                        }),
                        Some(123),
                    )
                })
                .ok_or(Malformed)
        }
    }

    fn validation_client(
        socket: &std::path::Path,
        bundle_version: &str,
    ) -> crate::observation_runtime::UnixObservationRuntimeClient {
        crate::observation_runtime::UnixObservationRuntimeClient::new(socket, bundle_version)
    }

    #[test]
    fn validation_windows_travel_the_formal_runtime_client_over_a_real_socket() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let socket = temporary.path().join("runtime.sock");
        let listener =
            std::os::unix::net::UnixListener::bind(&socket).expect("runtime socket binds");
        let server = std::thread::spawn(move || {
            let mut served = Vec::new();
            for _ in 0..3 {
                let (connection, _) = listener.accept().expect("repair validation connects");
                let mut sleeper = InertWindowSleeper;
                served.push(
                    crate::observation_runtime::ObservationRuntimeServer::new(
                        ValidationWindowProvider,
                    )
                    .serve_connection_with_sleeper(connection, &mut sleeper),
                );
            }
            served
        });

        validate_runtime_window(
            &validation_client(&socket, crate::version::probe_version()),
            RuntimeValidation::Temporary,
        )
        .expect("正式 Runtime 的完整窗口解码必须让临时验证通过");
        let window = validation_client(&socket, crate::version::probe_version())
            .request_finalized_window(Duration::from_secs(1), 1)
            .expect("验证请求在原预算内取得完整窗口");
        let mismatch = validate_runtime_window(
            &validation_client(&socket, "other-bundle"),
            RuntimeValidation::Canonical,
        )
        .expect_err("bundle 版本不一致不是验证成功");
        let served = server.join().expect("Runtime exits cleanly");
        assert!(
            served[0].is_ok() && served[1].is_ok(),
            "两次验证窗口都必须由 Runtime 完整写出，而不是靠关闭 peer 制造失败"
        );

        assert_eq!(
            window
                .attempts
                .iter()
                .map(|attempt| attempt.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3],
            "修复验证取得的是从 seq1 开始的完整窗口，而不是 Hub 历史或 ready 断言"
        );
        assert_eq!(
            mismatch.code(),
            "probe_repair_canonical_runtime_validation_failed",
            "版本不一致必须保持 canonical 段的 typed 失败"
        );

        let stopped = validate_runtime_window(
            &validation_client(&socket, crate::version::probe_version()),
            RuntimeValidation::Temporary,
        )
        .expect_err("Runtime 已停止时验证必须失败");
        assert_eq!(
            stopped.code(),
            "probe_repair_runtime_validation_failed",
            "关闭的 peer 不得被当作验证成功"
        );
    }

    #[test]
    fn temporary_validation_failure_recovers_reporting_without_a_root_gate() {
        let fixture = LiveFixture::new();
        *fixture.runtime.fail_on.borrow_mut() = Some(RuntimeValidation::Temporary);

        let error =
            match drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()) {
                Ok(_) => panic!("临时 Runtime 验证失败必须阻断修复"),
                Err(error) => error,
            };

        assert_eq!(error.code(), "probe_repair_runtime_validation_failed");
        for path in [RUNTIME_REPAIR_PERMIT, RUNTIME_REPAIR_DROP_IN] {
            assert!(
                !rooted(fixture.root.path(), path).exists(),
                "补偿后不得留下 root 验证 gate: {path}"
            );
        }
        {
            let state = fixture.state.borrow();
            assert!(
                state.probe_active,
                "补偿必须把普通 Probe 上报恢复到本地活跃状态"
            );
            assert!(state.socket_started);
            assert!(!state.socket_masked);
            assert!(!state.services_stopped);
            assert!(!state.canonical_runtime_healthy);
        }
        let intent: serde_json::Value = serde_json::from_slice(
            &fs::read(
                fixture
                    .root
                    .path()
                    .join("var/lib/enoki-probe/runtime-failure/repair-intent.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            intent["lastErrorCode"], "probe_repair_runtime_validation_failed",
            "补偿必须持久化本次验证失败而不是伪造成功"
        );
        assert!(
            resume_installed_bundle_repair_at(fixture.root.path(), unsafe { libc::geteuid() })
                .unwrap()
                .is_some(),
            "验证失败的 intent 必须仍可重入"
        );
        assert!(
            installed_bundle_failure_is_current_at(
                fixture.root.path(),
                unsafe { libc::geteuid() },
                &mut TerminalRuntime,
            ),
            "补偿不得消费剩余的 epoch/latch 证据"
        );
    }

    #[test]
    fn canonical_validation_failure_forwards_custody_instead_of_a_local_success() {
        let fixture = LiveFixture::new();
        *fixture.runtime.fail_on.borrow_mut() = Some(RuntimeValidation::Canonical);
        let identity_before = identity_of(&fixture);

        let error =
            match drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()) {
                Ok(_) => panic!("canonical Runtime 验证失败必须阻断修复"),
                Err(error) => error,
            };

        assert_eq!(
            error.code(),
            "probe_repair_canonical_runtime_validation_failed"
        );
        assert!(
            !fixture.state.borrow().canonical_runtime_healthy,
            "验证失败不得被当作 canonical Runtime 已健康"
        );
        assert!(
            fixture.stage.exists(),
            "canonical 验证失败不得退休 operation-private stage"
        );
        let journal = fixture
            .root
            .path()
            .join("var/lib/enoki-probe-bootstrap/installed-bundle-repair.json");
        assert!(
            journal.exists(),
            "canonical 验证失败必须保留恢复日志 custody"
        );
        for path in [RUNTIME_REPAIR_PERMIT, RUNTIME_REPAIR_DROP_IN] {
            assert!(
                rooted(fixture.root.path(), path).exists(),
                "失败必须保留同一 intent 的 canonical-validation shape 以便重入: {path}"
            );
        }
        assert_eq!(
            identity_of(&fixture),
            identity_before,
            "验证失败不得改写本机 Probe Identity"
        );
        let intent: serde_json::Value = serde_json::from_slice(
            &fs::read(
                fixture
                    .root
                    .path()
                    .join("var/lib/enoki-probe/runtime-failure/repair-intent.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            intent["lastErrorCode"], "probe_repair_canonical_runtime_validation_failed",
            "已过提交边界的失败必须如实持久化错误码"
        );
        assert!(
            resume_installed_bundle_repair_at(fixture.root.path(), unsafe { libc::geteuid() })
                .unwrap()
                .is_some(),
            "canonical 验证失败的 intent 必须仍可 forward-only 重入"
        );

        *fixture.runtime.fail_on.borrow_mut() = None;
        let outcome =
            drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()).unwrap();
        assert_eq!(outcome.probe_id, "probe_01");
        assert_converged(&fixture, &identity_before);
    }

    #[test]
    fn retirement_failure_gates_final_ordinary_activation_on_a_trusted_journal_parent() {
        let fault = (
            FaultEvent::Gate(LiveRepairEffect::StatusPublishedBeforeRetirement),
            1,
        );
        let fixture = LiveFixture::with_fault(Some(fault));
        let identity_before = identity_of(&fixture);
        drive_until_crash(&fixture);
        assert!(!fixture.stage.exists(), "stage 必须先于恢复日志退休");
        let journal = fixture
            .root
            .path()
            .join("var/lib/enoki-probe-bootstrap/installed-bundle-repair.json");
        assert!(journal.exists(), "退休崩溃前必须保留恢复日志 custody");

        // 模拟 unlink 之后进程消失：日志已缺失，但其父目录不再可信。
        fs::remove_file(&journal).unwrap();
        fs::set_permissions(journal.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        let error =
            match drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()) {
                Ok(_) => panic!("不可信的耐久父目录不能被当作退休已完成"),
                Err(error) => error,
            };
        assert_eq!(error.code(), "probe_repair_bundle_cleanup_failed");
        assert_eq!(
            fixture
                .fault
                .borrow()
                .transcript
                .iter()
                .filter(
                    |event| **event == FaultEvent::Runner(RepairSystemdAction::StopRepairServices)
                )
                .count(),
            2,
            "必需退休未完成时不得启动最终普通探针"
        );
        assert!(
            fixture
                .root
                .path()
                .join("var/lib/enoki-probe/runtime-failure/repair-intent.json")
                .exists(),
            "退休未完成必须保留 intent 作为 resume authority"
        );

        fs::set_permissions(journal.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        let outcome =
            drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()).unwrap();
        assert_eq!(outcome.probe_id, "probe_01");
        assert_converged(&fixture, &identity_before);
    }

    #[test]
    fn validation_drop_ins_carry_the_fixed_permit_and_latch_conditions() {
        for (fault, expected) in [
            (
                (
                    FaultEvent::Gate(LiveRepairEffect::TemporaryGateInstalled),
                    1,
                ),
                VALIDATION_DROP_IN_TEMPORARY,
            ),
            ((FaultEvent::SystemdReload, 6), VALIDATION_DROP_IN_CANONICAL),
        ] {
            let fixture = LiveFixture::with_fault(Some(fault));
            let identity_before = identity_of(&fixture);
            drive_until_crash(&fixture);
            let root = fixture.root.path();
            assert_eq!(
                fs::read(rooted(root, RUNTIME_REPAIR_DROP_IN)).unwrap(),
                expected
            );
            let permit_path = rooted(root, RUNTIME_REPAIR_PERMIT);
            assert_eq!(
                fs::read(&permit_path).unwrap(),
                b"installed-bundle-repair\n"
            );
            for path in [RUNTIME_REPAIR_DROP_IN, RUNTIME_REPAIR_PERMIT] {
                assert_eq!(
                    fs::metadata(rooted(root, path))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600,
                    "验证 gate 文件必须是 root-only 0600: {path}"
                );
            }
            assert_eq!(
                fs::metadata(rooted(root, RUNTIME_REPAIR_RUN_DIR))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700,
                "验证 gate 的父目录必须是 root-only 0700"
            );

            let outcome =
                drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context())
                    .unwrap();
            assert_eq!(outcome.probe_id, "probe_01");
            assert_converged(&fixture, &identity_before);
            assert_exact_crash_restart_transcript(&fixture, fault);
        }
    }

    #[test]
    fn restored_ordinary_runtime_unit_carries_both_negative_start_conditions() {
        let fixture = LiveFixture::new();
        drive_live_installed_bundle_repair_with(fixture.resume(), fixture.context()).unwrap();
        let unit = fs::read_to_string(
            fixture
                .root
                .path()
                .join("etc/systemd/system/enoki-observation-runtime.service"),
        )
        .unwrap();
        assert!(
            unit.contains("ConditionPathExists=!/var/lib/enoki-probe/runtime-failure/latch"),
            "普通 Runtime 必须保留 latch 负启动条件"
        );
        assert!(
            unit.contains(
                "ConditionPathExists=!/var/lib/enoki-probe-bootstrap/installed-bundle-repair.json"
            ),
            "普通 Runtime 必须保留修复日志负启动条件"
        );
        assert!(
            !unit.contains(RUNTIME_REPAIR_PERMIT),
            "普通 Runtime 不得依赖 root 验证 permit"
        );
    }
}
