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
            systemd: SystemSystemd::for_live_upgrade(),
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
        install_runtime_repair_validation_gate(&self.context.root)?;
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

    fn activate_probe_on_canonical_gate(&mut self) -> Result<(), Self::Error> {
        restore_canonical_runtime_gate(
            &self.context.root,
            &mut self.context.systemd,
            &mut self.context.runner,
            &mut self.context.crash,
        )?;
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

    fn recover_preboundary_reporting(&mut self) -> Result<(), Self::Error> {
        restore_canonical_runtime_gate(
            &self.context.root,
            &mut self.context.systemd,
            &mut self.context.runner,
            &mut self.context.crash,
        )?;
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
    StopRuntime,
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
            RepairSystemdAction::StopRuntime => &["stop", "enoki-observation-runtime.service"],
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
        crate::observation_runtime::UnixObservationRuntimeClient::production()
            .request_finalized_window(Duration::from_secs(1), 0)
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
}

const RUNTIME_REPAIR_RUN_DIR: &str = "/run/enoki-probe";
const RUNTIME_REPAIR_PERMIT: &str = "/run/enoki-probe/runtime-repair-permit";
const RUNTIME_REPAIR_DROP_IN_DIR: &str = "/run/systemd/system/enoki-observation-runtime.service.d";
const RUNTIME_REPAIR_DROP_IN: &str =
    "/run/systemd/system/enoki-observation-runtime.service.d/repair-validation.conf";

fn rooted(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn mask_runtime_validation_socket(
    runner: &mut impl FixedRepairSystemdRunner,
) -> Result<(), LiveInstalledBundleRepairError> {
    runner.run(RepairSystemdAction::StopRepairServices)?;
    runner.run(RepairSystemdAction::MaskRuntimeSocket)
}

fn install_runtime_repair_validation_gate(
    root: &Path,
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
    atomic_write(
        &rooted(root, RUNTIME_REPAIR_DROP_IN),
        b"[Unit]\nConditionPathExists=\nConditionPathExists=/run/enoki-probe/runtime-repair-permit\n",
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

fn restore_canonical_runtime_gate(
    root: &Path,
    systemd: &mut impl SystemdPort,
    runner: &mut impl FixedRepairSystemdRunner,
    crash: &mut impl LiveRepairCrashHook,
) -> Result<(), LiveInstalledBundleRepairError> {
    runner.run(RepairSystemdAction::StopRuntime)?;
    remove_runtime_repair_validation_gate(root)?;
    crash.after(LiveRepairEffect::CanonicalGateRemoved)?;
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
        InstalledBundleRepairProgress, RuntimeFailureSystemd, RuntimeUnitState,
        installed_bundle_failure_is_current_at, resume_installed_bundle_repair_at,
        tests::{repair_completion_fixture, repair_test_bundle},
    };

    struct TerminalRuntime;

    impl RuntimeFailureSystemd for TerminalRuntime {
        fn fixed_runtime_state(&mut self) -> std::io::Result<RuntimeUnitState> {
            Ok(RuntimeUnitState {
                active_state: "failed".into(),
                result: "start-limit-hit".into(),
            })
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
                }
                RepairSystemdAction::MaskRuntimeSocket => {
                    assert!(state.services_stopped);
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
                RepairSystemdAction::StopRuntime => {
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
        fault: SharedFault,
        state: SharedSystemState,
    }

    impl RuntimeValidator for TestRuntime {
        fn validate(
            &mut self,
            validation: RuntimeValidation,
        ) -> Result<(), LiveInstalledBundleRepairError> {
            self.transcript.borrow_mut().push(validation);
            let mut state = self.state.borrow_mut();
            assert!(
                state.socket_started,
                "Runtime validation requires its socket"
            );
            match validation {
                RuntimeValidation::Temporary => state.temporary_runtime_healthy = true,
                RuntimeValidation::Canonical => {
                    assert!(state.probe_active);
                    state.canonical_runtime_healthy = true;
                }
            }
            drop(state);
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
                RepairSystemdAction::StopRuntime => {
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

    fn fixed_live_effect_order() -> [FaultEvent; 23] {
        [
            FaultEvent::Runner(RepairSystemdAction::StopRepairServices),
            FaultEvent::Runner(RepairSystemdAction::MaskRuntimeSocket),
            FaultEvent::Gate(LiveRepairEffect::RuntimeGateRemoved),
            FaultEvent::SystemdReload,
            FaultEvent::SystemdStop,
            FaultEvent::SystemdReload,
            FaultEvent::Gate(LiveRepairEffect::TemporaryGateInstalled),
            FaultEvent::SystemdReload,
            FaultEvent::Runner(RepairSystemdAction::UnmaskRuntimeSocket),
            FaultEvent::Runner(RepairSystemdAction::StartRuntimeSocket),
            FaultEvent::Runtime(RuntimeValidation::Temporary),
            FaultEvent::Runner(RepairSystemdAction::StopRuntime),
            FaultEvent::Gate(LiveRepairEffect::CanonicalGateRemoved),
            FaultEvent::SystemdReload,
            FaultEvent::Runner(RepairSystemdAction::UnmaskRuntimeSocket),
            FaultEvent::ProbeStart,
            FaultEvent::ProbeWait,
            FaultEvent::Runner(RepairSystemdAction::ResetRuntimeFailed),
            FaultEvent::Runner(RepairSystemdAction::StartRuntimeSocket),
            FaultEvent::Runtime(RuntimeValidation::Canonical),
            FaultEvent::Gate(LiveRepairEffect::StatusPublishedBeforeRetirement),
            FaultEvent::StageRetirement,
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
            6..=10 => baseline[6..].to_vec(),
            11..=16 => baseline[11..].to_vec(),
            17..=19 => baseline[17..].to_vec(),
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
                InstalledBundleRepairCrashPoint::JournalCleanup => 21,
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
                FaultEvent::Gate(LiveRepairEffect::TemporaryGateInstalled),
                1,
            ),
            (FaultEvent::SystemdReload, 3),
            (
                FaultEvent::Runner(RepairSystemdAction::UnmaskRuntimeSocket),
                1,
            ),
            (
                FaultEvent::Runner(RepairSystemdAction::StartRuntimeSocket),
                1,
            ),
            (FaultEvent::Runtime(RuntimeValidation::Temporary), 1),
            (FaultEvent::Runner(RepairSystemdAction::StopRuntime), 1),
            (FaultEvent::Gate(LiveRepairEffect::CanonicalGateRemoved), 1),
            (FaultEvent::SystemdReload, 4),
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
}
