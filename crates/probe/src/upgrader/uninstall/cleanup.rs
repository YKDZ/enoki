//! 固定的 Uninstall/Replacement inventory 与 Host cleanup mechanics。

use super::{
    ProbeUninstallerRunInput, ProbeUpgraderRunError, ProbeUpgraderSystemdRunner,
    TrustedProbeInstallMetadata,
};
use crate::upgrader::{
    ensure_absolute_path, is_lifecycle_companion_path, is_lifecycle_companion_service,
    observation_services, observation_stop_services, preflight_rooted_path,
    read_trusted_probe_install_metadata_read_only, read_trusted_probe_install_preflight,
    rebase_trusted_install_metadata_paths, remove_empty_parent_dir, remove_path_if_exists,
    replacement::fixed_installed_probe_sha256, sync_directory, verify_path_absent,
};
use enoki_probe_bootstrap::acquisition::{
    INSTALLED_BUNDLE_REPAIR_STAGE_ROOT, discard_validated_unadmitted_installed_bundle_repair_stage,
    validate_unadmitted_installed_bundle_repair_stage,
};
use enoki_probe_bootstrap::replacement::{
    ReplacementCommitError, ReplacementCommitFact, ReplacementCommitStore, ReplacementIntent,
    commit_and_cleanup_replacement,
};
use std::{
    ffi::CString,
    fs,
    io::Write,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

#[cfg(test)]
use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod test_fault_controls {
    use std::cell::Cell;

    thread_local! {
        pub(super) static STRICT_REPAIR_LOADER_FAILURE: Cell<bool> = const { Cell::new(false) };
        pub(super) static STATE_SHELL_RETIRE_FAILURE: Cell<bool> = const { Cell::new(false) };
        pub(super) static STATE_SHELL_RETIRE_MODE_CHANGE: Cell<bool> = const { Cell::new(false) };
        pub(super) static STATE_SHELL_RETIRE_CANONICAL_PROJECTION_CHANGE: Cell<bool> = const { Cell::new(false) };
        pub(super) static EXPECTED_ROOT_OWNER: Cell<Option<(u32, u32)>> = const { Cell::new(None) };
        pub(super) static EXPECTED_CANONICAL_PRIVATE_ROOT_OWNER: Cell<Option<(u32, u32)>> = const { Cell::new(None) };
        pub(super) static EMPTY_SHELL_CHILD_AFTER_ADMISSION: Cell<bool> = const { Cell::new(false) };
    }
}

#[cfg(test)]
fn execute_probe_uninstall_with_install_metadata_path(
    input: &ProbeUninstallerRunInput,
    install_metadata: &TrustedProbeInstallMetadata,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    install_metadata_path: &Path,
) -> Result<(), ProbeUpgraderRunError> {
    let plan = plan_probe_uninstall_cleanup(input, install_metadata, install_metadata_path)?;
    execute_complete_uninstall_cleanup_oracle(&plan, systemd)
}

/// Replacement 在 durable migration commit 后使用的专属 seam。
/// 它复用 Uninstall cleanup mechanics，同时保留候选 Bootstrap 状态。
pub(in crate::upgrader) fn commit_replacement_and_cleanup_install_with_systemd<
    S: ReplacementCommitStore,
>(
    intent: ReplacementIntent,
    store: &mut S,
    install_metadata_path: &Path,
    test_root: Option<&Path>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<ReplacementCommitFact, ReplacementCommitError<S::Error, ProbeUpgraderRunError>> {
    commit_replacement_cleanup_with_metadata_retirement(
        intent,
        store,
        install_metadata_path,
        test_root,
        systemd,
        remove_path_if_exists,
    )
}

pub(super) fn commit_replacement_cleanup_with_metadata_retirement<S: ReplacementCommitStore>(
    intent: ReplacementIntent,
    store: &mut S,
    install_metadata_path: &Path,
    test_root: Option<&Path>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    retire_metadata: impl FnOnce(&Path) -> Result<(), ProbeUpgraderRunError>,
) -> Result<ReplacementCommitFact, ReplacementCommitError<S::Error, ProbeUpgraderRunError>> {
    let rooted_install_metadata_path = preflight_rooted_path(test_root, install_metadata_path);
    if rooted_install_metadata_path.exists() {
        let install_metadata =
            read_trusted_probe_install_metadata_read_only(&rooted_install_metadata_path, None)
                .map_err(ReplacementCommitError::Effect)?;
        validate_committed_replacement_install_receipt(
            &intent,
            &install_metadata,
            &rooted_install_metadata_path,
            test_root,
        )
        .map_err(ReplacementCommitError::Effect)?;
    }
    let cleanup_intent = intent.clone();
    let mut cleanup = || {
        cleanup_committed_replacement_install(
            &cleanup_intent,
            install_metadata_path,
            test_root,
            systemd,
        )
    };
    let fact = commit_and_cleanup_replacement(intent, store, &mut cleanup)?;
    let install_metadata_path = preflight_rooted_path(test_root, install_metadata_path);
    retire_metadata(&install_metadata_path).map_err(ReplacementCommitError::Effect)?;
    Ok(fact)
}

pub(super) fn cleanup_committed_replacement_install(
    intent: &ReplacementIntent,
    install_metadata_path: &Path,
    test_root: Option<&Path>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    let install_metadata_path = preflight_rooted_path(test_root, install_metadata_path);
    let mut install_metadata =
        read_trusted_probe_install_metadata_read_only(&install_metadata_path, None)?;
    validate_committed_replacement_install_receipt(
        intent,
        &install_metadata,
        &install_metadata_path,
        test_root,
    )?;
    rebase_trusted_install_metadata_paths(&mut install_metadata, test_root);
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: install_metadata.identity_path.clone(),
    };
    let plan =
        plan_committed_replacement_cleanup(&input, &install_metadata, &install_metadata_path)?;
    execute_committed_replacement_cleanup(&plan, systemd)
}

fn validate_committed_replacement_install_receipt(
    intent: &ReplacementIntent,
    metadata: &TrustedProbeInstallMetadata,
    rooted_metadata_path: &Path,
    test_root: Option<&Path>,
) -> Result<(), ProbeUpgraderRunError> {
    if metadata.hub_url != intent.hub_origin
        || metadata
            .bundle_version
            .as_deref()
            .is_some_and(|version| version != intent.source_probe_version)
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "committed Replacement metadata does not match the durable intent",
        ));
    }
    let rooted_probe = preflight_rooted_path(test_root, &metadata.install_path);
    if rooted_probe.exists()
        && fixed_installed_probe_sha256(&metadata.install_path, test_root)?
            != intent.source_probe_sha256
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "committed Replacement Probe does not match the durable intent",
        ));
    }
    let rooted_identity = preflight_rooted_path(test_root, &metadata.identity_path);
    if rooted_identity.exists() {
        let identity = read_trusted_probe_install_preflight(rooted_metadata_path, test_root)?;
        if identity.hub_url != intent.hub_origin || identity.probe_id != intent.old_probe_id {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "committed Replacement identity does not match the durable intent",
            ));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct ProbeUninstallCleanupPlan<'a> {
    pub(super) input: &'a ProbeUninstallerRunInput,
    pub(super) install_metadata: &'a TrustedProbeInstallMetadata,
    pub(super) install_metadata_path: &'a Path,
    unbound_repair_stage: Option<(Option<String>, u32)>,
}

/// 在 systemd 或文件系统变更前确定全部本机删除目标。
/// 离线公开命令与 Hub 授权操作都通过下方同一个 executor 调用此 planner。
pub(super) fn plan_probe_uninstall_cleanup<'a>(
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
) -> Result<ProbeUninstallCleanupPlan<'a>, ProbeUpgraderRunError> {
    let mut plan = plan_probe_uninstall_paths(input, install_metadata, install_metadata_path)?;
    plan.unbound_repair_stage =
        validate_unbound_installed_bundle_repair_stage(Path::new("/var/lib/enoki-probe"), false)?;
    validate_owned_bootstrap_assets_for_cleanup_with_repair(
        install_metadata,
        plan.unbound_repair_stage.is_some(),
    )?;
    Ok(plan)
}

pub(super) fn plan_probe_uninstall_recovery<'a>(
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
) -> Result<ProbeUninstallCleanupPlan<'a>, ProbeUpgraderRunError> {
    let mut plan = plan_probe_uninstall_paths(input, install_metadata, install_metadata_path)?;
    plan.unbound_repair_stage =
        validate_unbound_installed_bundle_repair_stage(&install_metadata.state_dir, true)?;
    validate_owned_bootstrap_assets_for_recovery_with_repair(
        install_metadata,
        plan.unbound_repair_stage.is_some(),
    )?;
    Ok(plan)
}

pub(super) fn plan_committed_replacement_cleanup<'a>(
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
) -> Result<ProbeUninstallCleanupPlan<'a>, ProbeUpgraderRunError> {
    let plan = plan_probe_uninstall_paths(input, install_metadata, install_metadata_path)?;
    // This is an admission-only projection: it establishes the fixed root's
    // type, mode and exact owner before any service or filesystem cleanup.
    // The executor deliberately repeats it while holding the pair lock.
    trusted_state_root_layout(
        &install_metadata.state_dir,
        StateRootOwner::BoundServiceOrEmptyShell {
            user: &install_metadata.service_user,
            group: &install_metadata.service_group,
        },
    )?;
    if matches!(install_metadata.schema_version, 2..=5) {
        validate_owned_bootstrap_role_for_recovery(
            install_metadata.bootstrap_acquirer_path.as_deref(),
        )?;
        validate_owned_bootstrap_role_for_recovery(
            install_metadata.bootstrap_activator_path.as_deref(),
        )?;
        validate_owned_bootstrap_state(
            install_metadata.bootstrap_state_dir.as_deref(),
            install_metadata.bundle_version.as_deref(),
        )?;
    }
    Ok(plan)
}

pub(super) fn plan_probe_uninstall_paths<'a>(
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
) -> Result<ProbeUninstallCleanupPlan<'a>, ProbeUpgraderRunError> {
    ensure_absolute_path(&input.bootstrap_config_path)?;
    for path in [
        install_metadata_path,
        &install_metadata.identity_path,
        &install_metadata.install_path,
        &install_metadata.service_unit_path,
        &install_metadata.state_dir,
    ] {
        ensure_absolute_path(path)?;
    }
    for path in [
        install_metadata.operation_sudoers_path.as_deref(),
        install_metadata.collector_helper_sudoers_path.as_deref(),
        install_metadata.bootstrap_acquirer_path.as_deref(),
        install_metadata.bootstrap_activator_path.as_deref(),
        install_metadata.bootstrap_state_dir.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        ensure_absolute_path(path)?;
    }
    for path in &install_metadata.old_sudoers_paths {
        ensure_absolute_path(path)?;
    }
    for path in [
        install_metadata.observation_runtime_path.as_deref(),
        install_metadata.cpu_provider_path.as_deref(),
        install_metadata.disk_health_provider_path.as_deref(),
        install_metadata.lifecycle_companion_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        ensure_absolute_path(path)?;
    }
    for path in &install_metadata.observation_unit_paths {
        ensure_absolute_path(path)?;
    }
    Ok(ProbeUninstallCleanupPlan {
        input,
        install_metadata,
        install_metadata_path,
        unbound_repair_stage: None,
    })
}

fn validate_owned_bootstrap_assets_for_cleanup_with_repair(
    metadata: &TrustedProbeInstallMetadata,
    has_unbound_repair_stage: bool,
) -> Result<(), ProbeUpgraderRunError> {
    if matches!(metadata.schema_version, 2..=5) {
        validate_owned_bootstrap_role(metadata.bootstrap_acquirer_path.as_deref())?;
        validate_owned_bootstrap_role(metadata.bootstrap_activator_path.as_deref())?;
        validate_owned_bootstrap_state_with_repair(
            metadata.bootstrap_state_dir.as_deref(),
            metadata.bundle_version.as_deref(),
            has_unbound_repair_stage,
        )?;
    }
    Ok(())
}

fn validate_owned_bootstrap_assets_for_recovery_with_repair(
    metadata: &TrustedProbeInstallMetadata,
    has_unbound_repair_stage: bool,
) -> Result<(), ProbeUpgraderRunError> {
    if matches!(metadata.schema_version, 2..=5) {
        validate_owned_bootstrap_role_for_recovery(metadata.bootstrap_acquirer_path.as_deref())?;
        validate_owned_bootstrap_role_for_recovery(metadata.bootstrap_activator_path.as_deref())?;
        validate_owned_bootstrap_state_for_recovery(
            metadata.bootstrap_state_dir.as_deref(),
            metadata.bundle_version.as_deref(),
            has_unbound_repair_stage,
        )?;
    }
    Ok(())
}

/// Planner 只读地区分 fixed child：durable intent 存在时必须先恢复；只有无 intent
/// 且通过固定 catalog 深验证的 orphan 才进入 executor cleanup plan。
fn validate_unbound_installed_bundle_repair_stage(
    public_state_dir: &Path,
    retained_uninstall_capsule: bool,
) -> Result<Option<(Option<String>, u32)>, ProbeUpgraderRunError> {
    // State root 不存在即可只读证明 intent 不存在。保留的 Uninstall capsule
    // 已授权本次 cleanup；它在同一无删除 effect pair lock 下证明 intent 缺席后，
    // 可以继续收敛残余 root，而不能要求已退休的 identity 重走 Repair loader。
    // 没有 capsule 的首次 Uninstall 对任何非空 root 仍走原严格 loader。
    let empty_or_absent = trusted_state_root_is_empty_or_absent_under_pair_lock(public_state_dir)?;
    let persisted_repair = if empty_or_absent || retained_uninstall_capsule {
        Ok(false)
    } else {
        #[cfg(test)]
        let repair = if test_fault_controls::STRICT_REPAIR_LOADER_FAILURE.with(std::cell::Cell::get)
        {
            Err(crate::runtime_failure::InstalledBundleRepairError::RecoveryPending)
        } else {
            crate::runtime_failure::resume_installed_bundle_repair()
        };
        #[cfg(not(test))]
        let repair = crate::runtime_failure::resume_installed_bundle_repair();
        repair.map(|repair| repair.is_some()).map_err(|_| {
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "Installed Bundle Repair intent is invalid",
            )
        })
    };
    let stage_present = match fs::symlink_metadata(INSTALLED_BUNDLE_REPAIR_STAGE_ROOT) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(ProbeUpgraderRunError::Io(error)),
        Ok(_) => true,
    };
    classify_uninstall_repair_stage(stage_present, persisted_repair, || {
        validate_unadmitted_installed_bundle_repair_stage().map_err(|_| {
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "unbound Installed Bundle Repair stage is not safely discardable",
            )
        })
    })
}

#[cfg(test)]
pub(super) fn set_strict_repair_loader_failure(failure: bool) {
    test_fault_controls::STRICT_REPAIR_LOADER_FAILURE.with(|value| value.set(failure));
}

fn classify_uninstall_repair_stage(
    stage_present: bool,
    persisted_repair: Result<bool, ProbeUpgraderRunError>,
    validate_unbound: impl FnOnce() -> Result<(Option<String>, u32), ProbeUpgraderRunError>,
) -> Result<Option<(Option<String>, u32)>, ProbeUpgraderRunError> {
    match persisted_repair? {
        true => Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Installed Bundle Repair recovery must finish before uninstall",
        )),
        false if !stage_present => Ok(None),
        false => validate_unbound().map(Some),
    }
}

pub(super) fn prepare_probe_uninstall_cleanup(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    let install_metadata = plan.install_metadata;
    if matches!(install_metadata.schema_version, 3..=5) {
        for service in observation_stop_services(install_metadata.schema_version)
            .iter()
            .copied()
            .filter(|service| *service != "enoki-probe-lifecycle-companion.socket")
        {
            systemd.stop_service(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_stop_failed",
                    "stopping an observation role",
                    error,
                )
            })?;
            systemd.verify_service_stopped(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_verification_failed",
                    "verifying an observation role stopped",
                    error,
                )
            })?;
            systemd.disable_service(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_disable_failed",
                    "disabling an observation role",
                    error,
                )
            })?;
        }
    }
    systemd
        .stop_service(&install_metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_stop_failed",
                "stopping the service",
                error,
            )
        })?;
    systemd
        .verify_service_stopped(&install_metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_verification_failed",
                "verifying the service stopped",
                error,
            )
        })?;
    systemd
        .disable_service(&install_metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_disable_failed",
                "disabling the service",
                error,
            )
        })?;
    remove_path_if_exists(&install_metadata.service_unit_path).map_err(|error| {
        probe_uninstall_cleanup_error(
            "probe_uninstall_service_unit_remove_failed",
            "removing the service unit",
            error,
        )
    })?;
    verify_path_absent(
        &install_metadata.service_unit_path,
        "probe_uninstall_service_unit_residue",
        "verifying the service unit is absent",
    )?;
    for path in &install_metadata.observation_unit_paths {
        if is_lifecycle_companion_path(path) {
            continue;
        }
        remove_path_if_exists(path)?;
        verify_path_absent(
            path,
            "probe_uninstall_service_unit_residue",
            "verifying an observation role unit is absent",
        )?;
    }
    systemd.daemon_reload().map_err(|error| {
        probe_uninstall_cleanup_error(
            "probe_uninstall_daemon_reload_failed",
            "reloading systemd",
            error,
        )
    })?;
    systemd
        .reset_failed(&install_metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_reset_failed",
                "resetting the failed service state",
                error,
            )
        })?;
    systemd
        .verify_service_absent(&install_metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_verification_failed",
                "verifying the service is absent",
                error,
            )
        })?;
    if matches!(install_metadata.schema_version, 3..=5) {
        for service in observation_services(install_metadata.schema_version) {
            if is_lifecycle_companion_service(service) {
                continue;
            }
            systemd.reset_failed(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_reset_failed",
                    "resetting an observation role failed state",
                    error,
                )
            })?;
            systemd.verify_service_absent(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_verification_failed",
                    "verifying an observation role is absent",
                    error,
                )
            })?;
        }
    }
    remove_path_if_exists(&install_metadata.install_path)?;
    for path in [
        install_metadata.observation_runtime_path.as_deref(),
        install_metadata.cpu_provider_path.as_deref(),
        install_metadata.disk_health_provider_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        remove_path_if_exists(path)?;
    }
    if let Some(path) = &install_metadata.operation_sudoers_path {
        remove_path_if_exists(path)?;
    }
    if let Some(path) = &install_metadata.collector_helper_sudoers_path {
        remove_path_if_exists(path)?;
    }
    for path in &install_metadata.old_sudoers_paths {
        remove_path_if_exists(path)?;
    }
    Ok(())
}

pub(super) fn remove_probe_bootstrap_roles(
    plan: &ProbeUninstallCleanupPlan<'_>,
) -> Result<(), ProbeUpgraderRunError> {
    for path in [
        plan.install_metadata.bootstrap_acquirer_path.as_deref(),
        plan.install_metadata.bootstrap_activator_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        remove_path_if_exists(path)?;
    }
    Ok(())
}

pub(super) fn remove_probe_bootstrap_state(
    plan: &ProbeUninstallCleanupPlan<'_>,
) -> Result<(), ProbeUpgraderRunError> {
    if let Some(path) = plan.install_metadata.bootstrap_state_dir.as_deref() {
        remove_owned_bootstrap_state(path, plan.install_metadata.bundle_version.as_deref())?;
    }
    Ok(())
}

pub(super) fn remove_probe_install_identities(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    let install_metadata = plan.install_metadata;
    // 在所有易失败的账户清理完成前，保留 Companion 激活资产和可信元数据。
    // 中断后管理员仍可从同一固定入口提交绑定到该安装收据的显式卸载请求。
    systemd
        .remove_service_identity(
            &install_metadata.service_user,
            &install_metadata.service_group,
        )
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_account_remove_failed",
                "removing the service account",
                error,
            )
        })?;
    if let Some(ipc_group) = install_metadata.observation_ipc_group.as_deref() {
        systemd
            .remove_fixed_ipc_group(ipc_group, None)
            .map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_group_remove_failed",
                    "removing the observation IPC group",
                    error,
                )
            })?;
    }
    if let Some((ipc_group, ownership)) = install_metadata
        .probe_ipc_group
        .as_deref()
        .zip(install_metadata.probe_ipc_group_ownership.as_deref())
    {
        systemd
            .remove_fixed_ipc_group(ipc_group, Some(ownership))
            .map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_group_remove_failed",
                    "removing the lifecycle IPC group",
                    error,
                )
            })?;
    }
    Ok(())
}

pub(super) fn remove_lifecycle_companion_activation(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    let install_metadata = plan.install_metadata;
    if matches!(install_metadata.schema_version, 4 | 5) {
        // 自删除是最后一个角色清理阶段；当前进程持有已打开的可执行文件，
        // 不需要第二套执行器或运行时选择的路径。
        let companion_services = if install_metadata.schema_version == 5 {
            &[
                "enoki-probe-lifecycle-upgrade.socket",
                "enoki-probe-lifecycle-companion.socket",
            ][..]
        } else {
            &["enoki-probe-lifecycle-companion.socket"][..]
        };
        for companion_service in companion_services {
            lifecycle_cleanup_diagnostic("socket_stop", companion_service, "begin");
            if let Err(error) = systemd.stop_service(companion_service) {
                lifecycle_cleanup_diagnostic("socket_stop", companion_service, "error");
                return Err(probe_uninstall_cleanup_error(
                    "probe_uninstall_service_stop_failed",
                    "stopping a lifecycle companion socket",
                    error,
                ));
            }
            if let Err(error) = systemd.verify_service_stopped(companion_service) {
                lifecycle_cleanup_diagnostic("socket_stop_verify", companion_service, "error");
                return Err(probe_uninstall_cleanup_error(
                    "probe_uninstall_service_verification_failed",
                    "verifying a lifecycle companion socket stopped",
                    error,
                ));
            }
            lifecycle_cleanup_diagnostic("socket_stop", companion_service, "ok");
            lifecycle_cleanup_diagnostic("socket_disable", companion_service, "begin");
            if let Err(error) = systemd.disable_service(companion_service) {
                lifecycle_cleanup_diagnostic("socket_disable", companion_service, "error");
                return Err(probe_uninstall_cleanup_error(
                    "probe_uninstall_service_disable_failed",
                    "disabling a lifecycle companion socket",
                    error,
                ));
            }
            lifecycle_cleanup_diagnostic("socket_disable", companion_service, "ok");
        }
        for path in install_metadata
            .observation_unit_paths
            .iter()
            .filter(|path| is_lifecycle_companion_path(path))
        {
            remove_path_if_exists(path)?;
        }
        lifecycle_cleanup_diagnostic("daemon_reload", "systemd", "begin");
        if let Err(error) = systemd.daemon_reload() {
            lifecycle_cleanup_diagnostic("daemon_reload", "systemd", "error");
            return Err(probe_uninstall_cleanup_error(
                "probe_uninstall_daemon_reload_failed",
                "reloading systemd after lifecycle companion removal",
                error,
            ));
        }
        lifecycle_cleanup_diagnostic("daemon_reload", "systemd", "ok");
        for companion_service in companion_services {
            lifecycle_cleanup_diagnostic("socket_reset_failed", companion_service, "begin");
            if let Err(error) = systemd.reset_failed(companion_service) {
                lifecycle_cleanup_diagnostic("socket_reset_failed", companion_service, "error");
                return Err(probe_uninstall_cleanup_error(
                    "probe_uninstall_service_reset_failed",
                    "resetting a lifecycle companion socket failed state",
                    error,
                ));
            }
            lifecycle_cleanup_diagnostic("socket_reset_failed", companion_service, "ok");
            lifecycle_cleanup_diagnostic("socket_absent_verify", companion_service, "begin");
            if let Err(error) = systemd.verify_service_absent(companion_service) {
                lifecycle_cleanup_diagnostic("socket_absent_verify", companion_service, "error");
                return Err(probe_uninstall_cleanup_error(
                    "probe_uninstall_service_verification_failed",
                    "verifying a lifecycle companion socket is absent",
                    error,
                ));
            }
            lifecycle_cleanup_diagnostic("socket_absent_verify", companion_service, "ok");
        }
    }
    Ok(())
}

fn lifecycle_cleanup_diagnostic(phase: &str, target: &str, outcome: &str) {
    write_lifecycle_cleanup_diagnostic(&mut std::io::stderr(), phase, target, outcome);
}

fn write_lifecycle_cleanup_diagnostic(
    writer: &mut impl Write,
    phase: &str,
    target: &str,
    outcome: &str,
) {
    let _ = writeln!(
        writer,
        "enoki.lifecycle.diagnostic role=companion phase=cleanup_{phase} target={target} outcome={outcome}"
    );
}

pub(super) fn remove_lifecycle_companion_binary(
    plan: &ProbeUninstallCleanupPlan<'_>,
) -> Result<(), ProbeUpgraderRunError> {
    if let Some(path) = plan.install_metadata.lifecycle_companion_path.as_deref() {
        remove_path_if_exists(path)?;
    }
    Ok(())
}

pub(super) fn finalize_recoverable_uninstall_cleanup(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    retire_unbound_installed_bundle_repair_stage_with(
        plan.unbound_repair_stage.as_ref(),
        |entry_name, owner_uid| {
            discard_validated_unadmitted_installed_bundle_repair_stage(entry_name, owner_uid)
                .map_err(|_| {
                    probe_uninstall_cleanup_error(
                        "probe_uninstall_repair_stage_remove_failed",
                        "retiring Installed Bundle Repair stage",
                        ProbeUpgraderRunError::InvalidInstallMetadata(
                            "Installed Bundle Repair stage changed after planning",
                        ),
                    )
                })
        },
    )?;
    remove_probe_bootstrap_roles(plan)?;
    remove_probe_install_identities(plan, systemd)?;
    remove_lifecycle_companion_activation(plan, systemd)?;
    remove_uninstall_local_state_with(plan, remove_path_if_exists)?;
    remove_empty_parent_dir(&plan.input.bootstrap_config_path)?;
    systemd.verify_fixed_ipc_groups_absent_or_harmless()?;
    verify_common_cleanup_residue_absent(plan, systemd)?;
    verify_uninstall_local_state_absent(plan)
}

fn retire_unbound_installed_bundle_repair_stage_with(
    stage: Option<&(Option<String>, u32)>,
    retire: impl FnOnce(Option<&str>, u32) -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    stage.map_or(Ok(()), |(entry_name, owner_uid)| {
        retire(entry_name.as_deref(), *owner_uid)
    })
}

#[cfg(test)]
fn execute_complete_uninstall_cleanup_oracle(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    prepare_probe_uninstall_cleanup(plan, systemd)?;
    finalize_recoverable_uninstall_cleanup(plan, systemd)?;
    remove_probe_bootstrap_state(plan)?;
    remove_lifecycle_companion_binary(plan)?;
    verify_lifecycle_companion_binary_absent(plan)
}

pub(super) fn execute_committed_replacement_cleanup(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    prepare_probe_uninstall_cleanup(plan, systemd)?;
    remove_probe_bootstrap_roles(plan)?;
    remove_lifecycle_companion_activation(plan, systemd)?;
    remove_lifecycle_companion_binary(plan)?;
    // 手动重装必须让可信 metadata 活过全部可失败清理与核验。cleanup_complete
    // 持久化后，metadata 由 exact commit custody 作为独立、幂等的退休动作处理。
    // v0.1.74 produced this exact ordinary root as the service account. Keep
    // that account until the fixed, metadata-bound root is cleared: after
    // userdel its numeric UID/GID is not an NSS fact a retry may guess.
    let state_cleanup = prepare_trusted_state_root_cleanup(
        &plan.install_metadata.state_dir,
        StateRootOwner::BoundServiceOrEmptyShell {
            user: &plan.install_metadata.service_user,
            group: &plan.install_metadata.service_group,
        },
    )?;
    remove_path_if_exists(&plan.input.bootstrap_config_path)?;
    let cleared_state_shell =
        clear_prepared_state_root_contents_with(state_cleanup, &mut remove_path_if_exists)?;
    remove_probe_install_identities(plan, systemd)?;
    systemd.verify_fixed_ipc_groups_absent_or_harmless()?;
    verify_replacement_residue_absent(plan, systemd, &cleared_state_shell)
}

pub(super) fn remove_uninstall_local_state_with(
    plan: &ProbeUninstallCleanupPlan<'_>,
    mut remove: impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    let state_cleanup =
        prepare_trusted_state_root_cleanup(&plan.install_metadata.state_dir, StateRootOwner::Root)?;
    remove(plan.install_metadata_path)?;
    remove(&plan.input.bootstrap_config_path)?;
    clear_prepared_state_root_contents_with(state_cleanup, &mut remove).map(|_| ())
}

#[cfg(test)]
pub(super) fn finalize_replacement_local_state_with(
    bootstrap_config_path: &Path,
    state_dir: &Path,
    mut remove: impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
    verify: impl FnOnce() -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    remove(bootstrap_config_path)?;
    let _runtime_failure_lock = runtime_failure_cleanup_lock(state_dir)?;
    remove(state_dir)?;
    verify()
}

#[cfg(test)]
fn runtime_failure_cleanup_lock(
    state_dir: &Path,
) -> Result<Option<crate::runtime_failure::RuntimeFailurePairLock>, ProbeUpgraderRunError> {
    match fs::symlink_metadata(state_dir) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            crate::runtime_failure::acquire_runtime_failure_pair_cleanup_lock_for_state(
                state_dir,
                unsafe { libc::geteuid() },
            )
            .map(Some)
            .map_err(ProbeUpgraderRunError::Io)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(_) => Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe state directory is unsafe",
        )),
        Err(error) => Err(ProbeUpgraderRunError::Io(error)),
    }
}

/// State is one installation-owned root, not an inventory of independently
/// retired children.  The caller has already established the metadata or
/// retained-capsule binding; this function only accepts the two fixed state
/// projections and keeps the existing pair lock across clear, sync and the
/// best-effort shell retirement.
fn clear_prepared_state_root_contents_with<'a>(
    cleanup: TrustedStateCleanup<'a>,
    remove: &mut impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
) -> Result<ClearedStateShell<'a>, ProbeUpgraderRunError> {
    clear_prepared_state_root_contents_with_shell(cleanup, remove, retire_state_shell)
}

fn clear_prepared_state_root_contents_with_shell<'a>(
    cleanup: TrustedStateCleanup<'a>,
    remove: &mut impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
    mut retire_shell: impl FnMut(&TrustedStateRoot) -> std::io::Result<()>,
) -> Result<ClearedStateShell<'a>, ProbeUpgraderRunError> {
    let Some(admission) = cleanup.admission else {
        return Ok(ClearedStateShell {
            layout: None,
            owner: cleanup.owner,
        });
    };
    let layout = admission.layout;

    #[cfg(test)]
    if admission.authority == StateRootCleanupAuthority::EmptyShellOnly
        && test_fault_controls::EMPTY_SHELL_CHILD_AFTER_ADMISSION.with(std::cell::Cell::get)
    {
        fs::write(
            layout.contents().join("appeared-after-empty-admission"),
            b"fixture",
        )?;
    }

    match admission.authority {
        StateRootCleanupAuthority::ContentAuthorized => {
            match fs::read_dir(layout.contents()) {
                Ok(entries) => {
                    for entry in entries {
                        let entry = entry?;
                        // remove_path_if_exists uses lstat: an entry symlink is
                        // unlinked and never traversed, while directories recurse.
                        remove(&entry.path())?;
                    }
                    sync_directory(layout.contents())?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        StateRootCleanupAuthority::EmptyShellOnly => {
            verify_state_root_empty(&layout)?;
            sync_directory(layout.contents())?;
        }
    }
    verify_state_root_empty(&layout)?;

    // A shell is not data.  Its removal is deliberately best effort, but a
    // failed rmdir may only be ignored after a fresh empty proof.
    let _ = retire_shell(&layout);
    verify_trusted_state_root_empty_or_absent(layout.public(), cleanup.owner)?;
    Ok(ClearedStateShell {
        layout: Some(layout),
        owner: cleanup.owner,
    })
}

/// An in-process proof produced only after the held pair lock has cleared and
/// synced the admitted state root. It carries no persistent ownership fact;
/// later Replacement cleanup may only re-check that this shell remains empty.
struct ClearedStateShell<'a> {
    layout: Option<TrustedStateRoot>,
    owner: StateRootOwner<'a>,
}

impl ClearedStateShell<'_> {
    fn verify_empty_or_absent(&self) -> Result<(), ProbeUpgraderRunError> {
        self.layout.as_ref().map_or(Ok(()), |layout| {
            verify_trusted_state_root_empty_or_absent(layout.public(), self.owner)
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StateRootCleanupAuthority {
    ContentAuthorized,
    EmptyShellOnly,
}

struct TrustedStateRootAdmission {
    layout: TrustedStateRoot,
    authority: StateRootCleanupAuthority,
}

struct TrustedStateCleanup<'a> {
    admission: Option<TrustedStateRootAdmission>,
    owner: StateRootOwner<'a>,
    // Held from the root proof through metadata/config retirement and content
    // cleanup; this is intentionally not a durable fact and is never unlinked.
    _runtime_failure_lock: Option<crate::runtime_failure::RuntimeFailurePairLock>,
}

fn prepare_trusted_state_root_cleanup<'a>(
    public_state_dir: &Path,
    ordinary_owner: StateRootOwner<'a>,
) -> Result<TrustedStateCleanup<'a>, ProbeUpgraderRunError> {
    // Admission is read-only and is backed by the caller's existing
    // metadata/capsule authority.  It intentionally has no cleanup effect:
    // the held-lock reread below is the only layout used for removal.
    let _admission = trusted_state_root_layout(public_state_dir, ordinary_owner)?;
    let lock = crate::runtime_failure::acquire_runtime_failure_pair_lock_for_state(
        public_state_dir,
        unsafe { libc::geteuid() },
    )
    .map_err(ProbeUpgraderRunError::Io)?;
    // The lock serializes writers, not root authority.  Re-read the exact
    // fixed projection while held before retiring any binding material.
    let admission = trusted_state_root_layout(public_state_dir, ordinary_owner)?;
    if let Some(admission) = admission.as_ref()
        && admission.authority == StateRootCleanupAuthority::ContentAuthorized
    {
        require_repair_intent_absent(&admission.layout)?;
        crate::runtime_failure::cleanup_runtime_failure_pair_at_concrete_state(
            admission.layout.contents(),
            unsafe { libc::geteuid() },
        )
        .map_err(ProbeUpgraderRunError::Io)?;
    }
    Ok(TrustedStateCleanup {
        admission,
        owner: ordinary_owner,
        _runtime_failure_lock: Some(lock),
    })
}

fn require_repair_intent_absent(root: &TrustedStateRoot) -> Result<(), ProbeUpgraderRunError> {
    let failure_dir = root.contents().join("runtime-failure");
    let failure_metadata = match fs::symlink_metadata(&failure_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(metadata) => metadata,
        Err(error) => return Err(error.into()),
    };
    if !failure_metadata.is_dir()
        || failure_metadata.file_type().is_symlink()
        || failure_metadata.uid() != unsafe { libc::geteuid() }
        || failure_metadata.mode() & 0o7777 != 0o700
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Installed Bundle Repair directory is unsafe",
        ));
    }
    match fs::symlink_metadata(failure_dir.join("repair-intent.json")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Installed Bundle Repair recovery must finish before uninstall",
        )),
        Err(error) => Err(error.into()),
    }
}

fn retire_state_shell(layout: &TrustedStateRoot) -> std::io::Result<()> {
    #[cfg(test)]
    if test_fault_controls::STATE_SHELL_RETIRE_MODE_CHANGE.with(std::cell::Cell::get) {
        fs::set_permissions(layout.contents(), fs::Permissions::from_mode(0o777))?;
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    #[cfg(test)]
    if test_fault_controls::STATE_SHELL_RETIRE_CANONICAL_PROJECTION_CHANGE
        .with(std::cell::Cell::get)
        && let TrustedStateRoot::Canonical { public, .. } = layout
    {
        fs::remove_file(public)?;
        std::os::unix::fs::symlink("private/untrusted", public)?;
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    #[cfg(test)]
    if test_fault_controls::STATE_SHELL_RETIRE_FAILURE.with(std::cell::Cell::get) {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    match layout {
        TrustedStateRoot::Ordinary(path) => fs::remove_dir(path),
        TrustedStateRoot::Canonical { public, private } => {
            if let Err(error) = fs::remove_dir(private)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(error);
            }
            fs::remove_file(public)
        }
    }
}

#[derive(Debug)]
enum TrustedStateRoot {
    Ordinary(PathBuf),
    Canonical { public: PathBuf, private: PathBuf },
}

#[derive(Clone, Copy)]
enum StateRootOwner<'a> {
    Root,
    BoundServiceOrEmptyShell { user: &'a str, group: &'a str },
}

#[derive(Clone, Copy, Default)]
enum StateRootRead<T> {
    #[default]
    NotReached,
    NotFound,
    IoError,
    Success(T),
}

#[derive(Clone, Copy, Default)]
enum StateRootNssOwner {
    #[default]
    NotReached,
    UserUnavailable,
    GroupUnavailable,
    Success(u32, u32),
}

#[derive(Clone, Copy)]
enum StateRootServiceIdentity {
    UserUnavailable,
    GroupUnavailable,
    Success(u32, u32),
}

#[derive(Default)]
struct StateRootAdmissionFacts {
    public_lstat: StateRootRead<StateRootLstatFacts>,
    private_lstat: StateRootRead<StateRootLstatFacts>,
    public_readlink: StateRootRead<Vec<u8>>,
    nss_owner: StateRootNssOwner,
    empty_shell: StateRootRead<bool>,
    first_rejection: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct StateRootLstatFacts {
    directory: bool,
    symlink: bool,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
}

impl From<&fs::Metadata> for StateRootLstatFacts {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            directory: metadata.is_dir(),
            symlink: metadata.file_type().is_symlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
            nlink: metadata.nlink(),
        }
    }
}

impl TrustedStateRoot {
    fn contents(&self) -> &Path {
        match self {
            Self::Ordinary(path) => path,
            Self::Canonical { private, .. } => private,
        }
    }

    fn public(&self) -> &Path {
        match self {
            Self::Ordinary(path) => path,
            Self::Canonical { public, .. } => public,
        }
    }
}

fn trusted_state_root_layout(
    public_state_dir: &Path,
    ordinary_owner: StateRootOwner<'_>,
) -> Result<Option<TrustedStateRootAdmission>, ProbeUpgraderRunError> {
    let mut facts = StateRootAdmissionFacts::default();
    let result = trusted_state_root_layout_with_facts(public_state_dir, ordinary_owner, &mut facts);
    if let Err(error) = &result {
        facts.first_rejection.get_or_insert(match error {
            ProbeUpgraderRunError::InvalidInstallMetadata(point) => point,
            _ => "state_root_io_error",
        });
        emit_state_root_admission_facts(&facts);
    }
    result
}

fn trusted_state_root_layout_with_facts(
    public_state_dir: &Path,
    ordinary_owner: StateRootOwner<'_>,
    facts: &mut StateRootAdmissionFacts,
) -> Result<Option<TrustedStateRootAdmission>, ProbeUpgraderRunError> {
    if !public_state_dir.ends_with("var/lib/enoki-probe") {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe state directory is not the fixed state root",
        ));
    }
    let private = public_state_dir
        .parent()
        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe state directory is unsafe",
        ))?
        .join("private/enoki-probe");
    let public_metadata = match fs::symlink_metadata(public_state_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            facts.public_lstat = StateRootRead::NotFound;
            return match fs::symlink_metadata(&private) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    facts.private_lstat = StateRootRead::NotFound;
                    Ok(None)
                }
                Err(error) => {
                    facts.private_lstat = StateRootRead::IoError;
                    facts.first_rejection.get_or_insert("private_lstat");
                    Err(error.into())
                }
                Ok(metadata) => {
                    facts.private_lstat = StateRootRead::Success((&metadata).into());
                    let authority =
                        validate_state_root_directory(&private, &metadata, ordinary_owner, facts)?;
                    Ok(Some(TrustedStateRootAdmission {
                        layout: TrustedStateRoot::Canonical {
                            public: public_state_dir.to_owned(),
                            private,
                        },
                        authority,
                    }))
                }
            };
        }
        Err(error) => {
            facts.public_lstat = StateRootRead::IoError;
            facts.first_rejection.get_or_insert("public_lstat");
            return Err(error.into());
        }
        Ok(metadata) => {
            facts.public_lstat = StateRootRead::Success((&metadata).into());
            metadata
        }
    };
    if public_metadata.is_dir() && !public_metadata.file_type().is_symlink() {
        let authority = validate_state_root_directory(
            public_state_dir,
            &public_metadata,
            ordinary_owner,
            facts,
        )?;
        match fs::symlink_metadata(&private) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                facts.private_lstat = StateRootRead::NotFound;
            }
            Ok(metadata) => {
                facts.private_lstat = StateRootRead::Success((&metadata).into());
                return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                    "Probe state directory has conflicting canonical residue",
                ));
            }
            Err(error) => {
                facts.private_lstat = StateRootRead::IoError;
                facts.first_rejection.get_or_insert("private_lstat");
                return Err(error.into());
            }
        }
        return Ok(Some(TrustedStateRootAdmission {
            layout: TrustedStateRoot::Ordinary(public_state_dir.to_owned()),
            authority,
        }));
    }
    if !public_metadata.file_type().is_symlink()
        || (public_metadata.uid(), public_metadata.gid())
            != expected_root_owner_for(public_state_dir)
        || public_metadata.nlink() != 1
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe state directory is unsafe",
        ));
    }
    let readlink = match fs::read_link(public_state_dir) {
        Ok(readlink) => {
            facts.public_readlink =
                StateRootRead::Success(readlink.as_os_str().as_bytes().to_vec());
            readlink
        }
        Err(error) => {
            facts.public_readlink = if error.kind() == std::io::ErrorKind::NotFound {
                StateRootRead::NotFound
            } else {
                StateRootRead::IoError
            };
            facts.first_rejection.get_or_insert("public_readlink");
            return Err(error.into());
        }
    };
    if readlink.as_os_str().as_bytes() != b"private/enoki-probe" {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe state directory is unsafe",
        ));
    }
    let authority = match fs::symlink_metadata(&private) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            facts.private_lstat = StateRootRead::NotFound;
            StateRootCleanupAuthority::ContentAuthorized
        }
        Err(error) => {
            facts.private_lstat = StateRootRead::IoError;
            facts.first_rejection.get_or_insert("private_lstat");
            return Err(error.into());
        }
        Ok(metadata) => {
            facts.private_lstat = StateRootRead::Success((&metadata).into());
            validate_state_root_directory(&private, &metadata, ordinary_owner, facts)?
        }
    };
    Ok(Some(TrustedStateRootAdmission {
        layout: TrustedStateRoot::Canonical {
            public: public_state_dir.to_owned(),
            private,
        },
        authority,
    }))
}

fn validate_state_root_directory(
    path: &Path,
    metadata: &fs::Metadata,
    owner: StateRootOwner<'_>,
    facts: &mut StateRootAdmissionFacts,
) -> Result<StateRootCleanupAuthority, ProbeUpgraderRunError> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o7777 != 0o750
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe state directory is unsafe",
        ));
    }
    state_root_authority(path, metadata, owner, facts)?.ok_or(
        ProbeUpgraderRunError::InvalidInstallMetadata("Probe state directory is unsafe"),
    )
}

fn state_root_authority(
    path: &Path,
    metadata: &fs::Metadata,
    owner: StateRootOwner<'_>,
    facts: &mut StateRootAdmissionFacts,
) -> Result<Option<StateRootCleanupAuthority>, ProbeUpgraderRunError> {
    let actual = (metadata.uid(), metadata.gid());
    let root = expected_root_owner_for(path);
    match owner {
        StateRootOwner::Root => Ok(state_root_owner_tuple_matches(actual, root, None)
            .then_some(StateRootCleanupAuthority::ContentAuthorized)),
        StateRootOwner::BoundServiceOrEmptyShell { user, group } => {
            let service_owner = service_identity_owner(user, group);
            facts.nss_owner = match service_owner {
                StateRootServiceIdentity::UserUnavailable => StateRootNssOwner::UserUnavailable,
                StateRootServiceIdentity::GroupUnavailable => StateRootNssOwner::GroupUnavailable,
                StateRootServiceIdentity::Success(uid, gid) => StateRootNssOwner::Success(uid, gid),
            };
            let service_owner = match service_owner {
                StateRootServiceIdentity::Success(uid, gid) => Some((uid, gid)),
                StateRootServiceIdentity::UserUnavailable
                | StateRootServiceIdentity::GroupUnavailable => None,
            };
            if state_root_owner_tuple_matches(actual, root, service_owner) {
                return Ok(Some(StateRootCleanupAuthority::ContentAuthorized));
            }
            if metadata.uid() != metadata.gid() {
                return Ok(None);
            }
            let empty = match state_root_is_empty(path) {
                Ok(empty) => {
                    facts.empty_shell = StateRootRead::Success(empty);
                    empty
                }
                Err(error) => {
                    facts.empty_shell = if error.kind() == std::io::ErrorKind::NotFound {
                        StateRootRead::NotFound
                    } else {
                        StateRootRead::IoError
                    };
                    facts.first_rejection.get_or_insert("empty_shell");
                    return Err(error.into());
                }
            };
            Ok(empty.then_some(StateRootCleanupAuthority::EmptyShellOnly))
        }
    }
}

fn emit_state_root_admission_facts(facts: &StateRootAdmissionFacts) {
    let render = |value: &StateRootRead<StateRootLstatFacts>| match value {
        StateRootRead::NotReached => "not_reached".to_owned(),
        StateRootRead::NotFound => "not_found".to_owned(),
        StateRootRead::IoError => "io_error".to_owned(),
        StateRootRead::Success(value) => format!(
            "dir={},link={},uid={},gid={},mode={:o},nlink={}",
            value.directory, value.symlink, value.uid, value.gid, value.mode, value.nlink
        ),
    };
    let readlink = match &facts.public_readlink {
        StateRootRead::Success(value) => value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        StateRootRead::NotReached => "not_reached".to_owned(),
        StateRootRead::NotFound => "not_found".to_owned(),
        StateRootRead::IoError => "io_error".to_owned(),
    };
    let nss = match facts.nss_owner {
        StateRootNssOwner::NotReached => "not_reached".to_owned(),
        StateRootNssOwner::UserUnavailable => "user_unavailable".to_owned(),
        StateRootNssOwner::GroupUnavailable => "group_unavailable".to_owned(),
        StateRootNssOwner::Success(uid, gid) => format!("{uid}:{gid}"),
    };
    let empty = match facts.empty_shell {
        StateRootRead::NotReached => "not_reached".to_owned(),
        StateRootRead::NotFound => "not_found".to_owned(),
        StateRootRead::IoError => "io_error".to_owned(),
        StateRootRead::Success(value) => value.to_string(),
    };
    let _ = writeln!(
        std::io::stderr(),
        "enoki.lifecycle.diagnostic role=companion phase=uninstall_failure outcome=failed operation=state_root_admission rejection={} public_lstat={} private_lstat={} public_readlink_hex={readlink} nss_owner={nss} empty_shell={empty}",
        facts.first_rejection.unwrap_or("unknown"),
        render(&facts.public_lstat),
        render(&facts.private_lstat),
    );
}

fn state_root_is_empty(path: &Path) -> std::io::Result<bool> {
    let mut entries = fs::read_dir(path)?;
    Ok(entries.next().transpose()?.is_none())
}

fn state_root_owner_tuple_matches(
    actual: (u32, u32),
    root: (u32, u32),
    service: Option<(u32, u32)>,
) -> bool {
    actual == root || service == Some(actual)
}

fn service_identity_owner(service_user: &str, service_group: &str) -> StateRootServiceIdentity {
    let Ok(service_user) = CString::new(service_user) else {
        return StateRootServiceIdentity::UserUnavailable;
    };
    let Ok(service_group) = CString::new(service_group) else {
        return StateRootServiceIdentity::GroupUnavailable;
    };
    // SAFETY: this copies the numeric fields while the NUL-terminated name
    // and the libc passwd result remain valid.
    let account = unsafe { libc::getpwnam(service_user.as_ptr()) };
    if account.is_null() {
        return StateRootServiceIdentity::UserUnavailable;
    }
    let (uid, account_gid) = unsafe { ((*account).pw_uid, (*account).pw_gid) };
    let group = unsafe { libc::getgrnam(service_group.as_ptr()) };
    if group.is_null() || account_gid != unsafe { (*group).gr_gid } {
        return StateRootServiceIdentity::GroupUnavailable;
    }
    StateRootServiceIdentity::Success(uid, unsafe { (*group).gr_gid })
}

fn expected_root_owner_for(_path: &Path) -> (u32, u32) {
    #[cfg(test)]
    {
        // The filesystem adapter maps production root ownership to the test
        // process identity, so these fixtures remain meaningful in a
        // non-root CI worker without weakening the production predicate.
        let expected_owner = test_fault_controls::EXPECTED_ROOT_OWNER
            .with(std::cell::Cell::get)
            .unwrap_or_else(|| (unsafe { libc::geteuid() }, unsafe { libc::getegid() }));
        if _path.ends_with("private/enoki-probe") {
            return test_fault_controls::EXPECTED_CANONICAL_PRIVATE_ROOT_OWNER
                .with(std::cell::Cell::get)
                .unwrap_or(expected_owner);
        }
        expected_owner
    }
    #[cfg(not(test))]
    (0, 0)
}

fn verify_state_root_empty(root: &TrustedStateRoot) -> Result<(), ProbeUpgraderRunError> {
    match fs::read_dir(root.contents()) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                    "Probe state directory was not cleared",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn verify_state_root_empty_or_absent(root: &TrustedStateRoot) -> Result<(), ProbeUpgraderRunError> {
    match fs::symlink_metadata(root.contents()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => verify_state_root_empty(root),
    }
}

fn verify_trusted_state_root_empty_or_absent(
    public_state_dir: &Path,
    owner: StateRootOwner<'_>,
) -> Result<(), ProbeUpgraderRunError> {
    match trusted_state_root_layout(public_state_dir, owner)? {
        None => Ok(()),
        Some(admission) => verify_state_root_empty_or_absent(&admission.layout),
    }
}

fn verify_replacement_residue_absent(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    cleared_state_shell: &ClearedStateShell,
) -> Result<(), ProbeUpgraderRunError> {
    verify_common_cleanup_residue_absent(plan, systemd)?;
    for (path, code, action) in [
        (
            plan.install_metadata.identity_path.as_path(),
            "probe_uninstall_identity_residue",
            "verifying the Probe identity is absent",
        ),
        (
            plan.input.bootstrap_config_path.as_path(),
            "probe_uninstall_config_residue",
            "verifying the Probe bootstrap config is absent",
        ),
    ] {
        verify_path_absent(path, code, action)?;
    }
    cleared_state_shell.verify_empty_or_absent()?;
    verify_lifecycle_companion_binary_absent(plan)
}

pub(super) fn verify_uninstall_local_state_absent(
    plan: &ProbeUninstallCleanupPlan<'_>,
) -> Result<(), ProbeUpgraderRunError> {
    for (path, code, action) in [
        (
            plan.install_metadata.identity_path.as_path(),
            "probe_uninstall_identity_residue",
            "verifying the Probe identity is absent",
        ),
        (
            plan.input.bootstrap_config_path.as_path(),
            "probe_uninstall_config_residue",
            "verifying the Probe bootstrap config is absent",
        ),
        (
            plan.install_metadata_path,
            "probe_uninstall_metadata_residue",
            "verifying install metadata is absent",
        ),
    ] {
        verify_path_absent(path, code, action)?;
    }
    verify_uninstall_state_shell_harmless(&plan.install_metadata.state_dir)?;
    Ok(())
}

pub(super) fn verify_uninstall_state_shell_harmless(
    public_state_dir: &Path,
) -> Result<(), ProbeUpgraderRunError> {
    match trusted_state_root_layout(public_state_dir, StateRootOwner::Root)? {
        None => Ok(()),
        Some(admission) => verify_state_root_empty(&admission.layout),
    }
}

/// Planner admission has no deletion authority.  It nevertheless observes
/// the fixed root under the same logical pair lock as cleanup so an empty
/// shell cannot race a newly published Repair intent into the no-intent path.
fn trusted_state_root_is_empty_or_absent_under_pair_lock(
    public_state_dir: &Path,
) -> Result<bool, ProbeUpgraderRunError> {
    let _lock = crate::runtime_failure::acquire_runtime_failure_pair_lock_for_state(
        public_state_dir,
        unsafe { libc::geteuid() },
    )
    .map_err(ProbeUpgraderRunError::Io)?;
    let layout = trusted_state_root_layout(public_state_dir, StateRootOwner::Root)?;
    match layout {
        None => Ok(true),
        Some(admission) => {
            require_repair_intent_absent(&admission.layout)?;
            match fs::read_dir(admission.layout.contents()) {
                Ok(mut entries) => Ok(entries.next().is_none()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
                Err(error) => Err(error.into()),
            }
        }
    }
}

pub(super) fn verify_lifecycle_companion_binary_absent(
    plan: &ProbeUninstallCleanupPlan<'_>,
) -> Result<(), ProbeUpgraderRunError> {
    if let Some(path) = plan.install_metadata.lifecycle_companion_path.as_deref() {
        verify_path_absent(
            path,
            "probe_uninstall_binary_residue",
            "verifying lifecycle companion binary is absent",
        )?;
    }
    Ok(())
}

pub(super) fn verify_common_cleanup_residue_absent(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    let metadata = plan.install_metadata;
    for (path, code, action) in [
        (
            metadata.install_path.as_path(),
            "probe_uninstall_binary_residue",
            "verifying the Probe binary is absent",
        ),
        (
            metadata.service_unit_path.as_path(),
            "probe_uninstall_service_unit_residue",
            "verifying the service unit is absent",
        ),
    ] {
        verify_path_absent(path, code, action)?;
    }
    for (path, code, action) in [
        (
            metadata.operation_sudoers_path.as_deref(),
            "probe_uninstall_operation_sudoers_residue",
            "verifying operation sudoers is absent",
        ),
        (
            metadata.collector_helper_sudoers_path.as_deref(),
            "probe_uninstall_collector_sudoers_residue",
            "verifying collector sudoers is absent",
        ),
    ] {
        if let Some(path) = path {
            verify_path_absent(path, code, action)?;
        }
    }
    for path in &metadata.old_sudoers_paths {
        verify_path_absent(
            path,
            "probe_uninstall_legacy_sudoers_residue",
            "verifying legacy sudoers is absent",
        )?;
    }
    for path in [
        metadata.observation_runtime_path.as_deref(),
        metadata.cpu_provider_path.as_deref(),
        metadata.disk_health_provider_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        verify_path_absent(
            path,
            "probe_uninstall_binary_residue",
            "verifying an observation role binary is absent",
        )?;
    }
    for path in &metadata.observation_unit_paths {
        verify_path_absent(
            path,
            "probe_uninstall_service_unit_residue",
            "verifying an observation role unit is absent",
        )?;
    }
    for (path, code, action) in [
        (
            metadata.bootstrap_acquirer_path.as_deref(),
            "probe_uninstall_bootstrap_acquirer_residue",
            "verifying Probe Bootstrap acquirer is absent",
        ),
        (
            metadata.bootstrap_activator_path.as_deref(),
            "probe_uninstall_bootstrap_activator_residue",
            "verifying Probe Bootstrap activator is absent",
        ),
    ] {
        if let Some(path) = path {
            verify_path_absent(path, code, action)?;
        }
    }
    systemd
        .verify_service_absent(&metadata.service_name)
        .map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_service_verification_failed",
                "verifying the service is absent",
                error,
            )
        })
}

pub(super) fn probe_uninstall_cleanup_error(
    code: &'static str,
    action: &'static str,
    error: ProbeUpgraderRunError,
) -> ProbeUpgraderRunError {
    match error {
        ProbeUpgraderRunError::UninstallCleanupFailure { .. } => error,
        ProbeUpgraderRunError::RestartFailure(message) => {
            ProbeUpgraderRunError::UninstallCleanupFailure {
                action,
                code,
                message,
            }
        }
        _ => ProbeUpgraderRunError::UninstallCleanupFailure {
            action,
            code,
            message: error.to_string(),
        },
    }
}

pub(super) fn validate_owned_bootstrap_role(
    path: Option<&Path>,
) -> Result<(), ProbeUpgraderRunError> {
    let path = path.ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
        "schema v2 metadata is missing Probe Bootstrap ownership",
    ))?;
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o755
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap role is not a root-owned regular 0755 file",
        ));
    }
    Ok(())
}

pub(super) fn validate_owned_bootstrap_role_for_recovery(
    path: Option<&Path>,
) -> Result<(), ProbeUpgraderRunError> {
    if path.is_some_and(|path| {
        fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }) {
        return Ok(());
    }
    validate_owned_bootstrap_role(path)
}

pub(super) fn validate_owned_bootstrap_state(
    path: Option<&Path>,
    expected_bundle_version: Option<&str>,
) -> Result<(), ProbeUpgraderRunError> {
    validate_owned_bootstrap_state_with_repair(path, expected_bundle_version, false)
}

fn validate_owned_bootstrap_state_with_repair(
    path: Option<&Path>,
    expected_bundle_version: Option<&str>,
    has_unbound_repair_stage: bool,
) -> Result<(), ProbeUpgraderRunError> {
    let path = path.ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
        "schema v2 metadata is missing Probe Bootstrap ownership",
    ))?;
    validate_owned_bootstrap_directory(path, 0o700)?;
    for entry in fs::read_dir(path).map_err(ProbeUpgraderRunError::Io)? {
        let entry = entry.map_err(ProbeUpgraderRunError::Io)?;
        match entry.file_name().to_str() {
            Some("trust") => {
                validate_owned_bootstrap_directory(&entry.path(), 0o700)?;
                for trust in fs::read_dir(entry.path()).map_err(ProbeUpgraderRunError::Io)? {
                    let trust = trust.map_err(ProbeUpgraderRunError::Io)?;
                    if !matches!(
                        trust.file_name().to_str(),
                        Some("delegation-generation" | ".delegation-generation.lock")
                    ) {
                        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                            "Probe Bootstrap state contains an unexpected entry",
                        ));
                    }
                    validate_owned_bootstrap_regular(&trust.path(), 0o600)?;
                }
            }
            Some("inbox") => {
                validate_owned_bootstrap_directory(&entry.path(), 0o700)?;
                if fs::read_dir(entry.path())
                    .map_err(ProbeUpgraderRunError::Io)?
                    .next()
                    .is_some()
                {
                    return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                        "Probe Bootstrap inbox is not empty",
                    ));
                }
            }
            Some("installed-bundle-repair-stage")
                if has_unbound_repair_stage
                    && entry.path() == Path::new(INSTALLED_BUNDLE_REPAIR_STAGE_ROOT) => {}
            Some("current-layout") => {
                validate_owned_bootstrap_current_layout(&entry.path(), expected_bundle_version)?;
            }
            Some("activation.lock") => {
                validate_owned_bootstrap_activation_lock(&entry.path())?;
            }
            _ => {
                return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                    "Probe Bootstrap state contains an unexpected entry",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_owned_bootstrap_state_for_recovery(
    path: Option<&Path>,
    expected_bundle_version: Option<&str>,
    has_unbound_repair_stage: bool,
) -> Result<(), ProbeUpgraderRunError> {
    if path.is_some_and(|path| {
        fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }) {
        if has_unbound_repair_stage {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Installed Bundle Repair stage parent is absent",
            ));
        }
        return Ok(());
    }
    validate_owned_bootstrap_state_with_repair(
        path,
        expected_bundle_version,
        has_unbound_repair_stage,
    )
}

pub(super) fn validate_owned_bootstrap_directory(
    path: &Path,
    mode: u32,
) -> Result<(), ProbeUpgraderRunError> {
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap state is not a root-owned private directory",
        ));
    }
    Ok(())
}
pub(super) fn validate_owned_bootstrap_regular(
    path: &Path,
    mode: u32,
) -> Result<(), ProbeUpgraderRunError> {
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != mode
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap state contains an unsafe entry",
        ));
    }
    Ok(())
}
fn validate_owned_bootstrap_current_layout(
    path: &Path,
    expected_bundle_version: Option<&str>,
) -> Result<(), ProbeUpgraderRunError> {
    let expected_bundle_version =
        expected_bundle_version.ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap current layout receipt has no bound bundle version",
        ))?;
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap current layout receipt is not a root-owned regular 0600 file",
        ));
    }
    let expected = format!("schema_version=1\nversion={expected_bundle_version}\n");
    if fs::read(path).map_err(ProbeUpgraderRunError::Io)? != expected.as_bytes() {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap current layout receipt is invalid",
        ));
    }
    Ok(())
}

fn validate_owned_bootstrap_activation_lock(path: &Path) -> Result<(), ProbeUpgraderRunError> {
    let metadata = fs::symlink_metadata(path).map_err(ProbeUpgraderRunError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap activation lock is not a root-owned regular 0600 file",
        ));
    }
    Ok(())
}

pub(super) fn remove_owned_bootstrap_state(
    path: &Path,
    expected_bundle_version: Option<&str>,
) -> Result<(), ProbeUpgraderRunError> {
    if fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) {
        return sync_and_verify_bootstrap_state_retired(path);
    }
    validate_owned_bootstrap_state(Some(path), expected_bundle_version)?;
    let activation_lock = path.join("activation.lock");
    // Keep the canonical generation linked until every other owned entry has
    // retired. Waiters therefore open this inode and fail its post-flock
    // pathname identity check after the directory is removed.
    for entry in fs::read_dir(path).map_err(ProbeUpgraderRunError::Io)? {
        let entry = entry.map_err(ProbeUpgraderRunError::Io)?;
        if entry.file_name() != "activation.lock" {
            remove_path_if_exists(&entry.path())?;
        }
    }
    remove_path_if_exists(&activation_lock)?;
    fs::remove_dir(path).map_err(ProbeUpgraderRunError::Io)?;
    sync_and_verify_bootstrap_state_retired(path)
}

fn sync_and_verify_bootstrap_state_retired(path: &Path) -> Result<(), ProbeUpgraderRunError> {
    let parent = path
        .parent()
        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap state has no parent",
        ))?;
    sync_directory(parent)?;
    verify_path_absent(
        path,
        "probe_uninstall_bootstrap_state_residue",
        "verifying retired Probe Bootstrap state",
    )
}

#[cfg(test)]
mod tests {
    use super::test_fault_controls::{
        EMPTY_SHELL_CHILD_AFTER_ADMISSION, EXPECTED_CANONICAL_PRIVATE_ROOT_OWNER,
        EXPECTED_ROOT_OWNER, STATE_SHELL_RETIRE_CANONICAL_PROJECTION_CHANGE,
        STATE_SHELL_RETIRE_FAILURE, STATE_SHELL_RETIRE_MODE_CHANGE,
    };
    use super::{
        ProbeUpgraderSystemdRunner, StateRootAdmissionFacts, StateRootNssOwner, StateRootOwner,
        StateRootRead, TrustedProbeInstallMetadata, classify_uninstall_repair_stage,
        commit_replacement_cleanup_with_metadata_retirement, execute_committed_replacement_cleanup,
        execute_probe_uninstall_with_install_metadata_path, finalize_recoverable_uninstall_cleanup,
        finalize_replacement_local_state_with, plan_committed_replacement_cleanup,
        plan_probe_uninstall_cleanup, plan_probe_uninstall_recovery,
        prepare_probe_uninstall_cleanup, remove_lifecycle_companion_binary,
        remove_probe_bootstrap_state, remove_uninstall_local_state_with,
        retire_unbound_installed_bundle_repair_stage_with, state_root_owner_tuple_matches,
        trusted_state_root_layout_with_facts, validate_owned_bootstrap_state,
    };
    use crate::upgrader::{
        ProbeUninstallerRunInput, ProbeUpgraderRunError, observation_stop_services,
    };
    use enoki_probe_bootstrap::replacement::{
        ReplacementCommitError, ReplacementCommitFact, ReplacementCommitStore, ReplacementIntent,
    };
    use std::{
        ffi::OsString,
        fs,
        os::unix::{
            ffi::OsStringExt,
            fs::{MetadataExt, PermissionsExt, symlink},
        },
        path::{Path, PathBuf},
        sync::mpsc::{self, RecvTimeoutError},
        thread,
        time::Duration,
    };

    #[derive(Default)]
    struct TestSystemd {
        calls: Vec<String>,
        fail_fixed_ipc_verification: bool,
    }

    impl ProbeUpgraderSystemdRunner for TestSystemd {
        fn restart_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("restart {service_name}"));
            Ok(())
        }

        fn stop_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("stop {service_name}"));
            Ok(())
        }

        fn disable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("disable {service_name}"));
            Ok(())
        }

        fn daemon_reload(&mut self) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push("daemon-reload".to_owned());
            Ok(())
        }

        fn reset_failed(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("reset-failed {service_name}"));
            Ok(())
        }

        fn verify_service_absent(
            &mut self,
            service_name: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.calls.push(format!("verify-absent {service_name}"));
            Ok(())
        }

        fn remove_service_identity(
            &mut self,
            service_user: &str,
            service_group: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.calls
                .push(format!("remove-identity {service_user}:{service_group}"));
            Ok(())
        }

        fn remove_owned_ipc_group(
            &mut self,
            group: &str,
            ownership_marker: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.calls
                .push(format!("remove-ipc-group {group}:{ownership_marker}"));
            Ok(())
        }

        fn verify_fixed_ipc_groups_absent_or_harmless(
            &mut self,
        ) -> Result<(), ProbeUpgraderRunError> {
            if self.fail_fixed_ipc_verification {
                return Err(ProbeUpgraderRunError::Io(std::io::Error::other(
                    "injected fixed IPC verification failure",
                )));
            }
            Ok(())
        }
    }

    fn metadata(root: &Path, schema_version: u32) -> TrustedProbeInstallMetadata {
        TrustedProbeInstallMetadata {
            schema_version,
            hub_url: "https://hub.example".to_owned(),
            identity_path: root.join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
            install_path: root.join("bin/enoki-probe"),
            operation_status_path: root.join("var/lib/enoki-probe/probe-operation-status.toml"),
            probe_asset_public_key_sha256: "a".repeat(64),
            probe_distribution_root_sha256: None,
            bootstrap_acquirer_path: None,
            bootstrap_activator_path: None,
            bootstrap_state_dir: None,
            service_name: "enoki-probe".to_owned(),
            service_group: "enoki-probe".to_owned(),
            service_unit_path: root.join("systemd/enoki-probe.service"),
            service_user: "enoki-probe".to_owned(),
            state_dir: root.join("var/lib/enoki-probe"),
            operation_sudoers_path: None,
            collector_helper_sudoers_path: None,
            old_sudoers_paths: Vec::new(),
            observation_runtime_path: None,
            cpu_provider_path: None,
            disk_health_provider_path: None,
            lifecycle_companion_path: None,
            observation_unit_paths: Vec::new(),
            probe_ipc_group: None,
            probe_ipc_group_ownership: None,
            observation_ipc_group: None,
            install_state_sha256: None,
            target_manifest_sha256: None,
            bundle_version: None,
            lifecycle_authority_install_key: None,
        }
    }

    fn create_file(path: &Path, mode: u32) {
        fs::create_dir_all(path.parent().expect("file parent")).expect("create parent");
        if path
            .parent()
            .is_some_and(|parent| parent.ends_with("var/lib/enoki-probe"))
        {
            fs::set_permissions(
                path.parent().expect("state parent"),
                fs::Permissions::from_mode(0o750),
            )
            .expect("trusted state root mode");
        }
        fs::write(path, b"fixture").expect("write fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
    }

    #[test]
    fn legacy_cleanup_oracle_removes_owned_inventory_in_exact_order() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut metadata = metadata(temporary.path(), 1);
        metadata.operation_sudoers_path = Some(temporary.path().join("sudoers/operations"));
        metadata.collector_helper_sudoers_path =
            Some(temporary.path().join("sudoers/collector-helpers"));
        metadata.old_sudoers_paths = vec![
            temporary.path().join("sudoers/upgrader"),
            temporary.path().join("sudoers/legacy-operation"),
        ];
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
        ] {
            create_file(path, 0o600);
        }
        for path in metadata
            .operation_sudoers_path
            .iter()
            .chain(metadata.collector_helper_sudoers_path.iter())
            .chain(metadata.old_sudoers_paths.iter())
        {
            create_file(path, 0o440);
        }
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let install_metadata_path = temporary.path().join("etc/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let mut systemd = TestSystemd::default();

        execute_probe_uninstall_with_install_metadata_path(
            &input,
            &metadata,
            &mut systemd,
            &install_metadata_path,
        )
        .expect("legacy cleanup");

        for path in [
            &metadata.install_path,
            &metadata.service_unit_path,
            &metadata.state_dir,
            &install_metadata_path,
        ]
        .into_iter()
        .chain(metadata.operation_sudoers_path.iter())
        .chain(metadata.collector_helper_sudoers_path.iter())
        .chain(metadata.old_sudoers_paths.iter())
        {
            assert!(!path.exists(), "{} remains", path.display());
        }
        assert_eq!(
            systemd.calls,
            [
                "stop enoki-probe",
                "disable enoki-probe",
                "daemon-reload",
                "reset-failed enoki-probe",
                "verify-absent enoki-probe",
                "remove-identity enoki-probe:enoki-probe",
                "verify-absent enoki-probe",
            ]
        );
    }

    #[test]
    fn planner_rejects_relative_inventory_with_exact_error_and_zero_effects() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let sentinel = temporary.path().join("sentinel");
        create_file(&sentinel, 0o600);
        let mut metadata = metadata(temporary.path(), 1);
        metadata.install_path = PathBuf::from("relative-probe");
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };

        assert!(matches!(
            plan_probe_uninstall_cleanup(
                &input,
                &metadata,
                &temporary.path().join("probe-install.toml")
            ),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "paths must be absolute"
            ))
        ));
        assert_eq!(fs::read(&sentinel).expect("sentinel remains"), b"fixture");
    }

    #[test]
    fn schema_two_cleanup_removes_the_complete_owned_probe_and_bootstrap_inventory() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut metadata = metadata(temporary.path(), 2);
        let acquirer = temporary.path().join("bin/enoki-bootstrap-acquire");
        let activator = temporary.path().join("bin/enoki-bootstrap-activate");
        let bootstrap_state = owned_state(temporary.path());
        let undeclared_legacy_sudoers = temporary.path().join("sudoers/preexisting-legacy");
        metadata.bootstrap_acquirer_path = Some(acquirer.clone());
        metadata.bootstrap_activator_path = Some(activator.clone());
        metadata.bootstrap_state_dir = Some(bootstrap_state.clone());
        assert!(metadata.old_sudoers_paths.is_empty());
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
            &acquirer,
            &activator,
        ] {
            create_file(
                path,
                if path == &acquirer || path == &activator {
                    0o755
                } else {
                    0o600
                },
            );
        }
        let install_metadata_path = temporary.path().join("etc/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        create_file(&undeclared_legacy_sudoers, 0o440);
        let legacy_bytes = fs::read(&undeclared_legacy_sudoers).expect("legacy sudoers bytes");
        let legacy_before =
            fs::metadata(&undeclared_legacy_sudoers).expect("legacy sudoers metadata");
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let mut systemd = TestSystemd::default();

        execute_probe_uninstall_with_install_metadata_path(
            &input,
            &metadata,
            &mut systemd,
            &install_metadata_path,
        )
        .expect("schema two cleanup");

        for path in [
            &acquirer,
            &activator,
            &bootstrap_state,
            &metadata.install_path,
            &metadata.service_unit_path,
            &metadata.identity_path,
            &metadata.state_dir,
            &install_metadata_path,
        ] {
            assert!(!path.exists(), "owned path remains: {}", path.display());
        }
        assert_eq!(
            fs::read(&undeclared_legacy_sudoers).expect("legacy sudoers remains"),
            legacy_bytes
        );
        let legacy_after =
            fs::metadata(&undeclared_legacy_sudoers).expect("legacy sudoers remains");
        assert_eq!(legacy_after.mode(), legacy_before.mode());
        assert_eq!(legacy_after.ino(), legacy_before.ino());
        assert_eq!(
            systemd.calls,
            [
                "stop enoki-probe",
                "disable enoki-probe",
                "daemon-reload",
                "reset-failed enoki-probe",
                "verify-absent enoki-probe",
                "remove-identity enoki-probe:enoki-probe",
                "verify-absent enoki-probe",
            ]
        );
    }

    #[test]
    fn schema_two_planner_rejects_bootstrap_role_symlink_without_any_host_effect() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut metadata = metadata(temporary.path(), 2);
        let acquirer = temporary.path().join("bin/enoki-bootstrap-acquire");
        let activator = temporary.path().join("bin/enoki-bootstrap-activate");
        let external_target = temporary.path().join("external-bootstrap-target");
        let legacy_sudoers = temporary.path().join("sudoers/preexisting-legacy");
        create_file(&external_target, 0o755);
        create_file(&activator, 0o755);
        create_file(&legacy_sudoers, 0o440);
        symlink(&external_target, &acquirer).expect("Bootstrap acquirer symlink");
        metadata.bootstrap_acquirer_path = Some(acquirer.clone());
        metadata.bootstrap_activator_path = Some(activator.clone());
        metadata.bootstrap_state_dir = Some(owned_state(temporary.path()));
        metadata.old_sudoers_paths = vec![legacy_sudoers.clone()];
        let target_before = fs::metadata(&external_target).expect("target metadata");
        let legacy_before = fs::metadata(&legacy_sudoers).expect("legacy metadata");
        let target_bytes = fs::read(&external_target).expect("target bytes");
        let legacy_bytes = fs::read(&legacy_sudoers).expect("legacy bytes");
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let install_metadata_path = temporary.path().join("etc/probe-install.toml");
        let sentinel = temporary.path().join("sentinel");
        create_file(&sentinel, 0o600);
        let mut systemd = TestSystemd::default();

        assert!(matches!(
            execute_probe_uninstall_with_install_metadata_path(
                &input,
                &metadata,
                &mut systemd,
                &install_metadata_path,
            ),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Probe Bootstrap role is not a root-owned regular 0755 file"
            ))
        ));
        assert!(systemd.calls.is_empty());
        assert!(acquirer.is_symlink());
        assert_eq!(
            fs::read(&external_target).expect("target remains"),
            target_bytes
        );
        let target_after = fs::metadata(&external_target).expect("target remains");
        assert_eq!(target_after.ino(), target_before.ino());
        assert_eq!(target_after.mode(), target_before.mode());
        assert_eq!(
            fs::read(&legacy_sudoers).expect("legacy remains"),
            legacy_bytes
        );
        let legacy_after = fs::metadata(&legacy_sudoers).expect("legacy remains");
        assert_eq!(legacy_after.ino(), legacy_before.ino());
        assert_eq!(legacy_after.mode(), legacy_before.mode());
        assert_eq!(
            fs::read(&sentinel).expect("zero-effect sentinel"),
            b"fixture"
        );
    }

    #[test]
    fn schema_three_cleanup_removes_complete_observation_role_inventory_in_systemd_order() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut metadata = metadata(temporary.path(), 3);
        metadata.bootstrap_acquirer_path = Some(temporary.path().join("bin/bootstrap-acquire"));
        metadata.bootstrap_activator_path = Some(temporary.path().join("bin/bootstrap-activate"));
        metadata.bootstrap_state_dir = Some(owned_state(temporary.path()));
        metadata.observation_runtime_path = Some(temporary.path().join("bin/observation-runtime"));
        metadata.cpu_provider_path = Some(temporary.path().join("bin/cpu-provider"));
        metadata.disk_health_provider_path = Some(temporary.path().join("bin/disk-provider"));
        metadata.observation_ipc_group = Some("enoki-observation-ipc".to_owned());
        metadata.observation_unit_paths = [
            "enoki-observation-runtime.service",
            "enoki-observation-runtime.socket",
            "enoki-cpu-resource-provider@.service",
            "enoki-cpu-resource-provider.socket",
            "enoki-disk-health-resource-provider@.service",
            "enoki-disk-health-resource-provider.socket",
        ]
        .map(|name| temporary.path().join("systemd").join(name))
        .to_vec();
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
        ]
        .into_iter()
        .chain(metadata.bootstrap_acquirer_path.iter())
        .chain(metadata.bootstrap_activator_path.iter())
        .chain(metadata.observation_runtime_path.iter())
        .chain(metadata.cpu_provider_path.iter())
        .chain(metadata.disk_health_provider_path.iter())
        .chain(metadata.observation_unit_paths.iter())
        {
            create_file(
                path,
                if metadata.bootstrap_acquirer_path.as_ref() == Some(path)
                    || metadata.bootstrap_activator_path.as_ref() == Some(path)
                {
                    0o755
                } else {
                    0o600
                },
            );
        }
        let install_metadata_path = temporary.path().join("etc/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let mut systemd = TestSystemd::default();

        execute_probe_uninstall_with_install_metadata_path(
            &input,
            &metadata,
            &mut systemd,
            &install_metadata_path,
        )
        .expect("schema three cleanup");

        for path in metadata
            .observation_unit_paths
            .iter()
            .chain(metadata.observation_runtime_path.iter())
            .chain(metadata.cpu_provider_path.iter())
            .chain(metadata.disk_health_provider_path.iter())
            .chain(metadata.bootstrap_acquirer_path.iter())
            .chain(metadata.bootstrap_activator_path.iter())
            .chain([
                &metadata.install_path,
                &metadata.service_unit_path,
                &metadata.identity_path,
                &metadata.state_dir,
                metadata
                    .bootstrap_state_dir
                    .as_ref()
                    .expect("bootstrap state"),
                &install_metadata_path,
            ])
        {
            assert!(!path.exists(), "schema three residue: {}", path.display());
        }
        assert_eq!(
            systemd.calls,
            [
                "stop enoki-disk-health-resource-provider.socket",
                "disable enoki-disk-health-resource-provider.socket",
                "stop enoki-cpu-resource-provider.socket",
                "disable enoki-cpu-resource-provider.socket",
                "stop enoki-observation-runtime.socket",
                "disable enoki-observation-runtime.socket",
                "stop enoki-observation-runtime.service",
                "disable enoki-observation-runtime.service",
                "stop enoki-probe",
                "disable enoki-probe",
                "daemon-reload",
                "reset-failed enoki-probe",
                "verify-absent enoki-probe",
                "reset-failed enoki-observation-runtime.service",
                "verify-absent enoki-observation-runtime.service",
                "reset-failed enoki-observation-runtime.socket",
                "verify-absent enoki-observation-runtime.socket",
                "reset-failed enoki-cpu-resource-provider.socket",
                "verify-absent enoki-cpu-resource-provider.socket",
                "reset-failed enoki-disk-health-resource-provider.socket",
                "verify-absent enoki-disk-health-resource-provider.socket",
                "remove-identity enoki-probe:enoki-probe",
                "remove-identity enoki-observation-ipc:enoki-observation-ipc",
                "verify-absent enoki-probe",
            ]
        );
        assert!(systemd.calls.iter().all(|call| !call.contains("@.service")));
    }

    #[test]
    fn schema_four_cleanup_keeps_reentry_assets_until_recoverable_finalize() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut metadata = metadata(temporary.path(), 4);
        let acquirer = temporary.path().join("bin/enoki-bootstrap-acquire");
        let activator = temporary.path().join("bin/enoki-bootstrap-activate");
        let bootstrap_state = temporary.path().join("bootstrap-state");
        let companion = temporary.path().join("bin/enoki-probe-lifecycle-companion");
        let companion_service = temporary
            .path()
            .join("systemd/enoki-probe-lifecycle-companion@.service");
        let companion_socket = temporary
            .path()
            .join("systemd/enoki-probe-lifecycle-companion.socket");
        let observation_runtime = temporary.path().join("bin/observation-runtime");
        let cpu_provider = temporary.path().join("bin/cpu-provider");
        let disk_provider = temporary.path().join("bin/disk-provider");
        let observation_units = [
            "enoki-observation-runtime.service",
            "enoki-observation-runtime.socket",
            "enoki-cpu-resource-provider@.service",
            "enoki-cpu-resource-provider.socket",
            "enoki-disk-health-resource-provider@.service",
            "enoki-disk-health-resource-provider.socket",
        ]
        .map(|name| temporary.path().join("systemd").join(name));
        metadata.bootstrap_acquirer_path = Some(acquirer.clone());
        metadata.bootstrap_activator_path = Some(activator.clone());
        metadata.bootstrap_state_dir = Some(bootstrap_state.clone());
        metadata.lifecycle_companion_path = Some(companion.clone());
        metadata.observation_runtime_path = Some(observation_runtime.clone());
        metadata.cpu_provider_path = Some(cpu_provider.clone());
        metadata.disk_health_provider_path = Some(disk_provider.clone());
        metadata.observation_unit_paths = observation_units
            .iter()
            .cloned()
            .chain([companion_service.clone(), companion_socket.clone()])
            .collect();
        metadata.probe_ipc_group = Some("enoki-probe-ipc".to_owned());
        metadata.probe_ipc_group_ownership = Some("!enoki-bootstrap-owned".to_owned());
        metadata.observation_ipc_group = Some("enoki-observation-ipc".to_owned());
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
            &companion,
            &companion_service,
            &companion_socket,
            &observation_runtime,
            &cpu_provider,
            &disk_provider,
        ] {
            create_file(path, 0o755);
        }
        for path in &observation_units {
            create_file(path, 0o600);
        }
        fs::set_permissions(&metadata.state_dir, fs::Permissions::from_mode(0o750))
            .expect("trusted state root mode");
        create_file(&acquirer, 0o755);
        create_file(&activator, 0o755);
        fs::create_dir(&bootstrap_state).expect("bootstrap state");
        fs::set_permissions(&bootstrap_state, fs::Permissions::from_mode(0o700))
            .expect("bootstrap state mode");
        let install_metadata_path = temporary.path().join("etc/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let plan = plan_probe_uninstall_cleanup(&input, &metadata, &install_metadata_path)
            .expect("schema four plan");
        let mut systemd = TestSystemd::default();

        prepare_probe_uninstall_cleanup(&plan, &mut systemd).expect("prepare cleanup");
        for path in [
            &metadata.identity_path,
            &install_metadata_path,
            &companion,
            &companion_service,
            &companion_socket,
        ] {
            assert!(path.exists(), "{} removed during prepare", path.display());
        }
        STATE_SHELL_RETIRE_FAILURE.with(|failure| failure.set(true));
        finalize_recoverable_uninstall_cleanup(&plan, &mut systemd).expect("recoverable finalize");
        STATE_SHELL_RETIRE_FAILURE.with(|failure| failure.set(false));
        remove_probe_bootstrap_state(&plan).expect("retire Bootstrap state");
        assert!(companion.exists(), "companion is the final reentry asset");
        remove_lifecycle_companion_binary(&plan).expect("remove companion binary");
        assert!(!companion.exists());
        assert!(!install_metadata_path.exists());
        assert!(!metadata.identity_path.exists());
        assert!(
            metadata.state_dir.exists(),
            "empty state shell is harmless residue"
        );
        assert!(
            fs::read_dir(&metadata.state_dir)
                .expect("state shell remains readable")
                .next()
                .is_none(),
            "the coordinator clears the complete trusted state root before retaining its shell"
        );
        for path in [
            &metadata.install_path,
            &metadata.service_unit_path,
            &acquirer,
            &activator,
            &bootstrap_state,
            &observation_runtime,
            &cpu_provider,
            &disk_provider,
            &companion_service,
            &companion_socket,
            &install_metadata_path,
        ]
        .into_iter()
        .chain(observation_units.iter())
        {
            assert!(!path.exists(), "schema four residue: {}", path.display());
        }
        assert_eq!(
            systemd.calls,
            [
                "stop enoki-disk-health-resource-provider@*.service",
                "disable enoki-disk-health-resource-provider@*.service",
                "stop enoki-cpu-resource-provider@*.service",
                "disable enoki-cpu-resource-provider@*.service",
                "stop enoki-disk-health-resource-provider.socket",
                "disable enoki-disk-health-resource-provider.socket",
                "stop enoki-cpu-resource-provider.socket",
                "disable enoki-cpu-resource-provider.socket",
                "stop enoki-observation-runtime.socket",
                "disable enoki-observation-runtime.socket",
                "stop enoki-observation-runtime.service",
                "disable enoki-observation-runtime.service",
                "stop enoki-probe",
                "disable enoki-probe",
                "daemon-reload",
                "reset-failed enoki-probe",
                "verify-absent enoki-probe",
                "reset-failed enoki-observation-runtime.service",
                "verify-absent enoki-observation-runtime.service",
                "reset-failed enoki-observation-runtime.socket",
                "verify-absent enoki-observation-runtime.socket",
                "reset-failed enoki-cpu-resource-provider.socket",
                "verify-absent enoki-cpu-resource-provider.socket",
                "reset-failed enoki-disk-health-resource-provider.socket",
                "verify-absent enoki-disk-health-resource-provider.socket",
                "reset-failed enoki-cpu-resource-provider@*.service",
                "verify-absent enoki-cpu-resource-provider@*.service",
                "reset-failed enoki-disk-health-resource-provider@*.service",
                "verify-absent enoki-disk-health-resource-provider@*.service",
                "remove-identity enoki-probe:enoki-probe",
                "remove-identity enoki-observation-ipc:enoki-observation-ipc",
                "remove-ipc-group enoki-probe-ipc:!enoki-bootstrap-owned",
                "stop enoki-probe-lifecycle-companion.socket",
                "disable enoki-probe-lifecycle-companion.socket",
                "daemon-reload",
                "reset-failed enoki-probe-lifecycle-companion.socket",
                "verify-absent enoki-probe-lifecycle-companion.socket",
                "verify-absent enoki-probe",
            ]
        );
    }

    #[test]
    fn local_state_failure_preserves_the_exact_cleanup_transcript() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let metadata = metadata(temporary.path(), 1);
        fs::create_dir_all(&metadata.state_dir).expect("state root");
        let remaining_state = metadata.state_dir.join("actual-state");
        create_file(&remaining_state, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let install_metadata_path = temporary.path().join("probe-install.toml");
        let plan = plan_probe_uninstall_recovery(&input, &metadata, &install_metadata_path)
            .expect("recovery plan");
        let mut calls = Vec::new();

        let error = remove_uninstall_local_state_with(&plan, |path| {
            calls.push(path.to_path_buf());
            (path != remaining_state)
                .then_some(())
                .ok_or_else(|| ProbeUpgraderRunError::Io(std::io::Error::other("injected")))
        })
        .expect_err("state removal failure");

        assert!(matches!(error, ProbeUpgraderRunError::Io(_)));
        assert_eq!(
            calls,
            [
                install_metadata_path,
                metadata.identity_path,
                remaining_state,
            ]
        );
    }

    #[test]
    fn replacement_cleanup_excludes_metadata_from_both_local_state_paths() {
        let config = Path::new("/var/lib/enoki-probe/identity/probe-bootstrap.toml");
        let state = Path::new("/var/lib/enoki-probe");
        let metadata = Path::new("/etc/enoki/probe-install.toml");
        for verification_fails in [true, false] {
            let mut calls = Vec::new();
            let result = finalize_replacement_local_state_with(
                config,
                state,
                |path| {
                    calls.push(path.to_path_buf());
                    Ok(())
                },
                || {
                    if verification_fails {
                        Err(ProbeUpgraderRunError::Io(std::io::Error::other(
                            "verification failed",
                        )))
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(calls, [config, state]);
            assert!(!calls.iter().any(|path| path == metadata));
            assert_eq!(result.is_err(), verification_fails);
        }
    }

    #[test]
    fn state_root_facts_keep_a_short_circuit_rejection_without_extra_reads() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let state = temporary.path().join("var/lib/enoki-probe");
        fs::create_dir_all(&state).expect("ordinary state root");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("unsafe state root mode");
        let mut facts = StateRootAdmissionFacts::default();

        let result = trusted_state_root_layout_with_facts(&state, StateRootOwner::Root, &mut facts);

        assert!(result.is_err(), "unsafe state root is rejected");
        assert!(matches!(facts.public_lstat, StateRootRead::Success(_)));
        assert!(matches!(facts.private_lstat, StateRootRead::NotReached));
        assert!(matches!(facts.public_readlink, StateRootRead::NotReached));
        assert!(matches!(facts.empty_shell, StateRootRead::NotReached));
    }

    #[test]
    fn state_root_facts_distinguish_a_missing_public_root_from_a_reached_private_root() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let state = temporary.path().join("var/lib/enoki-probe");
        let private = temporary.path().join("var/lib/private/enoki-probe");
        fs::create_dir_all(&private).expect("private state root");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o750))
            .expect("private state root mode");
        let mut facts = StateRootAdmissionFacts::default();

        let admission =
            trusted_state_root_layout_with_facts(&state, StateRootOwner::Root, &mut facts)
                .expect("missing public canonical projection admits the private root");

        assert!(admission.is_some());
        assert!(matches!(facts.public_lstat, StateRootRead::NotFound));
        assert!(matches!(facts.private_lstat, StateRootRead::Success(_)));
        assert!(matches!(facts.public_readlink, StateRootRead::NotReached));
        assert!(matches!(facts.nss_owner, StateRootNssOwner::NotReached));
        assert!(matches!(facts.empty_shell, StateRootRead::NotReached));
    }

    #[test]
    fn state_root_facts_keep_a_user_lookup_failure_distinct_from_group_lookup() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let state = temporary.path().join("var/lib/enoki-probe");
        fs::create_dir_all(&state).expect("ordinary state root");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).expect("state root mode");
        let mut facts = StateRootAdmissionFacts::default();

        trusted_state_root_layout_with_facts(
            &state,
            StateRootOwner::BoundServiceOrEmptyShell {
                user: "invalid\0account",
                group: "root",
            },
            &mut facts,
        )
        .expect("root-owned state remains admitted");

        assert!(matches!(
            facts.nss_owner,
            StateRootNssOwner::UserUnavailable
        ));
        assert!(matches!(facts.empty_shell, StateRootRead::NotReached));
    }

    #[test]
    fn state_root_facts_keep_the_public_lstat_io_rejection_point() {
        let state = PathBuf::from(OsString::from_vec(
            b"/tmp/enoki\0/var/lib/enoki-probe".to_vec(),
        ));
        let mut facts = StateRootAdmissionFacts::default();

        let result = trusted_state_root_layout_with_facts(&state, StateRootOwner::Root, &mut facts);

        assert!(result.is_err(), "NUL path causes the reached lstat to fail");
        assert!(matches!(facts.public_lstat, StateRootRead::IoError));
        assert_eq!(facts.first_rejection, Some("public_lstat"));
        assert!(matches!(facts.private_lstat, StateRootRead::NotReached));
    }

    #[test]
    fn committed_replacement_clears_the_exact_canonical_state_root() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let metadata = metadata(temporary.path(), 1);
        let private = temporary.path().join("var/lib/private/enoki-probe");
        fs::create_dir_all(private.parent().expect("private parent")).expect("private parent");
        fs::create_dir(&private).expect("private state root");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o750))
            .expect("private state root mode");
        symlink(
            "private/enoki-probe",
            temporary.path().join("var/lib/enoki-probe"),
        )
        .expect("exact public canonical root");
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
        ] {
            create_file(path, 0o600);
        }
        let install_metadata_path = temporary.path().join("etc/enoki/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let plan = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("committed Replacement plan");
        let mut systemd = TestSystemd::default();

        execute_committed_replacement_cleanup(&plan, &mut systemd)
            .expect("Replacement uses canonical trusted-root cleanup");

        assert!(
            fs::symlink_metadata(temporary.path().join("var/lib/enoki-probe")).is_err(),
            "public canonical shell is retired after its complete contents"
        );
        assert!(!private.exists(), "private canonical contents are retired");
        assert!(
            install_metadata_path.exists(),
            "commit custody retires metadata afterwards"
        );
    }

    #[test]
    fn committed_replacement_planner_rejects_noncurrent_canonical_contents_before_effects() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut metadata = metadata(temporary.path(), 1);
        metadata.service_user = "daemon".to_owned();
        metadata.service_group = "daemon".to_owned();
        let private = temporary.path().join("var/lib/private/enoki-probe");
        fs::create_dir_all(private.parent().expect("private parent")).expect("private parent");
        fs::create_dir(&private).expect("private state root");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o750))
            .expect("private state root mode");
        symlink("private/enoki-probe", &metadata.state_dir).expect("canonical root");
        create_file(&metadata.identity_path, 0o600);
        let install_metadata_path = temporary.path().join("etc/enoki/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };

        EXPECTED_CANONICAL_PRIVATE_ROOT_OWNER.with(|owner| owner.set(Some((u32::MAX, u32::MAX))));
        let result = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path);
        EXPECTED_CANONICAL_PRIVATE_ROOT_OWNER.with(|owner| owner.set(None));

        assert!(matches!(
            result,
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
        assert!(
            metadata.identity_path.exists(),
            "canonical contents were not touched"
        );
    }

    #[test]
    fn canonical_empty_shell_only_retains_a_child_written_after_held_lock_admission() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut metadata = metadata(temporary.path(), 1);
        metadata.service_user = "daemon".to_owned();
        metadata.service_group = "daemon".to_owned();
        let private = temporary.path().join("var/lib/private/enoki-probe");
        fs::create_dir_all(private.parent().expect("private parent")).expect("private parent");
        fs::create_dir(&private).expect("private state root");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o750))
            .expect("private state root mode");
        symlink("private/enoki-probe", &metadata.state_dir).expect("canonical root");
        for path in [&metadata.install_path, &metadata.service_unit_path] {
            create_file(path, 0o600);
        }
        let install_metadata_path = temporary.path().join("etc/enoki/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };

        EXPECTED_CANONICAL_PRIVATE_ROOT_OWNER.with(|owner| owner.set(Some((u32::MAX, u32::MAX))));
        let plan = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("empty canonical shell is admitted");
        EMPTY_SHELL_CHILD_AFTER_ADMISSION.with(|fault| fault.set(true));
        let result = execute_committed_replacement_cleanup(&plan, &mut TestSystemd::default());
        EMPTY_SHELL_CHILD_AFTER_ADMISSION.with(|fault| fault.set(false));
        EXPECTED_CANONICAL_PRIVATE_ROOT_OWNER.with(|owner| owner.set(None));

        assert!(
            result.is_err(),
            "empty-shell-only canonical cleanup must fail closed after a child appears"
        );
        assert!(
            private.join("appeared-after-empty-admission").exists(),
            "empty-shell-only canonical cleanup must not delete a post-admission child"
        );
    }

    #[test]
    fn replacement_revalidates_fixed_state_projection_after_a_failed_shell_retirement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let metadata = metadata(temporary.path(), 1);
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
        ] {
            create_file(path, 0o600);
        }
        let install_metadata_path = temporary.path().join("etc/enoki/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let plan = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("committed Replacement plan");

        STATE_SHELL_RETIRE_MODE_CHANGE.with(|fault| fault.set(true));
        let result = execute_committed_replacement_cleanup(&plan, &mut TestSystemd::default());
        STATE_SHELL_RETIRE_MODE_CHANGE.with(|fault| fault.set(false));

        assert!(matches!(
            result,
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
        assert_eq!(
            fs::metadata(&metadata.state_dir)
                .expect("changed shell remains for verification")
                .mode()
                & 0o7777,
            0o777
        );
    }

    #[test]
    fn replacement_revalidates_canonical_projection_after_a_failed_shell_retirement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let metadata = metadata(temporary.path(), 1);
        let private = temporary.path().join("var/lib/private/enoki-probe");
        fs::create_dir_all(private.parent().expect("private parent")).expect("private parent");
        fs::create_dir(&private).expect("private state root");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o750))
            .expect("private state root mode");
        symlink("private/enoki-probe", &metadata.state_dir).expect("canonical root");
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
        ] {
            create_file(path, 0o600);
        }
        let install_metadata_path = temporary.path().join("etc/enoki/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let plan = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("committed Replacement plan");

        STATE_SHELL_RETIRE_CANONICAL_PROJECTION_CHANGE.with(|fault| fault.set(true));
        let result = execute_committed_replacement_cleanup(&plan, &mut TestSystemd::default());
        STATE_SHELL_RETIRE_CANONICAL_PROJECTION_CHANGE.with(|fault| fault.set(false));

        assert!(matches!(
            result,
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
        assert_eq!(
            fs::read_link(&metadata.state_dir).expect("changed public canonical link"),
            Path::new("private/untrusted")
        );
        assert!(
            private.exists(),
            "bad projection did not retire private shell"
        );
    }

    #[test]
    fn bound_service_owner_tuple_accepts_only_root_or_the_exact_service_pair() {
        let root = (0, 0);
        let service = (995, 995);

        assert!(state_root_owner_tuple_matches(service, root, Some(service)));
        assert!(state_root_owner_tuple_matches(root, root, Some(service)));
        assert!(!state_root_owner_tuple_matches(
            (996, 996),
            root,
            Some(service)
        ));
    }

    #[test]
    fn committed_replacement_keeps_identity_until_an_empty_state_shell() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let metadata = metadata(temporary.path(), 1);
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
        ] {
            create_file(path, 0o600);
        }
        let install_metadata_path = temporary.path().join("etc/enoki/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let plan = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("committed Replacement plan");
        let mut systemd = TestSystemd::default();

        STATE_SHELL_RETIRE_FAILURE.with(|failure| failure.set(true));
        execute_committed_replacement_cleanup(&plan, &mut systemd)
            .expect("Replacement clears the state root before retiring its identity");
        STATE_SHELL_RETIRE_FAILURE.with(|failure| failure.set(false));

        assert!(
            metadata.state_dir.exists(),
            "empty shell may remain harmless"
        );
        assert!(
            fs::read_dir(&metadata.state_dir)
                .expect("state shell remains readable")
                .next()
                .is_none(),
            "the state shell is empty before identity retirement"
        );
        assert!(
            install_metadata_path.exists(),
            "commit custody retires metadata afterwards"
        );
    }

    #[test]
    fn committed_replacement_retries_an_empty_service_shell_after_identity_retirement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let metadata = metadata(temporary.path(), 1);
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
        ] {
            create_file(path, 0o600);
        }
        let install_metadata_path = temporary.path().join("etc/enoki/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let plan = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("initial committed Replacement plan");
        let mut failing_systemd = TestSystemd {
            fail_fixed_ipc_verification: true,
            ..TestSystemd::default()
        };

        STATE_SHELL_RETIRE_FAILURE.with(|failure| failure.set(true));
        let error = execute_committed_replacement_cleanup(&plan, &mut failing_systemd)
            .expect_err("post-identity verification failure retains cleanup");
        STATE_SHELL_RETIRE_FAILURE.with(|failure| failure.set(false));
        assert!(matches!(error, ProbeUpgraderRunError::Io(_)));
        assert!(
            failing_systemd
                .calls
                .iter()
                .any(|call| call.starts_with("remove-identity")),
            "identity retirement happened before the later failure"
        );
        assert!(
            fs::read_dir(&metadata.state_dir)
                .expect("retained state shell")
                .next()
                .is_none(),
            "only an empty shell is retained"
        );

        EXPECTED_ROOT_OWNER.with(|owner| owner.set(Some((u32::MAX, u32::MAX))));
        let retry = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("retained empty shell re-enters cleanup");
        let appeared = metadata.state_dir.join("appeared-after-planning");
        create_file(&appeared, 0o600);
        let error = execute_committed_replacement_cleanup(&retry, &mut TestSystemd::default())
            .expect_err("held-lock reread rejects a changed empty shell");
        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata(_)
        ));
        assert!(appeared.exists(), "changed state was not deleted");
        fs::remove_file(&appeared).expect("restore empty shell");

        let retry = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("restored empty shell re-enters cleanup");
        execute_committed_replacement_cleanup(&retry, &mut TestSystemd::default())
            .expect("empty shell retry completes");
        EXPECTED_ROOT_OWNER.with(|owner| owner.set(None));
    }

    #[test]
    fn empty_shell_only_retains_a_child_written_after_held_lock_admission() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let metadata = metadata(temporary.path(), 1);
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
        ] {
            create_file(path, 0o600);
        }
        let install_metadata_path = temporary.path().join("etc/enoki/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let plan = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("initial committed Replacement plan");
        let mut failing_systemd = TestSystemd {
            fail_fixed_ipc_verification: true,
            ..TestSystemd::default()
        };

        STATE_SHELL_RETIRE_FAILURE.with(|failure| failure.set(true));
        execute_committed_replacement_cleanup(&plan, &mut failing_systemd)
            .expect_err("post-identity failure retains cleanup");
        STATE_SHELL_RETIRE_FAILURE.with(|failure| failure.set(false));

        EXPECTED_ROOT_OWNER.with(|owner| owner.set(Some((u32::MAX, u32::MAX))));
        let retry = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect("empty shell is admitted");
        EMPTY_SHELL_CHILD_AFTER_ADMISSION.with(|fault| fault.set(true));
        let result = execute_committed_replacement_cleanup(&retry, &mut TestSystemd::default());
        EMPTY_SHELL_CHILD_AFTER_ADMISSION.with(|fault| fault.set(false));
        EXPECTED_ROOT_OWNER.with(|owner| owner.set(None));

        assert!(
            result.is_err(),
            "empty-shell-only cleanup must fail closed after a child appears"
        );
        assert!(
            metadata
                .state_dir
                .join("appeared-after-empty-admission")
                .exists(),
            "empty-shell-only cleanup must not delete a post-admission child"
        );
    }

    #[test]
    fn committed_replacement_planner_rejects_mismatched_owner_before_cleanup_effects() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut metadata = metadata(temporary.path(), 1);
        metadata.service_user = "daemon".to_owned();
        metadata.service_group = "daemon".to_owned();
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
        ] {
            create_file(path, 0o600);
        }
        let install_metadata_path = temporary.path().join("etc/enoki/probe-install.toml");
        create_file(&install_metadata_path, 0o600);
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };

        EXPECTED_ROOT_OWNER.with(|owner| owner.set(Some((u32::MAX, u32::MAX))));
        let error = plan_committed_replacement_cleanup(&input, &metadata, &install_metadata_path)
            .expect_err("unknown service owner must fail closed during planning");
        EXPECTED_ROOT_OWNER.with(|owner| owner.set(None));

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata(_)
        ));
        for path in [
            &metadata.identity_path,
            &metadata.install_path,
            &metadata.operation_status_path,
            &metadata.service_unit_path,
            &metadata.state_dir,
            &install_metadata_path,
        ] {
            assert!(path.exists(), "planner admission did not clean {path:?}");
        }
    }

    #[test]
    fn runtime_failure_cleanup_and_a_waiting_recorder_share_one_stable_lock_inode() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let state = temporary.path().join("var/lib/enoki-probe");
        let config = state.join("identity/probe-bootstrap.toml");
        let failure_dir = state.join("runtime-failure");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::create_dir_all(&failure_dir).unwrap();
        fs::set_permissions(&failure_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(failure_dir.join("epoch.toml"), b"epoch").unwrap();
        fs::write(failure_dir.join("latch"), b"generation").unwrap();
        fs::create_dir_all(temporary.path().join("run")).unwrap();
        fs::write(&config, b"identity").unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let mut contender = None;
        finalize_replacement_local_state_with(
            &config,
            &state,
            |path| {
                if path == state {
                    assert!(
                        !failure_dir.join("epoch.toml").exists(),
                        "cleanup custody must invalidate epoch authority first",
                    );
                    assert!(
                        !failure_dir.join("latch").exists(),
                        "cleanup custody must remove the latch only after epoch",
                    );
                    fs::remove_dir_all(path).map_err(ProbeUpgraderRunError::Io)?;
                    let contender_state = state.clone();
                    let started_tx = started_tx.clone();
                    let acquired_tx = acquired_tx.clone();
                    contender = Some(thread::spawn(move || {
                        started_tx.send(()).unwrap();
                        let _lock =
                            crate::runtime_failure::acquire_runtime_failure_pair_lock_for_state(
                                &contender_state,
                                unsafe { libc::geteuid() },
                            )
                            .unwrap();
                        acquired_tx.send(()).unwrap();
                    }));
                    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                    assert_eq!(
                        acquired_rx.recv_timeout(Duration::from_millis(100)),
                        Err(RecvTimeoutError::Timeout),
                        "state cleanup must not let a contender lock a replacement inode",
                    );
                } else {
                    fs::remove_file(path).map_err(ProbeUpgraderRunError::Io)?;
                }
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();

        acquired_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        contender.unwrap().join().unwrap();
        assert!(!state.exists());
        assert!(
            crate::runtime_failure::runtime_failure_pair_lock_path_for_state(&state)
                .unwrap()
                .is_file()
        );
    }

    fn replacement_intent() -> ReplacementIntent {
        ReplacementIntent {
            enrollment_id: "enr_0123456789abcdef".to_owned(),
            enrollment_token_sha256: "a".repeat(64),
            host_id: "7".to_owned(),
            hub_origin: "https://hub.example".to_owned(),
            old_probe_id: "probe_01".to_owned(),
            source_probe_version: "1.2.3".to_owned(),
            source_probe_sha256: "b".repeat(64),
            target_bundle_target: "x86_64-unknown-linux-gnu".to_owned(),
            target_probe_version: "1.2.4".to_owned(),
            target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
            target_manifest_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn completed_replacement_retries_metadata_retirement_without_cleanup_effects() {
        struct Store(ReplacementCommitFact);
        impl ReplacementCommitStore for Store {
            type Error = ();
            fn load(&mut self) -> Result<Option<ReplacementCommitFact>, Self::Error> {
                Ok(Some(self.0.clone()))
            }
            fn persist(&mut self, fact: &ReplacementCommitFact) -> Result<(), Self::Error> {
                self.0 = fact.clone();
                Ok(())
            }
        }
        let intent = replacement_intent();
        let mut store = Store(ReplacementCommitFact {
            schema_version: 1,
            canonical_intent_sha256: intent.canonical_sha256().expect("canonical intent"),
            intent: intent.clone(),
            cleanup_complete: true,
            candidate_layout_complete: false,
            canonical_identity_sha256: None,
        });
        let root = tempfile::tempdir().expect("test root");
        let mut systemd = TestSystemd::default();

        let result = commit_replacement_cleanup_with_metadata_retirement(
            intent,
            &mut store,
            Path::new("/etc/enoki/probe-install.toml"),
            Some(root.path()),
            &mut systemd,
            |_| {
                Err(ProbeUpgraderRunError::Io(std::io::Error::other(
                    "retire failed",
                )))
            },
        );

        assert!(matches!(result, Err(ReplacementCommitError::Effect(_))));
        assert!(store.0.cleanup_complete);
        assert!(systemd.calls.is_empty());
    }

    fn private_directory(path: &Path) {
        fs::create_dir(path).expect("private directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
    }

    fn owned_state(root: &Path) -> PathBuf {
        let state = root.join("bootstrap-state");
        private_directory(&state);
        private_directory(&state.join("trust"));
        private_directory(&state.join("inbox"));
        state
    }

    #[test]
    fn bootstrap_state_validation_rejects_symlinks_hardlinks_and_extra_entries() {
        let symlink_temp = tempfile::tempdir().expect("symlink temp");
        let symlink_state = owned_state(symlink_temp.path());
        fs::remove_dir(symlink_state.join("inbox")).expect("remove inbox");
        let outside = symlink_temp.path().join("outside");
        private_directory(&outside);
        symlink(&outside, symlink_state.join("inbox")).expect("unsafe inbox symlink");
        assert!(matches!(
            validate_owned_bootstrap_state(Some(&symlink_state), None),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Probe Bootstrap state is not a root-owned private directory"
            ))
        ));
        assert!(outside.exists());

        let hardlink_temp = tempfile::tempdir().expect("hardlink temp");
        let hardlink_state = owned_state(hardlink_temp.path());
        let outside = hardlink_temp.path().join("outside-generation");
        fs::write(&outside, "outside").expect("outside state");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).expect("outside mode");
        fs::hard_link(&outside, hardlink_state.join("trust/delegation-generation"))
            .expect("unsafe hardlink");
        assert!(matches!(
            validate_owned_bootstrap_state(Some(&hardlink_state), None),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Probe Bootstrap state contains an unsafe entry"
            ))
        ));
        assert_eq!(fs::read(&outside).expect("outside remains"), b"outside");

        let extra_temp = tempfile::tempdir().expect("extra entry temp");
        let extra_state = owned_state(extra_temp.path());
        fs::write(extra_state.join("unrecognised"), "extra").expect("extra entry");
        assert!(matches!(
            validate_owned_bootstrap_state(Some(&extra_state), None),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Probe Bootstrap state contains an unexpected entry"
            ))
        ));
        assert!(extra_state.join("unrecognised").exists());
    }

    #[test]
    fn final_uninstall_defers_bound_repair_and_retires_only_a_validated_orphan() {
        assert!(
            classify_uninstall_repair_stage(false, Ok(true), || {
                panic!("persisted repair without a stage must still defer uninstall")
            })
            .is_err()
        );
        assert!(
            classify_uninstall_repair_stage(true, Ok(true), || {
                panic!("bound stage must not enter orphan validation")
            })
            .is_err()
        );

        let stage = classify_uninstall_repair_stage(true, Ok(false), || {
            Ok((Some(".pending-repair-01".to_owned()), 12345))
        })
        .expect("validated orphan");
        let mut retired = None;
        retire_unbound_installed_bundle_repair_stage_with(stage.as_ref(), |entry, owner_uid| {
            retired = Some((entry.map(str::to_owned), owner_uid));
            Ok(())
        })
        .expect("retire orphan during execution");
        assert_eq!(
            retired,
            Some((Some(".pending-repair-01".to_owned()), 12345))
        );
    }

    #[test]
    fn schema_five_closes_activation_sockets_before_the_roles_they_can_start() {
        let services = observation_stop_services(5);
        let position = |service: &str| services.iter().position(|entry| *entry == service).unwrap();
        assert!(
            position("enoki-cpu-resource-provider.socket")
                < position("enoki-cpu-resource-provider@*.service")
        );
        assert!(
            position("enoki-disk-health-resource-provider.socket")
                < position("enoki-disk-health-resource-provider@*.service")
        );
        assert!(
            position("enoki-observation-runtime.socket")
                < position("enoki-observation-runtime.service")
        );
        assert!(
            position("enoki-observation-runtime.service")
                < position("enoki-observation-runtime-failure.service")
        );
        assert!(
            position("enoki-probe-lifecycle-upgrade.socket")
                < position("enoki-probe-lifecycle-upgrade@*.service")
        );
    }
}
