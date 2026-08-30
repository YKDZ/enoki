//! 固定的 Uninstall/Replacement inventory 与 Host cleanup mechanics。

use super::{
    ProbeUninstallerRunInput, ProbeUpgraderRunError, ProbeUpgraderSystemdRunner,
    TrustedProbeInstallMetadata,
};
use crate::upgrader::{
    ensure_absolute_path, is_lifecycle_companion_path, is_lifecycle_companion_service,
    observation_services, preflight_rooted_path, read_trusted_probe_install_metadata_read_only,
    read_trusted_probe_install_preflight, rebase_trusted_install_metadata_paths,
    remove_empty_parent_dir, remove_path_if_exists, replacement::fixed_installed_probe_sha256,
    verify_path_absent,
};
use enoki_probe_bootstrap::replacement::{
    ReplacementCommitError, ReplacementCommitFact, ReplacementCommitStore, ReplacementIntent,
    commit_and_cleanup_replacement,
};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

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
}

/// 在 systemd 或文件系统变更前确定全部本机删除目标。
/// 离线公开命令与 Hub 授权操作都通过下方同一个 executor 调用此 planner。
pub(super) fn plan_probe_uninstall_cleanup<'a>(
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
) -> Result<ProbeUninstallCleanupPlan<'a>, ProbeUpgraderRunError> {
    let plan = plan_probe_uninstall_paths(input, install_metadata, install_metadata_path)?;
    validate_owned_bootstrap_assets_for_cleanup(install_metadata)?;
    Ok(plan)
}

pub(super) fn plan_probe_uninstall_recovery<'a>(
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
) -> Result<ProbeUninstallCleanupPlan<'a>, ProbeUpgraderRunError> {
    let plan = plan_probe_uninstall_paths(input, install_metadata, install_metadata_path)?;
    validate_owned_bootstrap_assets_for_recovery(install_metadata)?;
    Ok(plan)
}

pub(super) fn plan_committed_replacement_cleanup<'a>(
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
) -> Result<ProbeUninstallCleanupPlan<'a>, ProbeUpgraderRunError> {
    let plan = plan_probe_uninstall_paths(input, install_metadata, install_metadata_path)?;
    if matches!(install_metadata.schema_version, 2..=5) {
        validate_owned_bootstrap_role_for_recovery(
            install_metadata.bootstrap_acquirer_path.as_deref(),
        )?;
        validate_owned_bootstrap_role_for_recovery(
            install_metadata.bootstrap_activator_path.as_deref(),
        )?;
        validate_owned_bootstrap_state(install_metadata.bootstrap_state_dir.as_deref())?;
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
    })
}

pub(super) fn validate_owned_bootstrap_assets_for_cleanup(
    metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    if matches!(metadata.schema_version, 2..=5) {
        validate_owned_bootstrap_role(metadata.bootstrap_acquirer_path.as_deref())?;
        validate_owned_bootstrap_role(metadata.bootstrap_activator_path.as_deref())?;
        validate_owned_bootstrap_state(metadata.bootstrap_state_dir.as_deref())?;
    }
    Ok(())
}

pub(super) fn validate_owned_bootstrap_assets_for_recovery(
    metadata: &TrustedProbeInstallMetadata,
) -> Result<(), ProbeUpgraderRunError> {
    if matches!(metadata.schema_version, 2..=5) {
        validate_owned_bootstrap_role_for_recovery(metadata.bootstrap_acquirer_path.as_deref())?;
        validate_owned_bootstrap_role_for_recovery(metadata.bootstrap_activator_path.as_deref())?;
        validate_owned_bootstrap_state_for_recovery(metadata.bootstrap_state_dir.as_deref())?;
    }
    Ok(())
}

pub(super) fn prepare_probe_uninstall_cleanup(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    let install_metadata = plan.install_metadata;
    if matches!(install_metadata.schema_version, 3..=5) {
        for service in observation_services(install_metadata.schema_version)
            .iter()
            .copied()
            .filter(|service| !is_lifecycle_companion_service(service))
            .rev()
        {
            systemd.stop_service(service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_stop_failed",
                    "stopping an observation role",
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
        remove_owned_bootstrap_state(path)?;
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
            .remove_service_identity(ipc_group, ipc_group)
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
            .remove_owned_ipc_group(ipc_group, ownership)
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
            systemd.stop_service(companion_service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_stop_failed",
                    "stopping a lifecycle companion socket",
                    error,
                )
            })?;
            systemd
                .disable_service(companion_service)
                .map_err(|error| {
                    probe_uninstall_cleanup_error(
                        "probe_uninstall_service_disable_failed",
                        "disabling a lifecycle companion socket",
                        error,
                    )
                })?;
        }
        for path in install_metadata
            .observation_unit_paths
            .iter()
            .filter(|path| is_lifecycle_companion_path(path))
        {
            remove_path_if_exists(path)?;
        }
        systemd.daemon_reload().map_err(|error| {
            probe_uninstall_cleanup_error(
                "probe_uninstall_daemon_reload_failed",
                "reloading systemd after lifecycle companion removal",
                error,
            )
        })?;
        for companion_service in companion_services {
            systemd.reset_failed(companion_service).map_err(|error| {
                probe_uninstall_cleanup_error(
                    "probe_uninstall_service_reset_failed",
                    "resetting a lifecycle companion socket failed state",
                    error,
                )
            })?;
            systemd
                .verify_service_absent(companion_service)
                .map_err(|error| {
                    probe_uninstall_cleanup_error(
                        "probe_uninstall_service_verification_failed",
                        "verifying a lifecycle companion socket is absent",
                        error,
                    )
                })?;
        }
    }
    Ok(())
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
    remove_probe_bootstrap_roles(plan)?;
    remove_probe_bootstrap_state(plan)?;
    remove_probe_install_identities(plan, systemd)?;
    remove_lifecycle_companion_activation(plan, systemd)?;
    remove_uninstall_local_state_with(plan, remove_path_if_exists)?;
    remove_empty_parent_dir(&plan.input.bootstrap_config_path)?;
    verify_uninstall_residue_absent(plan, systemd)
}

#[cfg(test)]
fn execute_complete_uninstall_cleanup_oracle(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    prepare_probe_uninstall_cleanup(plan, systemd)?;
    finalize_recoverable_uninstall_cleanup(plan, systemd)?;
    remove_lifecycle_companion_binary(plan)?;
    verify_lifecycle_companion_binary_absent(plan)
}

pub(super) fn execute_committed_replacement_cleanup(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    prepare_probe_uninstall_cleanup(plan, systemd)?;
    remove_probe_bootstrap_roles(plan)?;
    remove_probe_install_identities(plan, systemd)?;
    remove_lifecycle_companion_activation(plan, systemd)?;
    remove_lifecycle_companion_binary(plan)?;
    // 手动重装必须让可信 metadata 活过全部可失败清理与核验。cleanup_complete
    // 持久化后，metadata 由 exact commit custody 作为独立、幂等的退休动作处理。
    finalize_replacement_local_state_with(
        &plan.input.bootstrap_config_path,
        &plan.install_metadata.state_dir,
        remove_path_if_exists,
        || verify_replacement_residue_absent(plan, systemd),
    )
}

pub(super) fn remove_uninstall_local_state_with(
    plan: &ProbeUninstallCleanupPlan<'_>,
    mut remove: impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    remove(plan.install_metadata_path)?;
    remove(&plan.input.bootstrap_config_path)?;
    let _runtime_failure_lock = runtime_failure_cleanup_lock(&plan.install_metadata.state_dir)?;
    remove(&plan.install_metadata.state_dir)
}

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

pub(super) fn verify_uninstall_residue_absent(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<(), ProbeUpgraderRunError> {
    verify_common_cleanup_residue_absent(plan, systemd)?;
    verify_uninstall_local_state_absent(plan)?;
    if let Some(path) = plan.install_metadata.bootstrap_state_dir.as_deref() {
        verify_path_absent(
            path,
            "probe_uninstall_bootstrap_state_residue",
            "verifying Probe Bootstrap state is absent",
        )?;
    }
    Ok(())
}

pub(super) fn verify_replacement_residue_absent(
    plan: &ProbeUninstallCleanupPlan<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
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
        (
            plan.install_metadata.state_dir.as_path(),
            "probe_uninstall_state_residue",
            "verifying Probe state is absent",
        ),
    ] {
        verify_path_absent(path, code, action)?;
    }
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
        (
            plan.install_metadata.state_dir.as_path(),
            "probe_uninstall_state_residue",
            "verifying Probe state is absent",
        ),
    ] {
        verify_path_absent(path, code, action)?;
    }
    Ok(())
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
) -> Result<(), ProbeUpgraderRunError> {
    if path.is_some_and(|path| {
        fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }) {
        return Ok(());
    }
    validate_owned_bootstrap_state(path)
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
pub(super) fn remove_owned_bootstrap_state(path: &Path) -> Result<(), ProbeUpgraderRunError> {
    if fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) {
        return Ok(());
    }
    validate_owned_bootstrap_state(Some(path))?;
    fs::remove_dir_all(path).map_err(ProbeUpgraderRunError::Io)
}

#[cfg(test)]
mod tests {
    use super::{
        ProbeUpgraderSystemdRunner, TrustedProbeInstallMetadata,
        commit_replacement_cleanup_with_metadata_retirement,
        execute_probe_uninstall_with_install_metadata_path, finalize_recoverable_uninstall_cleanup,
        finalize_replacement_local_state_with, plan_probe_uninstall_cleanup,
        plan_probe_uninstall_recovery, prepare_probe_uninstall_cleanup,
        remove_lifecycle_companion_binary, remove_uninstall_local_state_with,
        validate_owned_bootstrap_state,
    };
    use crate::upgrader::{ProbeUninstallerRunInput, ProbeUpgraderRunError};
    use enoki_probe_bootstrap::replacement::{
        ReplacementCommitError, ReplacementCommitFact, ReplacementCommitStore, ReplacementIntent,
    };
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
        sync::mpsc::{self, RecvTimeoutError},
        thread,
        time::Duration,
    };

    #[derive(Default)]
    struct TestSystemd {
        calls: Vec<String>,
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
    }

    fn metadata(root: &Path, schema_version: u32) -> TrustedProbeInstallMetadata {
        TrustedProbeInstallMetadata {
            schema_version,
            hub_url: "https://hub.example".to_owned(),
            identity_path: root.join("state/identity.toml"),
            install_path: root.join("bin/enoki-probe"),
            operation_status_path: root.join("state/status.toml"),
            probe_asset_public_key_sha256: "a".repeat(64),
            probe_distribution_root_sha256: None,
            bootstrap_acquirer_path: None,
            bootstrap_activator_path: None,
            bootstrap_state_dir: None,
            service_name: "enoki-probe".to_owned(),
            service_group: "enoki-probe".to_owned(),
            service_unit_path: root.join("systemd/enoki-probe.service"),
            service_user: "enoki-probe".to_owned(),
            state_dir: root.join("state"),
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
        finalize_recoverable_uninstall_cleanup(&plan, &mut systemd).expect("recoverable finalize");
        assert!(companion.exists(), "companion is the final reentry asset");
        remove_lifecycle_companion_binary(&plan).expect("remove companion binary");
        assert!(!companion.exists());
        assert!(!install_metadata_path.exists());
        assert!(!metadata.identity_path.exists());
        assert!(!metadata.state_dir.exists());
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
        let input = ProbeUninstallerRunInput {
            bootstrap_config_path: metadata.identity_path.clone(),
        };
        let install_metadata_path = temporary.path().join("probe-install.toml");
        let plan = plan_probe_uninstall_recovery(&input, &metadata, &install_metadata_path)
            .expect("recovery plan");
        let mut calls = Vec::new();

        let error = remove_uninstall_local_state_with(&plan, |path| {
            calls.push(path.to_path_buf());
            (path != metadata.state_dir)
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
                metadata.state_dir,
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
            validate_owned_bootstrap_state(Some(&symlink_state)),
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
            validate_owned_bootstrap_state(Some(&hardlink_state)),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Probe Bootstrap state contains an unsafe entry"
            ))
        ));
        assert_eq!(fs::read(&outside).expect("outside remains"), b"outside");

        let extra_temp = tempfile::tempdir().expect("extra entry temp");
        let extra_state = owned_state(extra_temp.path());
        fs::write(extra_state.join("unrecognised"), "extra").expect("extra entry");
        assert!(matches!(
            validate_owned_bootstrap_state(Some(&extra_state)),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "Probe Bootstrap state contains an unexpected entry"
            ))
        ));
        assert!(extra_state.join("unrecognised").exists());
    }
}
