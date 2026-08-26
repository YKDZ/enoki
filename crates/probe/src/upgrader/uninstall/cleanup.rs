//! Fixed uninstall/replacement inventory and Host cleanup mechanics.

use super::{
    ProbeUninstallerRunInput, ProbeUpgraderRunError, ProbeUpgraderSystemdRunner,
    TrustedProbeInstallMetadata,
};
use crate::upgrader::{
    ensure_absolute_path, fixed_installed_probe_sha256, is_lifecycle_companion_path,
    is_lifecycle_companion_service, observation_services, preflight_rooted_path,
    read_trusted_probe_install_metadata_read_only, read_trusted_probe_install_preflight,
    rebase_trusted_install_metadata_paths, remove_empty_parent_dir, remove_path_if_exists,
    verify_path_absent,
};
use enoki_probe_bootstrap::replacement::{
    ReplacementCommitError, ReplacementCommitFact, ReplacementCommitStore, ReplacementIntent,
    commit_and_cleanup_replacement,
};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

#[cfg(test)]
pub(super) fn execute_probe_uninstall_with_install_metadata_path(
    input: &ProbeUninstallerRunInput,
    install_metadata: &TrustedProbeInstallMetadata,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
    install_metadata_path: &Path,
) -> Result<(), ProbeUpgraderRunError> {
    let plan = plan_probe_uninstall_cleanup(input, install_metadata, install_metadata_path)?;
    execute_complete_uninstall_cleanup_oracle(&plan, systemd)
}

/// Replacement-only seam used after the durable migration commit. It reuses
/// the uninstall cleanup mechanics while preserving candidate Bootstrap state.
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

/// Establishes every local deletion target before systemd or filesystem
/// mutation. Both the offline public command and Hub-authorized operation
/// invoke this planner through the same executor below.
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
pub(super) fn execute_complete_uninstall_cleanup_oracle(
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
    remove(&plan.install_metadata.state_dir)
}

pub(super) fn finalize_replacement_local_state_with(
    bootstrap_config_path: &Path,
    state_dir: &Path,
    mut remove: impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
    verify: impl FnOnce() -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    remove(bootstrap_config_path)?;
    remove(state_dir)?;
    verify()
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
    use super::validate_owned_bootstrap_state;
    use crate::upgrader::ProbeUpgraderRunError;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
    };

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
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
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
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
        assert_eq!(fs::read(&outside).expect("outside remains"), b"outside");

        let extra_temp = tempfile::tempdir().expect("extra entry temp");
        let extra_state = owned_state(extra_temp.path());
        fs::write(extra_state.join("unrecognised"), "extra").expect("extra entry");
        assert!(matches!(
            validate_owned_bootstrap_state(Some(&extra_state)),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
        assert!(extra_state.join("unrecognised").exists());
    }
}
