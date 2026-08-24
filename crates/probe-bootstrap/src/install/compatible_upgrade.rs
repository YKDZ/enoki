//! Compatible Upgrade 的 Host coordinator 与私有 lifecycle mechanics kernel。

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    acquisition::{
        VerifiedProbeUpgradeStage, VerifiedUpgradeStageReceipt, open_verified_probe_upgrade_stage,
        remove_verified_probe_upgrade_stage,
    },
    lifecycle::{
        LifecycleRequest, LifecycleRequestAuthority, LifecycleResponse, UpgradeCompletion,
    },
};

use super::{
    ConsumeBeforeOuterError, FixedInstallPaths, InstalledUpgradeBinding, SystemSystemd,
    UpgradeAttempt, UpgradeAuthorityConsumption, UpgradeRecoveryReceipt, VerifiedUpgradeComponents,
    abort_consumed_probe_upgrade_authority, consume_signed_before_upgrade_outer_checks,
    finalize_probe_upgrade_stage_cleanup, inspect_installed_probe_for_upgrade,
    recover_incomplete_probe_upgrade, upgrade_current_probe_for_operation,
};

/// Compatible Upgrade 的封闭生产 Interface。调用者只交付 Hub 的类型化请求与
/// Unix peer 身份，不能选择路径、unit、命令、权限、phase 或恢复模式。
pub fn run_compatible_upgrade(
    request: &LifecycleRequest,
    peer_uid: Option<u32>,
) -> LifecycleResponse {
    let LifecycleRequestAuthority::HubUpgrade {
        hub_origin,
        host_id,
        probe_id,
        operation_id,
        source_bundle_version,
        source_install_state_sha256,
        source_manifest_sha256,
        target_bundle_version,
        target_asset_set_digest,
        target_manifest_sha256,
        verified_stage_sha256,
        expires_at_ms,
        authority_signature,
    } = request.authority()
    else {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    };
    let Some(peer_uid) = peer_uid else {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    };
    let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => return LifecycleResponse::failed("lifecycle.invalid_authority"),
    };
    if now_ms > u128::from(*expires_at_ms) {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    }
    let canonical_authority = match request.canonical_upgrade_authority_bytes() {
        Ok(canonical) => canonical,
        Err(_) => return LifecycleResponse::failed("lifecycle.invalid_authority"),
    };

    let paths = FixedInstallPaths::production();
    let authority = UpgradeAuthorityConsumption {
        operation_id: operation_id.clone(),
        stage_owner_uid: peer_uid,
        hub_origin: hub_origin.clone(),
        host_id: host_id.clone(),
        probe_id: probe_id.clone(),
        source_bundle_version: source_bundle_version.clone(),
        source_install_state_sha256: source_install_state_sha256.clone(),
        source_manifest_sha256: source_manifest_sha256.clone(),
        target_bundle_version: target_bundle_version.clone(),
        target_asset_set_digest: target_asset_set_digest.clone(),
        target_manifest_sha256: target_manifest_sha256.clone(),
        verified_stage_sha256: verified_stage_sha256.clone(),
    };
    let receipt = VerifiedUpgradeStageReceipt {
        operation_id: operation_id.clone(),
        target_asset_set_digest: target_asset_set_digest.clone(),
        target_manifest_sha256: target_manifest_sha256.clone(),
        target_version: target_bundle_version.clone(),
        verified_stage_sha256: verified_stage_sha256.clone(),
    };
    let admitted = consume_signed_before_upgrade_outer_checks(
        &paths,
        &authority,
        &canonical_authority,
        authority_signature,
        |_| {
            let source = inspect_installed_probe_for_upgrade(&paths)
                .map_err(|_| "lifecycle.install_state_invalid")?;
            if source.hub_origin != *hub_origin
                || source.probe_id != *probe_id
                || source.source_bundle_version != *source_bundle_version
                || source.source_install_state_sha256 != *source_install_state_sha256
                || source.source_manifest_sha256 != *source_manifest_sha256
            {
                return Err("lifecycle.authority_mismatch");
            }
            let mut stage = open_verified_probe_upgrade_stage(&receipt, peer_uid)
                .map_err(|_| "lifecycle.upgrade_stage_invalid")?;
            stage
                .persist_generation_before_activation()
                .map_err(|_| "lifecycle.upgrade_stage_invalid")?;
            Ok((stage, source))
        },
    );
    let (consumed, (stage, expected_source)) = match admitted {
        Ok(ready) => ready,
        Err(ConsumeBeforeOuterError::Consume) => {
            return LifecycleResponse::failed("lifecycle.upgrade_authority_consumed");
        }
        Err(ConsumeBeforeOuterError::Outer { consumed, error }) => {
            return fail_before_activation(&paths, &consumed, operation_id, peer_uid, error);
        }
    };

    let plan = VerifiedMutationPlan {
        stage,
        expected_source,
        consumed,
        operation_id: operation_id.clone(),
        probe_id: probe_id.clone(),
        source_bundle_version: source_bundle_version.clone(),
        target_bundle_version: target_bundle_version.clone(),
        stage_owner_uid: peer_uid,
    };
    match mechanics::execute(plan) {
        CompatibleUpgradeOutcome::Activated => LifecycleResponse::succeeded(),
        CompatibleUpgradeOutcome::FailedBeforeActivation => {
            LifecycleResponse::failed("lifecycle.upgrade_failed_before_activation")
        }
        CompatibleUpgradeOutcome::RepairRequired => {
            LifecycleResponse::failed("lifecycle.upgrade_repair_required")
        }
    }
}

fn fail_before_activation(
    paths: &FixedInstallPaths,
    consumed: &UpgradeAttempt,
    operation_id: &str,
    stage_owner_uid: u32,
    failure_code: &'static str,
) -> LifecycleResponse {
    if remove_verified_probe_upgrade_stage(operation_id, stage_owner_uid).is_ok()
        && abort_consumed_probe_upgrade_authority(paths, consumed).is_ok()
    {
        LifecycleResponse::failed(failure_code)
    } else {
        LifecycleResponse::failed("lifecycle.upgrade_repair_required")
    }
}

struct VerifiedMutationPlan {
    stage: VerifiedProbeUpgradeStage,
    expected_source: InstalledUpgradeBinding,
    consumed: UpgradeAttempt,
    operation_id: String,
    probe_id: String,
    source_bundle_version: String,
    target_bundle_version: String,
    stage_owner_uid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompatibleUpgradeOutcome {
    Activated,
    FailedBeforeActivation,
    RepairRequired,
}

mod mechanics {
    use super::*;

    pub(super) fn execute(mut plan: VerifiedMutationPlan) -> CompatibleUpgradeOutcome {
        let paths = FixedInstallPaths::production();
        let mut systemd = SystemSystemd::for_live_upgrade();
        let result = upgrade_current_probe_for_operation(
            VerifiedUpgradeComponents {
                probe: &mut plan.stage.probe,
                observation_runtime: &mut plan.stage.observation_runtime,
                system_state_provider: &mut plan.stage.system_state_provider,
                disk_health_provider: &mut plan.stage.disk_health_provider,
                lifecycle_companion: &mut plan.stage.lifecycle_companion,
                bootstrap_acquirer: &mut plan.stage.bootstrap_acquirer,
                bootstrap_activator: &mut plan.stage.bootstrap_activator,
            },
            &plan.stage.bundle,
            &plan.expected_source,
            &plan.consumed,
            &paths,
            &mut systemd,
        );
        match result {
            Ok(UpgradeCompletion::Activated) => {
                let receipt = activated_recovery_receipt(&plan);
                if remove_verified_probe_upgrade_stage(&plan.operation_id, plan.stage_owner_uid)
                    .is_ok()
                    && finalize_probe_upgrade_stage_cleanup(&paths, &receipt).is_ok()
                {
                    CompatibleUpgradeOutcome::Activated
                } else {
                    CompatibleUpgradeOutcome::RepairRequired
                }
            }
            Ok(UpgradeCompletion::RepairRequired) => CompatibleUpgradeOutcome::RepairRequired,
            Err(_) => match recover_incomplete_probe_upgrade(&paths, &mut systemd) {
                Ok(Some(receipt))
                    if !receipt.activated
                        && remove_verified_probe_upgrade_stage(
                            &receipt.operation_id,
                            receipt.stage_owner_uid,
                        )
                        .is_ok()
                        && finalize_probe_upgrade_stage_cleanup(&paths, &receipt).is_ok() =>
                {
                    CompatibleUpgradeOutcome::FailedBeforeActivation
                }
                _ => CompatibleUpgradeOutcome::RepairRequired,
            },
        }
    }

    fn activated_recovery_receipt(plan: &VerifiedMutationPlan) -> UpgradeRecoveryReceipt {
        UpgradeRecoveryReceipt {
            operation_id: plan.operation_id.clone(),
            probe_id: plan.probe_id.clone(),
            stage_owner_uid: plan.stage_owner_uid,
            source_bundle_version: plan.source_bundle_version.clone(),
            target_bundle_version: plan.target_bundle_version.clone(),
            activated: true,
        }
    }
}
