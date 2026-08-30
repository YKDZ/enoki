//! 兼容升级的主机协调器与私有生命周期机制内核。

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
    UpgradeAttempt, UpgradeAuthorityConsumption, UpgradeOperationFailure,
    VerifiedUpgradeComponents, abort_consumed_probe_upgrade_authority,
    consume_signed_before_upgrade_outer_checks, finalize_probe_upgrade_stage_cleanup,
    inspect_installed_probe_for_upgrade, recover_incomplete_probe_upgrade,
    upgrade_current_probe_for_operation,
};

/// 兼容升级的封闭生产接口。调用者只交付 Hub 的类型化请求与
/// Unix 对等方身份，不能选择路径、单元、命令、权限、阶段或恢复模式。
pub fn run_compatible_upgrade(
    request: &LifecycleRequest,
    peer_uid: Option<u32>,
) -> LifecycleResponse {
    let mut host = ProductionCompatibleUpgradeHost::new();
    run_compatible_upgrade_with_host(request, peer_uid, &mut host)
}

struct CompatibleUpgradeAdmission<'a> {
    authority: UpgradeAuthorityConsumption,
    receipt: VerifiedUpgradeStageReceipt,
    canonical_authority: Vec<u8>,
    authority_signature: &'a str,
}

enum CompatibleUpgradeAdmissionFailure<C> {
    Consumed,
    RejectedAfterConsumption {
        consumed: C,
        rejection: CompatibleUpgradeAdmissionRejection,
    },
}

#[derive(Clone, Copy)]
enum CompatibleUpgradeAdmissionRejection {
    InstallStateInvalid,
    AuthorityMismatch,
    UpgradeStageInvalid,
}

impl CompatibleUpgradeAdmissionRejection {
    const fn code(self) -> &'static str {
        match self {
            Self::InstallStateInvalid => "lifecycle.install_state_invalid",
            Self::AuthorityMismatch => "lifecycle.authority_mismatch",
            Self::UpgradeStageInvalid => "lifecycle.upgrade_stage_invalid",
        }
    }
}

trait CompatibleUpgradeHost {
    type Consumed;
    type Plan;

    fn now_ms(&self) -> Result<u128, ()>;
    fn admit(
        &mut self,
        admission: CompatibleUpgradeAdmission<'_>,
    ) -> Result<Self::Plan, CompatibleUpgradeAdmissionFailure<Self::Consumed>>;
    fn cleanup_failed_admission(
        &mut self,
        consumed: &Self::Consumed,
        operation_id: &str,
        stage_owner_uid: u32,
    ) -> bool;
    fn execute(&mut self, plan: Self::Plan) -> CompatibleUpgradeOutcome;
}

struct ProductionCompatibleUpgradeHost {
    paths: FixedInstallPaths,
    systemd: SystemSystemd,
}

#[cfg(test)]
std::thread_local! {
    static PRODUCTION_HOST_CONSTRUCTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn production_host_constructions() -> usize {
    PRODUCTION_HOST_CONSTRUCTIONS.get()
}

impl ProductionCompatibleUpgradeHost {
    fn new() -> Self {
        let host = Self {
            paths: FixedInstallPaths::production(),
            systemd: SystemSystemd::for_live_upgrade(),
        };
        #[cfg(test)]
        PRODUCTION_HOST_CONSTRUCTIONS.set(PRODUCTION_HOST_CONSTRUCTIONS.get() + 1);
        host
    }
}

impl CompatibleUpgradeHost for ProductionCompatibleUpgradeHost {
    type Consumed = UpgradeAttempt;
    type Plan = VerifiedMutationPlan;

    fn now_ms(&self) -> Result<u128, ()> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .map_err(|_| ())
    }

    fn admit(
        &mut self,
        admission: CompatibleUpgradeAdmission<'_>,
    ) -> Result<Self::Plan, CompatibleUpgradeAdmissionFailure<Self::Consumed>> {
        let expected_source = InstalledUpgradeBinding {
            hub_origin: admission.authority.hub_origin.clone(),
            probe_id: admission.authority.probe_id.clone(),
            source_bundle_version: admission.authority.source_bundle_version.clone(),
            source_install_state_sha256: admission.authority.source_install_state_sha256.clone(),
            source_manifest_sha256: admission.authority.source_manifest_sha256.clone(),
        };
        let stage_owner_uid = admission.authority.stage_owner_uid;
        let admitted = consume_signed_before_upgrade_outer_checks(
            &self.paths,
            &admission.authority,
            &admission.canonical_authority,
            admission.authority_signature,
            |_| {
                let source = inspect_installed_probe_for_upgrade(&self.paths)
                    .map_err(|_| CompatibleUpgradeAdmissionRejection::InstallStateInvalid)?;
                if source != expected_source {
                    return Err(CompatibleUpgradeAdmissionRejection::AuthorityMismatch);
                }
                let mut stage =
                    open_verified_probe_upgrade_stage(&admission.receipt, stage_owner_uid)
                        .map_err(|_| CompatibleUpgradeAdmissionRejection::UpgradeStageInvalid)?;
                stage
                    .persist_generation_before_activation()
                    .map_err(|_| CompatibleUpgradeAdmissionRejection::UpgradeStageInvalid)?;
                Ok((stage, source))
            },
        );
        match admitted {
            Ok((consumed, (stage, expected_source))) => Ok(VerifiedMutationPlan {
                stage,
                expected_source,
                consumed,
            }),
            Err(ConsumeBeforeOuterError::Consume) => {
                Err(CompatibleUpgradeAdmissionFailure::Consumed)
            }
            Err(ConsumeBeforeOuterError::Outer {
                consumed,
                error: rejection,
            }) => Err(
                CompatibleUpgradeAdmissionFailure::RejectedAfterConsumption {
                    consumed,
                    rejection,
                },
            ),
        }
    }

    fn cleanup_failed_admission(
        &mut self,
        consumed: &Self::Consumed,
        operation_id: &str,
        stage_owner_uid: u32,
    ) -> bool {
        remove_verified_probe_upgrade_stage(operation_id, stage_owner_uid).is_ok()
            && abort_consumed_probe_upgrade_authority(&self.paths, consumed).is_ok()
    }

    fn execute(&mut self, plan: Self::Plan) -> CompatibleUpgradeOutcome {
        mechanics::execute(plan, &self.paths, &mut self.systemd)
    }
}

fn run_compatible_upgrade_with_host<H: CompatibleUpgradeHost>(
    request: &LifecycleRequest,
    peer_uid: Option<u32>,
    host: &mut H,
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
    let now_ms = match host.now_ms() {
        Ok(now_ms) => now_ms,
        Err(_) => return LifecycleResponse::failed("lifecycle.invalid_authority"),
    };
    if now_ms > u128::from(*expires_at_ms) {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    }
    let canonical_authority = match request.canonical_upgrade_authority_bytes() {
        Ok(canonical) => canonical,
        Err(_) => return LifecycleResponse::failed("lifecycle.invalid_authority"),
    };

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
    let plan = match host.admit(CompatibleUpgradeAdmission {
        authority,
        receipt,
        canonical_authority,
        authority_signature,
    }) {
        Ok(plan) => plan,
        Err(CompatibleUpgradeAdmissionFailure::Consumed) => {
            return LifecycleResponse::failed("lifecycle.upgrade_authority_consumed");
        }
        Err(CompatibleUpgradeAdmissionFailure::RejectedAfterConsumption {
            consumed,
            rejection,
        }) => {
            return if host.cleanup_failed_admission(&consumed, operation_id, peer_uid) {
                LifecycleResponse::failed(rejection.code())
            } else {
                LifecycleResponse::failed("lifecycle.upgrade_repair_required")
            };
        }
    };
    match host.execute(plan) {
        CompatibleUpgradeOutcome::Activated => LifecycleResponse::succeeded(),
        CompatibleUpgradeOutcome::FailedBeforeActivation => {
            LifecycleResponse::failed("lifecycle.upgrade_failed_before_activation")
        }
        CompatibleUpgradeOutcome::RepairRequired => {
            LifecycleResponse::failed("lifecycle.upgrade_repair_required")
        }
        CompatibleUpgradeOutcome::InstallStateInvalid => {
            LifecycleResponse::failed("lifecycle.install_state_invalid")
        }
    }
}

struct VerifiedMutationPlan {
    stage: VerifiedProbeUpgradeStage,
    expected_source: InstalledUpgradeBinding,
    consumed: UpgradeAttempt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompatibleUpgradeOutcome {
    Activated,
    FailedBeforeActivation,
    RepairRequired,
    InstallStateInvalid,
}

mod mechanics {
    use super::*;

    pub(super) fn execute(
        mut plan: VerifiedMutationPlan,
        paths: &FixedInstallPaths,
        systemd: &mut impl super::super::SystemdPort,
    ) -> CompatibleUpgradeOutcome {
        execute_verified_components(
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
            paths,
            systemd,
        )
    }

    pub(super) fn execute_verified_components(
        components: VerifiedUpgradeComponents<'_>,
        bundle: &crate::verifier::VerifiedBundle,
        expected_source: &InstalledUpgradeBinding,
        consumed: &UpgradeAttempt,
        paths: &FixedInstallPaths,
        systemd: &mut impl super::super::SystemdPort,
    ) -> CompatibleUpgradeOutcome {
        let result = upgrade_current_probe_for_operation(
            components,
            bundle,
            expected_source,
            consumed,
            paths,
            systemd,
        );
        match result {
            Ok(UpgradeCompletion::Activated) => {
                match recover_incomplete_probe_upgrade(paths, systemd) {
                    Ok(Some(receipt))
                        if receipt.activated()
                            && remove_verified_probe_upgrade_stage(
                                receipt.operation_id(),
                                receipt.stage_owner_uid(),
                            )
                            .is_ok()
                            && finalize_probe_upgrade_stage_cleanup(paths, &receipt).is_ok() =>
                    {
                        CompatibleUpgradeOutcome::Activated
                    }
                    _ => CompatibleUpgradeOutcome::RepairRequired,
                }
            }
            Ok(UpgradeCompletion::RepairRequired) => CompatibleUpgradeOutcome::RepairRequired,
            Err(UpgradeOperationFailure::CustodyRejected(_)) => {
                CompatibleUpgradeOutcome::InstallStateInvalid
            }
            Err(UpgradeOperationFailure::Failed(_)) => {
                match recover_incomplete_probe_upgrade(paths, systemd) {
                    Ok(Some(receipt))
                        if !receipt.activated()
                            && remove_verified_probe_upgrade_stage(
                                receipt.operation_id(),
                                receipt.stage_owner_uid(),
                            )
                            .is_ok()
                            && finalize_probe_upgrade_stage_cleanup(paths, &receipt).is_ok() =>
                    {
                        CompatibleUpgradeOutcome::FailedBeforeActivation
                    }
                    _ => CompatibleUpgradeOutcome::RepairRequired,
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) struct RealMechanicsForTest<'a, S> {
    pub(super) components: Option<VerifiedUpgradeComponents<'a>>,
    pub(super) bundle: &'a crate::verifier::VerifiedBundle,
    pub(super) expected_source: &'a InstalledUpgradeBinding,
    pub(super) consumed: &'a UpgradeAttempt,
    pub(super) paths: &'a FixedInstallPaths,
    pub(super) systemd: &'a mut S,
}

#[cfg(test)]
impl<S: super::SystemdPort> CompatibleUpgradeHost for RealMechanicsForTest<'_, S> {
    type Consumed = ();
    type Plan = ();

    fn now_ms(&self) -> Result<u128, ()> {
        Ok(0)
    }

    fn admit(
        &mut self,
        admission: CompatibleUpgradeAdmission<'_>,
    ) -> Result<Self::Plan, CompatibleUpgradeAdmissionFailure<Self::Consumed>> {
        (admission.authority.operation_id == self.consumed.operation_id
            && admission.authority.stage_owner_uid == self.consumed.stage_owner_uid
            && admission.authority.hub_origin == self.expected_source.hub_origin
            && admission.authority.probe_id == self.expected_source.probe_id
            && admission.authority.source_bundle_version
                == self.expected_source.source_bundle_version
            && admission.authority.source_install_state_sha256
                == self.expected_source.source_install_state_sha256
            && admission.authority.source_manifest_sha256
                == self.expected_source.source_manifest_sha256
            && admission.authority.target_bundle_version == self.bundle.version
            && admission.authority.target_manifest_sha256 == self.bundle.manifest_sha256)
            .then_some(())
            .ok_or(CompatibleUpgradeAdmissionFailure::Consumed)
    }

    fn cleanup_failed_admission(&mut self, _: &Self::Consumed, _: &str, _: u32) -> bool {
        false
    }

    fn execute(&mut self, _: Self::Plan) -> CompatibleUpgradeOutcome {
        mechanics::execute_verified_components(
            self.components
                .take()
                .expect("production mechanics runs once"),
            self.bundle,
            self.expected_source,
            self.consumed,
            self.paths,
            self.systemd,
        )
    }
}

#[cfg(test)]
pub(super) fn run_compatible_upgrade_with_real_mechanics_for_test(
    request: &LifecycleRequest,
    peer_uid: u32,
    host: &mut RealMechanicsForTest<'_, impl super::SystemdPort>,
) -> LifecycleResponse {
    run_compatible_upgrade_with_host(request, Some(peer_uid), host)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DeterministicHost {
        now_ms: u128,
        admission_attempted: bool,
        admission_failure: Option<CompatibleUpgradeAdmissionRejection>,
        cleanup_calls: Vec<(String, u32)>,
        cleanup_succeeds: bool,
        outcome: CompatibleUpgradeOutcome,
        execute_calls: usize,
        admitted_binding: Option<(String, String, String, u32)>,
    }

    impl CompatibleUpgradeHost for DeterministicHost {
        type Consumed = ();
        type Plan = ();

        fn now_ms(&self) -> Result<u128, ()> {
            Ok(self.now_ms)
        }

        fn admit(
            &mut self,
            admission: CompatibleUpgradeAdmission<'_>,
        ) -> Result<Self::Plan, CompatibleUpgradeAdmissionFailure<Self::Consumed>> {
            self.admission_attempted = true;
            self.admitted_binding = Some((
                admission.authority.operation_id,
                admission.authority.source_bundle_version,
                admission.receipt.target_version,
                admission.authority.stage_owner_uid,
            ));
            match self.admission_failure {
                Some(rejection) => Err(
                    CompatibleUpgradeAdmissionFailure::RejectedAfterConsumption {
                        consumed: (),
                        rejection,
                    },
                ),
                None => Ok(()),
            }
        }

        fn cleanup_failed_admission(
            &mut self,
            _: &Self::Consumed,
            operation_id: &str,
            stage_owner_uid: u32,
        ) -> bool {
            self.cleanup_calls
                .push((operation_id.to_owned(), stage_owner_uid));
            self.cleanup_succeeds
        }

        fn execute(&mut self, _: Self::Plan) -> CompatibleUpgradeOutcome {
            self.execute_calls += 1;
            self.outcome
        }
    }

    fn upgrade_request(expires_at_ms: u64) -> LifecycleRequest {
        LifecycleRequest::hub_upgrade(
            "https://hub.example",
            "host_01",
            "probe_01",
            "operation_01",
            "1.2.2",
            &"a".repeat(64),
            &"b".repeat(64),
            "1.2.3",
            &format!("sha256:{}", "c".repeat(64)),
            &"d".repeat(64),
            &"e".repeat(64),
            expires_at_ms,
            "signed-authority",
        )
        .expect("测试升级授权有效")
    }

    #[test]
    fn expired_authority_is_rejected_before_host_admission() {
        let mut host = DeterministicHost {
            now_ms: 1_800_000_000_001,
            admission_attempted: false,
            admission_failure: None,
            cleanup_calls: Vec::new(),
            cleanup_succeeds: true,
            outcome: CompatibleUpgradeOutcome::Activated,
            execute_calls: 0,
            admitted_binding: None,
        };

        let response = run_compatible_upgrade_with_host(
            &upgrade_request(1_800_000_000_000),
            Some(1000),
            &mut host,
        );

        assert_eq!(
            response,
            LifecycleResponse::failed("lifecycle.invalid_authority")
        );
        assert!(!host.admission_attempted);
    }

    #[test]
    fn source_mismatch_runs_preactivation_cleanup_before_returning_refusal() {
        let mut host = DeterministicHost {
            now_ms: 1_799_999_999_999,
            admission_attempted: false,
            admission_failure: Some(CompatibleUpgradeAdmissionRejection::AuthorityMismatch),
            cleanup_calls: Vec::new(),
            cleanup_succeeds: true,
            outcome: CompatibleUpgradeOutcome::Activated,
            execute_calls: 0,
            admitted_binding: None,
        };

        let response = run_compatible_upgrade_with_host(
            &upgrade_request(1_800_000_000_000),
            Some(1000),
            &mut host,
        );

        assert_eq!(
            response,
            LifecycleResponse::failed("lifecycle.authority_mismatch")
        );
        assert_eq!(host.cleanup_calls, [("operation_01".to_owned(), 1000)]);
        assert_eq!(
            host.admitted_binding,
            Some((
                "operation_01".to_owned(),
                "1.2.2".to_owned(),
                "1.2.3".to_owned(),
                1000,
            ))
        );
    }

    #[test]
    fn mechanics_outcomes_map_to_the_existing_lifecycle_contract() {
        for (outcome, expected) in [
            (
                CompatibleUpgradeOutcome::Activated,
                LifecycleResponse::succeeded(),
            ),
            (
                CompatibleUpgradeOutcome::FailedBeforeActivation,
                LifecycleResponse::failed("lifecycle.upgrade_failed_before_activation"),
            ),
            (
                CompatibleUpgradeOutcome::RepairRequired,
                LifecycleResponse::failed("lifecycle.upgrade_repair_required"),
            ),
            (
                CompatibleUpgradeOutcome::InstallStateInvalid,
                LifecycleResponse::failed("lifecycle.install_state_invalid"),
            ),
        ] {
            let mut host = DeterministicHost {
                now_ms: 1_799_999_999_999,
                admission_attempted: false,
                admission_failure: None,
                cleanup_calls: Vec::new(),
                cleanup_succeeds: true,
                outcome,
                execute_calls: 0,
                admitted_binding: None,
            };

            assert_eq!(
                run_compatible_upgrade_with_host(
                    &upgrade_request(1_800_000_000_000),
                    Some(1000),
                    &mut host,
                ),
                expected
            );
            assert_eq!(host.execute_calls, 1);
        }
    }

    #[test]
    fn production_entry_constructs_the_fixed_host_adapters() {
        let constructions_before = production_host_constructions();

        assert_eq!(
            run_compatible_upgrade(&upgrade_request(1), Some(unsafe { libc::geteuid() }),),
            LifecycleResponse::failed("lifecycle.invalid_authority")
        );

        assert_eq!(production_host_constructions(), constructions_before + 1);
    }
}
