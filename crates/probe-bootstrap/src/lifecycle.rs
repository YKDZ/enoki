//! 探针本机生命周期的封闭领域合同。

use serde::{Deserialize, Serialize};

pub const MAX_LIFECYCLE_REQUEST_BYTES: usize = 8 * 1024;
pub const MAX_OPERATION_TOKEN_BYTES: usize = 2 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleTransition {
    FreshInstall,
    Upgrade,
    Repair,
    ReplacementMigration,
    Uninstall,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleRequest {
    schema_version: u16,
    transition: LifecycleTransition,
    authority: LifecycleRequestAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LifecycleRequestAuthority {
    HubOperation {
        probe_id: String,
        operation_id: String,
        operation_token: String,
        install_state_sha256: String,
        target_manifest_sha256: String,
        bundle_version: String,
    },
    LocalRoot {
        probe_id: String,
        install_state_sha256: String,
        target_manifest_sha256: String,
        bundle_version: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleResultStatus {
    Succeeded,
    Failed,
    NotEnabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleResponse {
    schema_version: u16,
    status: LifecycleResultStatus,
    code: String,
}

impl LifecycleResponse {
    #[must_use]
    pub fn succeeded() -> Self {
        Self {
            schema_version: 1,
            status: LifecycleResultStatus::Succeeded,
            code: "lifecycle.succeeded".to_owned(),
        }
    }

    #[must_use]
    pub fn recovery_pending() -> Self {
        Self {
            schema_version: 1,
            status: LifecycleResultStatus::Succeeded,
            code: "lifecycle.recovery_pending".to_owned(),
        }
    }

    #[must_use]
    pub fn failed(code: &str) -> Self {
        Self {
            schema_version: 1,
            status: LifecycleResultStatus::Failed,
            code: bounded_result_code(code),
        }
    }

    #[must_use]
    pub fn not_enabled() -> Self {
        Self {
            schema_version: 1,
            status: LifecycleResultStatus::NotEnabled,
            code: LifecycleRejection::TransitionNotEnabled.code().to_owned(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("固定 Lifecycle Response 可序列化")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleRejection> {
        if bytes.is_empty() || bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        let response: Self =
            serde_json::from_slice(bytes).map_err(|_| LifecycleRejection::InvalidAuthority)?;
        if response.schema_version != 1
            || response.encode().as_slice() != bytes
            || bounded_result_code(&response.code) != response.code
        {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        Ok(response)
    }

    #[must_use]
    pub const fn status(&self) -> LifecycleResultStatus {
        self.status
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

fn bounded_result_code(code: &str) -> String {
    if (1..=96).contains(&code.len())
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        code.to_owned()
    } else {
        "lifecycle.failed".to_owned()
    }
}

impl LifecycleRequest {
    pub fn hub_uninstall(
        probe_id: &str,
        operation_id: &str,
        operation_token: &str,
        install_state_sha256: &str,
        target_manifest_sha256: &str,
        bundle_version: &str,
    ) -> Result<Self, LifecycleRejection> {
        let request = Self {
            schema_version: 1,
            transition: LifecycleTransition::Uninstall,
            authority: LifecycleRequestAuthority::HubOperation {
                probe_id: probe_id.to_owned(),
                operation_id: operation_id.to_owned(),
                operation_token: operation_token.to_owned(),
                install_state_sha256: install_state_sha256.to_owned(),
                target_manifest_sha256: target_manifest_sha256.to_owned(),
                bundle_version: bundle_version.to_owned(),
            },
        };
        request.validate()?;
        Ok(request)
    }

    pub fn local_uninstall(
        probe_id: &str,
        install_state_sha256: &str,
        target_manifest_sha256: &str,
        bundle_version: &str,
    ) -> Result<Self, LifecycleRejection> {
        let request = Self {
            schema_version: 1,
            transition: LifecycleTransition::Uninstall,
            authority: LifecycleRequestAuthority::LocalRoot {
                probe_id: probe_id.to_owned(),
                install_state_sha256: install_state_sha256.to_owned(),
                target_manifest_sha256: target_manifest_sha256.to_owned(),
                bundle_version: bundle_version.to_owned(),
            },
        };
        request.validate()?;
        Ok(request)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleRejection> {
        if bytes.is_empty() || bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| LifecycleRejection::InvalidAuthority)?;
        request.validate()?;
        if request.encode()?.as_slice() != bytes {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        Ok(request)
    }

    pub fn encode(&self) -> Result<Vec<u8>, LifecycleRejection> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| LifecycleRejection::InvalidAuthority)?;
        if bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), LifecycleRejection> {
        if self.schema_version != 1 {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        let (probe_id, install_state, manifest, version) = match &self.authority {
            LifecycleRequestAuthority::HubOperation {
                probe_id,
                operation_id,
                operation_token,
                install_state_sha256,
                target_manifest_sha256,
                bundle_version,
            } => {
                if !valid_identifier(operation_id)
                    || operation_token.is_empty()
                    || operation_token.len() > MAX_OPERATION_TOKEN_BYTES
                    || operation_token.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(LifecycleRejection::InvalidAuthority);
                }
                (
                    probe_id,
                    install_state_sha256,
                    target_manifest_sha256,
                    bundle_version,
                )
            }
            LifecycleRequestAuthority::LocalRoot {
                probe_id,
                install_state_sha256,
                target_manifest_sha256,
                bundle_version,
            } => (
                probe_id,
                install_state_sha256,
                target_manifest_sha256,
                bundle_version,
            ),
        };
        if !valid_identifier(probe_id)
            || !is_sha256_hex(install_state)
            || !is_sha256_hex(manifest)
            || !valid_bundle_version(version)
        {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        Ok(())
    }

    #[must_use]
    pub const fn transition(&self) -> LifecycleTransition {
        self.transition
    }

    #[must_use]
    pub const fn authority(&self) -> &LifecycleRequestAuthority {
        &self.authority
    }
}

impl LifecycleTransition {
    pub const ALL: [Self; 5] = [
        Self::FreshInstall,
        Self::Upgrade,
        Self::Repair,
        Self::ReplacementMigration,
        Self::Uninstall,
    ];

    #[must_use]
    pub const fn availability(self) -> TransitionAvailability {
        match self {
            Self::FreshInstall | Self::Uninstall => TransitionAvailability::Enabled,
            Self::Upgrade | Self::Repair | Self::ReplacementMigration => {
                TransitionAvailability::NotEnabled
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionAvailability {
    Enabled,
    NotEnabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRejection {
    InvalidAuthority,
    InvalidState,
    TransitionNotEnabled,
}

impl LifecycleRejection {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidAuthority => "lifecycle.invalid_authority",
            Self::InvalidState => "lifecycle.invalid_state",
            Self::TransitionNotEnabled => "lifecycle.transition_not_enabled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecyclePlan {
    transition: LifecycleTransition,
}

impl LifecyclePlan {
    pub fn for_transition(transition: LifecycleTransition) -> Result<Self, LifecycleRejection> {
        match transition.availability() {
            TransitionAvailability::Enabled => Ok(Self { transition }),
            TransitionAvailability::NotEnabled => Err(LifecycleRejection::TransitionNotEnabled),
        }
    }

    #[must_use]
    pub const fn transition(self) -> LifecycleTransition {
        self.transition
    }
}

/// 所有本机生命周期转换共享的有限执行状态。转换各自拥有一条固定路径，
/// 因而新装不能伪装成清理，卸载也不能进入暂存或激活阶段。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecyclePhase {
    Authorized,
    Verified,
    Staged,
    Activating,
    Cleaning,
    Reporting,
    Committing,
    Finalizing,
    Complete,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleExecution {
    transition: LifecycleTransition,
    phase: LifecyclePhase,
}

impl LifecycleExecution {
    pub fn begin(transition: LifecycleTransition) -> Result<Self, LifecycleRejection> {
        LifecyclePlan::for_transition(transition)?;
        Ok(Self {
            transition,
            phase: LifecyclePhase::Authorized,
        })
    }

    pub fn advance(&mut self, next: LifecyclePhase) -> Result<(), LifecycleRejection> {
        let valid = match (self.transition, self.phase, next) {
            (
                LifecycleTransition::FreshInstall,
                LifecyclePhase::Authorized,
                LifecyclePhase::Verified,
            )
            | (
                LifecycleTransition::FreshInstall,
                LifecyclePhase::Verified,
                LifecyclePhase::Staged,
            )
            | (
                LifecycleTransition::FreshInstall,
                LifecyclePhase::Staged,
                LifecyclePhase::Activating,
            )
            | (
                LifecycleTransition::FreshInstall,
                LifecyclePhase::Activating,
                LifecyclePhase::Complete,
            )
            | (
                LifecycleTransition::Uninstall,
                LifecyclePhase::Authorized,
                LifecyclePhase::Verified,
            )
            | (
                LifecycleTransition::Uninstall,
                LifecyclePhase::Verified,
                LifecyclePhase::Cleaning,
            )
            | (
                LifecycleTransition::Uninstall,
                LifecyclePhase::Cleaning,
                LifecyclePhase::Reporting,
            )
            | (
                LifecycleTransition::Uninstall,
                LifecyclePhase::Reporting,
                LifecyclePhase::Committing,
            )
            | (
                LifecycleTransition::Uninstall,
                LifecyclePhase::Committing,
                LifecyclePhase::Finalizing,
            )
            | (
                LifecycleTransition::Uninstall,
                LifecyclePhase::Finalizing,
                LifecyclePhase::Complete,
            ) => true,
            (_, phase, LifecyclePhase::Failed)
                if !matches!(phase, LifecyclePhase::Complete | LifecyclePhase::Failed) =>
            {
                true
            }
            _ => false,
        };
        if !valid {
            return Err(LifecycleRejection::InvalidState);
        }
        self.phase = next;
        Ok(())
    }

    #[must_use]
    pub const fn phase(self) -> LifecyclePhase {
        self.phase
    }

    /// 由状态机进入阶段后立即执行对应副作用；任一阶段失败都在返回前封闭为
    /// `Failed`，后续阶段不会被调用。
    pub fn run_uninstall<E>(
        &mut self,
        mut execute: impl FnMut(LifecyclePhase) -> Result<(), E>,
    ) -> Result<(), E> {
        for phase in [
            LifecyclePhase::Verified,
            LifecyclePhase::Cleaning,
            LifecyclePhase::Reporting,
            LifecyclePhase::Committing,
            LifecyclePhase::Finalizing,
        ] {
            self.advance(phase)
                .expect("固定卸载阶段序列必须符合封闭状态机");
            if let Err(error) = execute(phase) {
                self.advance(LifecyclePhase::Failed)
                    .expect("非终态卸载可封闭为失败");
                return Err(error);
            }
        }
        self.advance(LifecyclePhase::Complete)
            .expect("固定卸载 finalization 后可提交完成");
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_bundle_version(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_registry_keeps_only_fresh_install_and_uninstall_enabled() {
        assert_eq!(LifecycleTransition::ALL.len(), 5);
        assert_eq!(
            LifecycleTransition::FreshInstall.availability(),
            TransitionAvailability::Enabled
        );
        assert_eq!(
            LifecycleTransition::Uninstall.availability(),
            TransitionAvailability::Enabled
        );
        for transition in [
            LifecycleTransition::Upgrade,
            LifecycleTransition::Repair,
            LifecycleTransition::ReplacementMigration,
        ] {
            assert_eq!(
                transition.availability(),
                TransitionAvailability::NotEnabled
            );
        }
    }

    #[test]
    fn disabled_transitions_return_one_stable_result_before_planning() {
        for transition in [
            LifecycleTransition::Upgrade,
            LifecycleTransition::Repair,
            LifecycleTransition::ReplacementMigration,
        ] {
            assert_eq!(
                LifecyclePlan::for_transition(transition),
                Err(LifecycleRejection::TransitionNotEnabled),
            );
        }
    }

    #[test]
    fn lifecycle_request_round_trip_is_canonical_and_bound_to_fixed_authority_facts() {
        let request = LifecycleRequest::hub_uninstall(
            "probe_01",
            "operation_01",
            "opaque-operation-token",
            &"a".repeat(64),
            &"b".repeat(64),
            "1.2.3",
        )
        .expect("授权事实有效");
        let encoded = request.encode().expect("编码");

        assert_eq!(LifecycleRequest::decode(&encoded), Ok(request));
    }

    #[test]
    fn lifecycle_request_rejects_unbound_or_noncanonical_authority() {
        let invalid = format!(
            "{{\"schemaVersion\":1,\"transition\":\"uninstall\",\"authority\":{{\"kind\":\"hub-operation\",\"probe_id\":\"probe_01\",\"operationId\":\"operation_01\",\"operationToken\":\"token\",\"installStateSha256\":\"{}\",\"targetManifestSha256\":\"{}\",\"bundleVersion\":\"1.2.3\"}}}}",
            "a".repeat(64),
            "b".repeat(64),
        );
        assert_eq!(
            LifecycleRequest::decode(invalid.as_bytes()),
            Err(LifecycleRejection::InvalidAuthority),
        );
    }

    #[test]
    fn enabled_transitions_share_one_closed_execution_state_machine() {
        let mut install =
            LifecycleExecution::begin(LifecycleTransition::FreshInstall).expect("新装已启用");
        assert_eq!(install.phase(), LifecyclePhase::Authorized);
        for phase in [
            LifecyclePhase::Verified,
            LifecyclePhase::Staged,
            LifecyclePhase::Activating,
            LifecyclePhase::Complete,
        ] {
            install.advance(phase).expect("新装状态合法");
        }

        let mut uninstall =
            LifecycleExecution::begin(LifecycleTransition::Uninstall).expect("卸载已启用");
        for phase in [
            LifecyclePhase::Verified,
            LifecyclePhase::Cleaning,
            LifecyclePhase::Reporting,
            LifecyclePhase::Committing,
            LifecyclePhase::Finalizing,
            LifecyclePhase::Complete,
        ] {
            uninstall.advance(phase).expect("卸载状态合法");
        }
    }

    #[test]
    fn lifecycle_execution_rejects_cross_transition_phase_disguise() {
        let mut install =
            LifecycleExecution::begin(LifecycleTransition::FreshInstall).expect("新装已启用");
        assert_eq!(
            install.advance(LifecyclePhase::Cleaning),
            Err(LifecycleRejection::InvalidState),
        );
        let mut uninstall =
            LifecycleExecution::begin(LifecycleTransition::Uninstall).expect("卸载已启用");
        assert_eq!(
            uninstall.advance(LifecyclePhase::Staged),
            Err(LifecycleRejection::InvalidState),
        );
    }

    #[test]
    fn uninstall_runner_stops_at_the_exact_failed_effect_phase() {
        for failed in [
            LifecyclePhase::Verified,
            LifecyclePhase::Cleaning,
            LifecyclePhase::Reporting,
            LifecyclePhase::Committing,
            LifecyclePhase::Finalizing,
        ] {
            let mut execution =
                LifecycleExecution::begin(LifecycleTransition::Uninstall).expect("卸载已启用");
            let mut observed = Vec::new();
            let result = execution.run_uninstall(|phase| {
                observed.push(phase);
                (phase != failed).then_some(()).ok_or("stage-failed")
            });

            assert_eq!(result, Err("stage-failed"));
            assert_eq!(observed.last(), Some(&failed));
            assert_eq!(execution.phase(), LifecyclePhase::Failed);
        }
    }
}
