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
    ReplacementEnrollment {
        enrollment_token: String,
        hub_origin: String,
        target_asset_set_digest: String,
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

    pub fn replacement_migration(
        enrollment_token: &str,
        hub_origin: &str,
        target_asset_set_digest: &str,
        target_manifest_sha256: &str,
        bundle_version: &str,
    ) -> Result<Self, LifecycleRejection> {
        let request = Self {
            schema_version: 1,
            transition: LifecycleTransition::ReplacementMigration,
            authority: LifecycleRequestAuthority::ReplacementEnrollment {
                enrollment_token: enrollment_token.to_owned(),
                hub_origin: hub_origin.to_owned(),
                target_asset_set_digest: target_asset_set_digest.to_owned(),
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
            LifecycleRequestAuthority::ReplacementEnrollment {
                enrollment_token,
                hub_origin,
                target_asset_set_digest,
                target_manifest_sha256,
                bundle_version,
            } => {
                if self.transition != LifecycleTransition::ReplacementMigration
                    || enrollment_token.is_empty()
                    || enrollment_token.len() > MAX_OPERATION_TOKEN_BYTES
                    || enrollment_token.bytes().any(|byte| byte.is_ascii_control())
                    || !valid_hub_origin(hub_origin)
                    || !is_prefixed_sha256(target_asset_set_digest)
                    || !is_sha256_hex(target_manifest_sha256)
                    || !valid_bundle_version(bundle_version)
                {
                    return Err(LifecycleRejection::InvalidAuthority);
                }
                return Ok(());
            }
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
            Self::FreshInstall | Self::ReplacementMigration | Self::Uninstall => {
                TransitionAvailability::Enabled
            }
            Self::Upgrade | Self::Repair => TransitionAvailability::NotEnabled,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleCompletion {
    Complete,
    RecoveryPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UninstallCommitPolicy {
    Local,
    HubTerminal,
}

pub trait FreshInstallLifecycleEffects {
    type Error;

    fn verify(&mut self) -> Result<(), Self::Error>;
    fn stage_and_activate(&mut self) -> Result<(), Self::Error>;
}

pub fn execute_fresh_install_lifecycle<E: FreshInstallLifecycleEffects>(
    effects: &mut E,
) -> Result<(), E::Error> {
    LifecyclePlan::for_transition(LifecycleTransition::FreshInstall)
        .expect("构建期固定的新装转换必须保持启用");
    effects.verify()?;
    effects.stage_and_activate()
}

pub trait UninstallLifecycleEffects {
    type Error;

    fn verify(&mut self) -> Result<(), Self::Error>;
    fn clean(&mut self) -> Result<(), Self::Error>;
    fn report(&mut self) -> Result<(), Self::Error>;
    fn commit(&mut self) -> Result<(), Self::Error>;
    fn finalize(&mut self) -> Result<(), Self::Error>;
}

pub fn execute_uninstall_lifecycle<E: UninstallLifecycleEffects>(
    effects: &mut E,
    commit_policy: UninstallCommitPolicy,
) -> Result<LifecycleCompletion, E::Error> {
    effects.verify()?;
    effects.clean()?;
    effects.report()?;
    if let Err(error) = effects.commit() {
        return if commit_policy == UninstallCommitPolicy::HubTerminal {
            Ok(LifecycleCompletion::RecoveryPending)
        } else {
            Err(error)
        };
    }
    match effects.finalize() {
        Ok(()) => Ok(LifecycleCompletion::Complete),
        Err(_) if commit_policy == UninstallCommitPolicy::HubTerminal => {
            Ok(LifecycleCompletion::RecoveryPending)
        }
        Err(error) => Err(error),
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

fn is_prefixed_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_sha256_hex)
}

fn valid_hub_origin(value: &str) -> bool {
    crate::handoff::normalize_hub_origin(value).as_deref() == Some(value)
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
    fn transition_registry_enables_only_delivered_lifecycle_paths() {
        assert_eq!(LifecycleTransition::ALL.len(), 5);
        assert_eq!(
            LifecycleTransition::FreshInstall.availability(),
            TransitionAvailability::Enabled
        );
        assert_eq!(
            LifecycleTransition::ReplacementMigration.availability(),
            TransitionAvailability::Enabled
        );
        assert_eq!(
            LifecycleTransition::Uninstall.availability(),
            TransitionAvailability::Enabled
        );
        for transition in [LifecycleTransition::Upgrade, LifecycleTransition::Repair] {
            assert_eq!(
                transition.availability(),
                TransitionAvailability::NotEnabled
            );
        }
    }

    #[test]
    fn replacement_migration_authority_roundtrips_as_one_bounded_request() {
        let request = LifecycleRequest::replacement_migration(
            "enk_enroll_test",
            "https://hub.example",
            &format!("sha256:{}", "a".repeat(64)),
            &"b".repeat(64),
            "1.2.3",
        )
        .unwrap();
        let encoded = request.encode().unwrap();

        assert!(encoded.len() <= MAX_LIFECYCLE_REQUEST_BYTES);
        assert_eq!(LifecycleRequest::decode(&encoded), Ok(request));
    }

    #[test]
    fn disabled_transitions_return_one_stable_result_before_planning() {
        for transition in [LifecycleTransition::Upgrade, LifecycleTransition::Repair] {
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
    fn fresh_install_runner_executes_one_enabled_typed_effect() {
        struct Effects(Vec<&'static str>);
        impl FreshInstallLifecycleEffects for Effects {
            type Error = &'static str;
            fn verify(&mut self) -> Result<(), Self::Error> {
                self.0.push("verify");
                Ok(())
            }
            fn stage_and_activate(&mut self) -> Result<(), Self::Error> {
                self.0.push("stage-and-activate");
                Ok(())
            }
        }
        let mut effects = Effects(Vec::new());
        let result = execute_fresh_install_lifecycle(&mut effects);
        assert_eq!(result, Ok(()));
        assert_eq!(effects.0, ["verify", "stage-and-activate"]);
    }

    #[test]
    fn uninstall_runner_owns_effect_order_and_terminal_commit_policy() {
        struct Effects {
            calls: Vec<&'static str>,
            fail: Option<&'static str>,
        }
        impl UninstallLifecycleEffects for Effects {
            type Error = &'static str;
            fn verify(&mut self) -> Result<(), Self::Error> {
                self.call("verify")
            }
            fn clean(&mut self) -> Result<(), Self::Error> {
                self.call("clean")
            }
            fn report(&mut self) -> Result<(), Self::Error> {
                self.call("report")
            }
            fn commit(&mut self) -> Result<(), Self::Error> {
                self.call("commit")
            }
            fn finalize(&mut self) -> Result<(), Self::Error> {
                self.call("finalize")
            }
        }
        impl Effects {
            fn call(&mut self, phase: &'static str) -> Result<(), &'static str> {
                self.calls.push(phase);
                (self.fail != Some(phase))
                    .then_some(())
                    .ok_or("stage-failed")
            }
        }

        for failed in ["verify", "clean", "report", "commit"] {
            let mut effects = Effects {
                calls: Vec::new(),
                fail: Some(failed),
            };
            assert_eq!(
                execute_uninstall_lifecycle(&mut effects, UninstallCommitPolicy::Local),
                Err("stage-failed")
            );
            assert_eq!(effects.calls.last(), Some(&failed));
        }
        let mut remote = Effects {
            calls: Vec::new(),
            fail: Some("finalize"),
        };
        assert_eq!(
            execute_uninstall_lifecycle(&mut remote, UninstallCommitPolicy::HubTerminal),
            Ok(LifecycleCompletion::RecoveryPending)
        );
        let mut remote_commit = Effects {
            calls: Vec::new(),
            fail: Some("commit"),
        };
        assert_eq!(
            execute_uninstall_lifecycle(&mut remote_commit, UninstallCommitPolicy::HubTerminal),
            Ok(LifecycleCompletion::RecoveryPending)
        );
        assert_eq!(remote_commit.calls.last(), Some(&"commit"));
        let mut local = Effects {
            calls: Vec::new(),
            fail: Some("finalize"),
        };
        assert_eq!(
            execute_uninstall_lifecycle(&mut local, UninstallCommitPolicy::Local),
            Err("stage-failed")
        );
    }
}
