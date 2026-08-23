//! 探针本机生命周期的封闭领域合同。

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleTransition {
    FreshInstall,
    Upgrade,
    Repair,
    ReplacementMigration,
    Uninstall,
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
    TransitionNotEnabled,
}

impl LifecycleRejection {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidAuthority => "lifecycle.invalid_authority",
            Self::TransitionNotEnabled => "lifecycle.transition_not_enabled",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAuthority {
    transition: LifecycleTransition,
    host_id: Option<u64>,
    probe_id: Option<String>,
    operation_id: Option<String>,
    install_state_sha256: Option<String>,
    target_manifest_sha256: Option<String>,
    bundle_version: String,
}

impl LifecycleAuthority {
    pub fn hub_uninstall(
        host_id: u64,
        probe_id: &str,
        operation_id: &str,
        install_state_sha256: &str,
        target_manifest_sha256: &str,
        bundle_version: &str,
    ) -> Result<Self, LifecycleRejection> {
        if host_id == 0
            || !valid_identifier(probe_id)
            || !valid_identifier(operation_id)
            || !is_sha256_hex(install_state_sha256)
            || !is_sha256_hex(target_manifest_sha256)
            || !valid_bundle_version(bundle_version)
        {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        Ok(Self {
            transition: LifecycleTransition::Uninstall,
            host_id: Some(host_id),
            probe_id: Some(probe_id.to_owned()),
            operation_id: Some(operation_id.to_owned()),
            install_state_sha256: Some(install_state_sha256.to_owned()),
            target_manifest_sha256: Some(target_manifest_sha256.to_owned()),
            bundle_version: bundle_version.to_owned(),
        })
    }

    #[must_use]
    pub const fn transition(&self) -> LifecycleTransition {
        self.transition
    }

    #[must_use]
    pub const fn host_id(&self) -> Option<u64> {
        self.host_id
    }

    #[must_use]
    pub fn probe_id(&self) -> Option<&str> {
        self.probe_id.as_deref()
    }

    #[must_use]
    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_deref()
    }

    #[must_use]
    pub fn install_state_sha256(&self) -> Option<&str> {
        self.install_state_sha256.as_deref()
    }

    #[must_use]
    pub fn target_manifest_sha256(&self) -> Option<&str> {
        self.target_manifest_sha256.as_deref()
    }

    #[must_use]
    pub fn bundle_version(&self) -> &str {
        &self.bundle_version
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
    fn uninstall_authority_is_bound_only_to_identity_install_state_and_manifest_facts() {
        let install_state = "a".repeat(64);
        let target_manifest = "b".repeat(64);
        let authority = LifecycleAuthority::hub_uninstall(
            42,
            "probe_01",
            "operation_01",
            &install_state,
            &target_manifest,
            "1.2.3",
        )
        .expect("固定授权事实有效");

        assert_eq!(authority.transition(), LifecycleTransition::Uninstall);
        assert_eq!(authority.host_id(), Some(42));
        assert_eq!(authority.probe_id(), Some("probe_01"));
        assert_eq!(
            authority.install_state_sha256(),
            Some(install_state.as_str())
        );
        assert_eq!(
            authority.target_manifest_sha256(),
            Some(target_manifest.as_str())
        );
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
}
