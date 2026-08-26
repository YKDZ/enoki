//! 构建期固定的探针安装包角色合同。

pub(crate) const PROBE_PERMISSION_PROFILE: &str = "probe-v5";
pub(crate) const OBSERVATION_RUNTIME_PERMISSION_PROFILE: &str = "observation-runtime-v4";
pub(crate) const SYSTEM_STATE_PERMISSION_PROFILE: &str = "system-state-provider-v5";
pub(crate) const DISK_HEALTH_PERMISSION_PROFILE: &str = "disk-health-provider-v3";
pub(crate) const LIFECYCLE_COMPANION_PERMISSION_PROFILE: &str = "lifecycle-companion-v3";

pub(crate) const BUNDLE_COMPONENTS: [(&str, &str, &str, &str); 5] = [
    (
        "enoki-probe",
        PROBE_PERMISSION_PROFILE,
        "hub-reporting-v1",
        "probe",
    ),
    (
        "enoki-observation-runtime",
        OBSERVATION_RUNTIME_PERMISSION_PROFILE,
        "official-observation-v2",
        "observation-runtime",
    ),
    (
        "enoki-cpu-resource-provider",
        SYSTEM_STATE_PERMISSION_PROFILE,
        "system-state-v3",
        "system-state-provider",
    ),
    (
        "enoki-disk-health-resource-provider",
        DISK_HEALTH_PERMISSION_PROFILE,
        "disk-health-v1",
        "disk-health-provider",
    ),
    (
        "enoki-probe-lifecycle-companion",
        LIFECYCLE_COMPANION_PERMISSION_PROFILE,
        "local-lifecycle-v1",
        "lifecycle-companion",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bundle_closes_over_the_independent_lifecycle_companion() {
        assert_eq!(BUNDLE_COMPONENTS.len(), 5);
        assert!(BUNDLE_COMPONENTS.contains(&(
            "enoki-probe-lifecycle-companion",
            "lifecycle-companion-v3",
            "local-lifecycle-v1",
            "lifecycle-companion",
        )));
    }
}
