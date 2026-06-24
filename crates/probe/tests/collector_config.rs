use enoki_probe::collectors::{
    CollectorCadence, CollectorOutput, CollectorRequirement, official_collector_catalog,
    owner_configurable_collector_ids, required_collector_ids,
};
use enoki_probe::metrics::MetricsCollectionConfig;

#[test]
fn host_profile_is_required_but_not_owner_configurable() {
    let catalog = official_collector_catalog();
    let host_profile = catalog
        .iter()
        .find(|collector| collector.id == "official.host-profile")
        .expect("Host Profile collector is registered");

    assert_eq!(host_profile.output, CollectorOutput::Snapshot);
    assert_eq!(host_profile.cadence, CollectorCadence::Startup);
    assert_eq!(host_profile.requirement, CollectorRequirement::Required);
    assert!(required_collector_ids().contains(&"official.host-profile"));
    assert!(!owner_configurable_collector_ids().contains(&"official.host-profile"));
    assert_eq!(
        owner_configurable_collector_ids(),
        MetricsCollectionConfig::all_enabled().enabled_collector_config_ids(),
    );
}
