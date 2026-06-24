#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorOutput {
    Metrics,
    Snapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorCadence {
    EveryTick,
    Every12Ticks,
    Startup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorRequirement {
    OwnerConfigurable,
    Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorSpec {
    pub id: &'static str,
    pub output: CollectorOutput,
    pub cadence: CollectorCadence,
    pub requirement: CollectorRequirement,
}

pub const HOST_PROFILE_COLLECTOR_ID: &str = "official.host-profile";

const OFFICIAL_COLLECTOR_CATALOG: &[CollectorSpec] = &[
    CollectorSpec {
        id: HOST_PROFILE_COLLECTOR_ID,
        output: CollectorOutput::Snapshot,
        cadence: CollectorCadence::Startup,
        requirement: CollectorRequirement::Required,
    },
    owner_configurable_metrics_collector("official.cpu", CollectorCadence::EveryTick),
    owner_configurable_metrics_collector("official.memory", CollectorCadence::EveryTick),
    owner_configurable_metrics_collector("official.disk", CollectorCadence::EveryTick),
    owner_configurable_metrics_collector("official.network", CollectorCadence::EveryTick),
    owner_configurable_metrics_collector("official.load", CollectorCadence::EveryTick),
    owner_configurable_metrics_collector("official.uptime", CollectorCadence::EveryTick),
    owner_configurable_metrics_collector("official.temperature", CollectorCadence::EveryTick),
    owner_configurable_metrics_collector("official.battery", CollectorCadence::EveryTick),
    owner_configurable_metrics_collector("official.disk-health", CollectorCadence::Every12Ticks),
];

const fn owner_configurable_metrics_collector(
    id: &'static str,
    cadence: CollectorCadence,
) -> CollectorSpec {
    CollectorSpec {
        id,
        output: CollectorOutput::Metrics,
        cadence,
        requirement: CollectorRequirement::OwnerConfigurable,
    }
}

pub fn official_collector_catalog() -> &'static [CollectorSpec] {
    OFFICIAL_COLLECTOR_CATALOG
}

pub fn owner_configurable_collector_ids() -> Vec<&'static str> {
    OFFICIAL_COLLECTOR_CATALOG
        .iter()
        .filter(|collector| collector.requirement == CollectorRequirement::OwnerConfigurable)
        .map(|collector| collector.id)
        .collect()
}

pub fn is_owner_configurable_collector_id(id: &str) -> bool {
    OFFICIAL_COLLECTOR_CATALOG.iter().any(|collector| {
        collector.id == id && collector.requirement == CollectorRequirement::OwnerConfigurable
    })
}

pub fn required_collector_ids() -> Vec<&'static str> {
    OFFICIAL_COLLECTOR_CATALOG
        .iter()
        .filter(|collector| collector.requirement == CollectorRequirement::Required)
        .map(|collector| collector.id)
        .collect()
}
