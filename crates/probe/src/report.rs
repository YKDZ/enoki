use crate::{
    inventory::{host_profile_from_inventory, host_profile_hash, inventory_hash},
    protocol::enoki::v1::{
        HostProfileSnapshot, Inventory, MetricSample, ProbeReportRequest, Snapshot, snapshot,
    },
};

const HOST_PROFILE_COLLECTOR_ID: &str = "official.host-profile";

pub trait HostProfileSnapshotSource {
    fn host_profile_snapshot(&self) -> HostProfileSnapshot;

    fn legacy_inventory_hash(&self) -> String;
}

impl HostProfileSnapshotSource for Inventory {
    fn host_profile_snapshot(&self) -> HostProfileSnapshot {
        host_profile_from_inventory(self.clone())
    }

    fn legacy_inventory_hash(&self) -> String {
        inventory_hash(self)
    }
}

impl HostProfileSnapshotSource for HostProfileSnapshot {
    fn host_profile_snapshot(&self) -> HostProfileSnapshot {
        self.clone()
    }

    fn legacy_inventory_hash(&self) -> String {
        host_profile_hash(self)
    }
}

pub fn startup_report(
    probe_id: &str,
    boot_id: &str,
    sequence: u64,
    probe_configuration_version: &str,
    inventory: Inventory,
    metrics: Vec<MetricSample>,
) -> ProbeReportRequest {
    let inventory_hash = inventory_hash(&inventory);
    let host_profile = host_profile_from_inventory(inventory.clone());

    ProbeReportRequest {
        boot_id: boot_id.to_string(),
        inventory: Some(inventory),
        inventory_hash,
        metrics,
        operation_acknowledgements: Vec::new(),
        operation_statuses: Vec::new(),
        probe_configuration_error: None,
        probe_configuration_version: probe_configuration_version.to_string(),
        probe_id: probe_id.to_string(),
        sequence_end: sequence,
        sequence_start: sequence,
        snapshots: vec![full_host_profile_snapshot(host_profile)],
    }
}

pub fn full_inventory_report(
    probe_id: &str,
    boot_id: &str,
    sequence: u64,
    probe_configuration_version: &str,
    inventory: Inventory,
    metrics: Vec<MetricSample>,
) -> ProbeReportRequest {
    let inventory_hash = inventory_hash(&inventory);
    let host_profile = host_profile_from_inventory(inventory.clone());

    ProbeReportRequest {
        boot_id: boot_id.to_string(),
        inventory: Some(inventory),
        inventory_hash,
        metrics,
        operation_acknowledgements: Vec::new(),
        operation_statuses: Vec::new(),
        probe_configuration_error: None,
        probe_configuration_version: probe_configuration_version.to_string(),
        probe_id: probe_id.to_string(),
        sequence_end: sequence,
        sequence_start: sequence,
        snapshots: vec![full_host_profile_snapshot(host_profile)],
    }
}

pub fn regular_report(
    probe_id: &str,
    boot_id: &str,
    sequence_start: u64,
    sequence_end: u64,
    probe_configuration_version: &str,
    host_profile_source: &impl HostProfileSnapshotSource,
    metrics: Vec<MetricSample>,
) -> ProbeReportRequest {
    let host_profile = host_profile_source.host_profile_snapshot();

    ProbeReportRequest {
        boot_id: boot_id.to_string(),
        inventory: None,
        inventory_hash: host_profile_source.legacy_inventory_hash(),
        metrics,
        operation_acknowledgements: Vec::new(),
        operation_statuses: Vec::new(),
        probe_configuration_error: None,
        probe_configuration_version: probe_configuration_version.to_string(),
        probe_id: probe_id.to_string(),
        sequence_end,
        sequence_start,
        snapshots: vec![hash_only_host_profile_snapshot(&host_profile)],
    }
}

pub fn full_host_profile_snapshot(host_profile: HostProfileSnapshot) -> Snapshot {
    Snapshot {
        collector_id: HOST_PROFILE_COLLECTOR_ID.to_string(),
        snapshot_hash: host_profile_hash(&host_profile),
        payload: Some(snapshot::Payload::HostProfile(host_profile)),
    }
}

pub fn hash_only_host_profile_snapshot(host_profile: &HostProfileSnapshot) -> Snapshot {
    Snapshot {
        collector_id: HOST_PROFILE_COLLECTOR_ID.to_string(),
        snapshot_hash: host_profile_hash(host_profile),
        payload: None,
    }
}
