use crate::{
    inventory::inventory_hash,
    protocol::enoki::v1::{Inventory, MetricSample, ProbeReportRequest},
};

pub fn startup_report(
    probe_id: &str,
    boot_id: &str,
    sequence: u64,
    probe_configuration_version: &str,
    inventory: Inventory,
    metrics: Vec<MetricSample>,
) -> ProbeReportRequest {
    let inventory_hash = inventory_hash(&inventory);

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
    }
}

pub fn regular_report(
    probe_id: &str,
    boot_id: &str,
    sequence_start: u64,
    sequence_end: u64,
    probe_configuration_version: &str,
    inventory: &Inventory,
    metrics: Vec<MetricSample>,
) -> ProbeReportRequest {
    ProbeReportRequest {
        boot_id: boot_id.to_string(),
        inventory: None,
        inventory_hash: inventory_hash(inventory),
        metrics,
        operation_acknowledgements: Vec::new(),
        operation_statuses: Vec::new(),
        probe_configuration_error: None,
        probe_configuration_version: probe_configuration_version.to_string(),
        probe_id: probe_id.to_string(),
        sequence_end,
        sequence_start,
    }
}
