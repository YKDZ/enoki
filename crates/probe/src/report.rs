use std::collections::BTreeSet;

use crate::{
    collectors::HOST_PROFILE_COLLECTOR_ID,
    host_profile::host_profile_hash,
    protocol::enoki::v1::{
        CpuResourceCollectionOutcome, HostProfileSnapshot, MetricSample, ObservationWindowFailure,
        ProbeOperationAcknowledgement, ProbeOperationStatus, ProbeReportRequest, Snapshot,
        snapshot,
    },
};

#[derive(Debug, Default)]
pub struct OperationReportProgress {
    acknowledgements: Vec<ProbeOperationAcknowledgement>,
    statuses: Vec<ProbeOperationStatus>,
}

impl OperationReportProgress {
    pub fn from_statuses(statuses: Vec<ProbeOperationStatus>) -> Self {
        let mut operation_ids = BTreeSet::new();
        let statuses = statuses
            .into_iter()
            .filter(|status| {
                !status.operation_id.is_empty() && operation_ids.insert(status.operation_id.clone())
            })
            .collect::<Vec<_>>();
        let acknowledgements = statuses
            .iter()
            .map(|status| ProbeOperationAcknowledgement {
                operation_id: status.operation_id.clone(),
            })
            .collect();

        Self {
            acknowledgements,
            statuses,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        Vec<ProbeOperationAcknowledgement>,
        Vec<ProbeOperationStatus>,
    ) {
        (self.acknowledgements, self.statuses)
    }
}

pub struct StartupReportInput<'a> {
    pub boot_id: &'a str,
    pub enrollment_id: &'a str,
    pub operation_progress: OperationReportProgress,
    pub probe_configuration_version: &'a str,
    pub probe_id: &'a str,
}

pub struct SnapshotReplayInput<'a> {
    pub boot_id: &'a str,
    pub host_profile: HostProfileSnapshot,
    pub probe_configuration_version: &'a str,
    pub probe_id: &'a str,
    pub sequence: u64,
}

pub struct ObservationBatchInput<'a> {
    pub boot_id: &'a str,
    pub enrollment_id: &'a str,
    pub host_profile: Option<&'a HostProfileSnapshot>,
    pub host_profile_is_full: bool,
    pub metrics: Vec<MetricSample>,
    pub cpu_resource_collection_outcomes: Vec<CpuResourceCollectionOutcome>,
    pub observation_window_failure: Option<ObservationWindowFailure>,
    pub operation_progress: OperationReportProgress,
    pub probe_configuration_error: Option<crate::protocol::enoki::v1::ProbeConfigurationError>,
    pub probe_configuration_version: &'a str,
    pub probe_id: &'a str,
    pub sequence_end: u64,
    pub sequence_start: u64,
}

pub fn startup_report(input: StartupReportInput<'_>) -> ProbeReportRequest {
    let (operation_acknowledgements, operation_statuses) = input.operation_progress.into_parts();

    ProbeReportRequest {
        boot_id: input.boot_id.to_string(),
        enrollment_id: input.enrollment_id.to_string(),
        metrics: Vec::new(),
        cpu_resource_collection_outcomes: Vec::new(),
        observation_window_failure: None,
        operation_acknowledgements,
        operation_statuses,
        probe_configuration_error: None,
        probe_configuration_version: input.probe_configuration_version.to_string(),
        probe_id: input.probe_id.to_string(),
        sequence_end: 1,
        sequence_start: 1,
        snapshots: Vec::new(),
        probe_asset_bundle_version: crate::version::probe_version().to_string(),
    }
}

pub fn snapshot_replay_report(input: SnapshotReplayInput<'_>) -> ProbeReportRequest {
    ProbeReportRequest {
        boot_id: input.boot_id.to_string(),
        enrollment_id: String::new(),
        metrics: Vec::new(),
        cpu_resource_collection_outcomes: Vec::new(),
        observation_window_failure: None,
        operation_acknowledgements: Vec::new(),
        operation_statuses: Vec::new(),
        probe_configuration_error: None,
        probe_configuration_version: input.probe_configuration_version.to_string(),
        probe_id: input.probe_id.to_string(),
        sequence_end: input.sequence,
        sequence_start: input.sequence,
        snapshots: vec![full_host_profile_snapshot(input.host_profile)],
        probe_asset_bundle_version: String::new(),
    }
}

pub fn observation_batch_report(input: ObservationBatchInput<'_>) -> ProbeReportRequest {
    let (operation_acknowledgements, operation_statuses) = input.operation_progress.into_parts();

    ProbeReportRequest {
        boot_id: input.boot_id.to_string(),
        enrollment_id: input.enrollment_id.to_string(),
        metrics: input.metrics,
        cpu_resource_collection_outcomes: input.cpu_resource_collection_outcomes,
        observation_window_failure: input.observation_window_failure,
        operation_acknowledgements,
        operation_statuses,
        probe_configuration_error: input.probe_configuration_error,
        probe_configuration_version: input.probe_configuration_version.to_string(),
        probe_id: input.probe_id.to_string(),
        sequence_end: input.sequence_end,
        sequence_start: input.sequence_start,
        snapshots: input
            .host_profile
            .map(|profile| {
                if input.host_profile_is_full {
                    full_host_profile_snapshot(profile.clone())
                } else {
                    hash_only_host_profile_snapshot(profile)
                }
            })
            .into_iter()
            .collect(),
        probe_asset_bundle_version: String::new(),
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
