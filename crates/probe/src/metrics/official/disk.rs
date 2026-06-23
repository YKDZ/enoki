use std::fs;

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, DiskCounterSnapshot,
    MetricCollector, collect_disk_counters_from_proc_diskstats, collect_disk_metrics_from_mounts,
    filesystem_capacity,
};
use crate::protocol::enoki::v1::MetricSample;

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Disk, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct DiskMetricCollector {
    previous: Option<DiskCounterSnapshot>,
}

impl MetricCollector for DiskMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        let disk_counters = fs::read_to_string("/proc/diskstats")
            .ok()
            .and_then(|contents| collect_disk_counters_from_proc_diskstats(&contents));
        let disks = fs::read_to_string("/proc/mounts")
            .map(|contents| {
                collect_disk_metrics_from_mounts(
                    &contents,
                    |mount_point| filesystem_capacity(mount_point),
                    disk_counters.as_ref(),
                    self.previous.as_ref(),
                )
            })
            .unwrap_or_default();
        if let Some(snapshot) = disk_counters {
            self.previous = Some(snapshot);
        }
        let produced = !disks.is_empty();
        sample.disks = disks;

        Ok(produced)
    }
}
