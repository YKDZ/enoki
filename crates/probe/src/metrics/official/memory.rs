use std::fs;

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
    collect_memory_metrics_from_proc_meminfo,
};
use crate::protocol::enoki::v1::MetricSample;

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Memory, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct MemoryMetricCollector;

impl MetricCollector for MemoryMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        let Some(metrics) = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|contents| collect_memory_metrics_from_proc_meminfo(&contents))
        else {
            return Ok(false);
        };

        sample.memory_cache_bytes = Some(metrics.cache_bytes);
        sample.memory_total_bytes = Some(metrics.total_bytes);
        sample.memory_used_bytes = Some(metrics.used_bytes);
        sample.swap_total_bytes = Some(metrics.swap_total_bytes);
        sample.swap_used_bytes = Some(metrics.swap_used_bytes);

        Ok(true)
    }
}
