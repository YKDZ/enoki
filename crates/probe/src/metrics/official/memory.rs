use std::fs;

use crate::metrics::{
    CollectorCadenceClass, CollectorError, MetricCollector, MetricsCollectionConfig,
    collect_memory_metrics_from_proc_meminfo,
};
use crate::protocol::enoki::v1::MetricSample;

#[derive(Default)]
pub struct MemoryMetricCollector;

impl MetricCollector for MemoryMetricCollector {
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::HighFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        if !config.collect_memory {
            return Ok(false);
        }

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
