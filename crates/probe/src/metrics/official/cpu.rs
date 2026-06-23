use std::fs;

use crate::metrics::{
    CollectorCadenceClass, CollectorError, CpuCounterSnapshot, MetricCollector,
    MetricsCollectionConfig, collect_cpu_metrics_from_proc_stat,
};
use crate::protocol::enoki::v1::MetricSample;

#[derive(Default)]
pub struct CpuMetricCollector {
    previous: Option<CpuCounterSnapshot>,
}

impl MetricCollector for CpuMetricCollector {
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::HighFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        if !config.collect_cpu {
            return Ok(false);
        }

        let Some(metrics) = fs::read_to_string("/proc/stat").ok().and_then(|contents| {
            collect_cpu_metrics_from_proc_stat(&contents, self.previous.as_ref())
        }) else {
            return Ok(false);
        };

        self.previous = Some(metrics.snapshot.clone());
        sample.cpu_cores = metrics.cores;
        sample.cpu_percent = Some(metrics.aggregate_percent);
        sample.cpu_idle_percent = Some(metrics.breakdown.idle_percent);
        sample.cpu_iowait_percent = Some(metrics.breakdown.iowait_percent);
        sample.cpu_steal_percent = Some(metrics.breakdown.steal_percent);
        sample.cpu_system_percent = Some(metrics.breakdown.system_percent);
        sample.cpu_user_percent = Some(metrics.breakdown.user_percent);

        Ok(true)
    }
}
