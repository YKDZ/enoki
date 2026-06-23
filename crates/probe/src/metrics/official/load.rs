use std::fs;

use crate::metrics::{
    CollectorCadenceClass, CollectorError, MetricCollector, MetricsCollectionConfig,
    collect_load_metrics_from_proc_loadavg,
};
use crate::protocol::enoki::v1::MetricSample;

#[derive(Default)]
pub struct LoadMetricCollector;

impl MetricCollector for LoadMetricCollector {
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::HighFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        if !config.collect_load {
            return Ok(false);
        }

        let Some(metrics) = fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|contents| collect_load_metrics_from_proc_loadavg(&contents))
        else {
            return Ok(false);
        };

        sample.load_1 = Some(metrics.one);
        sample.load_5 = Some(metrics.five);
        sample.load_15 = Some(metrics.fifteen);

        Ok(true)
    }
}
