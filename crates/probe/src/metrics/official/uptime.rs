use std::fs;

use crate::metrics::{
    CollectorCadenceClass, CollectorError, MetricCollector, MetricsCollectionConfig,
    collect_uptime_seconds_from_proc_uptime,
};
use crate::protocol::enoki::v1::MetricSample;

#[derive(Default)]
pub struct UptimeMetricCollector;

impl MetricCollector for UptimeMetricCollector {
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::HighFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        if !config.collect_uptime {
            return Ok(false);
        }

        let Some(uptime_seconds) = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|contents| collect_uptime_seconds_from_proc_uptime(&contents))
        else {
            return Ok(false);
        };

        sample.uptime_seconds = Some(uptime_seconds);

        Ok(true)
    }
}
