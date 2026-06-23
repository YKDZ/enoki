use crate::metrics::{
    CollectorCadenceClass, CollectorError, MetricCollector, MetricsCollectionConfig,
    collect_battery_metrics_from_sysfs,
};
use crate::protocol::enoki::v1::MetricSample;

#[derive(Default)]
pub struct BatteryMetricCollector;

impl MetricCollector for BatteryMetricCollector {
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::HighFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        _config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        let Some(metrics) = collect_battery_metrics_from_sysfs("/sys/class/power_supply") else {
            return Ok(false);
        };

        sample.battery_percent = Some(metrics.percent);
        sample.battery_state = Some(metrics.state);

        Ok(true)
    }
}
