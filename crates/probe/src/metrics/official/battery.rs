use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
    collect_battery_metrics_from_sysfs,
};
use crate::protocol::enoki::v1::MetricSample;

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Battery, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct BatteryMetricCollector;

impl MetricCollector for BatteryMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        let Some(metrics) = collect_battery_metrics_from_sysfs("/sys/class/power_supply") else {
            return Ok(false);
        };

        sample.battery_percent = Some(metrics.percent);
        sample.battery_state = Some(metrics.state);

        Ok(true)
    }
}
