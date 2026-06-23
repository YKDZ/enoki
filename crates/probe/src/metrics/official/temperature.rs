use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
    collect_temperature_celsius_from_sysfs,
};
use crate::protocol::enoki::v1::MetricSample;

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Temperature, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct TemperatureMetricCollector;

impl MetricCollector for TemperatureMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        let Some(temperature_celsius) = collect_temperature_celsius_from_sysfs("/sys/class/hwmon")
        else {
            return Ok(false);
        };

        sample.temperature_celsius = Some(temperature_celsius);

        Ok(true)
    }
}
