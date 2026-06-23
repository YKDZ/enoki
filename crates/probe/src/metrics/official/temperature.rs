use crate::metrics::{
    CollectorCadenceClass, CollectorError, MetricCollector, MetricsCollectionConfig,
    collect_temperature_celsius_from_sysfs,
};
use crate::protocol::enoki::v1::MetricSample;

#[derive(Default)]
pub struct TemperatureMetricCollector;

impl MetricCollector for TemperatureMetricCollector {
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::HighFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        _config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        let Some(temperature_celsius) = collect_temperature_celsius_from_sysfs("/sys/class/hwmon")
        else {
            return Ok(false);
        };

        sample.temperature_celsius = Some(temperature_celsius);

        Ok(true)
    }
}
