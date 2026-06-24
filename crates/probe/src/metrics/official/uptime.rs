use std::fs;

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
};
use crate::protocol::enoki::v1::MetricSample;

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Uptime, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct UptimeMetricCollector;

impl MetricCollector for UptimeMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
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

pub fn collect_uptime_seconds_from_proc_uptime(contents: &str) -> Option<u64> {
    let uptime_seconds = contents.split_whitespace().next()?.parse::<f64>().ok()?;

    uptime_seconds.is_finite().then_some(uptime_seconds as u64)
}
