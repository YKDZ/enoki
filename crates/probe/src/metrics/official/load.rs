use std::fs;

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
};
use crate::protocol::enoki::v1::MetricSample;

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Load, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct LoadMetricCollector;

impl MetricCollector for LoadMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
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

#[derive(Debug)]
pub struct LoadMetrics {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

pub fn collect_load_metrics_from_proc_loadavg(contents: &str) -> Option<LoadMetrics> {
    let mut parts = contents.split_whitespace();

    Some(LoadMetrics {
        one: parts.next()?.parse().ok()?,
        five: parts.next()?.parse().ok()?,
        fifteen: parts.next()?.parse().ok()?,
    })
}
