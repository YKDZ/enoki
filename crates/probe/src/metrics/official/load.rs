use std::fs;

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
    collect_load_metrics_from_proc_loadavg,
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
