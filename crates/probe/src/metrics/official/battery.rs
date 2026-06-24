use std::{fs, path::Path};

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatteryMetrics {
    pub percent: u32,
    pub state: String,
}

pub fn collect_battery_metrics_from_sysfs(root: impl AsRef<Path>) -> Option<BatteryMetrics> {
    let mut best: Option<BatteryMetrics> = None;
    let entries = fs::read_dir(root).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if read_trimmed(path.join("type")).as_deref() != Some("Battery") {
            continue;
        }
        let Some(percent) = read_trimmed(path.join("capacity"))
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value <= 100)
        else {
            continue;
        };
        let state = read_trimmed(path.join("status")).unwrap_or_else(|| "Unknown".to_string());
        let metrics = BatteryMetrics { percent, state };
        if best
            .as_ref()
            .is_none_or(|current| metrics.percent > current.percent)
        {
            best = Some(metrics);
        }
    }

    best
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
