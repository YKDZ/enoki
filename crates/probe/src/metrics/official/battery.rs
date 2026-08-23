use std::{fs, path::Path};

use crate::metrics::{CollectorCadence, CollectorDefinition, CollectorId};

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Battery, CollectorCadence::EveryTick);

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
