use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
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

pub fn collect_temperature_celsius_from_sysfs(root: impl AsRef<Path>) -> Option<f64> {
    let mut highest: Option<f64> = None;
    let entries = fs::read_dir(root).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let sensor_name = read_trimmed(path.join("name")).unwrap_or_default();
        for temperature_path in glob_numbered_files(&path, "temp", "_input") {
            let Some(raw) =
                read_trimmed(temperature_path).and_then(|value| value.parse::<f64>().ok())
            else {
                continue;
            };
            let celsius = if raw > 1_000.0 { raw / 1_000.0 } else { raw };
            if !(0.0..200.0).contains(&celsius) {
                continue;
            }
            if !sensor_name.is_empty()
                && sensor_name.contains("nvme")
                && highest.is_some_and(|current| current >= celsius)
            {
                continue;
            }
            highest = Some(highest.map_or(celsius, |current| current.max(celsius)));
        }
    }

    highest
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn glob_numbered_files(root: &Path, prefix: &str, suffix: &str) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .map(|entry| entry.path())
        .filter(|path| {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return false;
            };

            name.starts_with(prefix) && name.ends_with(suffix)
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}
