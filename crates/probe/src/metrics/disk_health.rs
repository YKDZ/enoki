use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicI8, Ordering},
    time::Duration,
};

use serde::Deserialize;

use crate::metrics::{
    CollectorCadenceClass, CollectorError, MetricCollector, MetricsCollectionConfig,
};
use crate::privileged_runtime::{
    CollectorRuntimeProfile, LocalPrivilegedRuntimeRunner, NetworkAccess, PrivilegedCollector,
    PrivilegedCollectorId, PrivilegedCollectorRuntime, PrivilegedRuntimeRunner,
    SystemdPrivilegedRuntimeProcessRunner,
};
use crate::protocol::enoki::v1::{DiskHealthMetric, MetricSample};

const DISK_HEALTH_AVAILABILITY_UNKNOWN: i8 = -1;
const DISK_HEALTH_AVAILABILITY_UNAVAILABLE: i8 = 0;
const DISK_HEALTH_AVAILABILITY_AVAILABLE: i8 = 1;
const DISK_HEALTH_SMARTCTL_RUNTIME_PROFILE: CollectorRuntimeProfile = CollectorRuntimeProfile {
    timeout: Duration::from_secs(10),
    network_access: NetworkAccess::Disabled,
};

static LAST_DISK_HEALTH_COLLECTOR_AVAILABILITY: AtomicI8 =
    AtomicI8::new(DISK_HEALTH_AVAILABILITY_UNKNOWN);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskHealthAvailability {
    Available,
    Unavailable,
}

impl DiskHealthAvailability {
    pub fn from_smartctl_result(
        result: Result<Option<DiskHealthMetric>, serde_json::Error>,
    ) -> DiskHealthAvailability {
        match result {
            Ok(Some(_)) => DiskHealthAvailability::Available,
            Ok(None) | Err(_) => DiskHealthAvailability::Unavailable,
        }
    }
}

pub fn last_disk_health_collector_availability() -> Option<DiskHealthAvailability> {
    match LAST_DISK_HEALTH_COLLECTOR_AVAILABILITY.load(Ordering::Relaxed) {
        DISK_HEALTH_AVAILABILITY_AVAILABLE => Some(DiskHealthAvailability::Available),
        DISK_HEALTH_AVAILABILITY_UNAVAILABLE => Some(DiskHealthAvailability::Unavailable),
        _ => None,
    }
}

fn record_disk_health_collector_availability(availability: DiskHealthAvailability) {
    let value = match availability {
        DiskHealthAvailability::Available => DISK_HEALTH_AVAILABILITY_AVAILABLE,
        DiskHealthAvailability::Unavailable => DISK_HEALTH_AVAILABILITY_UNAVAILABLE,
    };
    LAST_DISK_HEALTH_COLLECTOR_AVAILABILITY.store(value, Ordering::Relaxed);
}

pub fn collect_disk_health_metrics_from_smartctl_json(
    device_name: &str,
    contents: &str,
) -> Result<Option<DiskHealthMetric>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(contents)?;

    if value
        .pointer("/smart_support/available")
        .and_then(serde_json::Value::as_bool)
        == Some(false)
    {
        return Ok(None);
    }

    let Some(passed) = value
        .pointer("/smart_status/passed")
        .and_then(serde_json::Value::as_bool)
    else {
        return Ok(None);
    };

    Ok(Some(DiskHealthMetric {
        device_name: device_name.to_string(),
        model: json_string(&value, "/model_name").unwrap_or_default(),
        power_on_hours: json_u64(&value, "/power_on_time/hours"),
        serial_number: json_string(&value, "/serial_number").unwrap_or_default(),
        passed,
        temperature_celsius: json_f64(&value, "/temperature/current"),
    }))
}

pub fn collect_disk_health_metrics_with_smartctl() -> Result<Vec<DiskHealthMetric>, CollectorError>
{
    let scan_output = Command::new("smartctl")
        .args(["--scan-open", "--json"])
        .output()
        .map_err(|error| CollectorError::new(format!("smartctl unavailable: {error}")))?;
    if !scan_output.status.success() {
        return Err(CollectorError::new("smartctl scan failed"));
    }

    let scan_json = String::from_utf8_lossy(&scan_output.stdout);
    let devices = smartctl_scan_devices(&scan_json)
        .map_err(|error| CollectorError::new(format!("smartctl scan output malformed: {error}")))?;
    let mut metrics = Vec::new();

    for device in devices {
        let output = Command::new("smartctl")
            .args(["-a", "--json", &device])
            .output()
            .map_err(|error| {
                CollectorError::new(format!("smartctl failed for {device}: {error}"))
            })?;

        if !output.status.success() && output.stdout.is_empty() {
            continue;
        }

        let json = String::from_utf8_lossy(&output.stdout);
        match collect_disk_health_metrics_from_smartctl_json(&device, &json) {
            Ok(Some(metric)) => metrics.push(metric),
            Ok(None) => {}
            Err(_) => {}
        }
    }

    Ok(metrics)
}

pub fn format_disk_health_metrics_json(metrics: &[DiskHealthMetric]) -> String {
    let values = metrics
        .iter()
        .map(|metric| {
            serde_json::json!({
                "device_name": metric.device_name,
                "model": metric.model,
                "serial_number": metric.serial_number,
                "passed": metric.passed,
                "temperature_celsius": metric.temperature_celsius,
                "power_on_hours": metric.power_on_hours,
            })
        })
        .collect::<Vec<_>>();

    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

pub trait DiskHealthMetricsRunner {
    fn collect_disk_health_metrics(&mut self) -> Result<Vec<DiskHealthMetric>, CollectorError>;
}

pub struct DiskHealthMetricCollector<R = PrivilegedDiskHealthMetricsRunner> {
    runner: R,
}

impl<R> DiskHealthMetricCollector<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl Default for DiskHealthMetricCollector {
    fn default() -> Self {
        Self::new(PrivilegedDiskHealthMetricsRunner::default())
    }
}

impl<R> MetricCollector for DiskHealthMetricCollector<R>
where
    R: DiskHealthMetricsRunner,
{
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::LowFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        _config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        let metrics = match self.runner.collect_disk_health_metrics() {
            Ok(metrics) => metrics,
            Err(error) => {
                record_disk_health_collector_availability(DiskHealthAvailability::Unavailable);
                return Err(error);
            }
        };
        if metrics.is_empty() {
            record_disk_health_collector_availability(DiskHealthAvailability::Unavailable);
            return Ok(false);
        }

        record_disk_health_collector_availability(DiskHealthAvailability::Available);
        sample.disk_health = metrics;
        Ok(true)
    }
}

pub struct PrivilegedDiskHealthMetricsRunner<R = LocalPrivilegedRuntimeRunner> {
    runtime: PrivilegedCollectorRuntime<R>,
}

impl Default for PrivilegedDiskHealthMetricsRunner {
    fn default() -> Self {
        let probe_binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("enoki-probe"));
        Self::new(LocalPrivilegedRuntimeRunner::new(
            probe_binary,
            SystemdPrivilegedRuntimeProcessRunner,
        ))
    }
}

impl<R> PrivilegedDiskHealthMetricsRunner<R> {
    pub fn new(runner: R) -> Self {
        Self {
            runtime: PrivilegedCollectorRuntime::new(runner),
        }
    }
}

impl<R> DiskHealthMetricsRunner for PrivilegedDiskHealthMetricsRunner<R>
where
    R: PrivilegedRuntimeRunner,
{
    fn collect_disk_health_metrics(&mut self) -> Result<Vec<DiskHealthMetric>, CollectorError> {
        let output = self
            .runtime
            .run(&DiskHealthSmartctlPrivilegedCollector)
            .map_err(|error| CollectorError::new(error.to_string()))?;

        parse_privileged_disk_health_output(&output.stdout)
            .map_err(|error| CollectorError::new(error.to_string()))
    }
}

struct DiskHealthSmartctlPrivilegedCollector;

impl PrivilegedCollector for DiskHealthSmartctlPrivilegedCollector {
    fn collector_id(&self) -> PrivilegedCollectorId {
        PrivilegedCollectorId::DiskHealthSmartctl
    }

    fn runtime_profile(&self) -> &'static CollectorRuntimeProfile {
        &DISK_HEALTH_SMARTCTL_RUNTIME_PROFILE
    }
}

#[derive(Deserialize)]
struct PrivilegedDiskHealthOutput {
    device_name: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    serial_number: String,
    passed: bool,
    temperature_celsius: Option<f64>,
    power_on_hours: Option<u64>,
}

fn parse_privileged_disk_health_output(
    contents: &str,
) -> Result<Vec<DiskHealthMetric>, serde_json::Error> {
    let disks: Vec<PrivilegedDiskHealthOutput> = serde_json::from_str(contents)?;

    Ok(disks
        .into_iter()
        .map(|disk| DiskHealthMetric {
            device_name: disk.device_name,
            model: disk.model,
            passed: disk.passed,
            power_on_hours: disk.power_on_hours,
            serial_number: disk.serial_number,
            temperature_celsius: disk.temperature_celsius,
        })
        .collect())
}

fn json_string(value: &serde_json::Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn json_u64(value: &serde_json::Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer).and_then(serde_json::Value::as_u64)
}

fn json_f64(value: &serde_json::Value, pointer: &str) -> Option<f64> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_f64)
        .filter(|value| value.is_finite())
}

fn smartctl_scan_devices(contents: &str) -> Result<Vec<String>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(contents)?;

    Ok(value
        .pointer("/devices")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|device| json_string(device, "/name"))
        .collect())
}
