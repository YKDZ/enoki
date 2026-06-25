use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicI32, Ordering},
    },
};

use serde::{Deserialize, Serialize};

use crate::local_privilege_boundary::{
    AutoLocalPrivilegeBoundaryProcessRunner, CollectorHelperExposureEnvironment,
    CollectorHelperProfile, DISK_HEALTH_SMARTCTL_HELPER_PROFILE,
    LocalCollectorHelperExposureEnvironment, LocalPrivilegeBoundaryRunner,
    PrivilegedCollectorHelper, PrivilegedCollectorHelperError, PrivilegedCollectorHelperId,
    PrivilegedCollectorHelperRunner, ProbeLocalPrivilegeBoundary, disk_health_smartctl_path,
};
use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
    filesystem_capacity,
};
use crate::protocol::enoki::v1::{
    DiskHealthCollectorCapability, DiskHealthCollectorCapabilityStatus, DiskHealthMetric,
    MetricSample,
};

const DISK_HEALTH_STATUS_UNKNOWN: i32 = -1;
pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::DiskHealth, CollectorCadence::Every12Ticks);

static LAST_DISK_HEALTH_COLLECTOR_STATUS: AtomicI32 = AtomicI32::new(DISK_HEALTH_STATUS_UNKNOWN);
static LAST_DISK_HEALTH_COLLECTOR_DIAGNOSTIC: Mutex<String> = Mutex::new(String::new());

thread_local! {
    static THREAD_DISK_HEALTH_COLLECTOR_CAPABILITY: RefCell<Option<DiskHealthCollectorCapability>> =
        const { RefCell::new(None) };
}

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
    match last_disk_health_collector_capability().map(|capability| capability.status()) {
        Some(DiskHealthCollectorCapabilityStatus::Available) => {
            Some(DiskHealthAvailability::Available)
        }
        Some(_) => Some(DiskHealthAvailability::Unavailable),
        None => None,
    }
}

pub fn last_disk_health_collector_capability() -> Option<DiskHealthCollectorCapability> {
    if let Some(capability) =
        THREAD_DISK_HEALTH_COLLECTOR_CAPABILITY.with(|capability| capability.borrow().clone())
    {
        return Some(capability);
    }

    let status = LAST_DISK_HEALTH_COLLECTOR_STATUS.load(Ordering::Relaxed);
    if status == DISK_HEALTH_STATUS_UNKNOWN {
        return None;
    }

    Some(DiskHealthCollectorCapability {
        status,
        diagnostic: LAST_DISK_HEALTH_COLLECTOR_DIAGNOSTIC
            .lock()
            .map(|diagnostic| diagnostic.clone())
            .unwrap_or_default(),
    })
}

fn record_disk_health_collector_capability(collection: &DiskHealthCollection) {
    let capability = DiskHealthCollectorCapability {
        status: collection.status as i32,
        diagnostic: collection.diagnostic.clone(),
    };

    THREAD_DISK_HEALTH_COLLECTOR_CAPABILITY.with(|thread_capability| {
        *thread_capability.borrow_mut() = Some(capability);
    });
    LAST_DISK_HEALTH_COLLECTOR_STATUS.store(collection.status as i32, Ordering::Relaxed);
    if let Ok(mut diagnostic) = LAST_DISK_HEALTH_COLLECTOR_DIAGNOSTIC.lock() {
        *diagnostic = collection.diagnostic.clone();
    }
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
        role: String::new(),
        serial_number: json_string(&value, "/serial_number").unwrap_or_default(),
        passed,
        temperature_celsius: json_f64(&value, "/temperature/current"),
        total_bytes: json_u64(&value, "/user_capacity/bytes"),
        usage_mount_point: String::new(),
        used_bytes: None,
    }))
}

pub fn collect_disk_health_metrics_with_smartctl()
-> Result<Vec<DiskHealthMetric>, DiskHealthCollectionError> {
    let environment = LocalCollectorHelperExposureEnvironment;
    let Some(smartctl_path) = disk_health_smartctl_path(&environment) else {
        return Err(DiskHealthCollectionError::new(
            DiskHealthCollectorCapabilityStatus::MissingSmartctl,
            "smartctl is not installed",
        ));
    };

    collect_disk_health_metrics_with_smartctl_at(&smartctl_path)
}

pub fn collect_disk_health_metrics_with_smartctl_at(
    smartctl_path: &Path,
) -> Result<Vec<DiskHealthMetric>, DiskHealthCollectionError> {
    let scan_output = Command::new(smartctl_path)
        .args(["--scan-open", "--json"])
        .output()
        .map_err(|error| {
            DiskHealthCollectionError::new(
                DiskHealthCollectorCapabilityStatus::MissingSmartctl,
                format!("smartctl unavailable: {error}"),
            )
        })?;
    if !scan_output.status.success() {
        return Err(DiskHealthCollectionError::new(
            DiskHealthCollectorCapabilityStatus::ScanFailed,
            "smartctl scan failed",
        ));
    }

    let scan_json = String::from_utf8_lossy(&scan_output.stdout);
    let devices = smartctl_scan_devices(&scan_json).map_err(|error| {
        DiskHealthCollectionError::new(
            DiskHealthCollectorCapabilityStatus::MalformedOutput,
            format!("smartctl scan output malformed: {error}"),
        )
    })?;
    let mut metrics = Vec::new();
    let mut unsupported_count = 0;
    let mut malformed_count = 0;

    for device in devices {
        let output = Command::new(smartctl_path)
            .args(["-a", "--json", &device])
            .output()
            .map_err(|error| {
                DiskHealthCollectionError::new(
                    DiskHealthCollectorCapabilityStatus::HelperFailed,
                    format!("smartctl failed for {device}: {error}"),
                )
            })?;

        if !output.status.success() && output.stdout.is_empty() {
            return Err(DiskHealthCollectionError::new(
                DiskHealthCollectorCapabilityStatus::HelperFailed,
                format!("smartctl failed for {device}"),
            ));
        }

        let json = String::from_utf8_lossy(&output.stdout);
        match collect_disk_health_metrics_from_smartctl_json(&device, &json) {
            Ok(Some(metric)) => metrics.push(metric),
            Ok(None) => unsupported_count += 1,
            Err(_) => malformed_count += 1,
        }
    }

    if metrics.is_empty() && malformed_count > 0 {
        return Err(DiskHealthCollectionError::new(
            DiskHealthCollectorCapabilityStatus::MalformedOutput,
            "smartctl device output malformed",
        ));
    }

    if metrics.is_empty() && unsupported_count > 0 {
        return Err(DiskHealthCollectionError::new(
            DiskHealthCollectorCapabilityStatus::UnsupportedSmartData,
            "SMART data is unsupported for scanned devices",
        ));
    }

    enrich_disk_health_metrics_with_usage(&mut metrics);
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
                "role": metric.role,
                "total_bytes": metric.total_bytes,
                "usage_mount_point": metric.usage_mount_point,
                "used_bytes": metric.used_bytes,
            })
        })
        .collect::<Vec<_>>();

    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

pub trait DiskHealthMetricsRunner {
    fn collect_disk_health_metrics(
        &mut self,
    ) -> Result<DiskHealthCollection, DiskHealthCollectionError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiskHealthCollection {
    pub metrics: Vec<DiskHealthMetric>,
    pub status: DiskHealthCollectorCapabilityStatus,
    pub diagnostic: String,
}

impl DiskHealthCollection {
    pub fn available(metrics: Vec<DiskHealthMetric>) -> Self {
        Self {
            metrics,
            status: DiskHealthCollectorCapabilityStatus::Available,
            diagnostic: String::new(),
        }
    }

    pub fn unavailable(
        status: DiskHealthCollectorCapabilityStatus,
        diagnostic: impl Into<String>,
    ) -> Self {
        Self {
            metrics: Vec::new(),
            status,
            diagnostic: diagnostic.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiskHealthCollectionError {
    pub status: DiskHealthCollectorCapabilityStatus,
    pub diagnostic: String,
}

impl DiskHealthCollectionError {
    pub fn new(status: DiskHealthCollectorCapabilityStatus, diagnostic: impl Into<String>) -> Self {
        Self {
            status,
            diagnostic: diagnostic.into(),
        }
    }
}

impl fmt::Display for DiskHealthCollectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl Error for DiskHealthCollectionError {}

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
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        let collection = match self.runner.collect_disk_health_metrics() {
            Ok(collection) => collection,
            Err(error) => {
                let collection =
                    DiskHealthCollection::unavailable(error.status, error.diagnostic.clone());
                record_disk_health_collector_capability(&collection);
                return Err(CollectorError::new(error.to_string()));
            }
        };
        record_disk_health_collector_capability(&collection);
        if collection.metrics.is_empty() {
            return Ok(false);
        }

        sample.disk_health = collection.metrics;
        Ok(true)
    }
}

pub struct PrivilegedDiskHealthMetricsRunner<
    R = LocalPrivilegeBoundaryRunner,
    E = LocalCollectorHelperExposureEnvironment,
> {
    local_privilege_boundary: ProbeLocalPrivilegeBoundary<R>,
    exposure_environment: E,
}

impl Default for PrivilegedDiskHealthMetricsRunner {
    fn default() -> Self {
        let probe_binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("enoki-probe"));
        Self::new(LocalPrivilegeBoundaryRunner::new(
            probe_binary,
            AutoLocalPrivilegeBoundaryProcessRunner::default(),
        ))
    }
}

impl<R> PrivilegedDiskHealthMetricsRunner<R> {
    pub fn new(runner: R) -> Self {
        Self::new_with_exposure_environment(runner, LocalCollectorHelperExposureEnvironment)
    }
}

impl<R, E> PrivilegedDiskHealthMetricsRunner<R, E> {
    pub fn new_with_exposure_environment(runner: R, exposure_environment: E) -> Self {
        Self {
            local_privilege_boundary: ProbeLocalPrivilegeBoundary::new(runner),
            exposure_environment,
        }
    }
}

impl<R, E> DiskHealthMetricsRunner for PrivilegedDiskHealthMetricsRunner<R, E>
where
    R: PrivilegedCollectorHelperRunner,
    E: CollectorHelperExposureEnvironment,
{
    fn collect_disk_health_metrics(
        &mut self,
    ) -> Result<DiskHealthCollection, DiskHealthCollectionError> {
        if disk_health_smartctl_path(&self.exposure_environment).is_none() {
            return Err(DiskHealthCollectionError::new(
                DiskHealthCollectorCapabilityStatus::MissingSmartctl,
                "smartctl is not installed",
            ));
        }

        let output = self
            .local_privilege_boundary
            .run(&DiskHealthSmartctlPrivilegedCollectorHelper)
            .map_err(disk_health_collection_error_from_helper_error)?;

        parse_privileged_disk_health_collection_output(&output.stdout).map_err(|error| {
            DiskHealthCollectionError::new(
                DiskHealthCollectorCapabilityStatus::MalformedOutput,
                format!("privileged disk health output malformed: {error}"),
            )
        })
    }
}

fn disk_health_collection_error_from_helper_error(
    error: PrivilegedCollectorHelperError,
) -> DiskHealthCollectionError {
    match error {
        PrivilegedCollectorHelperError::TimedOut { timeout } => DiskHealthCollectionError::new(
            DiskHealthCollectorCapabilityStatus::HelperFailed,
            format!("privileged collector helper timed out after {timeout:?}"),
        ),
        PrivilegedCollectorHelperError::LocalPrivilegeBoundaryUnavailable(message) => {
            DiskHealthCollectionError::new(
                DiskHealthCollectorCapabilityStatus::InsufficientLocalPrivilege,
                message,
            )
        }
        PrivilegedCollectorHelperError::CollectorFailed(message) => DiskHealthCollectionError::new(
            DiskHealthCollectorCapabilityStatus::HelperFailed,
            message,
        ),
    }
}

struct DiskHealthSmartctlPrivilegedCollectorHelper;

impl PrivilegedCollectorHelper for DiskHealthSmartctlPrivilegedCollectorHelper {
    fn helper_id(&self) -> PrivilegedCollectorHelperId {
        PrivilegedCollectorHelperId::DiskHealthSmartctl
    }

    fn helper_profile(&self) -> &'static CollectorHelperProfile {
        &DISK_HEALTH_SMARTCTL_HELPER_PROFILE
    }
}

#[derive(Deserialize, Serialize)]
struct PrivilegedDiskHealthOutput {
    device_name: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    serial_number: String,
    passed: bool,
    temperature_celsius: Option<f64>,
    power_on_hours: Option<u64>,
    #[serde(default)]
    role: String,
    total_bytes: Option<u64>,
    #[serde(default)]
    usage_mount_point: String,
    used_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PrivilegedDiskHealthPayload {
    Collection(PrivilegedDiskHealthCollectionOutput),
    LegacyMetrics(Vec<PrivilegedDiskHealthOutput>),
}

#[derive(Deserialize)]
struct PrivilegedDiskHealthCollectionOutput {
    status: i32,
    #[serde(default)]
    diagnostic: String,
    #[serde(default)]
    metrics: Vec<PrivilegedDiskHealthOutput>,
}

pub fn format_disk_health_collection_json(collection: &DiskHealthCollection) -> String {
    let metrics = collection
        .metrics
        .iter()
        .map(|metric| {
            serde_json::json!({
                "device_name": metric.device_name,
                "model": metric.model,
                "serial_number": metric.serial_number,
                "passed": metric.passed,
                "temperature_celsius": metric.temperature_celsius,
                "power_on_hours": metric.power_on_hours,
                "role": metric.role,
                "total_bytes": metric.total_bytes,
                "usage_mount_point": metric.usage_mount_point,
                "used_bytes": metric.used_bytes,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "status": collection.status as i32,
        "diagnostic": collection.diagnostic,
        "metrics": metrics,
    })
    .to_string()
}

fn parse_privileged_disk_health_collection_output(
    contents: &str,
) -> Result<DiskHealthCollection, serde_json::Error> {
    match serde_json::from_str::<PrivilegedDiskHealthPayload>(contents)? {
        PrivilegedDiskHealthPayload::Collection(collection) => {
            let status = DiskHealthCollectorCapabilityStatus::try_from(collection.status)
                .unwrap_or(DiskHealthCollectorCapabilityStatus::Unspecified);
            let metrics = disk_health_metrics_from_privileged_output(collection.metrics);

            if status == DiskHealthCollectorCapabilityStatus::Available {
                return Ok(DiskHealthCollection::available(metrics));
            }

            Ok(DiskHealthCollection::unavailable(
                status,
                collection.diagnostic,
            ))
        }
        PrivilegedDiskHealthPayload::LegacyMetrics(disks) => {
            let metrics = disk_health_metrics_from_privileged_output(disks);

            if metrics.is_empty() {
                return Ok(DiskHealthCollection::unavailable(
                    DiskHealthCollectorCapabilityStatus::UnsupportedSmartData,
                    "no supported SMART data returned",
                ));
            }

            Ok(DiskHealthCollection::available(metrics))
        }
    }
}

fn disk_health_metrics_from_privileged_output(
    disks: Vec<PrivilegedDiskHealthOutput>,
) -> Vec<DiskHealthMetric> {
    disks
        .into_iter()
        .map(|disk| DiskHealthMetric {
            device_name: disk.device_name,
            model: disk.model,
            passed: disk.passed,
            power_on_hours: disk.power_on_hours,
            role: disk.role,
            serial_number: disk.serial_number,
            temperature_celsius: disk.temperature_celsius,
            total_bytes: disk.total_bytes,
            usage_mount_point: disk.usage_mount_point,
            used_bytes: disk.used_bytes,
        })
        .collect()
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DiskPhysicalUsage {
    mount_point: String,
    role: String,
    total_bytes: u64,
    used_bytes: u64,
}

fn enrich_disk_health_metrics_with_usage(metrics: &mut [DiskHealthMetric]) {
    let usage_by_device = disk_usage_by_device();

    for metric in metrics {
        let Some(usage) = usage_by_device.get(&metric.device_name) else {
            continue;
        };

        apply_disk_physical_usage(metric, usage);
    }
}

fn apply_disk_physical_usage(metric: &mut DiskHealthMetric, usage: &DiskPhysicalUsage) {
    metric.role = usage.role.clone();
    metric.total_bytes = metric.total_bytes.or(Some(usage.total_bytes));
    metric.usage_mount_point = usage.mount_point.clone();
    metric.used_bytes = Some(usage.used_bytes);
}

fn disk_usage_by_device() -> BTreeMap<String, DiskPhysicalUsage> {
    let unraid = disk_usage_by_device_from_unraid_disks_ini("/var/local/emhttp/disks.ini");
    if !unraid.is_empty() {
        return unraid;
    }

    fs::read_to_string("/proc/mounts")
        .map(|mounts| disk_usage_by_device_from_mounts(&mounts))
        .unwrap_or_default()
}

fn disk_usage_by_device_from_mounts(contents: &str) -> BTreeMap<String, DiskPhysicalUsage> {
    let mut usage_by_device = BTreeMap::new();
    let mut seen_sources = BTreeSet::new();

    for mount in contents.lines().filter_map(parse_mount) {
        if EXCLUDED_USAGE_FILESYSTEMS.contains(&mount.filesystem_type.as_str())
            || mount.mount_point.starts_with("/run/")
            || mount.mount_point.starts_with("/var/lib/docker/")
        {
            continue;
        }
        if !seen_sources.insert((mount.source.clone(), mount.mount_point.clone())) {
            continue;
        }

        let Some(device_name) = physical_device_name(&mount.source) else {
            continue;
        };
        let Some(capacity) = filesystem_capacity(&mount.mount_point) else {
            continue;
        };
        if capacity.total_bytes == 0 {
            continue;
        }

        let used_bytes = capacity.total_bytes.saturating_sub(capacity.free_bytes);
        merge_disk_usage(
            &mut usage_by_device,
            &device_name,
            DiskPhysicalUsage {
                mount_point: mount.mount_point,
                role: String::new(),
                total_bytes: capacity.total_bytes,
                used_bytes,
            },
        );
    }

    usage_by_device
}

fn disk_usage_by_device_from_unraid_disks_ini(path: &str) -> BTreeMap<String, DiskPhysicalUsage> {
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };

    disk_usage_by_device_from_unraid_disks_ini_contents(&contents)
}

fn disk_usage_by_device_from_unraid_disks_ini_contents(
    contents: &str,
) -> BTreeMap<String, DiskPhysicalUsage> {
    let mut usage_by_device = BTreeMap::new();
    let mut current = UnraidDiskSection::default();

    for line in contents.lines() {
        if line.starts_with("[\"") && line.ends_with("\"]") {
            insert_unraid_disk_usage(&mut usage_by_device, &current);
            current = UnraidDiskSection::default();
            current.name = line
                .trim_start_matches("[\"")
                .trim_end_matches("\"]")
                .to_string();
            continue;
        }

        let Some((key, value)) = parse_ini_assignment(line) else {
            continue;
        };
        match key {
            "device" => current.device = value,
            "fsMountpoint" => current.mount_point = value,
            "fsSize" => current.total_kib = value.parse().ok(),
            "fsUsed" => current.used_kib = value.parse().ok(),
            "type" => current.role = value,
            _ => {}
        }
    }

    insert_unraid_disk_usage(&mut usage_by_device, &current);
    usage_by_device
}

fn insert_unraid_disk_usage(
    usage_by_device: &mut BTreeMap<String, DiskPhysicalUsage>,
    section: &UnraidDiskSection,
) {
    let Some(total_kib) = section.total_kib else {
        return;
    };
    let Some(used_kib) = section.used_kib else {
        return;
    };
    if section.device.is_empty() || section.mount_point.is_empty() || total_kib == 0 {
        return;
    }

    let usage = DiskPhysicalUsage {
        mount_point: section.mount_point.clone(),
        role: if section.role.is_empty() {
            section.name.clone()
        } else {
            section.role.clone()
        },
        total_bytes: total_kib.saturating_mul(1024),
        used_bytes: used_kib.saturating_mul(1024),
    };

    for device_name in smartctl_device_aliases(&section.device) {
        merge_disk_usage(usage_by_device, &device_name, usage.clone());
    }
}

fn merge_disk_usage(
    usage_by_device: &mut BTreeMap<String, DiskPhysicalUsage>,
    device_name: &str,
    usage: DiskPhysicalUsage,
) {
    usage_by_device
        .entry(device_name.to_string())
        .and_modify(|current| {
            current.total_bytes = current.total_bytes.saturating_add(usage.total_bytes);
            current.used_bytes = current.used_bytes.saturating_add(usage.used_bytes);
            if !current.mount_point.contains(&usage.mount_point) {
                if !current.mount_point.is_empty() {
                    current.mount_point.push_str(", ");
                }
                current.mount_point.push_str(&usage.mount_point);
            }
        })
        .or_insert(usage);
}

fn parse_ini_assignment(line: &str) -> Option<(&str, String)> {
    let (key, raw_value) = line.split_once('=')?;
    Some((key.trim(), raw_value.trim().trim_matches('"').to_string()))
}

fn parse_mount(line: &str) -> Option<MountEntry> {
    let mut parts = line.split_whitespace();
    let source = unescape_mount_value(parts.next()?);
    let mount_point = unescape_mount_value(parts.next()?);
    let filesystem_type = parts.next()?.to_string();

    Some(MountEntry {
        filesystem_type,
        mount_point,
        source,
    })
}

fn physical_device_name(source: &str) -> Option<String> {
    physical_device_name_with_sysfs(source, Path::new("/sys/class/block"))
}

fn physical_device_name_with_sysfs(source: &str, sysfs_block_root: &Path) -> Option<String> {
    let name = source.strip_prefix("/dev/")?;
    if let Some(name) = physical_device_name_from_direct_block_name(name) {
        return Some(name);
    }

    let basename = block_device_basename(source).or_else(|| Some(name.to_string()))?;
    let physical_names = physical_device_names_from_sysfs(&basename, sysfs_block_root);

    if physical_names.len() == 1 {
        return physical_names.into_iter().next();
    }

    None
}

fn physical_device_name_from_direct_block_name(name: &str) -> Option<String> {
    if name.starts_with("mapper/") || name.starts_with("md") || name.starts_with("dm-") {
        return None;
    }

    Some(format!("/dev/{}", physical_device_basename(name)?))
}

fn block_device_basename(source: &str) -> Option<String> {
    let canonical = fs::canonicalize(source).ok()?;
    canonical.file_name()?.to_str().map(ToOwned::to_owned)
}

fn physical_device_names_from_sysfs(block_name: &str, sysfs_block_root: &Path) -> BTreeSet<String> {
    let mut visited = BTreeSet::new();
    physical_device_names_from_sysfs_inner(block_name, sysfs_block_root, &mut visited)
}

fn physical_device_names_from_sysfs_inner(
    block_name: &str,
    sysfs_block_root: &Path,
    visited: &mut BTreeSet<String>,
) -> BTreeSet<String> {
    let mut physical_names = BTreeSet::new();
    if !visited.insert(block_name.to_string()) {
        return physical_names;
    }

    if let Some(name) = physical_device_name_from_direct_block_name(block_name) {
        physical_names.insert(name);
        return physical_names;
    }

    let Ok(slaves) = fs::read_dir(sysfs_block_root.join(block_name).join("slaves")) else {
        return physical_names;
    };

    for slave in slaves.flatten() {
        let Some(slave_name) = slave.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        physical_names.extend(physical_device_names_from_sysfs_inner(
            &slave_name,
            sysfs_block_root,
            visited,
        ));
    }

    physical_names
}

fn physical_device_basename(name: &str) -> Option<String> {
    if let Some(controller) = nvme_controller_name(name) {
        return Some(controller);
    }

    let trimmed = name
        .trim_end_matches(|character: char| character.is_ascii_digit())
        .trim_end_matches('p');
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn smartctl_device_aliases(device: &str) -> Vec<String> {
    let mut aliases = vec![format!("/dev/{device}")];
    if let Some(controller) = nvme_controller_name(device) {
        aliases.push(format!("/dev/{controller}"));
    }

    aliases
}

fn nvme_controller_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("nvme")?;
    let digits = rest
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() || !rest[digits.len()..].starts_with('n') {
        return None;
    }

    Some(format!("nvme{digits}"))
}

fn unescape_mount_value(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[derive(Default)]
struct UnraidDiskSection {
    device: String,
    mount_point: String,
    name: String,
    role: String,
    total_kib: Option<u64>,
    used_kib: Option<u64>,
}

struct MountEntry {
    filesystem_type: String,
    mount_point: String,
    source: String,
}

const EXCLUDED_USAGE_FILESYSTEMS: &[&str] = &[
    "cgroup",
    "cgroup2",
    "debugfs",
    "devtmpfs",
    "fuse.shfs",
    "fusectl",
    "overlay",
    "proc",
    "squashfs",
    "sysfs",
    "tmpfs",
    "tracefs",
];

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unraid_disks_ini_maps_devices_to_usage_bytes() {
        let usage = disk_usage_by_device_from_unraid_disks_ini_contents(
            r#"["disk1"]
name="disk1"
device="sdc"
type="Data"
fsMountpoint="/mnt/disk1"
fsSize="100"
fsUsed="40"
["cache"]
name="cache"
device="nvme0n1"
type="Cache"
fsMountpoint="/mnt/cache"
fsSize="200"
fsUsed="90"
"#,
        );

        assert_eq!(
            usage.get("/dev/sdc"),
            Some(&DiskPhysicalUsage {
                mount_point: "/mnt/disk1".to_string(),
                role: "Data".to_string(),
                total_bytes: 100 * 1024,
                used_bytes: 40 * 1024,
            }),
        );
        assert_eq!(
            usage.get("/dev/nvme0"),
            Some(&DiskPhysicalUsage {
                mount_point: "/mnt/cache".to_string(),
                role: "Cache".to_string(),
                total_bytes: 200 * 1024,
                used_bytes: 90 * 1024,
            }),
        );
    }

    #[test]
    fn physical_device_names_match_smartctl_device_names() {
        assert_eq!(
            physical_device_name("/dev/sda1").as_deref(),
            Some("/dev/sda")
        );
        assert_eq!(
            physical_device_name("/dev/nvme0n1p1").as_deref(),
            Some("/dev/nvme0"),
        );
        assert_eq!(physical_device_name("/dev/md1p1"), None);
        assert_eq!(physical_device_name("/dev/mapper/vg-root"), None);
    }

    #[test]
    fn smartctl_json_preserves_physical_user_capacity() {
        let metric = collect_disk_health_metrics_from_smartctl_json(
            "/dev/nvme0",
            r#"{
  "model_name": "GVL-1TB",
  "serial_number": "0009462008226",
  "smart_support": { "available": true },
  "smart_status": { "passed": true },
  "temperature": { "current": 40 },
  "power_on_time": { "hours": 24773 },
  "user_capacity": { "blocks": 2000409264, "bytes": 1024209543168 }
}"#,
        )
        .expect("smartctl json parses")
        .expect("smartctl metric is available");

        assert_eq!(metric.total_bytes, Some(1_024_209_543_168));
    }

    #[test]
    fn disk_usage_enrichment_does_not_override_physical_capacity() {
        let mut metric = DiskHealthMetric {
            device_name: "/dev/nvme0".to_string(),
            model: "GVL-1TB".to_string(),
            passed: true,
            power_on_hours: Some(24_773),
            role: String::new(),
            serial_number: "0009462008226".to_string(),
            temperature_celsius: Some(40.0),
            total_bytes: Some(1_024_209_543_168),
            usage_mount_point: String::new(),
            used_bytes: None,
        };

        apply_disk_physical_usage(
            &mut metric,
            &DiskPhysicalUsage {
                mount_point: "/boot, /boot/efi".to_string(),
                role: String::new(),
                total_bytes: 3_165_372_416,
                used_bytes: 216_649_728,
            },
        );

        assert_eq!(metric.total_bytes, Some(1_024_209_543_168));
        assert_eq!(metric.used_bytes, Some(216_649_728));
        assert_eq!(metric.usage_mount_point, "/boot, /boot/efi");
    }

    #[test]
    fn lvm_dm_device_maps_to_single_physical_nvme_controller() {
        let temp = tempfile::tempdir().expect("tempdir");
        let slaves = temp.path().join("dm-0/slaves");
        fs::create_dir_all(&slaves).expect("slaves dir");
        fs::write(slaves.join("nvme0n1p3"), "").expect("slave marker");

        assert_eq!(
            physical_device_name_with_sysfs("/dev/dm-0", temp.path()).as_deref(),
            Some("/dev/nvme0"),
        );
    }

    #[test]
    fn privileged_disk_health_output_preserves_usage_fields() {
        let collection = parse_privileged_disk_health_collection_output(
            r#"[
  {
    "device_name": "/dev/sdc",
    "model": "Samsung SSD 870 EVO 1TB",
    "serial_number": "S6PTEST",
    "passed": true,
    "temperature_celsius": 31.0,
    "power_on_hours": 12345,
    "role": "Data",
    "total_bytes": 102400,
    "usage_mount_point": "/mnt/disk1",
    "used_bytes": 40960
  }
]"#,
        )
        .expect("privileged output parses");
        let metrics = collection.metrics;

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].role, "Data");
        assert_eq!(metrics[0].total_bytes, Some(102400));
        assert_eq!(metrics[0].usage_mount_point, "/mnt/disk1");
        assert_eq!(metrics[0].used_bytes, Some(40960));
    }
}
