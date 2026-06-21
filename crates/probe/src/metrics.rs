use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::protocol::enoki::v1::{CpuCoreMetric, DiskUsageMetric, NetworkInterfaceMetric};

const EXCLUDED_FILESYSTEMS: &[&str] = &[
    "cgroup", "cgroup2", "debugfs", "devtmpfs", "fusectl", "overlay", "proc", "squashfs", "sysfs",
    "tmpfs", "tracefs",
];

#[derive(Debug)]
pub struct CpuMetrics {
    pub aggregate_percent: f64,
    pub cores: Vec<CpuCoreMetric>,
    pub snapshot: CpuCounterSnapshot,
}

#[derive(Debug)]
pub struct MemoryMetrics {
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug)]
pub struct LoadMetrics {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

#[derive(Clone, Debug, Default)]
pub struct CpuCounterSnapshot {
    counters_by_name: BTreeMap<String, CpuCounters>,
}

#[derive(Clone, Debug, Default)]
pub struct NetworkCounterSnapshot {
    counters_by_name: BTreeMap<String, NetworkCounters>,
}

#[derive(Debug)]
pub struct NetworkMetrics {
    pub interfaces: Vec<NetworkInterfaceMetric>,
    pub snapshot: NetworkCounterSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemCapacity {
    pub available_bytes: u64,
    pub free_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricsCollectionConfig {
    pub collect_cpu: bool,
    pub collect_disk: bool,
    pub collect_load: bool,
    pub collect_memory: bool,
    pub collect_network: bool,
    pub collect_uptime: bool,
}

impl MetricsCollectionConfig {
    pub fn all_enabled() -> Self {
        Self {
            collect_cpu: true,
            collect_disk: true,
            collect_load: true,
            collect_memory: true,
            collect_network: true,
            collect_uptime: true,
        }
    }

    pub fn any_enabled(&self) -> bool {
        self.collect_cpu
            || self.collect_disk
            || self.collect_load
            || self.collect_memory
            || self.collect_network
            || self.collect_uptime
    }
}

#[derive(Default)]
pub struct MetricsCollector {
    previous_cpu: Option<CpuCounterSnapshot>,
    previous_network: Option<NetworkCounterSnapshot>,
}

impl MetricsCollector {
    pub fn collect(
        &mut self,
        sequence: u64,
        config: MetricsCollectionConfig,
    ) -> crate::protocol::enoki::v1::MetricSample {
        let cpu = config.collect_cpu.then(|| {
            fs::read_to_string("/proc/stat").ok().and_then(|contents| {
                collect_cpu_metrics_from_proc_stat(&contents, self.previous_cpu.as_ref())
            })
        });
        let memory = config.collect_memory.then(|| {
            fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|contents| collect_memory_metrics_from_proc_meminfo(&contents))
        });
        let load = config.collect_load.then(|| {
            fs::read_to_string("/proc/loadavg")
                .ok()
                .and_then(|contents| collect_load_metrics_from_proc_loadavg(&contents))
        });
        let uptime_seconds = config.collect_uptime.then(|| {
            fs::read_to_string("/proc/uptime")
                .ok()
                .and_then(|contents| collect_uptime_seconds_from_proc_uptime(&contents))
        });
        let disks = if config.collect_disk {
            fs::read_to_string("/proc/mounts")
                .map(|contents| {
                    collect_disk_metrics_from_mounts(&contents, |mount_point| {
                        filesystem_capacity(mount_point)
                    })
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let network_interfaces = if config.collect_network {
            let network = fs::read_to_string("/proc/net/dev")
                .ok()
                .and_then(|contents| {
                    collect_network_metrics_from_proc_net_dev(
                        &contents,
                        self.previous_network.as_ref(),
                    )
                });
            if let Some(metrics) = network {
                self.previous_network = Some(metrics.snapshot);
                metrics.interfaces
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let cpu = cpu.flatten();
        if let Some(metrics) = cpu.as_ref() {
            self.previous_cpu = Some(metrics.snapshot.clone());
        }
        let memory = memory.flatten();
        let load = load.flatten();

        crate::protocol::enoki::v1::MetricSample {
            collected_at_ms: unix_time_millis(),
            cpu_cores: cpu
                .as_ref()
                .map(|metrics| metrics.cores.clone())
                .unwrap_or_default(),
            cpu_percent: cpu.as_ref().map(|metrics| metrics.aggregate_percent),
            disks,
            load_1: load.as_ref().map(|metrics| metrics.one),
            load_5: load.as_ref().map(|metrics| metrics.five),
            load_15: load.as_ref().map(|metrics| metrics.fifteen),
            memory_total_bytes: memory.as_ref().map(|metrics| metrics.total_bytes),
            memory_used_bytes: memory.as_ref().map(|metrics| metrics.used_bytes),
            network_interfaces,
            sequence,
            uptime_seconds: uptime_seconds.flatten(),
        }
    }
}

pub fn collect_cpu_metrics_from_proc_stat(
    contents: &str,
    previous: Option<&CpuCounterSnapshot>,
) -> Option<CpuMetrics> {
    let mut counters_by_name = BTreeMap::new();

    for line in contents.lines() {
        let Some(counters) = parse_cpu_line(line) else {
            continue;
        };

        counters_by_name.insert(counters.name.clone(), counters);
    }

    let aggregate = counters_by_name.get("cpu")?;
    let aggregate_previous =
        previous.and_then(|snapshot| snapshot.counters_by_name.get(aggregate.name.as_str()));
    let cores = counters_by_name
        .values()
        .filter(|counters| counters.name != "cpu" && counters.name.starts_with("cpu"))
        .map(|counters| {
            let previous_counters =
                previous.and_then(|snapshot| snapshot.counters_by_name.get(counters.name.as_str()));

            counters.clone().into_metric(previous_counters)
        })
        .collect();

    Some(CpuMetrics {
        aggregate_percent: aggregate.usage_percent_since(aggregate_previous),
        cores,
        snapshot: CpuCounterSnapshot { counters_by_name },
    })
}

pub fn collect_memory_metrics_from_proc_meminfo(contents: &str) -> Option<MemoryMetrics> {
    let total_bytes = meminfo_kilobytes(contents, "MemTotal:")?.saturating_mul(1024);
    let available_bytes = meminfo_kilobytes(contents, "MemAvailable:")?.saturating_mul(1024);

    Some(MemoryMetrics {
        total_bytes,
        used_bytes: total_bytes.saturating_sub(available_bytes),
    })
}

pub fn collect_load_metrics_from_proc_loadavg(contents: &str) -> Option<LoadMetrics> {
    let mut parts = contents.split_whitespace();

    Some(LoadMetrics {
        one: parts.next()?.parse().ok()?,
        five: parts.next()?.parse().ok()?,
        fifteen: parts.next()?.parse().ok()?,
    })
}

pub fn collect_uptime_seconds_from_proc_uptime(contents: &str) -> Option<u64> {
    let uptime_seconds = contents.split_whitespace().next()?.parse::<f64>().ok()?;

    uptime_seconds.is_finite().then_some(uptime_seconds as u64)
}

pub fn collect_disk_metrics_from_mounts(
    contents: &str,
    capacity_for_mount: impl Fn(&str) -> Option<FilesystemCapacity>,
) -> Vec<DiskUsageMetric> {
    let mut disks_by_mount_point = BTreeMap::new();
    let mut seen_filesystems = BTreeSet::new();

    for mount in contents.lines().filter_map(parse_mount) {
        if EXCLUDED_FILESYSTEMS.contains(&mount.filesystem_type.as_str())
            || is_runtime_mount_path(&mount.mount_point)
        {
            continue;
        }
        let filesystem_identity = (mount.source.clone(), mount.filesystem_type.clone());
        if seen_filesystems.contains(&filesystem_identity)
            || disks_by_mount_point.contains_key(&mount.mount_point)
        {
            continue;
        }

        let Some(capacity) = capacity_for_mount(&mount.mount_point) else {
            continue;
        };

        if capacity.total_bytes == 0 {
            continue;
        }

        seen_filesystems.insert(filesystem_identity);
        disks_by_mount_point.insert(
            mount.mount_point.clone(),
            DiskUsageMetric {
                available_bytes: capacity.available_bytes,
                filesystem_type: mount.filesystem_type,
                mount_point: mount.mount_point,
                total_bytes: capacity.total_bytes,
                used_bytes: capacity.total_bytes.saturating_sub(capacity.free_bytes),
            },
        );
    }

    disks_by_mount_point.into_values().collect()
}

pub fn collect_network_metrics_from_proc_net_dev(
    contents: &str,
    previous: Option<&NetworkCounterSnapshot>,
) -> Option<NetworkMetrics> {
    let mut counters_by_name = BTreeMap::new();

    for line in contents.lines() {
        let Some(counters) = parse_network_interface_line(line) else {
            continue;
        };

        counters_by_name.insert(counters.name.clone(), counters);
    }

    if counters_by_name.is_empty() {
        return None;
    }

    let interfaces = counters_by_name
        .values()
        .map(|counters| {
            let previous_counters =
                previous.and_then(|snapshot| snapshot.counters_by_name.get(counters.name.as_str()));

            NetworkInterfaceMetric {
                name: counters.name.clone(),
                rx_bytes: counters.rx_bytes,
                rx_bytes_delta: previous_counters
                    .map(|previous| counters.rx_bytes.saturating_sub(previous.rx_bytes))
                    .unwrap_or(0),
                tx_bytes: counters.tx_bytes,
                tx_bytes_delta: previous_counters
                    .map(|previous| counters.tx_bytes.saturating_sub(previous.tx_bytes))
                    .unwrap_or(0),
            }
        })
        .collect();

    Some(NetworkMetrics {
        interfaces,
        snapshot: NetworkCounterSnapshot { counters_by_name },
    })
}

fn meminfo_kilobytes(contents: &str, key: &str) -> Option<u64> {
    let line = contents.lines().find(|line| line.starts_with(key))?;

    line.split_whitespace().nth(1)?.parse().ok()
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

fn unescape_mount_value(value: &str) -> String {
    value.replace("\\040", " ")
}

fn is_runtime_mount_path(path: &str) -> bool {
    matches!(path, "/dev" | "/proc" | "/run" | "/sys")
        || path.starts_with("/dev/")
        || path.starts_with("/proc/")
        || path.starts_with("/run/")
        || path.starts_with("/sys/")
}

fn filesystem_capacity(path: impl AsRef<Path>) -> Option<FilesystemCapacity> {
    let c_path = CString::new(path.as_ref().as_os_str().as_encoded_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: c_path is a valid nul-terminated path and stat points to writable memory.
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };

    if result != 0 {
        return None;
    }

    // SAFETY: statvfs returned success and initialized stat.
    let stat = unsafe { stat.assume_init() };
    let fragment_size = stat.f_frsize;

    Some(FilesystemCapacity {
        available_bytes: stat.f_bavail.saturating_mul(fragment_size),
        free_bytes: stat.f_bfree.saturating_mul(fragment_size),
        total_bytes: stat.f_blocks.saturating_mul(fragment_size),
    })
}

fn unix_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

struct MountEntry {
    filesystem_type: String,
    mount_point: String,
    source: String,
}

#[derive(Clone, Debug)]
struct NetworkCounters {
    name: String,
    rx_bytes: u64,
    tx_bytes: u64,
}

fn parse_network_interface_line(line: &str) -> Option<NetworkCounters> {
    let (name, counters) = line.split_once(':')?;
    let name = name.trim();

    if name.is_empty() {
        return None;
    }

    if name == "lo" {
        return None;
    }

    let values = counters.split_whitespace().collect::<Vec<_>>();

    Some(NetworkCounters {
        name: name.to_string(),
        rx_bytes: values.first()?.parse().ok()?,
        tx_bytes: values.get(8)?.parse().ok()?,
    })
}

fn parse_cpu_line(line: &str) -> Option<CpuCounters> {
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_string();

    if !name.starts_with("cpu") {
        return None;
    }

    Some(CpuCounters {
        name,
        user: parse_counter(parts.next())?,
        nice: parse_counter(parts.next())?,
        system: parse_counter(parts.next())?,
        idle: parse_counter(parts.next())?,
        iowait: parse_counter(parts.next()).unwrap_or(0),
        irq: parse_counter(parts.next()).unwrap_or(0),
        softirq: parse_counter(parts.next()).unwrap_or(0),
        steal: parse_counter(parts.next()).unwrap_or(0),
    })
}

fn parse_counter(value: Option<&str>) -> Option<u64> {
    value?.parse().ok()
}

#[derive(Clone, Debug)]
struct CpuCounters {
    name: String,
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuCounters {
    fn into_metric(self, previous: Option<&CpuCounters>) -> CpuCoreMetric {
        let usage_percent = self.usage_percent_since(previous);

        CpuCoreMetric {
            idle: self.idle,
            iowait: self.iowait,
            irq: self.irq,
            name: self.name,
            nice: self.nice,
            softirq: self.softirq,
            steal: self.steal,
            system: self.system,
            usage_percent,
            user: self.user,
        }
    }

    fn usage_percent_since(&self, previous: Option<&CpuCounters>) -> f64 {
        let Some(previous) = previous else {
            return 0.0;
        };
        let delta = CpuCounterDelta {
            user: self.user.saturating_sub(previous.user),
            nice: self.nice.saturating_sub(previous.nice),
            system: self.system.saturating_sub(previous.system),
            idle: self.idle.saturating_sub(previous.idle),
            iowait: self.iowait.saturating_sub(previous.iowait),
            irq: self.irq.saturating_sub(previous.irq),
            softirq: self.softirq.saturating_sub(previous.softirq),
            steal: self.steal.saturating_sub(previous.steal),
        };

        delta.usage_percent()
    }
}

struct CpuCounterDelta {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuCounterDelta {
    fn usage_percent(&self) -> f64 {
        let idle = self.idle.saturating_add(self.iowait);
        let non_idle = self
            .user
            .saturating_add(self.nice)
            .saturating_add(self.system)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal);
        let total = idle.saturating_add(non_idle);

        if total == 0 {
            0.0
        } else {
            (non_idle as f64 / total as f64) * 100.0
        }
    }
}
