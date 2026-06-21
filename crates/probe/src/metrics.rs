use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs,
    path::{Path, PathBuf},
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
    pub breakdown: CpuBreakdownMetrics,
    pub cores: Vec<CpuCoreMetric>,
    pub snapshot: CpuCounterSnapshot,
}

#[derive(Debug)]
pub struct MemoryMetrics {
    pub cache_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
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

#[derive(Clone, Debug, Default)]
pub struct DiskCounterSnapshot {
    collected_at_ms: i64,
    counters_by_name: BTreeMap<String, DiskCounters>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuBreakdownMetrics {
    pub idle_percent: f64,
    pub iowait_percent: f64,
    pub steal_percent: f64,
    pub system_percent: f64,
    pub user_percent: f64,
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
    previous_disk: Option<DiskCounterSnapshot>,
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
            let disk_counters = fs::read_to_string("/proc/diskstats")
                .ok()
                .and_then(|contents| collect_disk_counters_from_proc_diskstats(&contents));
            let disks = fs::read_to_string("/proc/mounts")
                .map(|contents| {
                    collect_disk_metrics_from_mounts(
                        &contents,
                        |mount_point| filesystem_capacity(mount_point),
                        disk_counters.as_ref(),
                        self.previous_disk.as_ref(),
                    )
                })
                .unwrap_or_default();
            if let Some(snapshot) = disk_counters {
                self.previous_disk = Some(snapshot);
            }
            disks
        } else {
            Vec::new()
        };
        let temperature_celsius = collect_temperature_celsius_from_sysfs("/sys/class/hwmon");
        let battery = collect_battery_metrics_from_sysfs("/sys/class/power_supply");
        let network_interfaces = if config.collect_network {
            let network = fs::read_to_string("/proc/net/dev")
                .ok()
                .and_then(|contents| {
                    let default_route_interfaces =
                        collect_default_route_interfaces_from_proc_routes(
                            fs::read_to_string("/proc/net/route").ok().as_deref(),
                            fs::read_to_string("/proc/net/ipv6_route").ok().as_deref(),
                        );

                    collect_network_metrics_from_proc_net_dev(
                        &contents,
                        default_route_interfaces.as_ref(),
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
            cpu_idle_percent: cpu.as_ref().map(|metrics| metrics.breakdown.idle_percent),
            cpu_iowait_percent: cpu.as_ref().map(|metrics| metrics.breakdown.iowait_percent),
            cpu_steal_percent: cpu.as_ref().map(|metrics| metrics.breakdown.steal_percent),
            cpu_system_percent: cpu.as_ref().map(|metrics| metrics.breakdown.system_percent),
            cpu_user_percent: cpu.as_ref().map(|metrics| metrics.breakdown.user_percent),
            disks,
            load_1: load.as_ref().map(|metrics| metrics.one),
            load_5: load.as_ref().map(|metrics| metrics.five),
            load_15: load.as_ref().map(|metrics| metrics.fifteen),
            battery_percent: battery.as_ref().map(|metrics| metrics.percent),
            battery_state: battery.as_ref().map(|metrics| metrics.state.clone()),
            memory_cache_bytes: memory.as_ref().map(|metrics| metrics.cache_bytes),
            memory_total_bytes: memory.as_ref().map(|metrics| metrics.total_bytes),
            memory_used_bytes: memory.as_ref().map(|metrics| metrics.used_bytes),
            network_interfaces,
            sequence,
            swap_total_bytes: memory.as_ref().map(|metrics| metrics.swap_total_bytes),
            swap_used_bytes: memory.as_ref().map(|metrics| metrics.swap_used_bytes),
            temperature_celsius,
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
        breakdown: aggregate.breakdown_since(aggregate_previous),
        cores,
        snapshot: CpuCounterSnapshot { counters_by_name },
    })
}

pub fn collect_memory_metrics_from_proc_meminfo(contents: &str) -> Option<MemoryMetrics> {
    let total_bytes = meminfo_kilobytes(contents, "MemTotal:")?.saturating_mul(1024);
    let available_bytes = meminfo_kilobytes(contents, "MemAvailable:")?.saturating_mul(1024);
    let buffers_bytes = meminfo_kilobytes(contents, "Buffers:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let cached_bytes = meminfo_kilobytes(contents, "Cached:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let sreclaimable_bytes = meminfo_kilobytes(contents, "SReclaimable:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let shmem_bytes = meminfo_kilobytes(contents, "Shmem:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let swap_total_bytes = meminfo_kilobytes(contents, "SwapTotal:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let swap_free_bytes = meminfo_kilobytes(contents, "SwapFree:")
        .unwrap_or(0)
        .saturating_mul(1024);

    Some(MemoryMetrics {
        cache_bytes: buffers_bytes
            .saturating_add(cached_bytes)
            .saturating_add(sreclaimable_bytes)
            .saturating_sub(shmem_bytes),
        swap_total_bytes,
        swap_used_bytes: swap_total_bytes.saturating_sub(swap_free_bytes),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatteryMetrics {
    pub percent: u32,
    pub state: String,
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

pub fn collect_disk_metrics_from_mounts(
    contents: &str,
    capacity_for_mount: impl Fn(&str) -> Option<FilesystemCapacity>,
    current_counters: Option<&DiskCounterSnapshot>,
    previous_counters: Option<&DiskCounterSnapshot>,
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
        let counters = current_counters.and_then(|snapshot| {
            snapshot
                .counters_by_name
                .get(block_device_name(&mount.source)?.as_str())
        });
        let previous = counters.and_then(|counters| {
            previous_counters.and_then(|snapshot| {
                snapshot
                    .counters_by_name
                    .get(counters.name.as_str())
                    .map(|previous| (snapshot.collected_at_ms, previous))
            })
        });
        let io = counters.map(|counters| counters.io_since(current_counters, previous));

        disks_by_mount_point.insert(
            mount.mount_point.clone(),
            DiskUsageMetric {
                available_bytes: capacity.available_bytes,
                filesystem_type: mount.filesystem_type,
                io_utilization_percent: io.map(|io| io.io_utilization_percent),
                mount_point: mount.mount_point,
                read_await_ms: io.map(|io| io.read_await_ms),
                read_bytes_delta: io.map(|io| io.read_bytes_delta).unwrap_or(0),
                total_bytes: capacity.total_bytes,
                used_bytes: capacity.total_bytes.saturating_sub(capacity.free_bytes),
                weighted_io_percent: io.map(|io| io.weighted_io_percent),
                write_await_ms: io.map(|io| io.write_await_ms),
                write_bytes_delta: io.map(|io| io.write_bytes_delta).unwrap_or(0),
            },
        );
    }

    disks_by_mount_point.into_values().collect()
}

pub fn collect_disk_counters_from_proc_diskstats(contents: &str) -> Option<DiskCounterSnapshot> {
    let counters_by_name = contents
        .lines()
        .filter_map(parse_diskstats_line)
        .map(|counters| (counters.name.clone(), counters))
        .collect::<BTreeMap<_, _>>();

    (!counters_by_name.is_empty()).then_some(DiskCounterSnapshot {
        collected_at_ms: unix_time_millis(),
        counters_by_name,
    })
}

pub fn collect_network_metrics_from_proc_net_dev(
    contents: &str,
    included_interfaces: Option<&BTreeSet<String>>,
    previous: Option<&NetworkCounterSnapshot>,
) -> Option<NetworkMetrics> {
    let mut counters_by_name = BTreeMap::new();

    for line in contents.lines() {
        let Some(counters) = parse_network_interface_line(line) else {
            continue;
        };
        if let Some(included_interfaces) = included_interfaces
            && !included_interfaces.contains(&counters.name)
        {
            continue;
        }

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

pub fn collect_default_route_interfaces_from_proc_routes(
    ipv4_route: Option<&str>,
    ipv6_route: Option<&str>,
) -> Option<BTreeSet<String>> {
    let mut interfaces = BTreeSet::new();
    if let Some(ipv4_route) = ipv4_route {
        collect_ipv4_default_route_interfaces(ipv4_route, &mut interfaces);
    }

    if let Some(ipv6_route) = ipv6_route {
        collect_ipv6_default_route_interfaces(ipv6_route, &mut interfaces);
    }

    (!interfaces.is_empty()).then_some(interfaces)
}

fn collect_ipv4_default_route_interfaces(contents: &str, interfaces: &mut BTreeSet<String>) {
    let mut best_metric: Option<u32> = None;
    let mut best_interfaces = BTreeSet::new();

    for line in contents.lines().skip(1) {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        let Some(interface) = columns.first() else {
            continue;
        };
        let Some(destination) = columns.get(1) else {
            continue;
        };
        let metric = columns
            .get(6)
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(u32::MAX);

        if *destination != "00000000" || *interface == "lo" {
            continue;
        }

        match best_metric {
            None => {
                best_metric = Some(metric);
                best_interfaces.insert((*interface).to_string());
            }
            Some(current) if metric < current => {
                best_metric = Some(metric);
                best_interfaces.clear();
                best_interfaces.insert((*interface).to_string());
            }
            Some(current) if metric == current => {
                best_interfaces.insert((*interface).to_string());
            }
            Some(_) => {}
        }
    }

    interfaces.extend(best_interfaces);
}

fn collect_ipv6_default_route_interfaces(contents: &str, interfaces: &mut BTreeSet<String>) {
    let mut best_metric: Option<u32> = None;
    let mut best_interfaces = BTreeSet::new();

    for line in contents.lines() {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        let Some(destination) = columns.first() else {
            continue;
        };
        let Some(prefix_length) = columns.get(1) else {
            continue;
        };
        let Some(interface) = columns.last() else {
            continue;
        };
        let metric = columns
            .get(5)
            .and_then(|value| u32::from_str_radix(value, 16).ok())
            .unwrap_or(u32::MAX);

        if *destination != "00000000000000000000000000000000"
            || *prefix_length != "00"
            || *interface == "lo"
        {
            continue;
        }

        match best_metric {
            None => {
                best_metric = Some(metric);
                best_interfaces.insert((*interface).to_string());
            }
            Some(current) if metric < current => {
                best_metric = Some(metric);
                best_interfaces.clear();
                best_interfaces.insert((*interface).to_string());
            }
            Some(current) if metric == current => {
                best_interfaces.insert((*interface).to_string());
            }
            Some(_) => {}
        }
    }

    interfaces.extend(best_interfaces);
}

fn meminfo_kilobytes(contents: &str, key: &str) -> Option<u64> {
    let line = contents.lines().find(|line| line.starts_with(key))?;

    line.split_whitespace().nth(1)?.parse().ok()
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

fn block_device_name(source: &str) -> Option<String> {
    if !source.starts_with("/dev/") {
        return None;
    }

    let name = Path::new(source).file_name()?.to_str()?.trim();
    (!name.is_empty()).then_some(name.to_string())
}

#[derive(Clone, Debug)]
pub struct DiskCounters {
    name: String,
    read_bytes: u64,
    read_count: u64,
    read_time_ms: u64,
    write_bytes: u64,
    write_count: u64,
    write_time_ms: u64,
    io_time_ms: u64,
    weighted_io_time_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct DiskIoMetrics {
    io_utilization_percent: f64,
    read_await_ms: f64,
    read_bytes_delta: u64,
    weighted_io_percent: f64,
    write_await_ms: f64,
    write_bytes_delta: u64,
}

impl DiskCounters {
    fn io_since(
        &self,
        current_snapshot: Option<&DiskCounterSnapshot>,
        previous: Option<(i64, &DiskCounters)>,
    ) -> DiskIoMetrics {
        let (Some(current_snapshot), Some((previous_collected_at_ms, previous))) =
            (current_snapshot, previous)
        else {
            return DiskIoMetrics::default();
        };
        let elapsed_ms =
            (current_snapshot.collected_at_ms - previous_collected_at_ms).max(0) as u64;

        let read_count_delta = self.read_count.saturating_sub(previous.read_count);
        let write_count_delta = self.write_count.saturating_sub(previous.write_count);

        DiskIoMetrics {
            io_utilization_percent: percent_from_delta(
                self.io_time_ms.saturating_sub(previous.io_time_ms),
                elapsed_ms,
            ),
            read_await_ms: average_ms(
                self.read_time_ms.saturating_sub(previous.read_time_ms),
                read_count_delta,
            ),
            read_bytes_delta: self.read_bytes.saturating_sub(previous.read_bytes),
            weighted_io_percent: percent_from_delta(
                self.weighted_io_time_ms
                    .saturating_sub(previous.weighted_io_time_ms),
                elapsed_ms,
            ),
            write_await_ms: average_ms(
                self.write_time_ms.saturating_sub(previous.write_time_ms),
                write_count_delta,
            ),
            write_bytes_delta: self.write_bytes.saturating_sub(previous.write_bytes),
        }
    }
}

fn average_ms(total_ms: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        total_ms as f64 / count as f64
    }
}

fn percent_from_delta(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (value as f64 / total as f64) * 100.0
    }
}

fn parse_diskstats_line(line: &str) -> Option<DiskCounters> {
    let columns = line.split_whitespace().collect::<Vec<_>>();

    Some(DiskCounters {
        name: columns.get(2)?.to_string(),
        read_count: columns.get(3)?.parse().ok()?,
        read_bytes: columns.get(5)?.parse::<u64>().ok()?.saturating_mul(512),
        read_time_ms: columns.get(6)?.parse().ok()?,
        write_count: columns.get(7)?.parse().ok()?,
        write_bytes: columns.get(9)?.parse::<u64>().ok()?.saturating_mul(512),
        write_time_ms: columns.get(10)?.parse().ok()?,
        io_time_ms: columns.get(12)?.parse().ok()?,
        weighted_io_time_ms: columns.get(13)?.parse().ok()?,
    })
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
        let delta = self.delta_since(previous);

        delta.usage_percent()
    }

    fn breakdown_since(&self, previous: Option<&CpuCounters>) -> CpuBreakdownMetrics {
        let Some(previous) = previous else {
            return CpuBreakdownMetrics::default();
        };
        let delta = self.delta_since(previous);

        CpuBreakdownMetrics {
            idle_percent: delta.percent(delta.idle),
            iowait_percent: delta.percent(delta.iowait),
            steal_percent: delta.percent(delta.steal),
            system_percent: delta.percent(
                delta
                    .system
                    .saturating_add(delta.irq)
                    .saturating_add(delta.softirq),
            ),
            user_percent: delta.percent(delta.user.saturating_add(delta.nice)),
        }
    }

    fn delta_since(&self, previous: &CpuCounters) -> CpuCounterDelta {
        CpuCounterDelta {
            user: self.user.saturating_sub(previous.user),
            nice: self.nice.saturating_sub(previous.nice),
            system: self.system.saturating_sub(previous.system),
            idle: self.idle.saturating_sub(previous.idle),
            iowait: self.iowait.saturating_sub(previous.iowait),
            irq: self.irq.saturating_sub(previous.irq),
            softirq: self.softirq.saturating_sub(previous.softirq),
            steal: self.steal.saturating_sub(previous.steal),
        }
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

    fn total(&self) -> u64 {
        self.user
            .saturating_add(self.nice)
            .saturating_add(self.system)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal)
    }

    fn percent(&self, value: u64) -> f64 {
        let total = self.total();

        if total == 0 {
            0.0
        } else {
            (value as f64 / total as f64) * 100.0
        }
    }
}
