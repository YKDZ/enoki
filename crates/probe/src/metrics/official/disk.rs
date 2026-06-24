use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, FilesystemCapacity,
    MetricCollector, filesystem_capacity, unix_time_millis,
};
use crate::protocol::enoki::v1::{DiskUsageMetric, MetricSample};

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Disk, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct DiskMetricCollector {
    previous: Option<DiskCounterSnapshot>,
}

impl MetricCollector for DiskMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        let disk_counters = fs::read_to_string("/proc/diskstats")
            .ok()
            .and_then(|contents| collect_disk_counters_from_proc_diskstats(&contents));
        let disks = fs::read_to_string("/proc/mounts")
            .map(|contents| {
                collect_disk_metrics_from_mounts(
                    &contents,
                    |mount_point| filesystem_capacity(mount_point),
                    disk_counters.as_ref(),
                    self.previous.as_ref(),
                )
            })
            .unwrap_or_default();
        if let Some(snapshot) = disk_counters {
            self.previous = Some(snapshot);
        }
        let produced = !disks.is_empty();
        sample.disks = disks;

        Ok(produced)
    }
}

const EXCLUDED_FILESYSTEMS: &[&str] = &[
    "cgroup", "cgroup2", "debugfs", "devtmpfs", "fusectl", "overlay", "proc", "squashfs", "sysfs",
    "tmpfs", "tracefs",
];

#[derive(Clone, Debug, Default)]
pub struct DiskCounterSnapshot {
    collected_at_ms: i64,
    counters_by_name: BTreeMap<String, DiskCounters>,
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
