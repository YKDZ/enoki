use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

pub mod disk_health;
mod official;
pub use disk_health::collect_disk_health_metrics_from_smartctl_json;
pub use official::{
    BatteryMetrics, CpuBreakdownMetrics, CpuCounterRecord, CpuCounterSnapshot, CpuMetrics,
    DiskCounterSnapshot, LoadMetrics, MemoryMetrics, NetworkCounterSnapshot, NetworkMetrics,
    collect_cpu_metrics_from_counter_records, collect_cpu_metrics_from_proc_stat,
    collect_default_route_interfaces_from_proc_routes, collect_disk_counters_from_proc_diskstats,
    collect_disk_counters_from_proc_diskstats_at, collect_disk_metrics_from_mounts,
    collect_load_metrics_from_proc_loadavg, collect_memory_metrics_from_proc_meminfo,
    collect_network_metrics_from_proc_net_dev, collect_uptime_seconds_from_proc_uptime,
    parse_linux_proc_stat_cpu_counters,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemCapacity {
    pub available_bytes: u64,
    pub free_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CollectorId {
    Cpu,
    Memory,
    Disk,
    Network,
    Load,
    Uptime,
    Temperature,
    Battery,
    DiskHealth,
}

impl CollectorId {
    const ALL_OFFICIAL: &'static [CollectorId] = &[
        CollectorId::Cpu,
        CollectorId::Memory,
        CollectorId::Disk,
        CollectorId::Network,
        CollectorId::Load,
        CollectorId::Uptime,
        CollectorId::Temperature,
        CollectorId::Battery,
        CollectorId::DiskHealth,
    ];

    pub fn all_official() -> &'static [CollectorId] {
        Self::ALL_OFFICIAL
    }

    pub fn as_config_id(self) -> &'static str {
        match self {
            CollectorId::Cpu => "official.cpu",
            CollectorId::Memory => "official.memory",
            CollectorId::Disk => "official.disk",
            CollectorId::Network => "official.network",
            CollectorId::Load => "official.load",
            CollectorId::Uptime => "official.uptime",
            CollectorId::Temperature => "official.temperature",
            CollectorId::Battery => "official.battery",
            CollectorId::DiskHealth => "official.disk-health",
        }
    }

    pub fn from_config_id(value: &str) -> Option<Self> {
        match value {
            "official.cpu" => Some(CollectorId::Cpu),
            "official.memory" => Some(CollectorId::Memory),
            "official.disk" => Some(CollectorId::Disk),
            "official.network" => Some(CollectorId::Network),
            "official.load" => Some(CollectorId::Load),
            "official.uptime" => Some(CollectorId::Uptime),
            "official.temperature" => Some(CollectorId::Temperature),
            "official.battery" => Some(CollectorId::Battery),
            "official.disk-health" => Some(CollectorId::DiskHealth),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricsCollectionConfig {
    enabled_collectors: BTreeSet<CollectorId>,
}

impl MetricsCollectionConfig {
    pub fn all_enabled() -> Self {
        Self::from_enabled_collectors(CollectorId::all_official().iter().copied())
    }

    pub fn none_enabled() -> Self {
        Self {
            enabled_collectors: BTreeSet::new(),
        }
    }

    pub fn from_enabled_collectors(collector_ids: impl IntoIterator<Item = CollectorId>) -> Self {
        Self {
            enabled_collectors: collector_ids.into_iter().collect(),
        }
    }

    pub fn any_enabled(&self) -> bool {
        !self.enabled_collectors.is_empty()
    }

    pub fn collector_enabled(&self, collector_id: CollectorId) -> bool {
        self.enabled_collectors.contains(&collector_id)
    }

    pub fn set_collector_enabled(&mut self, collector_id: CollectorId, enabled: bool) {
        if enabled {
            self.enabled_collectors.insert(collector_id);
        } else {
            self.enabled_collectors.remove(&collector_id);
        }
    }

    pub fn enabled_collectors(&self) -> &BTreeSet<CollectorId> {
        &self.enabled_collectors
    }

    pub fn enabled_collector_config_ids(&self) -> Vec<&'static str> {
        self.enabled_collectors
            .iter()
            .map(|collector_id| collector_id.as_config_id())
            .collect()
    }
}

pub(crate) fn unix_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}
