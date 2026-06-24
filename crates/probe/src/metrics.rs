use std::{
    collections::BTreeSet,
    ffi::CString,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::protocol::enoki::v1::MetricSample;

pub mod disk_health;
mod official;
pub use disk_health::{
    DiskHealthAvailability, DiskHealthMetricCollector, DiskHealthMetricsRunner,
    collect_disk_health_metrics_from_smartctl_json, collect_disk_health_metrics_with_smartctl,
    format_disk_health_metrics_json, last_disk_health_collector_availability,
};
pub use official::{
    BatteryMetrics, CpuBreakdownMetrics, CpuCounterSnapshot, CpuMetrics, DiskCounterSnapshot,
    LoadMetrics, MemoryMetrics, NetworkCounterSnapshot, NetworkMetrics,
    collect_battery_metrics_from_sysfs, collect_cpu_metrics_from_proc_stat,
    collect_default_route_interfaces_from_proc_routes, collect_disk_counters_from_proc_diskstats,
    collect_disk_metrics_from_mounts, collect_load_metrics_from_proc_loadavg,
    collect_memory_metrics_from_proc_meminfo, collect_network_metrics_from_proc_net_dev,
    collect_temperature_celsius_from_sysfs, collect_uptime_seconds_from_proc_uptime,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorCadence {
    EveryTick,
    Every12Ticks,
    Startup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorDefinition {
    pub id: CollectorId,
    pub cadence: CollectorCadence,
}

impl CollectorDefinition {
    pub const fn new(id: CollectorId, cadence: CollectorCadence) -> Self {
        Self { id, cadence }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorCadenceSchedule {
    tick_interval: Duration,
}

impl CollectorCadenceSchedule {
    pub fn new(tick_interval: Duration) -> Self {
        Self {
            tick_interval: tick_interval.max(Duration::from_secs(1)),
        }
    }

    pub fn for_tick_interval(tick_interval: Duration) -> Self {
        Self::new(tick_interval)
    }

    pub fn for_high_frequency_interval(tick_interval: Duration) -> Self {
        Self::new(tick_interval)
    }

    pub fn for_runtime_collection_interval(tick_interval: Duration) -> Self {
        Self::new(tick_interval)
    }

    fn tick_for(&self, elapsed: Duration) -> u64 {
        let tick = elapsed.as_nanos() / self.tick_interval.as_nanos().max(1);

        tick.min(u128::from(u64::MAX)) as u64
    }
}

fn collector_is_due(
    last_collected_tick: Option<u64>,
    current_tick: u64,
    cadence: CollectorCadence,
) -> bool {
    if current_tick == 0 || last_collected_tick == Some(current_tick) {
        return false;
    }

    match cadence {
        CollectorCadence::EveryTick => true,
        CollectorCadence::Every12Ticks => current_tick.is_multiple_of(12),
        CollectorCadence::Startup => current_tick == 1 && last_collected_tick.is_none(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectorError {
    message: String,
}

impl CollectorError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CollectorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

pub trait MetricCollector {
    fn definition(&self) -> CollectorDefinition;

    fn collector_id(&self) -> CollectorId {
        self.definition().id
    }

    fn cadence(&self) -> CollectorCadence {
        self.definition().cadence
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError>;
}

struct RegisteredCollector {
    definition: CollectorDefinition,
    collector: Box<dyn MetricCollector>,
}

pub struct CollectorRegistry {
    collectors: Vec<RegisteredCollector>,
    last_collected_tick: Vec<Option<u64>>,
}

impl CollectorRegistry {
    pub fn official() -> Self {
        let mut collectors = official::collectors();
        collectors.push(Box::<DiskHealthMetricCollector>::default());

        Self::from_collectors(collectors)
    }

    pub fn from_collectors(collectors: Vec<Box<dyn MetricCollector>>) -> Self {
        let collectors = collectors
            .into_iter()
            .map(|collector| RegisteredCollector {
                definition: collector.definition(),
                collector,
            })
            .collect::<Vec<_>>();
        let last_collected_tick = vec![None; collectors.len()];

        Self {
            collectors,
            last_collected_tick,
        }
    }

    pub fn collect_due(
        &mut self,
        sequence: u64,
        elapsed: Duration,
        schedule: CollectorCadenceSchedule,
        config: &MetricsCollectionConfig,
    ) -> Option<MetricSample> {
        let mut sample = MetricSample {
            collected_at_ms: unix_time_millis(),
            sequence,
            ..MetricSample::default()
        };
        let mut produced = false;
        let current_tick = schedule.tick_for(elapsed);

        for (index, collector) in self.collectors.iter_mut().enumerate() {
            if !config.collector_enabled(collector.definition.id) {
                continue;
            }

            if !collector_is_due(
                self.last_collected_tick[index],
                current_tick,
                collector.definition.cadence,
            ) {
                continue;
            }

            let sample_before_collection = sample.clone();
            match collector.collector.collect(&mut sample) {
                Ok(true) => {
                    produced = true;
                    self.last_collected_tick[index] = Some(current_tick);
                }
                Ok(false) => {
                    self.last_collected_tick[index] = Some(current_tick);
                }
                Err(_) => {
                    sample = sample_before_collection;
                    self.last_collected_tick[index] = Some(current_tick);
                }
            }
        }

        produced.then_some(sample)
    }
}

pub struct MetricsCollector {
    elapsed: Duration,
    registry: CollectorRegistry,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self {
            elapsed: Duration::ZERO,
            registry: CollectorRegistry::official(),
        }
    }
}

impl MetricsCollector {
    pub fn from_registry(registry: CollectorRegistry) -> Self {
        Self {
            elapsed: Duration::ZERO,
            registry,
        }
    }

    pub fn collect(&mut self, sequence: u64, config: MetricsCollectionConfig) -> MetricSample {
        self.elapsed += Duration::from_secs(1);
        self.collect_due(
            sequence,
            self.elapsed,
            CollectorCadenceSchedule::for_high_frequency_interval(Duration::from_secs(1)),
            &config,
        )
        .unwrap_or_else(|| MetricSample {
            collected_at_ms: unix_time_millis(),
            sequence,
            ..MetricSample::default()
        })
    }

    pub fn collect_due(
        &mut self,
        sequence: u64,
        elapsed: Duration,
        schedule: CollectorCadenceSchedule,
        config: &MetricsCollectionConfig,
    ) -> Option<MetricSample> {
        self.elapsed = elapsed;
        self.registry
            .collect_due(sequence, elapsed, schedule, config)
    }

    pub fn collect_after(
        &mut self,
        sequence: u64,
        elapsed_since_last_collection: Duration,
        schedule: CollectorCadenceSchedule,
        config: &MetricsCollectionConfig,
    ) -> Option<MetricSample> {
        self.elapsed += elapsed_since_last_collection;
        self.registry
            .collect_due(sequence, self.elapsed, schedule, config)
    }

    pub fn advance_time(&mut self, elapsed: Duration) {
        self.elapsed += elapsed;
    }
}

pub(crate) fn filesystem_capacity(path: impl AsRef<Path>) -> Option<FilesystemCapacity> {
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

pub(crate) fn unix_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}
