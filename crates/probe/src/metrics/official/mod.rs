use crate::metrics::{CollectorDefinition, CollectorId, MetricCollector};

mod battery;
mod cpu;
mod disk;
mod load;
mod memory;
mod network;
mod temperature;
mod uptime;

pub use battery::{BatteryMetrics, collect_battery_metrics_from_sysfs};
pub use cpu::{
    CpuBreakdownMetrics, CpuCounterRecord, CpuCounterSnapshot, CpuMetrics,
    collect_cpu_metrics_from_counter_records, collect_cpu_metrics_from_proc_stat,
    parse_linux_proc_stat_cpu_counters,
};
pub use disk::{
    DiskCounterSnapshot, collect_disk_counters_from_proc_diskstats,
    collect_disk_metrics_from_mounts,
};
pub use load::{LoadMetrics, collect_load_metrics_from_proc_loadavg};
pub use memory::{MemoryMetrics, collect_memory_metrics_from_proc_meminfo};
pub use network::{
    NetworkCounterSnapshot, NetworkMetrics, collect_default_route_interfaces_from_proc_routes,
    collect_network_metrics_from_proc_net_dev,
};
pub use temperature::collect_temperature_celsius_from_sysfs;
pub use uptime::collect_uptime_seconds_from_proc_uptime;

pub const COLLECTOR_DEFINITIONS: &[CollectorDefinition] = &[
    cpu::DEFINITION,
    memory::DEFINITION,
    disk::DEFINITION,
    network::DEFINITION,
    load::DEFINITION,
    uptime::DEFINITION,
    temperature::DEFINITION,
    battery::DEFINITION,
];

pub fn collectors() -> Vec<Box<dyn MetricCollector>> {
    COLLECTOR_DEFINITIONS
        .iter()
        // 这些 Collector 已迁入 Observation Runtime，Probe 不得直接读取其资源。
        .filter(|definition| {
            !matches!(
                definition.id,
                CollectorId::Cpu | CollectorId::Memory | CollectorId::Load | CollectorId::Uptime
            )
        })
        .map(|definition| collector_for_id(definition.id))
        .collect()
}

fn collector_for_id(collector_id: CollectorId) -> Box<dyn MetricCollector> {
    match collector_id {
        CollectorId::Cpu => unreachable!("CPU is owned by the Observation Runtime"),
        CollectorId::Memory => unreachable!("Memory is owned by the Observation Runtime"),
        CollectorId::Disk => Box::<disk::DiskMetricCollector>::default(),
        CollectorId::Network => Box::<network::NetworkMetricCollector>::default(),
        CollectorId::Load => unreachable!("Load is owned by the Observation Runtime"),
        CollectorId::Uptime => unreachable!("Uptime is owned by the Observation Runtime"),
        CollectorId::Temperature => Box::<temperature::TemperatureMetricCollector>::default(),
        CollectorId::Battery => Box::<battery::BatteryMetricCollector>::default(),
        CollectorId::DiskHealth => unreachable!("Disk Health is registered outside official core"),
    }
}
