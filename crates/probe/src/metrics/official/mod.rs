use crate::metrics::{CollectorDefinition, CollectorId, MetricCollector};

mod battery;
mod cpu;
mod disk;
mod load;
mod memory;
mod network;
mod temperature;
mod uptime;

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
        .map(|definition| collector_for_id(definition.id))
        .collect()
}

fn collector_for_id(collector_id: CollectorId) -> Box<dyn MetricCollector> {
    match collector_id {
        CollectorId::Cpu => Box::<cpu::CpuMetricCollector>::default(),
        CollectorId::Memory => Box::<memory::MemoryMetricCollector>::default(),
        CollectorId::Disk => Box::<disk::DiskMetricCollector>::default(),
        CollectorId::Network => Box::<network::NetworkMetricCollector>::default(),
        CollectorId::Load => Box::<load::LoadMetricCollector>::default(),
        CollectorId::Uptime => Box::<uptime::UptimeMetricCollector>::default(),
        CollectorId::Temperature => Box::<temperature::TemperatureMetricCollector>::default(),
        CollectorId::Battery => Box::<battery::BatteryMetricCollector>::default(),
        CollectorId::DiskHealth => unreachable!("Disk Health is registered outside official core"),
    }
}
