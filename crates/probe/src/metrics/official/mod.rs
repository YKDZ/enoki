use crate::metrics::MetricCollector;

mod battery;
mod cpu;
mod disk;
mod load;
mod memory;
mod network;
mod temperature;
mod uptime;

pub fn collectors() -> Vec<Box<dyn MetricCollector>> {
    vec![
        Box::<cpu::CpuMetricCollector>::default(),
        Box::<memory::MemoryMetricCollector>::default(),
        Box::<disk::DiskMetricCollector>::default(),
        Box::<network::NetworkMetricCollector>::default(),
        Box::<load::LoadMetricCollector>::default(),
        Box::<uptime::UptimeMetricCollector>::default(),
        Box::<temperature::TemperatureMetricCollector>::default(),
        Box::<battery::BatteryMetricCollector>::default(),
    ]
}
