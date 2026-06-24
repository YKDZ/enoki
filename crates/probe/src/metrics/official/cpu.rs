use std::{collections::BTreeMap, fs};

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
};
use crate::protocol::enoki::v1::{CpuCoreMetric, MetricSample};

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Cpu, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct CpuMetricCollector {
    previous: Option<CpuCounterSnapshot>,
}

impl MetricCollector for CpuMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        let Some(metrics) = fs::read_to_string("/proc/stat").ok().and_then(|contents| {
            collect_cpu_metrics_from_proc_stat(&contents, self.previous.as_ref())
        }) else {
            return Ok(false);
        };

        self.previous = Some(metrics.snapshot.clone());
        sample.cpu_cores = metrics.cores;
        sample.cpu_percent = Some(metrics.aggregate_percent);
        sample.cpu_idle_percent = Some(metrics.breakdown.idle_percent);
        sample.cpu_iowait_percent = Some(metrics.breakdown.iowait_percent);
        sample.cpu_steal_percent = Some(metrics.breakdown.steal_percent);
        sample.cpu_system_percent = Some(metrics.breakdown.system_percent);
        sample.cpu_user_percent = Some(metrics.breakdown.user_percent);

        Ok(true)
    }
}

#[derive(Debug)]
pub struct CpuMetrics {
    pub aggregate_percent: f64,
    pub breakdown: CpuBreakdownMetrics,
    pub cores: Vec<CpuCoreMetric>,
    pub snapshot: CpuCounterSnapshot,
}

#[derive(Clone, Debug, Default)]
pub struct CpuCounterSnapshot {
    counters_by_name: BTreeMap<String, CpuCounters>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuBreakdownMetrics {
    pub idle_percent: f64,
    pub iowait_percent: f64,
    pub steal_percent: f64,
    pub system_percent: f64,
    pub user_percent: f64,
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
