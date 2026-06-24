use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
};
use crate::protocol::enoki::v1::{MetricSample, NetworkInterfaceMetric};

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Network, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct NetworkMetricCollector {
    previous: Option<NetworkCounterSnapshot>,
}

impl MetricCollector for NetworkMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        let network = fs::read_to_string("/proc/net/dev")
            .ok()
            .and_then(|contents| {
                let default_route_interfaces = collect_default_route_interfaces_from_proc_routes(
                    fs::read_to_string("/proc/net/route").ok().as_deref(),
                    fs::read_to_string("/proc/net/ipv6_route").ok().as_deref(),
                );

                collect_network_metrics_from_proc_net_dev(
                    &contents,
                    default_route_interfaces.as_ref(),
                    self.previous.as_ref(),
                )
            });
        let Some(metrics) = network else {
            return Ok(false);
        };
        self.previous = Some(metrics.snapshot);
        sample.network_interfaces = metrics.interfaces;

        Ok(!sample.network_interfaces.is_empty())
    }
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
