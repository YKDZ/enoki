use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::enoki::v1::NetworkInterfaceMetric;

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

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n";

    #[test]
    fn proc_net_dev_excludes_loopback_and_computes_interface_deltas() {
        let previous = collect_network_metrics_from_proc_net_dev(
            &format!("{HEADER}lo: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\neth0: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0\n"),
            None,
            None,
        )
        .expect("previous counters");
        let current = collect_network_metrics_from_proc_net_dev(
            &format!("{HEADER}lo: 1500 15 0 0 0 0 0 0 2600 26 0 0 0 0 0 0\neth0: 9000 90 0 0 0 0 0 0 9000 90 0 0 0 0 0 0\n"),
            None,
            Some(&previous.snapshot),
        )
        .expect("current counters");

        assert_eq!(current.interfaces.len(), 1);
        let interface = &current.interfaces[0];
        assert_eq!(interface.name, "eth0");
        assert_eq!((interface.rx_bytes, interface.tx_bytes), (9_000, 9_000));
        assert_eq!(
            (interface.rx_bytes_delta, interface.tx_bytes_delta),
            (4_000, 2_000)
        );
    }

    #[test]
    fn known_default_routes_filter_network_interfaces() {
        let routes = collect_default_route_interfaces_from_proc_routes(
            Some("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\ndocker0 00000000 010011AC 0003 0 0 200 00000000 0 0 0\neth0 00000000 010011AC 0003 0 0 0 00000000 0 0 0\n"),
            None,
        )
        .expect("default route");
        let metrics = collect_network_metrics_from_proc_net_dev(
            &format!("{HEADER}eth0: 9 1 0 0 0 0 0 0 9 1 0 0 0 0 0 0\ndocker0: 7 1 0 0 0 0 0 0 8 1 0 0 0 0 0 0\n"),
            Some(&routes),
            None,
        )
        .expect("filtered metrics");

        assert_eq!(metrics.interfaces[0].name, "eth0");
        assert_eq!(metrics.interfaces.len(), 1);
    }

    #[test]
    fn equal_metric_ipv4_and_ipv6_default_routes_are_all_preserved() {
        let routes = collect_default_route_interfaces_from_proc_routes(
            Some("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth1 00000000 010011AC 0003 0 0 10 00000000 0 0 0\neth0 00000000 010011AC 0003 0 0 10 00000000 0 0 0\n"),
            Some("00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 0000000a 00000001 00000000 00200200 wg0\n00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n"),
        )
        .expect("default routes");

        assert_eq!(
            routes.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["eth0", "eth1", "wg0"],
        );
    }
}
