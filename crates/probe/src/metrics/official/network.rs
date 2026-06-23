use std::fs;

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
    NetworkCounterSnapshot, collect_default_route_interfaces_from_proc_routes,
    collect_network_metrics_from_proc_net_dev,
};
use crate::protocol::enoki::v1::MetricSample;

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
