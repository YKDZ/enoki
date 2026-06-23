use std::fs;

use crate::metrics::{
    CollectorCadenceClass, CollectorError, MetricCollector, MetricsCollectionConfig,
    NetworkCounterSnapshot, collect_default_route_interfaces_from_proc_routes,
    collect_network_metrics_from_proc_net_dev,
};
use crate::protocol::enoki::v1::MetricSample;

#[derive(Default)]
pub struct NetworkMetricCollector {
    previous: Option<NetworkCounterSnapshot>,
}

impl MetricCollector for NetworkMetricCollector {
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::HighFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        if !config.collect_network {
            return Ok(false);
        }

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
