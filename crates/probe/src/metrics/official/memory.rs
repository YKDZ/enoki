use std::fs;

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorError, CollectorId, MetricCollector,
};
use crate::protocol::enoki::v1::MetricSample;

pub const DEFINITION: CollectorDefinition =
    CollectorDefinition::new(CollectorId::Memory, CollectorCadence::EveryTick);

#[derive(Default)]
pub struct MemoryMetricCollector;

impl MetricCollector for MemoryMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        DEFINITION
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        let Some(metrics) = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|contents| collect_memory_metrics_from_proc_meminfo(&contents))
        else {
            return Ok(false);
        };

        sample.memory_cache_bytes = Some(metrics.cache_bytes);
        sample.memory_total_bytes = Some(metrics.total_bytes);
        sample.memory_used_bytes = Some(metrics.used_bytes);
        sample.swap_total_bytes = Some(metrics.swap_total_bytes);
        sample.swap_used_bytes = Some(metrics.swap_used_bytes);

        Ok(true)
    }
}

#[derive(Debug)]
pub struct MemoryMetrics {
    pub cache_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub total_bytes: u64,
    pub used_bytes: u64,
}

pub fn collect_memory_metrics_from_proc_meminfo(contents: &str) -> Option<MemoryMetrics> {
    let total_bytes = meminfo_kilobytes(contents, "MemTotal:")?.saturating_mul(1024);
    let available_bytes = meminfo_kilobytes(contents, "MemAvailable:")?.saturating_mul(1024);
    let buffers_bytes = meminfo_kilobytes(contents, "Buffers:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let cached_bytes = meminfo_kilobytes(contents, "Cached:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let sreclaimable_bytes = meminfo_kilobytes(contents, "SReclaimable:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let shmem_bytes = meminfo_kilobytes(contents, "Shmem:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let swap_total_bytes = meminfo_kilobytes(contents, "SwapTotal:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let swap_free_bytes = meminfo_kilobytes(contents, "SwapFree:")
        .unwrap_or(0)
        .saturating_mul(1024);

    Some(MemoryMetrics {
        cache_bytes: buffers_bytes
            .saturating_add(cached_bytes)
            .saturating_add(sreclaimable_bytes)
            .saturating_sub(shmem_bytes),
        swap_total_bytes,
        swap_used_bytes: swap_total_bytes.saturating_sub(swap_free_bytes),
        total_bytes,
        used_bytes: total_bytes.saturating_sub(available_bytes),
    })
}

fn meminfo_kilobytes(contents: &str, key: &str) -> Option<u64> {
    let line = contents.lines().find(|line| line.starts_with(key))?;

    line.split_whitespace().nth(1)?.parse().ok()
}
