#[derive(Clone, Debug, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_meminfo_preserves_byte_units_and_linux_cache_semantics() {
        let metrics = collect_memory_metrics_from_proc_meminfo(
            "MemTotal: 2048000 kB\nMemAvailable: 1536000 kB\nBuffers: 64000 kB\nCached: 256000 kB\nSReclaimable: 32000 kB\nShmem: 16000 kB\nSwapTotal: 1024000 kB\nSwapFree: 768000 kB\n",
        )
        .expect("memory metrics");

        assert_eq!(metrics.total_bytes, 2_097_152_000);
        assert_eq!(metrics.used_bytes, 524_288_000);
        assert_eq!(metrics.cache_bytes, 344_064_000);
        assert_eq!(metrics.swap_total_bytes, 1_048_576_000);
        assert_eq!(metrics.swap_used_bytes, 262_144_000);
    }
}
