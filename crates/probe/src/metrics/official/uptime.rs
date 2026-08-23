pub fn collect_uptime_seconds_from_proc_uptime(contents: &str) -> Option<u64> {
    let uptime_seconds = contents.split_whitespace().next()?.parse::<f64>().ok()?;

    uptime_seconds.is_finite().then_some(uptime_seconds as u64)
}
