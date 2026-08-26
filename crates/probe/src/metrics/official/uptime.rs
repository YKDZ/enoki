pub fn collect_uptime_seconds_from_proc_uptime(contents: &str) -> Option<u64> {
    let uptime_seconds = contents.split_whitespace().next()?.parse::<f64>().ok()?;

    uptime_seconds.is_finite().then_some(uptime_seconds as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_uptime_reports_whole_seconds() {
        assert_eq!(
            collect_uptime_seconds_from_proc_uptime("12345.67 89012.34"),
            Some(12_345),
        );
    }
}
