#[derive(Clone, Debug, PartialEq)]
pub struct LoadMetrics {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

pub fn collect_load_metrics_from_proc_loadavg(contents: &str) -> Option<LoadMetrics> {
    let mut parts = contents.split_whitespace();

    Some(LoadMetrics {
        one: parts.next()?.parse().ok()?,
        five: parts.next()?.parse().ok()?,
        fifteen: parts.next()?.parse().ok()?,
    })
}
