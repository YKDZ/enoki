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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_loadavg_preserves_all_three_linux_load_windows() {
        let load = collect_load_metrics_from_proc_loadavg("0.12 0.34 0.56 1/234 5678")
            .expect("load metrics");

        assert_eq!(
            load,
            LoadMetrics {
                one: 0.12,
                five: 0.34,
                fifteen: 0.56
            }
        );
    }
}
