const DEVELOPMENT_VERSION: &str = "dev";

pub fn probe_version() -> &'static str {
    option_env!("ENOKI_PROBE_VERSION").unwrap_or(DEVELOPMENT_VERSION)
}
