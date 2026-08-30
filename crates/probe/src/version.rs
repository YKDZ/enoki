const EMBEDDED_VERSION: &str = env!("ENOKI_PROBE_EMBEDDED_VERSION");
#[used]
#[unsafe(no_mangle)]
pub static ENOKI_PROBE_RELEASE_IDENTITY: &str = concat!(
    "ENOKI_PROBE_TARGET=",
    env!("ENOKI_PROBE_EMBEDDED_TARGET"),
    "\0ENOKI_PROBE_VERSION=",
    env!("ENOKI_PROBE_EMBEDDED_VERSION"),
    "\0",
);

pub fn probe_version() -> &'static str {
    // The signed-asset validator reads this marker without executing a
    // cross-architecture binary. The externally retained static preserves the
    // target/version identity in optimized, stripped release binaries.
    std::hint::black_box(ENOKI_PROBE_RELEASE_IDENTITY);
    EMBEDDED_VERSION
}
