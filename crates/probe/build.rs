use std::env;

fn main() {
    let target = env::var("TARGET").expect("Cargo provides TARGET to build scripts");
    let version = env::var("ENOKI_PROBE_VERSION").unwrap_or_else(|_| "dev".to_string());

    println!("cargo:rerun-if-env-changed=ENOKI_PROBE_VERSION");
    println!("cargo:rustc-env=ENOKI_PROBE_EMBEDDED_TARGET={target}");
    println!("cargo:rustc-env=ENOKI_PROBE_EMBEDDED_VERSION={version}");
}
