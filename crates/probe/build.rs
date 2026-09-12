use std::env;

fn main() {
    let target = env::var("TARGET").expect("Cargo provides TARGET to build scripts");
    let version = env::var("ENOKI_PROBE_VERSION").unwrap_or_else(|_| "dev".to_string());
    let boot_probe = env::var("ENOKI_BOOT_PROBE").as_deref() == Ok("1");

    println!("cargo:rerun-if-env-changed=ENOKI_PROBE_VERSION");
    println!("cargo:rerun-if-env-changed=ENOKI_BOOT_PROBE");
    println!("cargo:rustc-env=ENOKI_PROBE_EMBEDDED_TARGET={target}");
    println!("cargo:rustc-env=ENOKI_PROBE_EMBEDDED_VERSION={version}");
    if boot_probe {
        println!(
            "cargo:rustc-link-arg-bin=enoki-probe-lifecycle-companion=-Wl,--undefined=enoki_bootstrap_build_identity"
        );
    }
}
