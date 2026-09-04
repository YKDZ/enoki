//! 独立编译的 root-only Bootstrap role。

fn main() -> std::process::ExitCode {
    enoki_probe_bootstrap::activation::run_bootstrap_activate_process()
}
