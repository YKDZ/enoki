//! 独立、短生命周期的本机生命周期角色入口。

fn main() -> std::process::ExitCode {
    enoki_probe::run_lifecycle_companion_process()
}
