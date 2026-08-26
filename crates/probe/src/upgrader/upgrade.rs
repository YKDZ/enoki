//! Compatible Upgrade 的封闭 coordinator seam。
//!
//! 深 Implementation 位于 Probe Bootstrap；这里直接收窄其既有 Interface，
//! 不增加 pass-through runner 或第二套升级路径。

pub(super) use enoki_probe_bootstrap::install::run_compatible_upgrade as coordinate;
