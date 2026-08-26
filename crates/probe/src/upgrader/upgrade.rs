//! Compatible Upgrade 的两个 Probe 入口 Adapter。
//!
//! Companion socket 与固定 `--upgrade` CLI Adapter 都把同一个类型化 request
//! 交给 Probe Bootstrap 的唯一深 coordinator；本 Module 只封闭入口分类，
//! 不复制 authority、身份保持、激活或失败语义。

use enoki_probe_bootstrap::lifecycle::{LifecycleRequest, LifecycleResponse, LifecycleTransition};

pub(super) fn coordinate_from_companion(
    request: &LifecycleRequest,
    peer_uid: Option<u32>,
) -> LifecycleResponse {
    enter_deep_coordinator(request, peer_uid)
}

pub(super) fn coordinate_from_fixed_cli(
    request: &LifecycleRequest,
    peer_uid: Option<u32>,
) -> LifecycleResponse {
    if request.transition() != LifecycleTransition::Upgrade {
        return LifecycleResponse::not_enabled();
    }
    enter_deep_coordinator(request, peer_uid)
}

fn enter_deep_coordinator(request: &LifecycleRequest, peer_uid: Option<u32>) -> LifecycleResponse {
    enoki_probe_bootstrap::install::run_compatible_upgrade(request, peer_uid)
}
