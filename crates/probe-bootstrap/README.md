# Probe Bootstrap

`enoki-probe-bootstrap` 是 Probe 首次安装的最小信任入口。它不单独分发：每个目标平台只有一个签名的 Probe Asset Bundle，包内固定包含 `probe`、`observation-runtime`、`system-state-provider`、`bootstrap-acquirer` 与 `bootstrap-activator` 五个同版本角色；每个运行角色同时绑定固定权限配置与资源合同。为兼容既有 schema 3 安装路径，`system-state-provider` 角色仍使用 `enoki-cpu-resource-provider` 二进制与对应 unit/socket 文件名；签名清单中的角色和资源合同以 `system-state-provider/system-state-v1` 为准。

管理员先从 GitHub Release 取得静态 recipe 与公开 recipe record，核对 recipe 版本、字节数、SHA-256、Probe Distribution Trust Root 指纹、目标平台及 Probe Asset Bundle Version。非 root recipe 从 Hub 下载一个目标平台安装包，验证离线根、委派、签名清单、归档 receipt 和完整角色 closure；验证后的 acquirer 字节直接进入 sealed memfd，并由绑定该 FD 的 `/proc/self/fd` 路径执行，不会落入用户可写 pathname 后再重读。

Verified acquirer 从同一个私有归档复验全部角色，把 verified activator 封存在不可写 memfd，并通过私有 socket/FD handoff 交给 `sudo`。root activator 不联网，不接收下载 URL、目标路径或可选 role；它复验 handoff、activator、acquirer 与 Probe 的精确 receipt，再把五个固定角色放入同一 `ActivationLock` 与 `TransactionJournal` 完成 no-replace 发布、父目录 fsync、失败回滚和重启恢复。Enrollment Token 始终只经 stdin 传递，不进入 root argv、环境或诊断。

旧清单 `cpu-provider/cpu-counters-v1` 与当前清单的精确角色闭包不兼容：历史 verifier 会拒绝当前候选，当前 verifier 也会拒绝旧合同或 mixed manifest。按照 ADR-0077，这类 source-to-target 边界必须在 Release Verification 前由签名的 Release Transition Contract 声明为 `replacement-required`，经既有 Probe Replacement Migration 完成；不得把它提交为原地 Probe Upgrade，也不得通过放宽当前清单闭包伪造兼容性。
