/**
 * 当前单 Probe 产品的固定安装包角色清单。
 *
 * Bootstrap 仍由更窄的构建环境产出，但这里只把它视为同一个公开
 * Probe Asset Bundle 的固定入口，不能从调用方输入推导路径或角色。
 */
export const probeBundleComponentProfiles = Object.freeze({
  probe: Object.freeze({
    path: "enoki-probe",
    permissionProfile: "probe-v4",
    resourceContract: "hub-reporting-v1",
  }),
  "observation-runtime": Object.freeze({
    path: "enoki-observation-runtime",
    permissionProfile: "observation-runtime-v4",
    resourceContract: "official-observation-v2",
  }),
  "system-state-provider": Object.freeze({
    path: "enoki-cpu-resource-provider",
    permissionProfile: "system-state-provider-v5",
    resourceContract: "system-state-v3",
  }),
  "disk-health-provider": Object.freeze({
    path: "enoki-disk-health-resource-provider",
    permissionProfile: "disk-health-provider-v3",
    resourceContract: "disk-health-v1",
  }),
  "lifecycle-companion": Object.freeze({
    path: "enoki-probe-lifecycle-companion",
    permissionProfile: "lifecycle-companion-v1",
    resourceContract: "local-lifecycle-v1",
  }),
});

export const probeBundledBootstrapAssets = Object.freeze([
  Object.freeze({
    archivePath: "bootstrap/enoki-probe-bootstrap-acquire",
    bootstrapBuildRole: "acquirer",
    key: "acquirer",
    permissionProfile: "bootstrap-acquirer-v1",
    role: "bootstrap-acquirer",
  }),
  Object.freeze({
    archivePath: "bootstrap/enoki-probe-bootstrap-activate",
    bootstrapBuildRole: "activator",
    key: "activator",
    permissionProfile: "bootstrap-activator-v1",
    role: "bootstrap-activator",
  }),
]);
