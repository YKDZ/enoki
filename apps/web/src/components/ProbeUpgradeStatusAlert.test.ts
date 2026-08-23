// @vitest-environment happy-dom

import type { ProbeUpgradeStatus } from "@enoki/api-client";
import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import ProbeUpgradeStatusAlert from "./ProbeUpgradeStatusAlert.vue";

describe("Probe Upgrade current problem", () => {
  it.each([
    ["pending", "探针升级等待中"],
    ["accepted", "探针已接收升级请求"],
    ["running", "探针升级进行中"],
  ] as const)("renders the %s current state", (state, title) => {
    const wrapper = mount(ProbeUpgradeStatusAlert, {
      props: { status: probeUpgradeStatus({ state }) },
    });

    expect(
      wrapper.get('[data-testid="probe-upgrade-status"]').text(),
    ).toContain(title);
    expect(wrapper.text()).toContain("目标探针版本：0.2.0");
    expect(wrapper.find("button").exists()).toBe(false);
  });

  it("offers a fresh confirmation for retryable failures", async () => {
    const wrapper = mount(ProbeUpgradeStatusAlert, {
      props: {
        status: failedProbeUpgradeStatus("retry_probe_upgrade"),
      },
    });

    expect(wrapper.text()).toContain("请再次确认升级");
    await wrapper.get("button").trigger("click");
    expect(wrapper.emitted("retryProbeUpgrade")).toHaveLength(1);
  });

  it.each([
    ["pending", "探针修复请求等待中"],
    ["accepted", "探针已接收修复请求"],
    ["running", "探针修复进行中"],
  ] as const)("renders the Repair %s current state", (state, title) => {
    const wrapper = mount(ProbeUpgradeStatusAlert, {
      props: {
        status: probeUpgradeStatus({ kind: "probe_repair", state }),
      },
    });
    expect(wrapper.text()).toContain(title);
  });

  it("shows the fixed local repair command only for the Hub repair disposition", () => {
    const wrapper = mount(ProbeUpgradeStatusAlert, {
      props: { status: failedProbeUpgradeStatus("probe_repair") },
    });

    expect(wrapper.text()).toContain("修复探针");
    expect(wrapper.text()).toContain("sudo enoki-probe repair");
    expect(wrapper.find("button").exists()).toBe(false);
  });

  it("keeps a manual-reinstall problem visible while leaving its single action to the Hub policy", () => {
    const wrapper = mount(ProbeUpgradeStatusAlert, {
      props: {
        status: failedProbeUpgradeStatus("manual_reinstall_required"),
      },
    });

    expect(wrapper.text()).toContain("手动重新安装探针");
    expect(wrapper.text()).toContain("Hub 验证迁移目标后");
    expect(wrapper.find("button").exists()).toBe(false);
  });

  it("does not infer a privileged action when the Hub disposition is unknown", () => {
    const wrapper = mount(ProbeUpgradeStatusAlert, {
      props: { status: failedProbeUpgradeStatus(null) },
    });

    expect(wrapper.text()).toContain("Hub 无法安全判断恢复方式");
    expect(wrapper.text()).not.toContain("需要修复探针");
    expect(wrapper.find("button").exists()).toBe(false);
    expect(wrapper.text()).not.toContain("sudo");
    expect(wrapper.text()).not.toContain("http");
  });

  it("uses a closed Repair presentation without exposing failure text", () => {
    const wrapper = mount(ProbeUpgradeStatusAlert, {
      props: {
        status: probeUpgradeStatus({
          failure: { recoveryDisposition: null },
          kind: "probe_repair",
          state: "failed",
        }),
      },
    });
    expect(wrapper.text()).toContain("探针修复失败：未知问题");
    expect(wrapper.text()).not.toContain("sudo");
  });

  it.each([
    ["probe_repair", "探针修复失败：需要重新修复探针", true],
    [
      "manual_reinstall_required",
      "探针修复失败：需要手动重新安装探针",
      false,
    ],
    [null, "探针修复失败：未知问题", false],
  ] as const)(
    "renders the fixed failed Repair presentation for %s",
    (recoveryDisposition, title, showsCommand) => {
      const wrapper = mount(ProbeUpgradeStatusAlert, {
        props: {
          status: probeUpgradeStatus({
            failure: { recoveryDisposition },
            kind: "probe_repair",
            state: "failed",
          }),
        },
      });
      expect(wrapper.text()).toContain(title);
      expect(wrapper.text()).not.toContain("探针升级失败");
      expect(wrapper.text().includes("sudo enoki-probe repair")).toBe(
        showsCommand,
      );
      expect(wrapper.text()).not.toContain("server-private-failure");
    },
  );

  it.each(["succeeded", "canceled", "superseded"] as const)(
    "does not render the historical %s terminal state inline",
    (state) => {
      const wrapper = mount(ProbeUpgradeStatusAlert, {
        props: { status: probeUpgradeStatus({ state }) },
      });

      expect(
        wrapper.find('[data-testid="probe-upgrade-status"]').exists(),
      ).toBe(false);
    },
  );
});

function failedProbeUpgradeStatus(
  recoveryDisposition: NonNullable<
    ProbeUpgradeStatus["failure"]
  >["recoveryDisposition"],
) {
  return probeUpgradeStatus({
    failure: { recoveryDisposition },
    state: "failed",
  });
}

function probeUpgradeStatus(
  overrides: Partial<ProbeUpgradeStatus>,
): ProbeUpgradeStatus {
  return {
    acceptedAtMs: null,
    completedAtMs: null,
    createdAtMs: 1_725_000_000_000,
    failure: null,
    id: 9,
    kind: "probe_upgrade",
    runningAtMs: null,
    state: "pending",
    targetProbeVersion: "0.2.0",
    updatedAtMs: 1_725_000_000_000,
    ...overrides,
  };
}
