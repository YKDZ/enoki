// @vitest-environment happy-dom

import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it } from "vitest";

import ProbeUpgradeAllDialog from "./ProbeUpgradeAllDialog.vue";

describe("Probe Upgrade all confirmation", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("confirms one fixed all-active-Host scope without a browser Host selection", async () => {
    const wrapper = mount(ProbeUpgradeAllDialog, {
      attachTo: document.body,
      props: { isSubmitting: false, open: false },
    });

    await wrapper.get("button").trigger("click");
    expect(wrapper.emitted("update:open")).toEqual([[true]]);
    await wrapper.setProps({ open: true });
    const dialog = document.querySelector(
      '[data-testid="probe-upgrade-all-dialog"]',
    );
    expect(dialog?.textContent).toContain("全部活动主机");
    expect(dialog?.textContent).toContain("不受当前分页、排序或过滤影响");
    expect(dialog?.textContent).not.toContain("预览");

    const confirm = [...document.querySelectorAll("button")].find((button) =>
      button.textContent?.includes("确认升级全部探针"),
    );
    await confirm?.click();
    expect(wrapper.emitted("confirm")).toHaveLength(1);

    wrapper.unmount();
  });
});
