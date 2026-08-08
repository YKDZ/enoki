import { expect, test, type Page, type Route } from "@playwright/test";

import type { HostDetail } from "../../apps/web/src/types";
import { releaseUiLifecycleVersions } from "./release-ui-contract-fixture";

type ProbeUpgradeStatus = NonNullable<HostDetail["probeUpgradeStatus"]>;

const ownerPassword =
  process.env.ENOKI_RELEASE_UI_OWNER_PASSWORD ?? "correct horse battery staple";
const isCandidateImageGate = Boolean(process.env.ENOKI_RELEASE_UI_BASE_URL);
const { candidateVersion, currentProbeVersion, targetProbeVersion } =
  releaseUiLifecycleVersions();
const hostId = 41;

test.describe("候选 Hub 探针生命周期 UI Contract", () => {
  test("由候选 Hub 提供 Candidate Manifest 对应的 Probe Asset Set", async ({
    request,
  }) => {
    test.skip(!isCandidateImageGate, "只在候选镜像 gate 中校验候选资产身份");

    const response = await request.get("/api/probe/assets/manifest.json");
    expect(response.ok()).toBe(true);
    await expect(response.json()).resolves.toMatchObject({
      version: candidateVersion,
    });
  });

  test("显示等待中的 Probe Upgrade", async ({ page }) => {
    await openHostDetail(page, probeUpgrade("pending"));

    const status = page.getByTestId("probe-upgrade-status");
    await expect(status).toContainText("探针升级等待中");
    await expect(status).toContainText(targetProbeVersion);
  });

  test("显示进行中的 Probe Upgrade", async ({ page }) => {
    await openHostDetail(page, probeUpgrade("running"));

    await expect(page.getByTestId("probe-upgrade-status")).toContainText(
      "探针升级进行中",
    );
  });

  test("显示已完成的 Probe Upgrade", async ({ page }) => {
    await openHostDetail(page, probeUpgrade("succeeded"));

    await expect(page.getByTestId("probe-upgrade-status")).toContainText(
      "探针升级完成",
    );
  });

  test("失败的 Probe Upgrade 只提供 Probe Repair 恢复方向", async ({
    page,
  }) => {
    await openHostDetail(
      page,
      probeUpgrade("failed", {
        code: "probe_upgrade_running_timeout",
        message: "探针升级后未恢复上报。",
      }),
    );

    const status = page.getByTestId("probe-upgrade-status");
    await expect(status).toContainText("探针升级失败");
    await expect(status).toContainText("probe_upgrade_running_timeout");
    await expect(status).toContainText("以 root 权限运行 Probe Repair");
    await expect(status).not.toContainText("降级");
    await expect(status).not.toContainText("重新安装");
    await expect(status).not.toContainText("重新注册");
    await expect(
      page.getByRole("button", {
        name: `探针可升级到 ${targetProbeVersion}`,
      }),
    ).toHaveCount(0);
  });

  test("Owner 确认后发送一次带会话认证的 Probe Upgrade 请求", async ({
    page,
  }) => {
    let requestCount = 0;
    let ownerCookie = "";
    await openHostDetail(page, null, {
      async onHostRequest(route) {
        if (route.request().method() !== "POST") {
          return false;
        }
        requestCount += 1;
        ownerCookie = route.request().headers().cookie ?? "";
        await route.fulfill({
          contentType: "application/json",
          json: { probeUpgradeRequest: probeUpgrade("pending") },
          status: 201,
        });
        return true;
      },
    });

    const upgrade = page.getByRole("button", {
      name: `探针可升级到 ${targetProbeVersion}`,
    });
    await upgrade.click();
    await expect(
      page.getByRole("dialog", { name: "确认升级探针" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "返回" }).click();
    expect(requestCount).toBe(0);

    await upgrade.click();
    await page.getByRole("button", { name: "确认升级" }).click();

    await expect(page.getByTestId("probe-upgrade-status")).toContainText(
      "探针升级等待中",
    );
    expect(requestCount).toBe(1);
    expect(ownerCookie).toContain("enoki_owner_session=");
  });

  test("Owner 确认后发送一次带会话认证的 Probe Uninstall 请求", async ({
    page,
  }) => {
    let requestCount = 0;
    let ownerCookie = "";
    await openHostDetail(page, null, {
      async onHostRequest(route) {
        if (route.request().method() !== "DELETE") {
          return false;
        }
        requestCount += 1;
        ownerCookie = route.request().headers().cookie ?? "";
        await route.fulfill({
          contentType: "application/json",
          json: {
            probeUninstallRequest: {
              createdAtMs: 1_725_000_000_000,
              failure: null,
              id: 72,
              state: "pending",
              updatedAtMs: 1_725_000_000_000,
            },
          },
          status: 202,
        });
        return true;
      },
    });

    const deleteButton = page.getByRole("button", {
      exact: true,
      name: "删除",
    });
    const confirmation = page.getByRole("alertdialog", { name: "删除主机" });
    await deleteButton.click();
    await expect(confirmation).toBeVisible();
    await page.getByRole("button", { name: "取消" }).click();
    await expect(confirmation).toBeHidden();
    expect(requestCount).toBe(0);

    await deleteButton.click();
    await page.getByRole("button", { name: "卸载并删除" }).click();

    await expect(page.getByText("已下发探针卸载请求")).toBeVisible();
    expect(requestCount).toBe(1);
    expect(ownerCookie).toContain("enoki_owner_session=");
  });
});

async function openHostDetail(
  page: Page,
  probeUpgradeStatus: ProbeUpgradeStatus | null,
  options: {
    onHostRequest?: (route: Route) => Promise<boolean>;
  } = {},
) {
  const host = hostDetail(probeUpgradeStatus);
  await page.route("**/api/web/hosts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { hosts: [host] },
    });
  });
  await page.route(`**/api/web/hosts/${hostId}`, async (route) => {
    if (await options.onHostRequest?.(route)) {
      return;
    }
    await route.fulfill({
      contentType: "application/json",
      json: { host },
    });
  });
  await page.route(
    `**/api/web/hosts/${hostId}/probe-upgrade-requests`,
    async (route) => {
      if (await options.onHostRequest?.(route)) {
        return;
      }
      await route.abort("blockedbyclient");
    },
  );
  await page.route(
    `**/api/web/hosts/${hostId}/metrics?window=*`,
    async (route) => {
      await route.fulfill({
        contentType: "application/json",
        json: { metrics: { samples: [], window: "1m" } },
      });
    },
  );

  await page.goto("/");
  await page.locator("#owner-password").fill(ownerPassword);
  await page.getByRole("button", { name: "登录" }).click();
  await page.goto(`/hosts/${hostId}`);
  await expect(
    page.getByRole("heading", { name: "UI Contract Host" }),
  ).toBeVisible();
}

function probeUpgrade(
  state: ProbeUpgradeStatus["state"],
  failure: ProbeUpgradeStatus["failure"] = null,
): ProbeUpgradeStatus {
  const accepted = ["accepted", "running", "succeeded", "failed"].includes(
    state,
  );
  const running = ["running", "succeeded"].includes(state);
  const completed = ["succeeded", "failed"].includes(state);
  return {
    acceptedAtMs: accepted ? 1_725_000_000_250 : null,
    completedAtMs: completed ? 1_725_000_001_000 : null,
    createdAtMs: 1_725_000_000_000,
    failure,
    id: 71,
    runningAtMs: running ? 1_725_000_000_500 : null,
    state,
    targetProbeVersion,
    updatedAtMs: 1_725_000_001_000,
  };
}

function hostDetail(probeUpgradeStatus: ProbeUpgradeStatus | null): HostDetail {
  return {
    clockSkew: { detected: false, lastDeltaMs: null },
    collectorCapabilities: null,
    connectAddress: "192.0.2.41",
    cpu: "1.0%",
    cpuModel: "Contract CPU",
    description: "",
    displayName: "UI Contract Host",
    hostMetadata: {
      connectAddress: "192.0.2.41",
      description: "",
      displayName: "UI Contract Host",
      observedIp: "192.0.2.41",
    },
    hostProfile: {
      architecture: "x86_64",
      cpuCount: 2,
      filesystems: [],
      hostname: "ui-contract-host",
      kernel: "6.8.0",
      memoryTotalBytes: 4_294_967_296,
      networkInterfaces: [],
      os: "Ubuntu 24.04",
      probeVersion: currentProbeVersion,
    },
    id: hostId,
    lastReportAtMs: 1_725_000_000_000,
    latestMetrics: null,
    memory: "1 GiB / 4 GiB",
    probeConfiguration: {
      configuration: {
        enabledCollectorIds: ["official.cpu", "official.memory"],
        metricsCollectionIntervalSeconds: 5,
        version: "default",
      },
      mode: "inherit",
    },
    probeUpgradeEligibility: {
      currentProbeAssetSetVersion: candidateVersion,
      currentProbeVersion,
      isUpgradeable:
        probeUpgradeStatus === null || probeUpgradeStatus.state === "failed",
      nonUpgradeableReason:
        probeUpgradeStatus === null || probeUpgradeStatus.state === "failed"
          ? null
          : "probe_version_current",
    },
    probeUpgradeStatus,
    probeVersion: currentProbeVersion,
    reportedProbeConfigurationVersion: "default",
    status: "online",
    system: "Ubuntu 24.04",
    warnings: [],
  };
}
