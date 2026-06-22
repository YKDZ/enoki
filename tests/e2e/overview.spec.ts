import { expect, test, type Page } from "@playwright/test";

import type { HostSummary } from "../../apps/web/src/types";

const now = Date.UTC(2026, 5, 22, 12, 0, 0);

test.describe("主页主机列表", () => {
  test("列表视图可以翻页并保留页码", async ({ page }) => {
    await mockAuthenticatedOverview(page, createHosts(25));
    await setOverviewView(page, "list");

    await page.goto("/");

    await expect(
      page.getByRole("button", { name: /测试主机 01/ }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /测试主机 10/ }),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: /测试主机 11/ })).toHaveCount(
      0,
    );
    await expect(page.getByText("1-10 / 25")).toBeVisible();

    await page.getByRole("button", { name: "下一页" }).click();

    await expect(
      page.getByRole("button", { name: /测试主机 11/ }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /测试主机 20/ }),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: /测试主机 01/ })).toHaveCount(
      0,
    );
    await expect(page.getByText("11-20 / 25")).toBeVisible();

    await page.reload();

    await expect(
      page.getByRole("button", { name: /测试主机 11/ }),
    ).toBeVisible();
    await expect(page.getByText("11-20 / 25")).toBeVisible();
  });

  test("列表视图只有一页时隐藏分页和每页数量", async ({ page }) => {
    await mockAuthenticatedOverview(page, createHosts(10));
    await setOverviewView(page, "list");

    await page.goto("/");

    await expect(
      page.getByRole("button", { name: /测试主机 01/ }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /测试主机 10/ }),
    ).toBeVisible();
    await expect(page.getByText("1-10 / 10")).toHaveCount(0);
    await expect(page.getByText("每页")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "下一页" })).toHaveCount(0);
  });

  test("卡片视图隐藏分页控件并通过滚动懒加载", async ({ page }) => {
    await mockAuthenticatedOverview(page, createHosts(18));
    await setOverviewView(page, "cards");
    await page.setViewportSize({ height: 720, width: 1280 });

    await page.goto("/");

    await expect(
      page.getByRole("button", { name: /测试主机 01/ }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /测试主机 12/ }),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: /测试主机 13/ })).toHaveCount(
      0,
    );
    await expect(page.getByText("每次加载")).toHaveCount(0);
    await expect(page.getByText("加载更多")).toHaveCount(0);
    await expect(page.getByText("1-12 / 18")).toHaveCount(0);

    await page.clock.install();
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));

    await expect(page.getByTestId("host-card-lazy-skeleton")).toHaveCount(12);
    await page.clock.fastForward(180);
    await expect(
      page.getByRole("button", { name: /测试主机 13/ }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /测试主机 18/ }),
    ).toBeVisible();
    await expect(page.getByText("加载更多")).toHaveCount(0);
  });
});

async function mockAuthenticatedOverview(page: Page, hosts: HostSummary[]) {
  await page.route("**/api/web/auth/session", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { authenticated: true },
    });
  });
  await page.route("**/api/web/hosts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { hosts },
    });
  });
}

async function setOverviewView(page: Page, view: "cards" | "list") {
  await page.addInitScript((nextView) => {
    window.localStorage.setItem("enoki-overview-view", nextView);
    window.localStorage.setItem("enoki-overview-list-page-size", "10");
  }, view);
}

function createHosts(count: number) {
  return Array.from({ length: count }, (_, index) => createHost(index + 1));
}

function createHost(id: number): HostSummary {
  const cpuPercent = (id * 7) % 100;
  const memoryTotalBytes = 16 * 1024 ** 3;
  const memoryUsedBytes = Math.round(memoryTotalBytes * (0.25 + id / 100));
  const diskTotalBytes = 256 * 1024 ** 3;
  const diskUsedBytes = Math.round(diskTotalBytes * (0.2 + id / 120));

  return {
    clockSkew: {
      detected: false,
      lastDeltaMs: null,
    },
    connectAddress: `10.0.0.${id}`,
    cpu: `${cpuPercent.toFixed(1)}%`,
    cpuModel: "E2E CPU",
    description: `第 ${id} 台测试主机`,
    displayName: `测试主机 ${String(id).padStart(2, "0")}`,
    id,
    lastReportAtMs: now - id * 1000,
    latestMetrics: {
      collectedAtMs: now - id * 1000,
      cpuPercent,
      diskTotalBytes,
      diskUsedBytes,
      memoryTotalBytes,
      memoryUsedBytes,
      networkRxBitsPerSecond: id * 1000,
      networkTxBitsPerSecond: id * 2000,
      receivedAtMs: now - id * 1000,
      uptimeSeconds: id * 3600,
    },
    memory: `${memoryUsedBytes} / ${memoryTotalBytes}`,
    probeConfiguration: {
      mode: "inherit",
      version: "default",
    },
    probeVersion: "0.1.39",
    status: "online",
    system: "Debian GNU/Linux 12",
  };
}
