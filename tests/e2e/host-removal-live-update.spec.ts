import { expect, test, type Page } from "@playwright/test";

declare global {
  interface Window {
    __enokiLiveSocketGeneration?: number;
  }
}

const ownerPassword = "correct horse battery staple";

test("removes a Host from open cards immediately and tolerates unrelated or duplicate hints", async ({
  page,
}) => {
  const state = await prepareLiveRemovalOverview(page);
  await login(page);
  await expect(page.getByText("Realtime removal host")).toBeVisible();

  await emitHostRemoved(page, 999);
  await expect(page.getByText("Realtime removal host")).toBeVisible();

  await emitHostRemoved(page, 71);
  await expect(page.getByText("Realtime removal host")).toBeHidden();
  await emitHostRemoved(page, 71);
  await expect(page.getByText("Realtime removal host")).toBeHidden();

  expect(state.hosts).toHaveLength(1);
});

test("removes a Host from the open list immediately", async ({ page }) => {
  await prepareLiveRemovalOverview(page);
  await login(page);
  await page.getByRole("button", { name: "切换到列表" }).click();
  await expect(page.getByText("Realtime removal host")).toBeVisible();

  await emitHostRemoved(page, 71);

  await expect(page.getByText("Realtime removal host")).toBeHidden();
});

test("recovers a Host removal that occurs in the reconnect window from HTTP after the next socket opens", async ({
  page,
}) => {
  const state = await prepareLiveRemovalOverview(page);
  await login(page);
  await expect(page.getByText("Realtime removal host")).toBeVisible();

  state.hosts = [];
  await page.evaluate(() => {
    (
      window as typeof window & {
        __enokiLiveSocket?: { close: () => void };
      }
    ).__enokiLiveSocket?.close();
  });

  await expect(page.getByText("Realtime removal host")).toBeHidden({
    timeout: 3_000,
  });
  await expect
    .poll(() => page.evaluate(() => window.__enokiLiveSocketGeneration ?? 0))
    .toBeGreaterThan(1);
});

async function prepareLiveRemovalOverview(page: Page) {
  const state: { hosts: unknown[] } = { hosts: [removalHost()] };
  await page.addInitScript(() => {
    class FakeWebSocket extends EventTarget {
      static readonly CLOSED = 3;
      static readonly CONNECTING = 0;
      static readonly OPEN = 1;

      readyState = FakeWebSocket.OPEN;

      constructor() {
        super();
        const liveWindow = window as typeof window & {
          __enokiLiveSocket?: FakeWebSocket;
          __enokiLiveSocketGeneration?: number;
        };
        liveWindow.__enokiLiveSocket = this;
        liveWindow.__enokiLiveSocketGeneration =
          (liveWindow.__enokiLiveSocketGeneration ?? 0) + 1;
        setTimeout(() => this.dispatchEvent(new Event("open")), 0);
      }

      close() {
        this.readyState = FakeWebSocket.CLOSED;
        this.dispatchEvent(new Event("close"));
      }

      emit(message: unknown) {
        this.dispatchEvent(
          new MessageEvent("message", {
            data: JSON.stringify(message),
          }),
        );
      }

      send() {}
    }

    window.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
  });
  await page.route("**/api/web/hosts", async (route) => {
    if (route.request().method() !== "GET") {
      await route.continue();
      return;
    }

    await route.fulfill({
      contentType: "application/json",
      json: { hosts: state.hosts },
    });
  });

  return state;
}

async function login(page: Page) {
  await page.goto("/");
  await page.locator("#owner-password").fill(ownerPassword);
  await page.getByRole("button", { name: "登录" }).click();
}

async function emitHostRemoved(page: Page, hostId: number) {
  await page.evaluate((removedHostId) => {
    (
      window as typeof window & {
        __enokiLiveSocket?: { emit: (message: unknown) => void };
      }
    ).__enokiLiveSocket?.emit({
      hostId: removedHostId,
      type: "host_removed",
    });
  }, hostId);
}

function removalHost() {
  return {
    clockSkew: { detected: false, lastDeltaMs: null },
    collectorCapabilities: null,
    connectAddress: "192.0.2.71",
    cpu: "2 cores",
    cpuModel: null,
    description: "",
    displayName: "Realtime removal host",
    id: 71,
    lastReportAtMs: null,
    latestMetrics: null,
    memory: "2 GB",
    probeConfiguration: {
      mode: "inherit",
      version: "default-v1",
    },
    probeVersion: "0.1.0",
    status: "offline",
    system: "Linux",
  };
}
