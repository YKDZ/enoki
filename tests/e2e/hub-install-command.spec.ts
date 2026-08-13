import { type BrowserContext, type Page } from "@playwright/test";

import { expect, test } from "./security-console";

type BrowserEnrollmentTarget =
  | { kind: "new_host" }
  | { hostId: number; kind: "existing_host" };

type BrowserEnrollmentStatus = {
  createdAtMs: number;
  enrollmentId: string;
  expiresAtMs: number;
  expiredAtMs: number | null;
  hostId: number | null;
  readyAtMs: number | null;
  rejectedAtMs: number | null;
  rejection: { code: string; message: string | null } | null;
  status: "expired" | "pending" | "ready" | "rejected" | "verifying";
  target: BrowserEnrollmentTarget;
  verificationDeadlineAtMs: number | null;
};

type BrowserEnrollmentResponse = BrowserEnrollmentStatus & {
  enrollmentToken: string;
  hubUrl: string;
  installCommand: string;
  installPath: string;
};

type BrowserHost = {
  clockSkew: { detected: boolean; lastDeltaMs: number | null };
  collectorCapabilities: null;
  connectAddress: string;
  cpu: string;
  cpuModel: null;
  description: string;
  displayName: string;
  id: number;
  lastReportAtMs: number | null;
  latestMetrics: null;
  memory: string;
  probeConfiguration: { mode: "inherit" | "override"; version: string };
  probeVersion: string;
  status: "offline" | "online" | "stale";
  system: string;
};

type BrowserScrollCall = {
  behavior?: ScrollBehavior;
  block?: ScrollLogicalPosition;
};

test("owner can generate a Hub-served probe install command", async ({
  context,
  page,
}) => {
  test.skip(
    process.platform === "darwin",
    "Control+A is a non-macOS contract.",
  );
  await page.goto("/");

  await page.getByRole("button", { name: "添加探针" }).click();

  await expect(page.getByRole("dialog", { name: "添加主机" })).toBeVisible();
  await expect(page.getByText("正在生成安装命令")).toBeHidden();

  const command = page.getByRole("textbox", { name: "安装命令" });
  await expect(command).toBeFocused();
  await expect(command).toHaveValue(/\/api\/probe\/install\.sh/);
  await expect(command).toHaveValue(
    /ENOKI_HUB_URL='http:\/\/127\.0\.0\.1:38201'/,
  );
  await expect(command).toHaveValue(/ENOKI_ENROLLMENT_TOKEN=/);
  await expect(command).not.toHaveValue(/github\.com/);

  await command.press("Control+A");
  await expect(command).toHaveJSProperty("selectionStart", 0);
  await expect(command).toHaveJSProperty(
    "selectionEnd",
    (await command.inputValue()).length,
  );
  await command.press("x");
  await expect(command).toHaveValue(/ENOKI_ENROLLMENT_TOKEN=/);

  await seedSystemClipboard(context, "must-not-paste");
  await command.press("Control+V");
  await expect(command).toHaveValue(/ENOKI_ENROLLMENT_TOKEN=/);
});

test("owner can select the command with Cmd+A on a macOS browser runner", async ({
  page,
}) => {
  test.skip(
    process.platform !== "darwin",
    "Cmd+A is executed only by the macOS Playwright gate.",
  );
  await page.goto("/");
  await page.getByRole("button", { name: "添加探针" }).click();

  const command = page.getByRole("textbox", { name: "安装命令" });
  await expect(command).toBeFocused();
  await command.press("Meta+A");
  await expect(command).toHaveJSProperty("selectionStart", 0);
  await expect(command).toHaveJSProperty(
    "selectionEnd",
    (await command.inputValue()).length,
  );
});

test("an expired Enrollment closes the matching dialog through its status API", async ({
  page,
}) => {
  const expiresAtMs = Date.now() - 1;
  await page.route("**/api/web/enrollments", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }

    await route.fulfill({
      contentType: "application/json",
      json: {
        createdAtMs: expiresAtMs - 1_000,
        enrollmentId: "enr_expired_browser",
        enrollmentToken: "enk_enroll_expired_browser",
        expiresAtMs,
        expiredAtMs: null,
        hostId: null,
        hubUrl: "http://127.0.0.1:38200",
        installCommand: "curl expired-command",
        installPath: "/usr/local/bin/enoki-probe",
        readyAtMs: null,
        rejectedAtMs: null,
        rejection: null,
        status: "pending",
        target: { kind: "new_host" },
        verificationDeadlineAtMs: null,
      },
      status: 201,
    });
  });
  await page.route(
    "**/api/web/enrollments/enr_expired_browser",
    async (route) => {
      await route.fulfill({
        contentType: "application/json",
        json: {
          createdAtMs: expiresAtMs - 1_000,
          enrollmentId: "enr_expired_browser",
          expiresAtMs,
          expiredAtMs: expiresAtMs,
          hostId: null,
          readyAtMs: null,
          rejectedAtMs: null,
          rejection: null,
          status: "expired",
          target: { kind: "new_host" },
          verificationDeadlineAtMs: null,
        },
      });
    },
  );

  await page.goto("/");
  await page.getByRole("button", { name: "添加探针" }).click();

  await expect(page.getByText("安装命令已过期")).toBeVisible();
  await expect(page.getByRole("dialog", { name: "添加主机" })).toBeHidden();
});

test("an authoritative ready Enrollment reveals and focuses its Host with reduced motion", async ({
  page,
}) => {
  await recordScrollIntoView(page);
  const readyHost = {
    clockSkew: { detected: false, lastDeltaMs: null },
    collectorCapabilities: null,
    connectAddress: "10.0.0.27",
    cpu: "1 core",
    cpuModel: null,
    description: "",
    displayName: "新就绪主机",
    id: 27,
    lastReportAtMs: Date.now(),
    latestMetrics: null,
    memory: "1 GB",
    probeConfiguration: { mode: "inherit", version: "default-v1" },
    probeVersion: "dev",
    status: "online",
    system: "Linux",
  };
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.route("**/api/web/auth/session", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { authenticated: true },
    });
  });
  await page.route("**/api/web/hosts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { hosts: [readyHost] },
    });
  });
  await page.route("**/api/web/enrollments", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    await route.fulfill({
      contentType: "application/json",
      json: pendingEnrollment("enr_ready_browser"),
      status: 201,
    });
  });
  await page.route(
    "**/api/web/enrollments/enr_ready_browser",
    async (route) => {
      await route.fulfill({
        contentType: "application/json",
        json: {
          ...pendingEnrollment("enr_ready_browser"),
          hostId: 27,
          readyAtMs: Date.now(),
          status: "ready",
        },
      });
    },
  );

  await page.goto("/");
  await page.getByRole("button", { name: "添加探针" }).click();

  const host = page.locator('[data-enoki-host-id="27"]');
  await expect(page.getByText("主机已就绪")).toBeVisible();
  await expect(host).toBeFocused();
  await expect(host).toHaveClass(/ring-primary/);
  await expect
    .poll(() => scrollIntoViewCalls(page))
    .toContainEqual({
      behavior: "auto",
      block: "center",
    });
});

test("a ready Host clears its highlight when its located card is absent after render", async ({
  page,
}) => {
  const readyHost = browserHost({
    displayName: "Missing rendered Host",
    id: 28,
    status: "online",
  });
  await page.addInitScript((hostId) => {
    const originalQuerySelector = document.querySelector.bind(document);
    document.querySelector = function querySelector(selectors: string) {
      if (selectors === `[data-enoki-host-id="${hostId}"]`) {
        return null;
      }

      return originalQuerySelector(selectors);
    };
  }, readyHost.id);
  await page.route("**/api/web/auth/session", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { authenticated: true },
    });
  });
  await page.route("**/api/web/hosts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { hosts: [readyHost] },
    });
  });
  await page.route("**/api/web/enrollments", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }

    await route.fulfill({
      contentType: "application/json",
      json: pendingEnrollment("enr_missing_rendered_host"),
      status: 201,
    });
  });
  await page.route(
    "**/api/web/enrollments/enr_missing_rendered_host",
    async (route) => {
      await route.fulfill({
        contentType: "application/json",
        json: {
          ...pendingEnrollment("enr_missing_rendered_host"),
          hostId: readyHost.id,
          readyAtMs: Date.now(),
          status: "ready",
        },
      });
    },
  );

  await page.goto("/");
  await page.getByRole("button", { name: "添加探针" }).click();

  const host = page.locator('[data-enoki-host-id="28"]');
  await expect(page.getByText("主机已就绪")).toBeVisible();
  await expect(host).not.toHaveClass(/ring-primary/);
});

test("a ready Host on a later sorted list page preserves overview preferences and uses normal-motion reveal", async ({
  page,
}) => {
  const initialHosts = Array.from({ length: 11 }, (_, index) =>
    browserHost({
      displayName: `Host ${String(index + 1).padStart(2, "0")}`,
      id: index + 1,
      status: "online",
    }),
  );
  const readyHost = browserHost({
    displayName: "Zulu ready Host",
    id: 99,
    status: "online",
  });
  let hostReadCount = 0;
  await page.addInitScript(() => {
    localStorage.setItem("enoki-overview-view", "list");
    localStorage.setItem("enoki-overview-list-sort-key", "name");
    localStorage.setItem("enoki-overview-list-sort-direction", "asc");
    localStorage.setItem("enoki-overview-list-page", "1");
    localStorage.setItem("enoki-overview-list-page-size", "10");
  });
  await recordScrollIntoView(page);
  await page.route("**/api/web/auth/session", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { authenticated: true },
    });
  });
  await page.route("**/api/web/hosts", async (route) => {
    hostReadCount += 1;
    await route.fulfill({
      contentType: "application/json",
      json: {
        hosts:
          hostReadCount === 1 ? initialHosts : [...initialHosts, readyHost],
      },
    });
  });
  await page.route("**/api/web/enrollments", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }

    await route.fulfill({
      contentType: "application/json",
      json: pendingEnrollment("enr_ready_list_page"),
      status: 201,
    });
  });
  await page.route(
    "**/api/web/enrollments/enr_ready_list_page",
    async (route) => {
      await route.fulfill({
        contentType: "application/json",
        json: {
          ...pendingEnrollment("enr_ready_list_page"),
          hostId: readyHost.id,
          readyAtMs: Date.now(),
          status: "ready",
        },
      });
    },
  );

  await page.goto("/");
  await expect(page.getByRole("button", { name: "切换到卡片" })).toBeVisible();
  await expect(page.getByText("1-10 / 11")).toBeVisible();
  await page.getByRole("button", { name: "添加探针" }).click();

  const readyHostRow = page.locator('[data-enoki-host-id="99"]');
  await expect(page.getByText("主机已就绪")).toBeVisible();
  await expect(page.getByText("11-12 / 12")).toBeVisible();
  await expect(readyHostRow).toBeFocused();
  await expect(readyHostRow).toHaveClass(/ring-primary/);
  await expect
    .poll(() => scrollIntoViewCalls(page))
    .toContainEqual({
      behavior: "smooth",
      block: "center",
    });
  await expect
    .poll(() =>
      page.evaluate(() => ({
        direction: localStorage.getItem("enoki-overview-list-sort-direction"),
        page: localStorage.getItem("enoki-overview-list-page"),
        pageSize: localStorage.getItem("enoki-overview-list-page-size"),
        sortKey: localStorage.getItem("enoki-overview-list-sort-key"),
        view: localStorage.getItem("enoki-overview-view"),
      })),
    )
    .toEqual({
      direction: "asc",
      page: "2",
      pageSize: "10",
      sortKey: "name",
      view: "list",
    });
});

test("a ready Host beyond the initial card batch is revealed without changing the cards preference", async ({
  page,
}) => {
  const initialHosts = Array.from({ length: 12 }, (_, index) =>
    browserHost({
      displayName: `Card Host ${String(index + 1).padStart(2, "0")}`,
      id: index + 1,
      status: "online",
    }),
  );
  const readyHost = browserHost({
    displayName: "Card Host 13",
    id: 99,
    status: "online",
  });
  let hostReadCount = 0;
  await page.route("**/api/web/auth/session", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { authenticated: true },
    });
  });
  await page.route("**/api/web/hosts", async (route) => {
    hostReadCount += 1;
    await route.fulfill({
      contentType: "application/json",
      json: {
        hosts:
          hostReadCount === 1 ? initialHosts : [...initialHosts, readyHost],
      },
    });
  });
  await page.route("**/api/web/enrollments", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }

    await route.fulfill({
      contentType: "application/json",
      json: pendingEnrollment("enr_ready_cards"),
      status: 201,
    });
  });
  await page.route("**/api/web/enrollments/enr_ready_cards", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: {
        ...pendingEnrollment("enr_ready_cards"),
        hostId: readyHost.id,
        readyAtMs: Date.now(),
        status: "ready",
      },
    });
  });

  await page.goto("/");
  await expect(page.getByRole("button", { name: "切换到列表" })).toBeVisible();
  await expect(page.locator('[data-enoki-host-id="99"]')).toHaveCount(0);
  await page.getByRole("button", { name: "添加探针" }).click();

  const readyHostCard = page.locator('[data-enoki-host-id="99"]');
  await expect(page.getByText("主机已就绪")).toBeVisible();
  await expect(readyHostCard).toBeFocused();
  await expect(readyHostCard).toHaveClass(/ring-primary/);
  await expect(page.getByRole("button", { name: "切换到列表" })).toBeVisible();
});

test("an offline Host matched by a rejected Enrollment opens its existing-host installation command", async ({
  page,
}) => {
  const requests = await prepareRejectedExistingHostEnrollment(page, {
    hosts: [browserHost({ id: 71, status: "offline" })],
  });

  await page.goto("/");
  await page.getByRole("button", { name: "添加探针" }).click();

  const recoveryAction = page.getByRole("button", {
    name: "查看可重新注册主机",
  });
  await expect(recoveryAction).toBeVisible({ timeout: 5_000 });
  await recoveryAction.click();

  await expect.poll(() => requests.existingHost).toBe(1);
  expect(requests.legacyExistingHost).toBe(0);
  await expect(requests.newHost).toBe(1);
  await expect(page.getByRole("dialog", { name: "添加主机" })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "安装命令" })).toHaveValue(
    "curl existing-host-command",
  );
});

for (const conflict of [
  {
    code: "existing_host_reenrollment_verifying",
    description: "已有重新注册正在进行中，请刷新后重试。",
    title: "已有重新注册进行中",
  },
  {
    code: "existing_host_reenrollment_unavailable",
    description: "主机状态已变化，请刷新后重试。",
    title: "主机状态已变化",
  },
]) {
  test(`an ExistingHost ${conflict.code} conflict is visible and can be retried`, async ({
    page,
  }) => {
    const requests = await prepareRejectedExistingHostEnrollment(
      page,
      {
        hosts: [browserHost({ id: 71, status: "offline" })],
      },
      (attempt) =>
        attempt === 1
          ? { json: { error: conflict.code }, status: 409 }
          : existingHostEnrollmentResponse(),
    );

    await page.goto("/");
    await page.getByRole("button", { name: "添加探针" }).click();
    await page.getByRole("button", { name: "查看可重新注册主机" }).click();

    await expect(page.getByText(conflict.title, { exact: true })).toBeVisible();
    await expect(page.getByText(conflict.description)).toBeVisible();
    await expect(page.getByRole("dialog", { name: "添加主机" })).toBeHidden();
    await expect(page.getByRole("button", { name: "重新尝试" })).toBeVisible();

    await page.getByRole("button", { name: "重新尝试" }).click();
    await expect.poll(() => requests.existingHost).toBe(2);
    await expect(page.getByRole("dialog", { name: "添加主机" })).toBeVisible();
    await expect(page.getByRole("textbox", { name: "安装命令" })).toHaveValue(
      "curl existing-host-command",
    );
  });
}

for (const scenario of [
  {
    hosts: [browserHost({ id: 71, status: "online" })],
    name: "online",
  },
  {
    hosts: [browserHost({ id: 71, status: "stale" })],
    name: "stale",
  },
  { hosts: [], name: "missing" },
  {
    hosts: [
      browserHost({ displayName: "Offline one", id: 71, status: "offline" }),
      browserHost({
        displayName: "Offline duplicate",
        id: 71,
        status: "offline",
      }),
    ],
    name: "duplicate",
  },
]) {
  test(`a rejected Enrollment does not offer recovery for a ${scenario.name} Host match`, async ({
    page,
  }) => {
    const requests = await prepareRejectedExistingHostEnrollment(
      page,
      scenario,
    );

    await page.goto("/");
    await page.getByRole("button", { name: "添加探针" }).click();

    await expect(page.getByText("检测到已有探针安装")).toBeVisible({
      timeout: 5_000,
    });
    await expect(
      page.getByRole("button", { name: "查看可重新注册主机" }),
    ).toHaveCount(0, { timeout: 200 });
    await expect(requests.newHost).toBe(1);
    await expect(requests.existingHost).toBe(0);
    await expect(page.getByRole("dialog", { name: "添加主机" })).toBeHidden();
  });
}

function pendingEnrollment(enrollmentId: string): BrowserEnrollmentResponse {
  return {
    createdAtMs: Date.now(),
    enrollmentId,
    enrollmentToken: "enk_enroll_ready_browser",
    expiresAtMs: Date.now() + 60_000,
    expiredAtMs: null,
    hostId: null,
    hubUrl: "http://127.0.0.1:38200",
    installCommand: "curl ready-command",
    installPath: "/usr/local/bin/enoki-probe",
    readyAtMs: null,
    rejectedAtMs: null,
    rejection: null,
    status: "pending",
    target: { kind: "new_host" },
    verificationDeadlineAtMs: null,
  };
}

async function prepareRejectedExistingHostEnrollment(
  page: Page,
  scenario: { hosts: BrowserHost[] },
  existingHostResponseForAttempt?: (attempt: number) => {
    json: unknown;
    status: number;
  },
) {
  const enrollmentId = "enr_existing_host_rejected";
  const requests = { existingHost: 0, legacyExistingHost: 0, newHost: 0 };
  await page.route("**/api/web/auth/session", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { authenticated: true },
    });
  });
  await page.route("**/api/web/hosts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: { hosts: scenario.hosts },
    });
  });
  await page.route("**/api/web/enrollments", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }

    const body = route.request().postData();
    const target = body
      ? (JSON.parse(body) as { target?: BrowserEnrollmentTarget }).target
      : undefined;
    if (target?.kind === "existing_host" && target.hostId === 71) {
      const existingHostResponse =
        existingHostResponseForAttempt?.(requests.existingHost + 1) ??
        existingHostEnrollmentResponse();
      requests.existingHost += 1;
      await route.fulfill({
        contentType: "application/json",
        json: existingHostResponse.json,
        status: existingHostResponse.status,
      });
      return;
    }

    requests.newHost += 1;
    await route.fulfill({
      contentType: "application/json",
      json: {
        ...pendingEnrollment(enrollmentId),
      },
      status: 201,
    });
  });
  await page.route(
    "**/api/web/enrollments/enr_existing_host_rejected",
    async (route) => {
      await route.fulfill({
        contentType: "application/json",
        json: rejectedExistingHostEnrollment(enrollmentId),
      });
    },
  );
  await page.route("**/api/web/enrollments/existing-host/71", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }

    requests.legacyExistingHost += 1;
    await route.fulfill({
      contentType: "application/json",
      json: {
        ...pendingEnrollment("enr_existing_host_recovery"),
        installCommand: "curl existing-host-command",
        target: { hostId: 71, kind: "existing_host" },
      },
      status: 201,
    });
  });

  return requests;
}

function existingHostEnrollmentResponse() {
  return {
    json: {
      ...pendingEnrollment("enr_existing_host_recovery"),
      installCommand: "curl existing-host-command",
      target: { hostId: 71, kind: "existing_host" },
    },
    status: 201,
  };
}

function rejectedExistingHostEnrollment(
  enrollmentId: string,
): BrowserEnrollmentStatus {
  return {
    ...pendingEnrollment(enrollmentId),
    hostId: 71,
    rejectedAtMs: Date.now(),
    rejection: {
      code: "existing_probe_installation",
      message: null,
    },
    status: "rejected",
    target: { hostId: 71, kind: "existing_host" },
  };
}

function browserHost(
  input: Partial<Pick<BrowserHost, "displayName" | "id" | "status">>,
): BrowserHost {
  return {
    clockSkew: { detected: false, lastDeltaMs: null },
    collectorCapabilities: null,
    connectAddress: "192.0.2.71",
    cpu: "2 cores",
    cpuModel: null,
    description: "",
    displayName: "Existing host",
    id: 71,
    lastReportAtMs: Date.now(),
    latestMetrics: null,
    memory: "2 GB",
    probeConfiguration: { mode: "inherit", version: "default-v1" },
    probeVersion: "dev",
    status: "offline",
    system: "Linux",
    ...input,
  };
}

async function recordScrollIntoView(page: Page) {
  await page.addInitScript(() => {
    const liveWindow = window as typeof window & {
      __enokiScrollIntoViewCalls?: BrowserScrollCall[];
    };
    liveWindow.__enokiScrollIntoViewCalls = [];
    Element.prototype.scrollIntoView = function scrollIntoView(
      options?: boolean | ScrollIntoViewOptions,
    ) {
      if (typeof options !== "object" || options === null) {
        return;
      }

      liveWindow.__enokiScrollIntoViewCalls?.push({
        behavior: options.behavior,
        block: options.block,
      });
    };
  });
}

async function scrollIntoViewCalls(page: Page) {
  return page.evaluate(() => {
    const liveWindow = window as typeof window & {
      __enokiScrollIntoViewCalls?: BrowserScrollCall[];
    };
    return liveWindow.__enokiScrollIntoViewCalls ?? [];
  });
}

async function seedSystemClipboard(context: BrowserContext, value: string) {
  const origin = "https://clipboard-fixture.test";
  await context.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin,
  });
  const clipboardPage = await context.newPage();
  await clipboardPage.route(`${origin}/`, (route) =>
    route.fulfill({ body: "<!doctype html><title>Clipboard fixture</title>" }),
  );
  await clipboardPage.goto(origin);
  await clipboardPage.evaluate(
    (text) => navigator.clipboard.writeText(text),
    value,
  );
  await expect
    .poll(() => clipboardPage.evaluate(() => navigator.clipboard.readText()))
    .toBe(value);
  await clipboardPage.close();
}
