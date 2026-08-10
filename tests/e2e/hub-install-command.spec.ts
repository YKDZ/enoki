import { expect, test } from "@playwright/test";

const ownerPassword = "correct horse battery staple";

test("owner can generate a Hub-served probe install command", async ({
  page,
}) => {
  test.skip(
    process.platform === "darwin",
    "Control+A is a non-macOS contract.",
  );
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "登录" })).toBeVisible();
  await page.locator("#owner-password").fill(ownerPassword);
  await page.getByRole("button", { name: "登录" }).click();

  await page.getByRole("button", { name: "添加探针" }).click();

  await expect(page.getByRole("dialog", { name: "添加主机" })).toBeVisible();
  await expect(page.getByText("正在生成安装命令")).toBeHidden();

  const command = page.getByRole("textbox", { name: "安装命令" });
  await expect(command).toBeFocused();
  await expect(command).toHaveValue(/\/api\/probe\/install\.sh/);
  await expect(command).toHaveValue(
    /ENOKI_HUB_URL='http:\/\/127\.0\.0\.1:38200'/,
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

  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.evaluate(() => navigator.clipboard.writeText("must-not-paste"));
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
  await page.locator("#owner-password").fill(ownerPassword);
  await page.getByRole("button", { name: "登录" }).click();
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
  await page.locator("#owner-password").fill(ownerPassword);
  await page.getByRole("button", { name: "登录" }).click();
  await page.getByRole("button", { name: "添加探针" }).click();

  await expect(page.getByText("安装命令已过期")).toBeVisible();
  await expect(page.getByRole("dialog", { name: "添加主机" })).toBeHidden();
});
