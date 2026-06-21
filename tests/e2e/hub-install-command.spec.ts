import { expect, test } from "@playwright/test";

const ownerPassword = "correct horse battery staple";

test("owner can generate a Hub-served probe install command", async ({
  page,
}) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "登录" })).toBeVisible();
  await page.locator("#owner-password").fill(ownerPassword);
  await page.getByRole("button", { name: "登录" }).click();

  await page.getByRole("button", { name: "添加探针" }).click();

  await expect(page.getByRole("dialog", { name: "添加主机" })).toBeVisible();
  await expect(page.getByText("正在生成安装命令")).toBeHidden();

  const command = page.locator("pre code");
  await expect(command).toContainText("/api/probe/install.sh");
  await expect(command).toContainText("ENOKI_HUB_URL='http://127.0.0.1:38200'");
  await expect(command).toContainText("ENOKI_ENROLLMENT_TOKEN=");
  await expect(command).not.toContainText("github.com");
});
