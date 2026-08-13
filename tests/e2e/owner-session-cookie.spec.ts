import { expect, test } from "@playwright/test";

const ownerPassword = "correct horse battery staple";

test("the browser sends the Owner cookie only within the management API namespace", async ({
  baseURL,
  context,
  page,
}) => {
  if (!baseURL) {
    throw new Error("The security E2E project must define a baseURL");
  }
  await page.goto("/");
  const loginStatus = await page.evaluate(async (password) => {
    const response = await fetch("/api/web/auth/login", {
      body: JSON.stringify({ password }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    return response.status;
  }, ownerPassword);
  expect(loginStatus).toBe(200);

  const cookies = await context.cookies(`${baseURL}/api/web/`);
  expect(cookies).toEqual([
    expect.objectContaining({
      domain: "127.0.0.1",
      httpOnly: true,
      name: "enoki_owner_session",
      path: "/api/web",
      sameSite: "Strict",
      secure: false,
    }),
  ]);

  let managementCookie: string | undefined;
  let probeCookie: string | undefined;
  await page.route("**/api/web/auth/session", async (route) => {
    managementCookie = (await route.request().allHeaders()).cookie;
    await route.continue();
  });
  await page.route("**/api/probe/assets/manifest.json", async (route) => {
    probeCookie = (await route.request().allHeaders()).cookie;
    await route.continue();
  });

  await page.evaluate(async () => {
    await fetch("/api/web/auth/session");
    await fetch("/api/probe/assets/manifest.json");
  });

  expect(managementCookie).toContain("enoki_owner_session=");
  expect(probeCookie).toBeUndefined();
});
