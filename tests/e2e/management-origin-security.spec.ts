import { expect, test } from "@playwright/test";

const attackerOrigin = "http://127.0.0.1:39877";
const ownerPassword = "correct horse battery staple";

test.beforeEach(async ({ page }) => {
  await page.route(`${attackerOrigin}/**`, async (route) => {
    await route.fulfill({
      body: "<!doctype html><title>attacker</title>",
      contentType: "text/html",
    });
  });
});

test("same-site cross-origin form login is forbidden", async ({
  baseURL,
  page,
}) => {
  const managementOrigin = requiredBaseURL(baseURL);
  await page.goto(attackerOrigin);

  const responsePromise = page.waitForResponse(
    `${managementOrigin}/api/web/auth/login`,
  );
  await page.evaluate(
    ({ origin, password }) => {
      const form = document.createElement("form");
      form.action = `${origin}/api/web/auth/login`;
      form.method = "POST";
      const input = document.createElement("input");
      input.name = "password";
      input.value = password;
      form.append(input);
      document.body.append(form);
      form.submit();
    },
    { origin: managementOrigin, password: ownerPassword },
  );

  expect((await responsePromise).status()).toBe(403);
  await expect(page.locator("body")).toHaveText("Forbidden");
});

test("cross-origin JSON write fails its preflight without credentials CORS", async ({
  baseURL,
  context,
  page,
}) => {
  const managementOrigin = requiredBaseURL(baseURL);
  await page.goto(attackerOrigin);

  const result = await page.evaluate(
    async ({ origin, password }) => {
      try {
        await fetch(`${origin}/api/web/auth/login`, {
          body: JSON.stringify({ password }),
          credentials: "include",
          headers: { "content-type": "application/json" },
          method: "POST",
        });
        return "resolved";
      } catch (error) {
        return error instanceof TypeError ? "type-error" : "other-error";
      }
    },
    { origin: managementOrigin, password: ownerPassword },
  );

  expect(result).toBe("type-error");
  expect(await context.cookies(`${managementOrigin}/api/web`)).toEqual([]);
});

test("same-origin text/plain JSON is rejected as content-type confusion", async ({
  baseURL,
  page,
}) => {
  const managementOrigin = requiredBaseURL(baseURL);
  await page.goto(managementOrigin);

  const result = await page.evaluate(async (password) => {
    const response = await fetch("/api/web/auth/login", {
      body: JSON.stringify({ password }),
      headers: { "content-type": "text/plain" },
      method: "POST",
    });
    return { body: await response.json(), status: response.status };
  }, ownerPassword);

  expect(result).toEqual({
    body: { error: "json_content_type_required" },
    status: 415,
  });
});

test("cross-origin WebSocket is rejected before upgrade", async ({
  baseURL,
  page,
}) => {
  const managementOrigin = requiredBaseURL(baseURL);
  await page.goto(attackerOrigin);

  const result = await page.evaluate(async (origin) => {
    return new Promise<string>((resolve) => {
      const socket = new WebSocket(
        `${origin.replace(/^http/, "ws")}/api/web/ws`,
      );
      socket.addEventListener("open", () => resolve("opened"));
      socket.addEventListener("error", () => resolve("rejected"));
    });
  }, managementOrigin);

  expect(result).toBe("rejected");
});

function requiredBaseURL(baseURL: string | undefined) {
  if (!baseURL) {
    throw new Error("The security E2E project must define a baseURL");
  }
  return baseURL;
}
