import {
  expect as baseExpect,
  test as baseTest,
  type Page,
} from "@playwright/test";

export const expect = baseExpect;
export const test = baseTest.extend({
  page: async ({ page }, use) => {
    const assertNoUnexpectedSecurityConsole = monitorSecurityConsole(page);
    await use(page);
    assertNoUnexpectedSecurityConsole();
  },
});

export function monitorSecurityConsole(page: Page, allowed: RegExp[] = []) {
  const unexpected: string[] = [];
  page.on("console", (message) => {
    const text = message.text();
    if (
      isSecurityPolicyMessage(text) &&
      !allowed.some((pattern) => pattern.test(text))
    ) {
      unexpected.push(text);
    }
  });

  return () => expect(unexpected).toEqual([]);
}

function isSecurityPolicyMessage(message: string) {
  return (
    message.includes("Error with Permissions-Policy header") ||
    message.includes("Content Security Policy")
  );
}
