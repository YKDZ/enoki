import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

const readme = await readFile("README.md", "utf8");

describe("README authentication configuration contract", () => {
  it("rejects the audited contradiction even when both no-password switches are mentioned", () => {
    const contradictedContract = [
      "所有部署都必须显式设置 `OWNER_PASSWORD`。",
      "`ENOKI_WEB_UI_NO_PASSWORD=true` 会启用无密码模式。",
      "生产或 Docker 环境还必须设置 `ENOKI_ALLOW_INSECURE_NO_PASSWORD=true`。",
    ].join(" ");

    expect(() => expectAuthProseContract(contradictedContract)).toThrow();
  });

  it.each([
    ["安全性", markdownSection(readme, "安全性")],
    ["部署", markdownSection(readme, "部署")],
  ])("makes the %s section self-contained", (_heading, section) => {
    expectAuthProseContract(section);
  });

  it("documents the linked environment-variable contract", () => {
    const rows = markdownTableRows(markdownSection(readme, "环境变量"));
    const ownerPassword = rows.get("OWNER_PASSWORD");
    const noPassword = rows.get("ENOKI_WEB_UI_NO_PASSWORD");
    const insecureConfirmation = rows.get("ENOKI_ALLOW_INSECURE_NO_PASSWORD");

    expect(ownerPassword?.description).toMatch(noPasswordExceptionPattern);
    expect(ownerPassword?.description).toMatch(/必(?:须|填)/);
    expect(noPassword?.defaultValue).toBe("false");
    expect(noPassword?.description).toContain(
      "ENOKI_ALLOW_INSECURE_NO_PASSWORD=true",
    );
    expect(noPassword?.description).toMatch(/生产.*Docker|Docker.*生产/);
    expect(insecureConfirmation?.defaultValue).toBe("false");
    expect(insecureConfirmation?.description).toMatch(/危险.*显式确认/);
    expect(insecureConfirmation?.description).toMatch(/生产.*Docker/);
    expect(insecureConfirmation?.description).toMatch(/必须[^。；]*`true`/);
    expect(insecureConfirmation?.description).toContain(
      "ENOKI_WEB_UI_NO_PASSWORD=true",
    );
  });
});

const noPasswordExceptionPattern = /除[^。；]*无密码模式[^。；]*(?:外|之外)/;
const requiredOwnerPasswordPattern =
  /(?:必(?:须|填)[^。；]*`?OWNER_PASSWORD`?|`?OWNER_PASSWORD`?[^。；]*必(?:须|填))/;

function expectAuthProseContract(text) {
  expect(text).toMatch(noPasswordExceptionPattern);
  expect(text).toMatch(requiredOwnerPasswordPattern);
  expect(text).toContain("ENOKI_WEB_UI_NO_PASSWORD=true");
  expect(text).toContain("ENOKI_ALLOW_INSECURE_NO_PASSWORD=true");
  expect(text).toMatch(/生产[^。；]*Docker|Docker[^。；]*生产/);
}

function markdownSection(markdown, heading) {
  const match = markdown.match(
    new RegExp(
      `^#{2,3} ${heading}\\n([\\s\\S]*?)(?=^#{2,3} |(?![\\s\\S]))`,
      "m",
    ),
  );
  expect(match, `README section ${heading}`).not.toBeNull();
  return match?.[1] ?? "";
}

function markdownTableRows(section) {
  return new Map(
    section
      .split("\n")
      .filter((line) => /^\| `[^`]+`/.test(line))
      .map((line) => {
        const [, variable = "", defaultValue = "", description = ""] = line
          .split("|")
          .map((cell) => cell.trim());
        return [
          variable.replaceAll("`", ""),
          { defaultValue: defaultValue.replaceAll("`", ""), description },
        ];
      }),
  );
}
