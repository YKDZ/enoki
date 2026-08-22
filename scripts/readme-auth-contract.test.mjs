import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

const readme = await readFile("README.md", "utf8");

describe("README authentication configuration contract", () => {
  it("rejects an unconditional password requirement", () => {
    const contradictedContract = [
      "所有环境都必须显式设置 `OWNER_PASSWORD`。",
      "`ENOKI_WEB_UI_NO_PASSWORD=true` 会启用无密码模式。",
      "生产或 Docker 环境还必须设置 `ENOKI_ALLOW_INSECURE_NO_PASSWORD=true`。",
    ].join(" ");

    expect(() => expectAuthProseContract(contradictedContract)).toThrow();
  });

  it.each([
    "除显式无密码模式外，`OWNER_PASSWORD` 并非必须。",
    "除显式无密码模式外，`OWNER_PASSWORD` 不是必填项。",
    "除显式无密码模式外，无需设置 `OWNER_PASSWORD`。",
  ])("rejects a negated OWNER_PASSWORD requirement: %s", (claim) => {
    const contradictedContract = [
      claim,
      "`ENOKI_WEB_UI_NO_PASSWORD=true` 会启用无密码模式。",
      "生产或 Docker 环境还必须设置 `ENOKI_ALLOW_INSECURE_NO_PASSWORD=true`。",
    ].join(" ");

    expect(() => expectAuthProseContract(contradictedContract)).toThrow();
  });

  it.each([
    "除显式无密码模式外，必须设置 `OWNER_PASSWORD`。",
    "显式无密码模式之外，`OWNER_PASSWORD` 是必填项。",
    "未启用显式无密码模式时，需要提供 `OWNER_PASSWORD`。",
  ])(
    "accepts a reasonably reworded OWNER_PASSWORD requirement: %s",
    (claim) => {
      expectOwnerPasswordRequired(claim);
    },
  );

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
    expectOwnerPasswordRequired(ownerPassword?.description ?? "", true);
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
    expect(insecureConfirmation?.description).toContain(
      "不会单独启用无密码模式",
    );
  });
});

const noPasswordExceptionPattern = /除[^。；]*无密码模式[^。；]*(?:外|之外)/;
const unconditionalPasswordPattern =
  /(?:^|[。；\n])\s*(?:-\s*)?所有(?:环境|部署)都必须显式设置 `OWNER_PASSWORD`/;

function expectAuthProseContract(text) {
  expect(text).toMatch(noPasswordExceptionPattern);
  expect(text).not.toMatch(unconditionalPasswordPattern);
  expectOwnerPasswordRequired(text);
  expect(text).toContain("ENOKI_WEB_UI_NO_PASSWORD=true");
  expect(text).toContain("ENOKI_ALLOW_INSECURE_NO_PASSWORD=true");
  expect(text).toMatch(/生产[^。；]*Docker|Docker[^。；]*生产/);
}

function expectOwnerPasswordRequired(text, subjectIsImplied = false) {
  const ownerPasswordStatements = text
    .split(/[。；\n]/)
    .filter(
      (statement) => subjectIsImplied || statement.includes("OWNER_PASSWORD"),
    );
  const statesRequirement = ownerPasswordStatements.some(
    (statement) =>
      !/(?:并非|不是|无需|不必|不需要|非必填)/.test(statement) &&
      /(?:必须|必填|需要(?:设置|提供|配置))/.test(statement),
  );

  expect(statesRequirement, "OWNER_PASSWORD must be positively required").toBe(
    true,
  );
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
