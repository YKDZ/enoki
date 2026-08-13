import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

describe("README authentication configuration contract", () => {
  it("documents OWNER_PASSWORD as required except in explicit no-password mode", async () => {
    const readme = await readFile("README.md", "utf8");

    expect(readme).toContain(
      "除显式启用无密码模式外，所有部署都必须显式设置 `OWNER_PASSWORD`。",
    );
    expect(readme).toContain(
      "除显式无密码模式外必填；Hub 不会生成或输出临时密码。",
    );
    expect(readme).not.toContain("所有环境必填；Hub 不会生成或输出临时密码。");
  });
});
