import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

describe("Enrollment dialog source", () => {
  it("renders install commands without clipboard controls", async () => {
    const source = await readFile(
      new URL("./EnrollmentDialog.vue", import.meta.url),
      "utf8",
    );

    expect(source).toContain("bg-black");
    expect(source).toContain("font-mono");
    expect(source).not.toContain("useClipboard");
    expect(source).not.toContain("copyInstallCommand");
    expect(source).not.toContain("复制失败");
  });
});
