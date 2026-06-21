import { describe, expect, it } from "vitest";

import { formatByteUsage, formatBytes, formatTrafficBytes } from "./format";

describe("format helpers", () => {
  it("renders byte sizes with decimal-looking MB and GB labels", () => {
    expect(formatBytes(969.5 * 1024 ** 2)).toBe("969.5 MB");
    expect(formatBytes(2 * 1024 ** 3)).toBe("2 GB");
    expect(formatByteUsage(401.8 * 1024 ** 2, 969.5 * 1024 ** 2)).toBe(
      "401.8 MB / 969.5 MB",
    );
  });

  it("renders traffic totals with useful precision below one MB", () => {
    expect(formatTrafficBytes(0)).toBe("0 KB");
    expect(formatTrafficBytes(61.75 * 1024)).toBe("61.8 KB");
    expect(formatTrafficBytes(1.5 * 1024 ** 2)).toBe("1.5 MB");
  });
});
