import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { readProbeDistributionRootPublicKeyFromImage } from "../src/probe/distribution-root.js";

describe("Probe Distribution Trust Root image material", () => {
  it("reads the build-fixed root independently of the Probe Asset directory", async () => {
    const paths: string[] = [];
    const root = Buffer.from("fixed distribution root");

    await expect(
      readProbeDistributionRootPublicKeyFromImage({
        readFile: async (filePath) => {
          paths.push(filePath);
          return root;
        },
      }),
    ).resolves.toEqual(root);

    expect(paths).toEqual(["/app/probe-distribution-root/root-key.pem"]);
  });

  it("keeps release transitions unavailable when the image has no fixed root", async () => {
    await expect(
      readProbeDistributionRootPublicKeyFromImage({
        readFile: async () => {
          throw Object.assign(new Error("missing"), { code: "ENOENT" });
        },
      }),
    ).resolves.toBeNull();
  });

  it("copies the verified release root into the fixed image location", async () => {
    const dockerfile = await readFile(
      new URL("../Dockerfile", import.meta.url),
      "utf8",
    );

    expect(dockerfile).toContain(
      "cp /app/probe-assets/root-key.pem /app/probe-distribution-root/root-key.pem",
    );
    expect(dockerfile).toContain(
      "COPY --from=builder --chown=node:node /app/probe-distribution-root probe-distribution-root",
    );
  });
});
