import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createProbeTrustDelegation,
  probeBundleComponentProfiles,
  probeBundledBootstrapAssets,
  verifyProbeTrustDelegation,
} from "./index.mjs";

describe("Probe release primitives", () => {
  it("keeps the fixed Probe Asset Bundle roles in one package", () => {
    expect(Object.keys(probeBundleComponentProfiles)).toEqual([
      "probe",
      "observation-runtime",
      "system-state-provider",
      "disk-health-provider",
      "lifecycle-companion",
    ]);
    expect(probeBundledBootstrapAssets.map(({ role }) => role)).toEqual([
      "bootstrap-acquirer",
      "bootstrap-activator",
    ]);
  });

  it("creates canonical delegation bytes accepted by the same verifier", () => {
    const root = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const release = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const signed = createProbeTrustDelegation({
      distribution: "enoki",
      generation: 3,
      releasePublicKeyPem: release.publicKey.export({
        format: "pem",
        type: "spki",
      }),
      rootPrivateKey: root.privateKey,
    });

    expect(signed.bytes).toEqual(
      Buffer.from(`${JSON.stringify(signed.delegation)}\n`, "utf8"),
    );
    expect(
      verifyProbeTrustDelegation({
        bytes: signed.bytes,
        expectedDistribution: "enoki",
        rootPublicKeyPem: root.publicKey.export({
          format: "pem",
          type: "spki",
        }),
        signature: signed.signature,
      }),
    ).toEqual(signed.delegation);
  });
});
