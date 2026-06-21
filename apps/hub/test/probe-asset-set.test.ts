import { describe, expect, it } from "vitest";

import {
  evaluateProbeUpgradeEligibility,
  probeAssetSetVersionFromManifest,
} from "../src/probe/asset-set.js";

describe("Probe Asset Set upgrade eligibility", () => {
  it("uses the signed manifest version as the Hub Probe Asset Set version", () => {
    expect(
      probeAssetSetVersionFromManifest(
        JSON.stringify({
          assets: [
            {
              file: "enoki-probe-x86_64-unknown-linux-gnu.tar.gz",
              sha256: "a".repeat(64),
              target: "x86_64-unknown-linux-gnu",
            },
          ],
          kind: "enoki-probe-assets",
          signature: {
            algorithm: "rsa-sha256",
            file: "manifest.json.sig",
          },
          version: "v1.4.0",
        }),
      ),
    ).toBe("1.4.0");
  });

  it("marks lower valid Probe versions upgradeable", () => {
    expect(
      evaluateProbeUpgradeEligibility({
        probeAssetSetVersion: "v1.4.0",
        probeVersion: "1.3.9",
      }),
    ).toEqual({
      currentProbeAssetSetVersion: "1.4.0",
      currentProbeVersion: "1.3.9",
      isUpgradeable: true,
      nonUpgradeableReason: null,
    });
  });

  it("keeps equal, higher, missing, malformed, and development Probe versions non-upgradeable with stable reasons", () => {
    expect(
      evaluateProbeUpgradeEligibility({
        probeAssetSetVersion: "1.4.0",
        probeVersion: "v1.4.0",
      }),
    ).toEqual({
      currentProbeAssetSetVersion: "1.4.0",
      currentProbeVersion: "1.4.0",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_version_current",
    });

    expect(
      evaluateProbeUpgradeEligibility({
        probeAssetSetVersion: "1.4.0",
        probeVersion: "1.5.0",
      }),
    ).toEqual({
      currentProbeAssetSetVersion: "1.4.0",
      currentProbeVersion: "1.5.0",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_version_newer",
    });

    expect(
      evaluateProbeUpgradeEligibility({
        probeAssetSetVersion: "1.4.0",
        probeVersion: "",
      }),
    ).toEqual({
      currentProbeAssetSetVersion: "1.4.0",
      currentProbeVersion: null,
      isUpgradeable: false,
      nonUpgradeableReason: "probe_version_missing",
    });

    expect(
      evaluateProbeUpgradeEligibility({
        probeAssetSetVersion: "1.4.0",
        probeVersion: "banana",
      }),
    ).toEqual({
      currentProbeAssetSetVersion: "1.4.0",
      currentProbeVersion: "banana",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_version_malformed",
    });

    expect(
      evaluateProbeUpgradeEligibility({
        probeAssetSetVersion: "1.4.0",
        probeVersion: "1.4.1-dev",
      }),
    ).toEqual({
      currentProbeAssetSetVersion: "1.4.0",
      currentProbeVersion: "1.4.1-dev",
      isUpgradeable: false,
      nonUpgradeableReason: "probe_version_development",
    });
  });
});
