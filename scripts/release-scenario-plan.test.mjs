import { createHash, sign } from "node:crypto";

import {
  releaseTransitionContractSigningInput,
  verifyReleaseTransitionContract,
} from "@enoki/probe-release";
import { describe, expect, it, vi } from "vitest";

import * as planner from "./release-scenario-plan.mjs";
import { rsa4096TestKeyPair } from "./test-rsa-key-pool.mjs";

describe("Release Scenario Planner", () => {
  it("compiles the exact Compatible capabilities without caller-selected scenarios", () => {
    const plan = planner.compileReleaseScenarioPlan({
      candidateManifest: candidateManifest(),
      releaseTransition: transitionContract({ transition: "compatible" }),
      supportedHostMatrix: supportedHostMatrix(),
    });

    expect(plan.transition.classification).toBe("compatible");
    expect(plan.scenarios).toEqual([
      {
        capabilities: [
          "baseline-forward-communication",
          "identity-preserving-upgrade",
          "final-uninstall",
        ],
        id: "compatible-upgrade-uninstall",
      },
      {
        capabilities: [
          "fresh-install",
          "installed-bundle-failure-repair",
          "canonical-report-response-loss",
          "final-uninstall",
        ],
        id: "fresh-install-uninstall",
      },
      {
        capabilities: [
          "failed-upgrade-repair",
          "identity-preserving-repair",
          "final-uninstall",
        ],
        id: "post-replacement-repair-uninstall",
      },
      {
        capabilities: [
          "baseline-forward-communication",
          "identity-preserving-upgrade",
          "hub-restore-compatible-identity",
        ],
        id: "hub-restore-compatibility-window",
      },
    ]);
    expect(plan.cells).toHaveLength(7);
  });

  it("compiles Replacement without claiming pre-commit snapshot restoration", () => {
    const plan = planner.compileReleaseScenarioPlan({
      candidateManifest: candidateManifest(),
      releaseTransition: transitionContract({
        transition: "replacement-required",
      }),
      supportedHostMatrix: supportedHostMatrix(),
    });

    expect(plan.transition.classification).toBe("replacement-required");
    expect(plan.scenarios).toEqual([
      {
        capabilities: [
          "baseline-forward-communication",
          "manual-reinstall",
          "host-history-preservation",
          "probe-identity-replacement",
          "old-installation-no-residue",
          "new-identity-readiness",
          "final-uninstall",
        ],
        id: "replacement-migration-uninstall",
      },
      {
        capabilities: [
          "fresh-install",
          "installed-bundle-failure-repair",
          "canonical-report-response-loss",
          "final-uninstall",
        ],
        id: "fresh-install-uninstall",
      },
    ]);
    expect(plan.cells).toHaveLength(4);
    expect(JSON.stringify(plan)).not.toMatch(/snapshot|restore/i);
  });

  it.each([
    ["missing", null],
    ["unknown", transitionContract({ transition: "downgrade" })],
    ["incomplete", { transition: "compatible" }],
    [
      "wrong candidate",
      transitionContract({ targetVersion: "9.9.9", transition: "compatible" }),
    ],
  ])(
    "fails closed for a %s transition before provisioning",
    async (_name, releaseTransition) => {
      const provision = vi.fn();

      await expect(
        planner.prepareReleaseScenarioCell({
          cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
          compilePlan: async () =>
            planner.compileReleaseScenarioPlan({
              candidateManifest: candidateManifest(),
              releaseTransition,
              supportedHostMatrix: supportedHostMatrix(),
            }),
          provision,
        }),
      ).rejects.toThrow(/transition contract|candidate/i);
      expect(provision).not.toHaveBeenCalled();
    },
  );

  it("provisions exactly the closed set of planned cells", async () => {
    const plan = planner.compileReleaseScenarioPlan({
      candidateManifest: candidateManifest(),
      releaseTransition: transitionContract(),
      supportedHostMatrix: supportedHostMatrix(),
    });
    const provisioned = [];

    for (const cell of plan.cells) {
      await planner.prepareReleaseScenarioCell({
        cellId: cell.cellId,
        compilePlan: async () => plan,
        provision: async (plannedCell) => provisioned.push(plannedCell),
      });
    }

    expect(provisioned).toEqual(plan.cells);
    expect(new Set(provisioned.map(({ cellId }) => cellId))).toEqual(
      new Set(plan.cells.map(({ cellId }) => cellId)),
    );
  });

  it("releases a provisioned plan cell when initialization fails", async () => {
    const plan = planner.compileReleaseScenarioPlan({
      candidateManifest: candidateManifest(),
      releaseTransition: transitionContract(),
      supportedHostMatrix: supportedHostMatrix(),
    });
    const provision = vi.fn(async () => ({ acquired: true }));
    const release = vi.fn(async () => ({ clean: true }));

    await expect(
      planner.prepareReleaseScenarioCell({
        cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
        compilePlan: async () => plan,
        initialize: async () => {
          throw new Error("journal initialization failed");
        },
        provision,
        release,
      }),
    ).rejects.toThrow("journal initialization failed");
    expect(provision).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledWith(
      expect.objectContaining({
        cell: expect.objectContaining({
          cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
        }),
        prepared: { acquired: true },
      }),
    );
  });

  it("does not release twice after the scenario runner takes cleanup ownership", async () => {
    const plan = planner.compileReleaseScenarioPlan({
      candidateManifest: candidateManifest(),
      releaseTransition: transitionContract(),
      supportedHostMatrix: supportedHostMatrix(),
    });
    const provision = vi.fn(async () => ({ acquired: true }));
    const release = vi.fn(async () => ({ clean: true }));

    await expect(
      planner.prepareReleaseScenarioCell({
        cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
        compilePlan: async () => plan,
        initialize: async ({ takeCleanupOwnership }) => {
          takeCleanupOwnership();
          await release({ prepared: { acquired: true } });
          throw new Error("scenario failed after runner cleanup");
        },
        provision,
        release,
      }),
    ).rejects.toThrow("scenario failed after runner cleanup");
    expect(provision).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledTimes(1);
  });

  it("rejects malformed or unsupported Hosts before provisioning", async () => {
    const provision = vi.fn();
    const matrix = supportedHostMatrix();
    matrix.environments[0].capabilityId = "ubuntu-20.04-x86_64";

    await expect(
      planner.prepareReleaseScenarioCell({
        cellId: "ubuntu-20.04-x86_64--compatible-upgrade-uninstall",
        compilePlan: async () =>
          planner.compileReleaseScenarioPlan({
            candidateManifest: candidateManifest(),
            releaseTransition: transitionContract(),
            supportedHostMatrix: matrix,
          }),
        provision,
      }),
    ).rejects.toThrow(/Host|capability|environment/i);
    expect(provision).not.toHaveBeenCalled();
  });

  it("rejects a wrong contract signature across verification and planning before provisioning", async () => {
    const root = rsa4096TestKeyPair("scenario-root");
    const contract = signedContractFixture(root.publicKey);
    const provision = vi.fn();

    await expect(
      planner.prepareReleaseScenarioCell({
        cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
        compilePlan: async () => {
          const releaseTransition = verifyReleaseTransitionContract({
            contractBytes: Buffer.from(`${JSON.stringify(contract)}\n`),
            contractSignature: Buffer.alloc(256),
            rootPublicKeyPem: root.publicKey,
          });
          return planner.compileReleaseScenarioPlan({
            candidateManifest: candidateManifest(),
            releaseTransition,
            supportedHostMatrix: supportedHostMatrix(),
          });
        },
        provision,
      }),
    ).rejects.toThrow(/root signature does not match/i);
    expect(provision).not.toHaveBeenCalled();
  });

  it("rejects a signed same-version and same-assets contract for a different candidate commit before provisioning", async () => {
    const root = rsa4096TestKeyPair("scenario-root");
    const contract = {
      ...signedContractFixture(root.publicKey),
      candidateCommit: "b".repeat(40),
    };
    const contractBytes = Buffer.from(`${JSON.stringify(contract)}\n`);
    const contractSignature = sign(
      "RSA-SHA256",
      releaseTransitionContractSigningInput(contractBytes),
      root.privateKey,
    );
    const provision = vi.fn();

    await expect(
      planner.prepareReleaseScenarioCell({
        cellId: "ubuntu-22.04-x86_64--compatible-upgrade-uninstall",
        compilePlan: async () => {
          const releaseTransition = verifyReleaseTransitionContract({
            contractBytes,
            contractSignature,
            expected: {
              classification: "compatible",
              sourceVersion: "1.2.2",
              targetAssetClosure: contract.target.assetClosure,
              targetAssetSetManifestSha256:
                contract.target.assetSetManifestSha256,
              targetVersion: "1.2.3",
            },
            rootPublicKeyPem: root.publicKey,
          });
          return planner.compileReleaseScenarioPlan({
            candidateManifest: candidateManifest(),
            releaseTransition,
            supportedHostMatrix: supportedHostMatrix(),
          });
        },
        provision,
      }),
    ).rejects.toThrow(/candidate does not match/i);
    expect(provision).not.toHaveBeenCalled();
  });

  it("projects no contract signature or authority into plan artifacts", () => {
    const releaseTransition = {
      ...transitionContract(),
      authorization: "sensitive-authorization",
      contractSignature: "sensitive-signature",
      privateKey: "sensitive-private-key",
      rootKeyId: "c".repeat(64),
    };
    const plan = planner.compileReleaseScenarioPlan({
      candidateManifest: candidateManifest(),
      releaseTransition,
      supportedHostMatrix: supportedHostMatrix(),
    });

    expect(JSON.stringify(plan)).not.toMatch(
      /sensitive|signature|privateKey|rootKeyId|probeComponents/,
    );
  });
});

function candidateManifest() {
  return {
    candidate: { commit: "a".repeat(40), version: "v1.2.3" },
    kind: "enoki-release-candidate",
    probeAssetSet: { version: "1.2.3" },
    releaseBaseline: {
      kind: "enoki-release-baseline",
      probeAssetSet: { version: "1.2.2" },
      tag: "v1.2.2",
    },
    schemaVersion: 4,
  };
}

function transitionContract({
  candidateCommit = "a".repeat(40),
  targetVersion = "1.2.3",
  transition = "compatible",
} = {}) {
  return {
    candidateCommit,
    source: { version: "1.2.2" },
    target: {
      assetSetManifestSha256: "b".repeat(64),
      version: targetVersion,
    },
    transition,
  };
}

function supportedHostMatrix() {
  return {
    environments: [
      {
        capabilityId: "ubuntu-22.04-x86_64",
        providerId: "github-actions-host-systemd",
      },
      {
        capabilityId: "ubuntu-24.04-x86_64",
        providerId: "github-actions-host-systemd",
      },
    ],
    providers: [
      {
        capabilities: [
          {
            architecture: "x86_64",
            id: "ubuntu-22.04-x86_64",
            operatingSystem: "ubuntu",
            operatingSystemVersion: "22.04",
            runner: "ubuntu-22.04",
          },
          {
            architecture: "x86_64",
            id: "ubuntu-24.04-x86_64",
            operatingSystem: "ubuntu",
            operatingSystemVersion: "24.04",
            runner: "ubuntu-24.04",
          },
        ],
        hostAdapter: "ci",
        id: "github-actions-host-systemd",
        provider: "github-actions",
        systemd: "host",
      },
    ],
    schemaVersion: 2,
  };
}

function signedContractFixture(rootPublicKeyPem) {
  const targets = [
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
  ];
  return {
    candidateCommit: "a".repeat(40),
    distribution: "enoki",
    kind: "enoki-release-transition-contract",
    rootKeyId: createHash("sha256").update(rootPublicKeyPem).digest("hex"),
    schemaVersion: 1,
    source: {
      assetSetManifestSha256: "a".repeat(64),
      probeComponents: targets.map((target) => ({
        file: "enoki-probe",
        role: "probe",
        sha256: "c".repeat(64),
        target,
      })),
      version: "1.2.2",
    },
    target: {
      assetClosure: targets.map((target) => ({
        bundleManifestSha256: "d".repeat(64),
        file: `enoki-probe-${target}.tar.gz`,
        sha256: "e".repeat(64),
        size: 1,
        target,
      })),
      assetSetManifestSha256: "b".repeat(64),
      delegationGeneration: 1,
      probeComponents: targets.map((target) => ({
        file: "enoki-probe",
        role: "probe",
        sha256: "a".repeat(64),
        target,
      })),
      signingKeyId: "f".repeat(64),
      version: "1.2.3",
    },
    transition: "compatible",
  };
}
