import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import type { AddressInfo } from "node:net";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { serve } from "@hono/node-server";
import { afterEach, expect, it } from "vitest";

// @ts-expect-error 仓库 JavaScript 角色清单没有类型声明。
import * as probeAssetBundle from "../../../scripts/probe-asset-bundle.mjs";
import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import { defaultEnabledCollectorIds } from "../src/probe-configuration/model";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture";
import { createTestProbeIdentity } from "./probe-test-auth";

const probeBinary = process.env.ENOKI_PRODUCTION_PROBE_BINARY;
const lifecycleCompanionBinary =
  process.env.ENOKI_PRODUCTION_LIFECYCLE_COMPANION_BINARY;
const systemdImage = process.env.ENOKI_PRODUCTION_SYSTEMD_IMAGE;
const workspaceRoot = fileURLToPath(new URL("../../..", import.meta.url));
const { probeBundleComponentProfiles, probeBundledBootstrapAssets } =
  probeAssetBundle;
const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    tempRoots
      .splice(0)
      .map((root) => rm(root, { force: true, recursive: true })),
  );
});

it.skipIf(!probeBinary || !lifecycleCompanionBinary)(
  "fresh production registration processes converge across response loss and identity rename crashes",
  async () => {
    const dataRoot = await mkdtemp(
      path.join(os.tmpdir(), "enoki-production-recovery-"),
    );
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    const assetDir = path.join(dataRoot, "probe-assets");
    await mkdir(assetDir);
    const sourceProbeSha256 = createHash("sha256")
      .update(await readFile(probeBinary!))
      .digest("hex");
    const release = await writeSignedProbeAssetSet(assetDir, {
      sourceVersion: "0.1.0",
      targetVersion: "0.2.0",
      transition: "replacement-required",
      x86_64GnuSourceProbeSha256: sourceProbeSha256,
    });
    const proxy = await startResponseLossProxy();
    const proxyOrigin = `http://127.0.0.1:${proxy.port}`;
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      installation: {
        bootstrapRecipe: {
          bundleVersion: "0.2.0",
          distribution: "enoki",
          kind: "enoki-probe-bootstrap-recipe-record",
          recipe: {
            file: "enoki-probe-bootstrap.py",
            sha256: "a".repeat(64),
            size: 123,
            version: "v1",
          },
          rootFingerprint: "b".repeat(64),
          schemaVersion: 1,
          targets: ["x86_64-unknown-linux-gnu"],
        },
        probeApiOrigin: proxyOrigin,
      },
      probeAssets: {
        assetDir,
        trustedRootPublicKeyPem: release.rootPublicKeyPem,
      },
      probeApiOrigin: proxyOrigin,
    });
    const hubServer = serve({
      fetch: app.fetch,
      hostname: "127.0.0.1",
      port: 0,
    });
    await listening(hubServer);
    proxy.setUpstream((hubServer.address() as AddressInfo).port);

    try {
      const oldProbeId = "probe_production_old";
      database.sqlite
        .prepare(`insert into managed_hosts (
        id, probe_id, probe_secret_hash, display_name, display_name_edited,
        connect_address, created_at_ms, clock_skew_detected, last_clock_skew_ms,
        probe_configuration_version, probe_version
      ) values (7, ?, 'old-secret-hash', 'Production Host', 0,
        '127.0.0.1', ?, 0, null, 'default-v1', '0.1.0')`)
        .run(oldProbeId, Date.now());
      const ownerSession = await loginOwner(app);
      const enrollmentResponse = await app.request(
        "/api/web/enrollments/manual-reinstall/7",
        { headers: { cookie: ownerSession }, method: "POST" },
      );
      expect(enrollmentResponse.status).toBe(201);
      const enrollmentCommand = (await enrollmentResponse.json()) as {
        enrollmentId: string;
        enrollmentToken: string;
        installCommand: string;
      };
      const { enrollmentId, enrollmentToken } = enrollmentCommand;
      const enrollment = installCommandEnrollment(
        enrollmentCommand.installCommand,
      );
      expect(enrollment.enrollmentToken).toBe(enrollmentToken);
      expect(enrollment.replacementMigration.enrollmentId).toBe(enrollmentId);

      const productionRoot = path.join(dataRoot, "production-root");
      const capsulePath = path.join(
        productionRoot,
        "var/lib/enoki-probe-registration/attempt.json",
      );
      await createOldProductionInstall({
        hubOrigin: proxyOrigin,
        oldProbeId,
        productionRoot,
      });
      const lifecycleRequest = replacementLifecycleRequest({
        enrollment,
        release,
      });
      const crashEnvironment = {
        ENOKI_TEST_REPLACEMENT_PRODUCTION_ROOT: productionRoot,
        ENOKI_TEST_SECURE_FILE_PATH: capsulePath,
      };

      const capsuleBeforeRename = await runLifecycleCompanion(
        lifecycleRequest,
        {
          ...crashEnvironment,
          ENOKI_TEST_SECURE_FILE_CRASH_POINT: "before-rename",
        },
      );
      expect(capsuleBeforeRename).toEqual(
        expect.objectContaining({ code: null }),
      );
      await expect(readFile(capsulePath)).rejects.toMatchObject({
        code: "ENOENT",
      });
      expect(proxy.requestTargets).toEqual([]);

      const capsuleAfterRename = await runLifecycleCompanion(lifecycleRequest, {
        ...crashEnvironment,
        ENOKI_TEST_SECURE_FILE_CRASH_POINT: "after-rename",
      });
      expect(capsuleAfterRename).toEqual(
        expect.objectContaining({ code: null }),
      );
      const publishedCapsule = await readFile(capsulePath);
      const [capsuleMetadata, capsuleParentMetadata] = await Promise.all([
        stat(capsulePath),
        stat(path.dirname(capsulePath)),
      ]);
      expect(capsuleMetadata.uid).toBe(0);
      expect(capsuleMetadata.mode & 0o777).toBe(0o600);
      expect(capsuleParentMetadata.uid).toBe(0);
      expect(capsuleParentMetadata.mode & 0o777).toBe(0o700);
      expect(proxy.requestTargets).toEqual([]);

      const tamperedLifecycleRequest = JSON.parse(lifecycleRequest) as {
        authority: { expected_probe_id: string };
      };
      tamperedLifecycleRequest.authority.expected_probe_id = "probe_other";
      const tamperedClosure = await runLifecycleCompanion(
        JSON.stringify(tamperedLifecycleRequest),
        crashEnvironment,
      );
      expect(tamperedClosure).toEqual(
        expect.objectContaining({
          code: 1,
          stdout: expect.stringContaining("lifecycle.authority_mismatch"),
        }),
      );
      expect(await readFile(capsulePath)).toEqual(publishedCapsule);
      expect(proxy.requestTargets).toEqual([]);

      proxy.loseNextResponse();
      const inspectionLoss = await runLifecycleCompanion(
        lifecycleRequest,
        crashEnvironment,
      );
      expect(inspectionLoss.code).toBe(1);
      expect(await readFile(capsulePath)).toEqual(publishedCapsule);
      expect(proxy.requestTargets).toEqual(["/api/probe/register"]);

      const registration = await registrationFixture({
        dataRoot,
        enrollmentToken,
        capsulePath,
      });
      const args = [
        "register",
        "--config",
        registration.configPath,
        "--enrollment-token",
        enrollmentToken,
        "--hub-url",
        proxyOrigin,
      ];

      proxy.loseNextResponse();
      expect((await runProbe(args)).code).not.toBe(0);
      expect(await readFile(registration.configPath, "utf8")).toContain(
        `enrollment_token = "${enrollmentToken}"`,
      );

      const beforeRename = await runProbe(args, {
        ENOKI_TEST_SECURE_FILE_PATH: registration.configPath,
        ENOKI_TEST_SECURE_FILE_CRASH_POINT: "before-rename",
      });
      expect(beforeRename).toEqual(expect.objectContaining({ code: null }));
      expect(await readFile(registration.configPath, "utf8")).toContain(
        `enrollment_token = "${enrollmentToken}"`,
      );

      const afterRename = await runProbe(args, {
        ENOKI_TEST_SECURE_FILE_PATH: registration.configPath,
        ENOKI_TEST_SECURE_FILE_CRASH_POINT: "after-rename",
      });
      expect(afterRename).toEqual(expect.objectContaining({ code: null }));
      const postRenameIdentity = await readFile(
        registration.configPath,
        "utf8",
      );
      expect(postRenameIdentity).not.toContain("enrollment_token =");
      expect(postRenameIdentity).toContain("probe_private_key_pem =");
      expect(postRenameIdentity).toContain(
        `registration_signed_attempt_sha256 = "${registration.signedAttemptSha256}"`,
      );

      const finalRun = await runProbe(args);
      expect(finalRun.code, finalRun.stderr).toBe(0);
      const convergedIdentity = await readFile(registration.configPath, "utf8");
      expect(withoutObservedClockOffset(convergedIdentity)).toBe(
        withoutObservedClockOffset(postRenameIdentity),
      );
      expect(proxy.requestBodies).toHaveLength(5);
      for (const body of proxy.requestBodies.slice(2)) {
        expect(body).toEqual(proxy.requestBodies[1]);
      }

      const identityProbeId = /probe_id = "([^"]+)"/.exec(
        convergedIdentity,
      )?.[1];
      expect(identityProbeId).toBeTruthy();
      expect(
        database.sqlite
          .prepare("select id, probe_id as probeId from managed_hosts")
          .all(),
      ).toEqual([{ id: 7, probeId: identityProbeId }]);
      expect(
        database.sqlite
          .prepare(
            "select count(*) as count from audit_log where action = 'probe.manual_reinstall_identity_replaced'",
          )
          .get(),
      ).toEqual({ count: 1 });
      expect(
        database.sqlite
          .prepare(
            "select count(*) as count from enrollment_tokens where enrollment_id = ? and used_at_ms is not null",
          )
          .get(enrollmentId),
      ).toEqual({ count: 1 });
      await expect(readFile(registration.capsulePath)).resolves.toBeTruthy();
      await rm(registration.capsulePath);
      const canonicalRestart = await runProbe(
        ["run", "--config", registration.configPath],
        { ENOKI_PROBE_MAX_REPORTS: "1" },
      );
      expect(canonicalRestart.code, canonicalRestart.stderr).toBe(0);
      expect(
        proxy.requestTargets.filter(
          (target) => target === "/api/probe/register",
        ),
      ).toHaveLength(5);
      expect(proxy.requestTargets).toContain("/api/probe/report");
    } finally {
      await Promise.allSettled([proxy.close(), closeServer(hubServer)]);
      database.close();
    }
  },
  30_000,
);

it.skipIf(!probeBinary || !lifecycleCompanionBinary || !systemdImage)(
  "production activation retains one exact attempt through response and config loss before root retirement",
  async () => {
    const dataRoot = await mkdtemp(
      path.join(os.tmpdir(), "enoki-production-systemd-recovery-"),
    );
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });
    const assetDir = path.join(dataRoot, "probe-assets");
    await mkdir(assetDir);
    const releaseAuthority = createTestProbeIdentity();
    const bundle = await buildProductionBundle({
      dataRoot,
      rootPublicKeyPem: releaseAuthority.publicKeyPem,
      version: "0.2.0",
    });
    const sourceProbeSha256 = createHash("sha256")
      .update(await readFile(probeBinary!))
      .digest("hex");
    const release = await writeSignedProbeAssetSet(assetDir, {
      authority: {
        privateKey: releaseAuthority.privateKeyPem,
        publicKey: releaseAuthority.publicKeyPem,
      },
      sourceVersion: "0.1.0",
      targetVersion: "0.2.0",
      transition: "replacement-required",
      x86_64GnuBundle: {
        archive: bundle.archive,
        bundleManifest: bundle.bundleManifest,
      },
      x86_64GnuSourceProbeSha256: sourceProbeSha256,
    });
    const proxy = await startResponseLossProxy("0.0.0.0");
    const dockerHubHost = await currentDockerBridgeAddress();
    const proxyOrigin = `http://${dockerHubHost}:${proxy.port}`;
    const app = createHubApp({
      auth: {
        failureDelayMs: 0,
        ownerPassword: "correct horse battery staple",
        sessionCookieName: "enoki_owner_session",
      },
      database,
      installation: {
        bootstrapRecipe: {
          bundleVersion: "0.2.0",
          distribution: "enoki",
          kind: "enoki-probe-bootstrap-recipe-record",
          recipe: {
            file: "enoki-probe-bootstrap.py",
            sha256: "a".repeat(64),
            size: 123,
            version: "v1",
          },
          rootFingerprint: "b".repeat(64),
          schemaVersion: 1,
          targets: ["x86_64-unknown-linux-gnu"],
        },
        probeApiOrigin: proxyOrigin,
      },
      probeAssets: {
        assetDir,
        trustedRootPublicKeyPem: release.rootPublicKeyPem,
      },
      probeApiOrigin: proxyOrigin,
    });
    const hubServer = serve({
      fetch: app.fetch,
      hostname: "0.0.0.0",
      port: 0,
    });
    await listening(hubServer);
    proxy.setUpstream((hubServer.address() as AddressInfo).port);

    try {
      const ownerSession = await loginOwner(app);
      const productionProbeConfigurationVersion =
        await publishProductionFixtureConfiguration(app, ownerSession);
      for (const [caseIndex, crashPoint] of [
        "before-rename",
        "after-rename",
      ].entries()) {
        const hostId = 7 + caseIndex;
        const oldProbeId = `probe_production_old_${hostId}`;
        database.sqlite
          .prepare(`insert into managed_hosts (
          id, probe_id, probe_secret_hash, display_name, display_name_edited,
          connect_address, created_at_ms, clock_skew_detected, last_clock_skew_ms,
          probe_configuration_version, probe_version
        ) values (?, ?, 'old-secret-hash', 'Production Host', 0,
          '127.0.0.1', ?, 0, null, 'default-v1', '0.1.0')`)
          .run(hostId, oldProbeId, Date.now());
        const enrollmentResponse = await app.request(
          `/api/web/enrollments/manual-reinstall/${hostId}`,
          { headers: { cookie: ownerSession }, method: "POST" },
        );
        expect(enrollmentResponse.status).toBe(201);
        const enrollmentCommand = (await enrollmentResponse.json()) as {
          enrollmentId: string;
          enrollmentToken: string;
          installCommand: string;
        };
        const enrollment = installCommandEnrollment(
          enrollmentCommand.installCommand,
        );
        const container = `enoki-c4-systemd-${crashPoint}-${randomUUID()}`;
        const requestStart = proxy.requestBodies.length;
        const reportStart = proxy.reportExchanges.length;
        await startSystemdContainer({
          acquirerPath: bundle.acquirerPath,
          assetDir,
          container,
          hubOrigin: proxyOrigin,
          lifecycleCompanionPath: lifecycleCompanionBinary!,
          oldProbeId,
          sourceProbeBinary: probeBinary!,
          stateRoot: dataRoot,
        });
        try {
          await docker(container, [
            "systemctl",
            "set-environment",
            "ENOKI_TEST_SECURE_FILE_PATH=/var/lib/enoki-probe/identity/probe-bootstrap.toml",
            `ENOKI_TEST_SECURE_FILE_CRASH_POINT=${crashPoint}`,
          ]);
          proxy.loseNextResponseWhen((target, body) => {
            if (target !== "/api/probe/register") return false;
            try {
              return (
                root.enoki.v1.ProbeRegistrationRequest.decode(body)
                  .canonicalAttempt.length > 0
              );
            } catch {
              return false;
            }
          });
          const activation = runDockerAcquirer({
            bundle,
            container,
            enrollment: JSON.stringify(enrollment),
            hubOrigin: proxyOrigin,
          });
          const firstBoundary = await Promise.race([
            activation.then((result) => ({
              kind: "activation" as const,
              result,
            })),
            waitForConfigRenameCrashAndDisarm(container).then((crash) => ({
              crash,
              kind: "config-crash" as const,
            })),
          ]);
          if (firstBoundary.kind === "activation") {
            const companionDiagnostic = await runCommand(
              "docker",
              [
                "exec",
                "--interactive",
                container,
                "/opt/enoki-probe-lifecycle-companion",
              ],
              replacementLifecycleRequest({ enrollment, release }),
            );
            const [status, journal, capsule, commit, identity] =
              await Promise.all([
                docker(container, [
                  "systemctl",
                  "status",
                  "--no-pager",
                  "enoki-probe.service",
                ]),
                docker(container, [
                  "journalctl",
                  "--no-pager",
                  "-u",
                  "enoki-probe.service",
                  "-n",
                  "80",
                ]),
                docker(container, [
                  "test",
                  "-e",
                  "/var/lib/enoki-probe-registration/attempt.json",
                ]),
                docker(container, [
                  "test",
                  "-e",
                  "/var/lib/enoki-probe-bootstrap/replacement-migration.json",
                ]),
                docker(container, [
                  "test",
                  "-e",
                  "/var/lib/enoki-probe/identity/probe-bootstrap.toml",
                ]),
              ]);
            throw new Error(
              `activation ended before config crash recovery (${firstBoundary.result.code}):\n${firstBoundary.result.stdout}\n${firstBoundary.result.stderr}\ncompanion=${companionDiagnostic.code}:${companionDiagnostic.stdout}:${companionDiagnostic.stderr}\nrequests=${JSON.stringify(proxy.requestTargets.slice(requestStart))}\ncapsule=${capsule.code} commit=${commit.code} identity=${identity.code}\n${status.stdout}\n${status.stderr}\n${journal.stdout}\n${journal.stderr}`,
            );
          }
          expect(firstBoundary.crash).toEqual(
            expect.objectContaining({
              activeState: "activating",
              execMainStatus: 6,
              nRestarts: 1,
              subState: "auto-restart",
            }),
          );
          expect(
            await docker(container, [
              "stat",
              "-c",
              "%u:%g:%a",
              "/var/lib/enoki-probe-registration/attempt.json",
            ]),
          ).toEqual(
            expect.objectContaining({
              code: 0,
              stdout: "0:0:600\n",
            }),
          );
          const retainedCapsuleSha256 = await docker(container, [
            "sha256sum",
            "/var/lib/enoki-probe-registration/attempt.json",
          ]);
          expect(retainedCapsuleSha256.code).toBe(0);
          const activated = await activation;
          expect(activated.code, activated.stderr).toBe(0);
          const identityPath =
            "/var/lib/enoki-probe/identity/probe-bootstrap.toml";
          const canonicalIdentity = await docker(container, [
            "cat",
            identityPath,
          ]);
          expect(canonicalIdentity.code, canonicalIdentity.stderr).toBe(0);
          expect(
            !canonicalIdentity.stdout.includes("registration_"),
            "canonical identity must not retain one-shot registration metadata",
          ).toBe(true);
          const acceptedStartupReports = proxy.reportExchanges
            .slice(reportStart)
            .filter(
              (exchange) =>
                exchange.status === 200 &&
                Number(exchange.sequenceStart) === 1 &&
                Number(exchange.sequenceEnd) === 1 &&
                Number(exchange.metricCount) === 0,
            );
          expect(
            acceptedStartupReports.length > 0 &&
              acceptedStartupReports.every(
                (exchange) =>
                  exchange.currentProbeConfigurationVersion ===
                  productionProbeConfigurationVersion,
              ),
            "authenticated startup responses must select the published production fixture configuration",
          ).toBe(true);
          expect(
            proxy.requestTargets
              .slice(requestStart)
              .includes("/api/probe/config"),
            "Probe must fetch the newer effective configuration through its authenticated config channel",
          ).toBe(true);
          const activeAfterActivation = await docker(container, [
            "systemctl",
            "is-active",
            "enoki-probe.service",
          ]);
          expect(
            activeAfterActivation,
            `report exchanges=${JSON.stringify(
              redactedReportExchangeSummary(
                proxy.reportExchanges.slice(reportStart),
              ),
            )}`,
          ).toEqual(expect.objectContaining({ code: 0, stdout: "active\n" }));
          await waitFor(
            () =>
              hasFullThenTwoCompactReplays(
                proxy.reportExchanges.slice(reportStart),
              ),
            45_000,
            () =>
              `report replay did not converge: ${JSON.stringify(
                redactedReportExchangeSummary(
                  proxy.reportExchanges.slice(reportStart),
                ),
              )}`,
          );
          expect(
            proxy.reportExchanges
              .slice(reportStart)
              .filter((exchange) => exchange.status === 400),
          ).toEqual([]);
          const acceptedReports = proxy.reportExchanges
            .slice(reportStart)
            .filter((exchange) => exchange.status === 200);
          const acceptedObservationIdentities =
            reportObservationIdentities(acceptedReports);
          const acceptedMetricIdentities =
            reportMetricIdentities(acceptedReports);
          expect(
            new Set(acceptedObservationIdentities.map(reportIdentityKey)).size,
          ).toBeLessThan(acceptedObservationIdentities.length);
          expect(
            new Set(acceptedObservationIdentities.map(({ bootId }) => bootId))
              .size,
          ).toBeGreaterThanOrEqual(2);
          expectPersistedReportIdentitiesExactlyOnce(
            database.sqlite,
            "report_observations",
            acceptedObservationIdentities,
          );
          expectPersistedReportIdentitiesExactlyOnce(
            database.sqlite,
            "metric_samples",
            acceptedMetricIdentities,
          );
          expect(
            await docker(container, [
              "systemctl",
              "is-active",
              "enoki-probe.service",
            ]),
          ).toEqual(expect.objectContaining({ code: 0, stdout: "active\n" }));
          await expectProcFactsHiddenInCanonicalServices(container);
          for (const retiredPath of [
            "/var/lib/enoki-probe-registration/attempt.json",
            "/var/lib/enoki-probe-bootstrap/replacement-migration.json",
            "/run/systemd/system/enoki-probe.service.d/10-enoki-replacement-registration.conf",
            "/run/credentials/enoki-probe.service/registration-attempt",
          ]) {
            expect(
              await docker(container, ["test", "!", "-e", retiredPath]),
              retiredPath,
            ).toEqual(expect.objectContaining({ code: 0 }));
          }

          const caseRequests = proxy.requestBodies
            .slice(requestStart)
            .filter((body, index) => {
              if (
                proxy.requestTargets.slice(requestStart)[index] !==
                "/api/probe/register"
              ) {
                return false;
              }
              try {
                return (
                  root.enoki.v1.ProbeRegistrationRequest.decode(body)
                    .canonicalAttempt.length > 0
                );
              } catch {
                return false;
              }
            });
          expect(caseRequests.length).toBe(
            crashPoint === "before-rename" ? 3 : 2,
          );
          for (const request of caseRequests.slice(1)) {
            expect(request).toEqual(caseRequests[0]);
          }
          const authorityQuery = database.sqlite.prepare(
            `select
              h.probe_id as probeId,
              e.status as enrollmentStatus,
              e.used_at_ms as usedAtMs,
              e.ready_at_ms as readyAtMs,
              (e.registration_attempt_sha256 is not null) as hasAttempt,
              (e.registration_outcome is not null) as hasOutcome,
              (select count(*) from audit_log where action = 'probe.manual_reinstall_identity_replaced') as auditCount
            from managed_hosts h
            join enrollment_tokens e on e.managed_host_id = h.id
            where h.id = ? and e.enrollment_id = ?`,
          );
          const authorityFacts = authorityQuery.get(
            hostId,
            enrollmentCommand.enrollmentId,
          );
          expect(authorityFacts).toEqual(
            expect.objectContaining({
              auditCount: caseIndex + 1,
              enrollmentStatus: "ready",
              hasAttempt: 1,
              hasOutcome: 1,
              probeId: expect.not.stringMatching(oldProbeId),
              readyAtMs: expect.any(Number),
              usedAtMs: expect.any(Number),
            }),
          );
          expect(
            database.sqlite
              .prepare(
                "select count(*) as count from enrollment_tokens where enrollment_id = ? and used_at_ms is not null",
              )
              .get(enrollmentCommand.enrollmentId),
          ).toEqual({ count: 1 });
          expect(
            database.sqlite
              .prepare(
                "select count(*) as count from enrollment_tokens where enrollment_id = ? and registration_attempt_sha256 is not null and registration_outcome is not null",
              )
              .get(enrollmentCommand.enrollmentId),
          ).toEqual({ count: 1 });
          expect(
            database.sqlite
              .prepare(
                "select probe_id as probeId from managed_hosts where id = ?",
              )
              .get(hostId),
          ).not.toEqual({ probeId: oldProbeId });
          expect(retainedCapsuleSha256.stdout).toMatch(/^[0-9a-f]{64}  /);

          const canonicalRestart = await docker(container, [
            "systemctl",
            "restart",
            "enoki-probe.service",
          ]);
          expect(
            canonicalRestart.code,
            `${canonicalRestart.stderr}\nreport exchanges=${JSON.stringify(
              proxy.reportExchanges.slice(reportStart),
            )}`,
          ).toBe(0);
          expect(
            await docker(container, [
              "systemctl",
              "is-active",
              "enoki-probe.service",
            ]),
          ).toEqual(expect.objectContaining({ code: 0, stdout: "active\n" }));
          expect(
            authorityQuery.get(hostId, enrollmentCommand.enrollmentId),
          ).toEqual(authorityFacts);

          if (caseIndex === 0) {
            const currentProbeId = (authorityFacts as { probeId: string })
              .probeId;
            const wrongProbeIdIdentity = canonicalIdentity.stdout.replace(
              `probe_id = ${JSON.stringify(currentProbeId)}`,
              'probe_id = "probe_tampered"',
            );
            expect(
              wrongProbeIdIdentity !== canonicalIdentity.stdout,
              "wrong-Probe-ID negative must alter the canonical Probe ID",
            ).toBe(true);
            await overwriteContainerFile(
              container,
              identityPath,
              wrongProbeIdIdentity,
            );
            const wrongProbeIdRestart = await docker(container, [
              "systemctl",
              "restart",
              "enoki-probe.service",
            ]);
            expect(
              wrongProbeIdRestart.code,
              "blocking restart must not accept the old active state for a wrong Probe ID",
            ).not.toBe(0);

            const wrongKeyIdentity = canonicalIdentity.stdout.replace(
              /^probe_private_key_pem = .*$/m,
              `probe_private_key_pem = ${JSON.stringify(
                createTestProbeIdentity().privateKeyPem,
              )}`,
            );
            expect(
              wrongKeyIdentity !== canonicalIdentity.stdout,
              "wrong-key negative must alter the canonical Probe private key",
            ).toBe(true);
            await overwriteContainerFile(
              container,
              identityPath,
              wrongKeyIdentity,
            );
            await docker(container, [
              "systemctl",
              "reset-failed",
              "enoki-probe.service",
            ]);
            const wrongKeyRestart = await docker(container, [
              "systemctl",
              "restart",
              "enoki-probe.service",
            ]);
            expect(
              wrongKeyRestart.code,
              "blocking restart must wait for authenticated READY from the new key",
            ).not.toBe(0);

            await overwriteContainerFile(
              container,
              identityPath,
              canonicalIdentity.stdout,
            );
            await docker(container, [
              "systemctl",
              "reset-failed",
              "enoki-probe.service",
            ]);
            for (const unit of [
              "enoki-observation-runtime.socket",
              "enoki-observation-runtime.service",
            ]) {
              const stopped = await docker(container, [
                "systemctl",
                "stop",
                unit,
              ]);
              expect(
                stopped.code === 0,
                "Runtime outage precondition must stop both units",
              ).toBe(true);
              const masked = await docker(container, [
                "systemctl",
                "mask",
                "--runtime",
                unit,
              ]);
              expect(
                masked.code === 0,
                "Runtime outage precondition must runtime-mask both units",
              ).toBe(true);
              const inactive = await docker(container, [
                "systemctl",
                "is-active",
                unit,
              ]);
              expect(
                inactive.code !== 0,
                "Runtime outage precondition requires both units to be inactive",
              ).toBe(true);
              const runtimeMasked = await docker(container, [
                "systemctl",
                "is-enabled",
                unit,
              ]);
              expect(
                runtimeMasked.code !== 0 &&
                  runtimeMasked.stdout.trim().startsWith("masked"),
                "Runtime outage precondition requires both units to be runtime-masked",
              ).toBe(true);
            }
            expect(
              (
                await docker(container, [
                  "test",
                  "!",
                  "-e",
                  "/run/enoki-observation-runtime.sock",
                ])
              ).code === 0,
              "Runtime outage precondition requires the observation socket path to be absent",
            ).toBe(true);
            const outageRequestStart = proxy.requestTargets.length;
            const outageReportStart = proxy.reportExchanges.length;
            const runtimeOutageRestart = await docker(container, [
              "systemctl",
              "restart",
              "enoki-probe.service",
            ]);
            expect(
              runtimeOutageRestart.code,
              `Runtime-outage restart did not reach authenticated READY; report exchanges=${JSON.stringify(
                redactedReportExchangeSummary(
                  proxy.reportExchanges.slice(outageReportStart),
                ),
              )}`,
            ).toBe(0);
            expect(
              (
                await docker(container, [
                  "systemctl",
                  "is-active",
                  "enoki-probe.service",
                ])
              ).code === 0,
              "Runtime-outage restart must leave the canonical Probe active",
            ).toBe(true);
            await waitFor(
              () => {
                const acceptedStartup = proxy.reportExchanges
                  .slice(outageReportStart)
                  .some(
                    (exchange) =>
                      exchange.status === 200 &&
                      Number(exchange.sequenceStart) === 1 &&
                      Number(exchange.sequenceEnd) === 1 &&
                      Number(exchange.metricCount) === 0 &&
                      exchange.probeReportResponseDecoded === true &&
                      exchange.currentProbeConfigurationVersion ===
                        productionProbeConfigurationVersion,
                  );
                return (
                  acceptedStartup &&
                  proxy.requestTargets
                    .slice(outageRequestStart)
                    .includes("/api/probe/config")
                );
              },
              45_000,
              () =>
                `Runtime-outage startup/config channel did not converge: reports=${JSON.stringify(
                  redactedReportExchangeSummary(
                    proxy.reportExchanges.slice(outageReportStart),
                  ),
                )} configRequested=${proxy.requestTargets
                  .slice(outageRequestStart)
                  .includes("/api/probe/config")}`,
            );
          }
          const installedUnit = await docker(container, [
            "cat",
            "/etc/systemd/system/enoki-probe.service",
          ]);
          expect(installedUnit.code).toBe(0);
          expect(installedUnit.stdout).not.toContain("LoadCredential=");
        } finally {
          await runCommand("docker", ["rm", "--force", container]);
        }
      }
    } finally {
      await Promise.allSettled([proxy.close(), closeServer(hubServer)]);
      database.close();
    }
  },
  // 一次 cold signed bundle build 后串行覆盖两个有独立 deadline 的 crash case。
  600_000,
);

type ProductionBundle = {
  acquirerPath: string;
  archive: Buffer;
  archivePath: string;
  bundleManifest: Buffer;
};

async function buildProductionBundle(input: {
  dataRoot: string;
  rootPublicKeyPem: string;
  version: string;
}): Promise<ProductionBundle> {
  const target = "x86_64-unknown-linux-gnu";
  const probeTargetDir = path.join(input.dataRoot, "cargo-probe");
  await requireCommand(
    "cargo",
    [
      "build",
      "-p",
      "enoki-probe",
      "--bins",
      "--features",
      "deterministic-test-seams",
      "--target",
      target,
      "--target-dir",
      probeTargetDir,
    ],
    {
      cwd: workspaceRoot,
      env: { ENOKI_PROBE_VERSION: input.version },
    },
  );
  const probeBinaryDir = path.join(probeTargetDir, target, "debug");
  const bootstrapPaths: Record<"acquirer" | "activator", string> = {
    acquirer: "",
    activator: "",
  };
  for (const role of ["acquirer", "activator"] as const) {
    const binaryName = `enoki-probe-bootstrap-${role === "acquirer" ? "acquire" : "activate"}`;
    const targetDir = path.join(input.dataRoot, `cargo-bootstrap-${role}`);
    await requireCommand(
      "cargo",
      [
        "build",
        "-p",
        "enoki-probe-bootstrap",
        "--bin",
        binaryName,
        "--no-default-features",
        "--features",
        `${role},compiled-trust`,
        "--target",
        target,
        "--target-dir",
        targetDir,
      ],
      {
        cwd: workspaceRoot,
        env: {
          ENOKI_BOOTSTRAP_BUILD_DISTRIBUTION: "enoki",
          ENOKI_BOOTSTRAP_BUILD_ROLE: role,
          ENOKI_BOOTSTRAP_BUILD_ROOT_PEM: input.rootPublicKeyPem,
          ENOKI_BOOTSTRAP_BUILD_TARGET: target,
          ENOKI_BOOTSTRAP_BUILD_VERSION: `v${input.version}`,
        },
      },
    );
    bootstrapPaths[role] = path.join(targetDir, target, "debug", binaryName);
  }

  const staging = path.join(input.dataRoot, "production-bundle");
  await mkdir(path.join(staging, "bootstrap"), { recursive: true });
  const componentProfiles = probeBundleComponentProfiles as Record<
    string,
    {
      path: string;
      permissionProfile: string;
      resourceContract: string;
    }
  >;
  const bootstrapAssets = probeBundledBootstrapAssets as Array<{
    archivePath: string;
    key: "acquirer" | "activator";
    permissionProfile: string;
    role: string;
  }>;
  const components = [];
  for (const [role, profile] of Object.entries(componentProfiles)) {
    const source = path.join(probeBinaryDir, profile.path);
    const destination = path.join(staging, profile.path);
    await copyFile(source, destination);
    await chmod(destination, 0o755);
    const bytes = await readFile(destination);
    components.push({
      path: profile.path,
      permissionProfile: profile.permissionProfile,
      resourceContract: profile.resourceContract,
      role,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.byteLength,
      version: input.version,
    });
  }
  const bootstrapComponents = [];
  for (const asset of bootstrapAssets) {
    const destination = path.join(staging, asset.archivePath);
    await copyFile(bootstrapPaths[asset.key], destination);
    await chmod(destination, 0o755);
    const bytes = await readFile(destination);
    bootstrapComponents.push({
      path: asset.archivePath,
      permissionProfile: asset.permissionProfile,
      role: asset.role,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.byteLength,
      version: input.version,
    });
  }
  const bundleManifest = Buffer.from(
    `${JSON.stringify(
      {
        bootstrapAssets: bootstrapComponents,
        components,
        kind: "enoki-probe-bundle",
        target,
        version: input.version,
      },
      null,
      2,
    )}\n`,
  );
  await writeFile(path.join(staging, "bundle-manifest.json"), bundleManifest);
  const archivePath = path.join(input.dataRoot, `enoki-probe-${target}.tar.gz`);
  await requireCommand("tar", [
    "--create",
    "--gzip",
    "--sort=name",
    "--owner=0",
    "--group=0",
    "--numeric-owner",
    "--blocking-factor=1",
    "--mtime=@0",
    "--format=gnu",
    "--file",
    archivePath,
    "--directory",
    staging,
    "bundle-manifest.json",
    ...Object.values(componentProfiles).map(
      ({ path: componentPath }) => componentPath,
    ),
    ...bootstrapAssets.map(({ archivePath: bootstrapPath }) => bootstrapPath),
  ]);
  return {
    acquirerPath: bootstrapPaths.acquirer,
    archive: await readFile(archivePath),
    archivePath,
    bundleManifest,
  };
}

async function startSystemdContainer(input: {
  acquirerPath: string;
  assetDir: string;
  container: string;
  hubOrigin: string;
  lifecycleCompanionPath: string;
  oldProbeId: string;
  sourceProbeBinary: string;
  stateRoot: string;
}) {
  const root = path.join(input.stateRoot, `root-${input.container}`);
  await createOldProductionInstall({
    hubOrigin: input.hubOrigin,
    oldProbeId: input.oldProbeId,
    productionRoot: root,
  });
  const unitPath = path.join(root, "etc/systemd/system/enoki-probe.service");
  const sudoersPath = path.join(root, "etc/sudoers.d/enoki-c4-installer");
  await mkdir(path.dirname(unitPath), { recursive: true });
  await mkdir(path.dirname(sudoersPath), { recursive: true });
  await writeFile(
    unitPath,
    "[Unit]\nDescription=Existing Enoki Probe\n\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n",
    { mode: 0o644 },
  );
  await writeFile(sudoersPath, "enoki-installer ALL=(root) NOPASSWD: ALL\n", {
    mode: 0o440,
  });
  await copyFile(
    input.sourceProbeBinary,
    path.join(root, "usr/local/bin/enoki-probe"),
  );
  await chmod(path.join(root, "usr/local/bin/enoki-probe"), 0o755);

  const started = await runCommand("docker", [
    "run",
    "--detach",
    "--privileged",
    "--cgroupns=host",
    "--name",
    input.container,
    systemdImage!,
    "/sbin/init",
  ]);
  expect(started.code, started.stderr).toBe(0);
  await waitForSystemd(input.container);
  await requireCommand("docker", [
    "exec",
    input.container,
    "mount",
    "--make-shared",
    "/run",
  ]);
  await requireCommand("docker", ["cp", `${root}/.`, `${input.container}:/`]);
  await requireCommand("docker", [
    "cp",
    input.assetDir,
    `${input.container}:/opt/enoki-assets`,
  ]);
  await requireCommand("docker", [
    "cp",
    input.acquirerPath,
    `${input.container}:/opt/enoki-probe-bootstrap-acquire`,
  ]);
  await requireCommand("docker", [
    "cp",
    input.lifecycleCompanionPath,
    `${input.container}:/opt/enoki-probe-lifecycle-companion`,
  ]);
  for (const command of [
    ["groupadd", "--system", "enoki-probe"],
    [
      "useradd",
      "--system",
      "--gid",
      "enoki-probe",
      "--home-dir",
      "/var/lib/enoki-probe",
      "--shell",
      "/usr/sbin/nologin",
      "enoki-probe",
    ],
    ["useradd", "--create-home", "--shell", "/bin/bash", "enoki-installer"],
    ["chown", "-R", "enoki-installer:enoki-installer", "/opt/enoki-assets"],
    ["chmod", "0700", "/opt/enoki-assets"],
    ["chmod", "0755", "/opt/enoki-probe-bootstrap-acquire"],
    ["chmod", "0755", "/opt/enoki-probe-lifecycle-companion"],
    ["systemctl", "daemon-reload"],
    ["systemctl", "enable", "enoki-probe.service"],
  ]) {
    const result = await docker(input.container, command);
    expect(result.code, `${command.join(" ")}: ${result.stderr}`).toBe(0);
  }
}

async function runDockerAcquirer(input: {
  bundle: ProductionBundle;
  container: string;
  enrollment: string;
  hubOrigin: string;
}) {
  return await runCommand(
    "docker",
    [
      "exec",
      "--interactive",
      "--user",
      "enoki-installer",
      "--env",
      `ENOKI_HUB_URL=${input.hubOrigin}`,
      "--env",
      "ENOKI_PROBE_LOCAL_ASSET_DIR=/opt/enoki-assets",
      "--env",
      `ENOKI_PROBE_LOCAL_BUNDLE_ARCHIVE=/opt/enoki-assets/${path.basename(input.bundle.archivePath)}`,
      input.container,
      "/opt/enoki-probe-bootstrap-acquire",
    ],
    input.enrollment,
  );
}

async function waitForSystemd(container: string) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const state = await docker(container, ["systemctl", "is-system-running"]);
    if (state.stdout.trim() === "running") return;
    await delay(100);
  }
  throw new Error("systemd did not become running");
}

async function currentDockerBridgeAddress() {
  const override = process.env.ENOKI_PRODUCTION_SYSTEMD_HUB_HOST;
  if (override) return override;
  const inspected = await runCommand("docker", [
    "inspect",
    "--format",
    '{{with index .NetworkSettings.Networks "bridge"}}{{.IPAddress}}{{end}}',
    os.hostname(),
  ]);
  const address = inspected.stdout.trim();
  if (inspected.code !== 0 || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) {
    throw new Error(
      `cannot resolve the workspace Docker bridge address: ${inspected.stderr}`,
    );
  }
  return address;
}

async function waitForConfigRenameCrashAndDisarm(container: string) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const state = await docker(container, [
      "systemctl",
      "show",
      "--property=ActiveState",
      "--property=ExecMainStartTimestampMonotonic",
      "--property=ExecMainStatus",
      "--property=NRestarts",
      "--property=SubState",
      "enoki-probe.service",
    ]);
    const properties = Object.fromEntries(
      state.stdout
        .trim()
        .split("\n")
        .map((line) => line.split(/=(.*)/s).slice(0, 2)),
    );
    if (
      state.code === 0 &&
      properties.ActiveState === "activating" &&
      Number(properties.ExecMainStatus) === 6 &&
      properties.SubState === "auto-restart"
    ) {
      const disarmed = await docker(container, [
        "systemctl",
        "unset-environment",
        "ENOKI_TEST_SECURE_FILE_PATH",
        "ENOKI_TEST_SECURE_FILE_CRASH_POINT",
      ]);
      expect(disarmed.code, disarmed.stderr).toBe(0);
      const managerEnvironment = await docker(container, [
        "systemctl",
        "show-environment",
      ]);
      expect(managerEnvironment.code, managerEnvironment.stderr).toBe(0);
      expect(managerEnvironment.stdout).not.toContain(
        "ENOKI_TEST_SECURE_FILE_",
      );
      return {
        activeState: properties.ActiveState,
        execMainStartTimestampMonotonic:
          properties.ExecMainStartTimestampMonotonic,
        execMainStatus: Number(properties.ExecMainStatus),
        nRestarts: Number(properties.NRestarts),
        subState: properties.SubState,
      };
    }
    await delay(250);
  }
  const status = await docker(container, [
    "systemctl",
    "status",
    "--no-pager",
    "enoki-probe.service",
  ]);
  throw new Error(
    `Probe did not stop at the first config rename crash:\n${status.stdout}\n${status.stderr}`,
  );
}

async function expectProcFactsHiddenInCanonicalServices(container: string) {
  const hiddenProcPaths = [
    "/proc/stat",
    "/proc/loadavg",
    "/proc/meminfo",
    "/proc/uptime",
    "/proc/cpuinfo",
    "/proc/mounts",
    "/proc/net/dev",
    "/proc/net/route",
    "/proc/net/ipv6_route",
    "/proc/diskstats",
    "/proc/sys/kernel/hostname",
    "/proc/sys/kernel/osrelease",
  ];
  for (const service of [
    "enoki-probe.service",
    "enoki-observation-runtime.service",
  ]) {
    const mainPid = await docker(container, [
      "systemctl",
      "show",
      "--property=MainPID",
      "--value",
      service,
    ]);
    expect(mainPid.code, `${service}: ${mainPid.stderr}`).toBe(0);
    const pid = Number(mainPid.stdout.trim());
    expect(pid, `${service} must have a live main process`).toBeGreaterThan(1);
    for (const hiddenPath of hiddenProcPaths) {
      const hidden = await docker(container, [
        "nsenter",
        `--mount=/proc/${pid}/ns/mnt`,
        "--",
        "test",
        "!",
        "-e",
        hiddenPath,
      ]);
      expect(hidden.code, `${service} can still see ${hiddenPath}`).toBe(0);
    }
  }
}

function delay(milliseconds: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

function docker(container: string, command: string[]) {
  return runCommand("docker", ["exec", container, ...command]);
}

async function overwriteContainerFile(
  container: string,
  filePath: string,
  contents: string,
) {
  const overwritten = await runCommand(
    "docker",
    ["exec", "--interactive", container, "tee", filePath],
    contents,
  );
  expect(overwritten.code, overwritten.stderr).toBe(0);
}

async function requireCommand(
  program: string,
  args: string[],
  options: { cwd?: string; env?: Record<string, string> } = {},
) {
  const result = await runCommand(program, args, undefined, options);
  if (result.code !== 0) {
    throw new Error(
      `${program} ${args.join(" ")} failed (${result.code}):\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result;
}

async function runCommand(
  program: string,
  args: string[],
  input?: string,
  options: { cwd?: string; env?: Record<string, string> } = {},
) {
  return await new Promise<{
    code: number | null;
    stderr: string;
    stdout: string;
  }>((resolve, reject) => {
    const child = spawn(program, args, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout!.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr!.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stderr, stdout }));
    if (input !== undefined) child.stdin?.end(input);
  });
}

async function registrationFixture(input: {
  dataRoot: string;
  enrollmentToken: string;
  capsulePath: string;
}) {
  const capsule = JSON.parse(await readFile(input.capsulePath, "utf8")) as {
    candidatePrivateKeyPem: string;
    requestHex: string;
    signedAttemptSha256: string;
  };
  const request = root.enoki.v1.ProbeRegistrationRequest.decode(
    Buffer.from(capsule.requestHex, "hex"),
  );
  const attempt = root.enoki.v1.ProbeRegistrationAttempt.decode(
    request.canonicalAttempt,
  );
  const configPath = path.join(input.dataRoot, "probe-bootstrap.toml");
  await writeFile(
    configPath,
    [
      `hub_url = ${JSON.stringify(attempt.hubOrigin)}`,
      `enrollment_token = ${JSON.stringify(input.enrollmentToken)}`,
      `registration_attempt_credential_path = ${JSON.stringify(input.capsulePath)}`,
      `registration_enrollment_id = ${JSON.stringify(attempt.enrollmentId)}`,
      `registration_host_id = ${JSON.stringify(attempt.hostId)}`,
      `registration_hub_origin = ${JSON.stringify(attempt.hubOrigin)}`,
      `registration_old_probe_id = ${JSON.stringify(attempt.oldProbeId)}`,
      `registration_source_probe_version = ${JSON.stringify(attempt.sourceProbeVersion)}`,
      `registration_committed_source_probe_sha256 = ${JSON.stringify(attempt.committedSourceProbeSha256)}`,
      `registration_target_probe_version = ${JSON.stringify(attempt.targetProbeVersion)}`,
      `registration_target_bundle_target = ${JSON.stringify(attempt.targetBundleTarget)}`,
      `registration_target_asset_set_digest = ${JSON.stringify(attempt.targetAssetSetDigest)}`,
      `registration_target_manifest_sha256 = ${JSON.stringify(attempt.targetManifestSha256)}`,
      `registration_replacement_commit_sha256 = ${JSON.stringify(attempt.replacementCommitSha256)}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  await chmod(configPath, 0o600);
  return {
    capsulePath: input.capsulePath,
    configPath,
    signedAttemptSha256: capsule.signedAttemptSha256,
  };
}

async function runProbe(
  args: string[],
  environment: Record<string, string> = {},
) {
  return await new Promise<{ code: number | null; stderr: string }>(
    (resolve, reject) => {
      const child = spawn(probeBinary!, args, {
        env: { ...process.env, ...environment },
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr.setEncoding("utf8").on("data", (chunk) => {
        stderr += chunk;
      });
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, stderr }));
    },
  );
}

type ReplacementInstallEnrollment = {
  enrollmentToken: string;
  hubOrigin: string;
  replacementMigration: {
    enrollmentId: string;
    expectedProbeId: string;
    sourceProbeSha256: string[];
    sourceProbeVersion: string;
    targetAssetSetDigest: string;
    targetHostId: string;
    targetProbeVersion: string;
  };
  schemaVersion: number;
};

function installCommandEnrollment(
  command: string,
): ReplacementInstallEnrollment {
  const match = /^printf '%s\\n' '([^']+)' \|/.exec(command);
  expect(match?.[1]).toBeTruthy();
  return JSON.parse(match![1]!) as ReplacementInstallEnrollment;
}

function replacementLifecycleRequest(input: {
  enrollment: ReplacementInstallEnrollment;
  release: Awaited<ReturnType<typeof writeSignedProbeAssetSet>>;
}) {
  const target = input.release.targetBundles.find(
    (bundle) => bundle.target === "x86_64-unknown-linux-gnu",
  )!;
  return JSON.stringify({
    schemaVersion: 1,
    transition: "replacement-migration",
    authority: {
      kind: "replacement-enrollment",
      enrollment_token: input.enrollment.enrollmentToken,
      enrollment_id: input.enrollment.replacementMigration.enrollmentId,
      hub_origin: input.enrollment.hubOrigin,
      host_id: input.enrollment.replacementMigration.targetHostId,
      expected_probe_id: input.enrollment.replacementMigration.expectedProbeId,
      source_probe_version:
        input.enrollment.replacementMigration.sourceProbeVersion,
      source_probe_sha256:
        input.enrollment.replacementMigration.sourceProbeSha256,
      target_asset_set_digest:
        input.enrollment.replacementMigration.targetAssetSetDigest,
      target_bundle_target: target.target,
      target_manifest_sha256: target.bundleManifestSha256,
      bundle_version: input.enrollment.replacementMigration.targetProbeVersion,
    },
  });
}

async function createOldProductionInstall(input: {
  hubOrigin: string;
  oldProbeId: string;
  productionRoot: string;
}) {
  const binary = path.join(input.productionRoot, "usr/local/bin/enoki-probe");
  const identity = path.join(
    input.productionRoot,
    "etc/enoki/probe-bootstrap.toml",
  );
  const metadata = path.join(
    input.productionRoot,
    "etc/enoki/probe-install.toml",
  );
  await Promise.all([
    mkdir(path.dirname(binary), { recursive: true }),
    mkdir(path.dirname(identity), { recursive: true }),
    mkdir(path.join(input.productionRoot, "var/lib/enoki-probe"), {
      recursive: true,
    }),
  ]);
  await copyFile(probeBinary!, binary);
  await chmod(binary, 0o755);
  const oldIdentity = createTestProbeIdentity();
  await writeFile(
    identity,
    [
      `hub_url = ${JSON.stringify(input.hubOrigin)}`,
      `probe_id = ${JSON.stringify(input.oldProbeId)}`,
      `probe_private_key_pem = ${JSON.stringify(oldIdentity.privateKeyPem)}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  await chmod(identity, 0o600);
  await writeFile(
    metadata,
    [
      "schema_version = 1",
      'install_path = "/usr/local/bin/enoki-probe"',
      `hub_url = ${JSON.stringify(input.hubOrigin)}`,
      'operation_status_path = "/var/lib/enoki-probe/probe-operation-status.toml"',
      'state_dir = "/var/lib/enoki-probe"',
      'operation_sudoers_path = "/etc/sudoers.d/enoki-probe-operations"',
      'collector_helper_sudoers_path = "/etc/sudoers.d/enoki-probe-collector-helpers"',
      'service_name = "enoki-probe"',
      'service_user = "enoki-probe"',
      'identity_path = "/etc/enoki/probe-bootstrap.toml"',
      'service_group = "enoki-probe"',
      'service_unit_path = "/etc/systemd/system/enoki-probe.service"',
      `probe_asset_public_key_sha256 = ${JSON.stringify("a".repeat(64))}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  await chmod(metadata, 0o600);
}

async function runLifecycleCompanion(
  request: string,
  environment: Record<string, string>,
) {
  return await new Promise<{
    code: number | null;
    stderr: string;
    stdout: string;
  }>((resolve, reject) => {
    const child = spawn(lifecycleCompanionBinary!, [], {
      env: { ...process.env, ...environment },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stderr, stdout }));
    child.stdin.end(request);
  });
}

async function loginOwner(app: ReturnType<typeof createHubApp>) {
  const response = await app.request("/api/web/auth/login", {
    body: JSON.stringify({ password: "correct horse battery staple" }),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  expect(response.status).toBe(200);
  return response.headers.get("set-cookie") ?? "";
}

async function publishProductionFixtureConfiguration(
  app: ReturnType<typeof createHubApp>,
  ownerSession: string,
) {
  const response = await app.request("/api/web/probe-configuration", {
    body: JSON.stringify({
      enabledCollectorIds: [...defaultEnabledCollectorIds],
      metricsCollectionIntervalSeconds: 1,
    }),
    headers: {
      "content-type": "application/json",
      cookie: ownerSession,
    },
    method: "PUT",
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as {
    configuration: {
      metricsCollectionIntervalSeconds: number;
      version: string;
    };
  };
  expect(body.configuration.metricsCollectionIntervalSeconds).toBe(1);
  expect(body.configuration.version).not.toBe("default-v1");
  return body.configuration.version;
}

async function startResponseLossProxy(hostname = "127.0.0.1") {
  let upstreamPort = 0;
  let responseLossMatcher: ((target: string, body: Buffer) => boolean) | null =
    null;
  const requestBodies: Buffer[] = [];
  const requestTargets: string[] = [];
  const reportExchanges: Array<Record<string, unknown>> = [];
  const server = net.createServer((client) => {
    const requestChunks: Buffer[] = [];
    let forwarded = false;
    client.on("data", (chunk) => {
      if (forwarded) return;
      requestChunks.push(Buffer.from(chunk));
      const request = Buffer.concat(requestChunks);
      const body = completeHttpBody(request);
      if (!body) return;
      forwarded = true;
      const target =
        request
          .subarray(0, request.indexOf("\r\n"))
          .toString("latin1")
          .split(" ")[1] ?? "";
      requestBodies.push(body);
      requestTargets.push(target);
      const reportExchange =
        target === "/api/probe/report" ? summarizeReport(body) : null;
      if (reportExchange) reportExchanges.push(reportExchange);
      const loseResponse = responseLossMatcher?.(target, body) ?? false;
      if (loseResponse) responseLossMatcher = null;
      const upstream = net.connect({ host: "127.0.0.1", port: upstreamPort });
      upstream.on("connect", () => upstream.write(request));
      const responseChunks: Buffer[] = [];
      upstream.on("data", (responseChunk) => {
        responseChunks.push(Buffer.from(responseChunk));
        if (!reportExchange) return;
        const response = Buffer.concat(responseChunks);
        const responseBody = completeHttpBody(response);
        if (!responseBody) return;
        reportExchange.status = Number(
          /^HTTP\/1\.1 (\d{3})/m.exec(response.toString("latin1"))?.[1],
        );
        if (reportExchange.status === 200) {
          try {
            const decodedResponse =
              root.enoki.v1.ProbeReportResponse.decode(responseBody);
            reportExchange.probeReportResponseDecoded = true;
            reportExchange.currentProbeConfigurationVersion =
              decodedResponse.currentProbeConfigurationVersion;
            reportExchange.requestedSnapshotCollectorIds = [
              ...decodedResponse.requestedSnapshotCollectorIds,
            ];
          } catch {
            reportExchange.probeReportResponseDecoded = false;
            reportExchange.currentProbeConfigurationVersion =
              "unparseable_response";
            reportExchange.requestedSnapshotCollectorIds = [
              "unparseable_response",
            ];
          }
        } else {
          try {
            reportExchange.errorCode = JSON.parse(
              responseBody.toString("utf8"),
            ).error;
          } catch {
            reportExchange.errorCode = "unparseable_error";
          }
        }
      });
      if (!loseResponse) {
        upstream.pipe(client);
        return;
      }
      upstream.on("data", () => {
        if (completeHttpBody(Buffer.concat(responseChunks))) {
          client.destroy();
          upstream.destroy();
        }
      });
    });
  });
  server.listen(0, hostname);
  await listening(server);
  return {
    close: () => closeServer(server),
    loseNextResponse: () => {
      responseLossMatcher = () => true;
    },
    loseNextResponseWhen: (
      matcher: (target: string, body: Buffer) => boolean,
    ) => {
      responseLossMatcher = matcher;
    },
    port: (server.address() as AddressInfo).port,
    reportExchanges,
    requestBodies,
    requestTargets,
    setUpstream: (port: number) => {
      upstreamPort = port;
    },
  };
}

function summarizeReport(body: Buffer): Record<string, unknown> | null {
  try {
    const report = root.enoki.v1.ProbeReportRequest.decode(body);
    return {
      bootId: report.bootId,
      metricCount: report.metrics.length,
      metricSequences: report.metrics.map((metric) => Number(metric.sequence)),
      observationWindowFailure: report.observationWindowFailure != null,
      probeId: report.probeId,
      sequenceEnd: Number(report.sequenceEnd),
      sequenceStart: Number(report.sequenceStart),
      snapshots: report.snapshots.map((snapshot) => ({
        hasPayload: snapshot.hostProfile != null,
        snapshotHash: snapshot.snapshotHash,
      })),
    };
  } catch {
    return null;
  }
}

type ReportIdentity = {
  bootId: string;
  probeId: string;
  sequence: number;
};

function reportObservationIdentities(
  exchanges: Array<Record<string, unknown>>,
): ReportIdentity[] {
  return exchanges.flatMap((exchange) => {
    const identities: ReportIdentity[] = [];
    for (
      let sequence = Number(exchange.sequenceStart);
      sequence <= Number(exchange.sequenceEnd);
      sequence += 1
    ) {
      identities.push({
        bootId: String(exchange.bootId),
        probeId: String(exchange.probeId),
        sequence,
      });
    }
    return identities;
  });
}

function reportMetricIdentities(
  exchanges: Array<Record<string, unknown>>,
): ReportIdentity[] {
  return exchanges.flatMap((exchange) =>
    ((exchange.metricSequences as number[] | undefined) ?? []).map(
      (sequence) => ({
        bootId: String(exchange.bootId),
        probeId: String(exchange.probeId),
        sequence,
      }),
    ),
  );
}

function reportIdentityKey(identity: ReportIdentity) {
  return JSON.stringify([identity.probeId, identity.bootId, identity.sequence]);
}

function compareReportIdentities(left: ReportIdentity, right: ReportIdentity) {
  return (
    left.probeId.localeCompare(right.probeId) ||
    left.bootId.localeCompare(right.bootId) ||
    left.sequence - right.sequence
  );
}

function expectPersistedReportIdentitiesExactlyOnce(
  sqlite: DatabaseSync,
  table: "metric_samples" | "report_observations",
  capturedIdentities: ReportIdentity[],
) {
  const identities = [
    ...new Map(
      capturedIdentities.map((identity) => [
        reportIdentityKey(identity),
        identity,
      ]),
    ).values(),
  ];
  expect(identities.length).toBeGreaterThan(0);
  const values = identities.map(() => "(?, ?, ?)").join(", ");
  const parameters = identities.flatMap(({ bootId, probeId, sequence }) => [
    probeId,
    bootId,
    sequence,
  ]);
  const persisted = sqlite
    .prepare(
      `with expected(probe_id, boot_id, sequence) as (values ${values})
       select
         expected.probe_id as probeId,
         expected.boot_id as bootId,
         expected.sequence as sequence,
         count(actual.id) as persistedCount
       from expected
       left join ${table} actual
         on actual.probe_id = expected.probe_id
        and actual.boot_id = expected.boot_id
        and actual.sequence = expected.sequence
       group by expected.probe_id, expected.boot_id, expected.sequence
       order by expected.probe_id, expected.boot_id, expected.sequence`,
    )
    .all(...parameters)
    .map((row) => ({
      bootId: String(row.bootId),
      persistedCount: Number(row.persistedCount),
      probeId: String(row.probeId),
      sequence: Number(row.sequence),
    }))
    .sort(compareReportIdentities);
  expect(persisted).toEqual(
    identities
      .map(({ bootId, probeId, sequence }) => ({
        bootId,
        persistedCount: 1,
        probeId,
        sequence,
      }))
      .sort(compareReportIdentities),
  );
}

function hasFullThenTwoCompactReplays(
  exchanges: Array<Record<string, unknown>>,
) {
  const accepted = exchanges.filter((exchange) => exchange.status === 200);
  const firstFull = accepted.find(
    (exchange) =>
      Number(exchange.metricCount) > 0 &&
      reportSnapshot(exchange)?.hasPayload === true,
  );
  const firstFullHash = firstFull
    ? reportSnapshot(firstFull)?.snapshotHash
    : null;
  if (!firstFullHash) return false;

  const replayedHashes = new Set<string>();
  for (const compact of accepted) {
    const compactSnapshot = reportSnapshot(compact);
    if (
      Number(compact.metricCount) === 0 ||
      compactSnapshot?.hasPayload !== false ||
      !compactSnapshot.snapshotHash ||
      compactSnapshot.snapshotHash === firstFullHash ||
      !(
        compact.requestedSnapshotCollectorIds as string[] | undefined
      )?.includes("official.host-profile")
    ) {
      continue;
    }
    const replay = accepted.find(
      (exchange) =>
        Number(exchange.metricCount) === 0 &&
        Number(exchange.sequenceStart) === Number(compact.sequenceEnd) &&
        Number(exchange.sequenceEnd) === Number(compact.sequenceEnd) &&
        reportSnapshot(exchange)?.hasPayload === true &&
        reportSnapshot(exchange)?.snapshotHash === compactSnapshot.snapshotHash,
    );
    if (replay) replayedHashes.add(compactSnapshot.snapshotHash);
  }
  return replayedHashes.size >= 2;
}

function reportSnapshot(exchange: Record<string, unknown>) {
  const snapshots = exchange.snapshots as
    | Array<{ hasPayload?: boolean; snapshotHash?: string }>
    | undefined;
  return snapshots?.length === 1 ? snapshots[0] : null;
}

function redactedReportExchangeSummary(
  exchanges: Array<Record<string, unknown>>,
) {
  const bootReferences = new Map<string, string>();
  const configurationReferences = new Map<string, string>();
  const snapshotReferences = new Map<string, string>();
  const reference = (
    references: Map<string, string>,
    value: unknown,
    prefix: string,
  ) => {
    const key = String(value ?? "");
    if (!references.has(key)) {
      references.set(key, `${prefix}-${references.size + 1}`);
    }
    return references.get(key);
  };

  return exchanges.map((exchange) => {
    const snapshot = reportSnapshot(exchange);
    const sequenceStart = Number(exchange.sequenceStart);
    const sequenceEnd = Number(exchange.sequenceEnd);
    const metricCount = Number(exchange.metricCount);
    const snapshotKind = snapshot
      ? snapshot.hasPayload === true
        ? "full"
        : "compact"
      : "none";
    return {
      boot: reference(bootReferences, exchange.bootId, "boot"),
      configuration:
        typeof exchange.currentProbeConfigurationVersion === "string"
          ? reference(
              configurationReferences,
              exchange.currentProbeConfigurationVersion,
              "configuration",
            )
          : null,
      error: exchange.errorCode ?? null,
      metricCount,
      observationWindowFailure: exchange.observationWindowFailure === true,
      requestedHostProfile:
        (
          exchange.requestedSnapshotCollectorIds as string[] | undefined
        )?.includes("official.host-profile") ?? false,
      responseDecoded: exchange.probeReportResponseDecoded === true,
      sameSequenceReplay:
        sequenceStart === sequenceEnd &&
        metricCount === 0 &&
        snapshotKind === "full",
      sequenceEnd,
      sequenceStart,
      snapshot: snapshot
        ? {
            kind: snapshotKind,
            ref: reference(
              snapshotReferences,
              snapshot.snapshotHash,
              "snapshot",
            ),
          }
        : null,
      status: exchange.status ?? null,
    };
  });
}

function completeHttpBody(message: Buffer) {
  const headerEnd = message.indexOf("\r\n\r\n");
  if (headerEnd < 0) return null;
  const header = message.subarray(0, headerEnd).toString("latin1");
  const length = Number(/\r\ncontent-length: (\d+)/i.exec(header)?.[1]);
  if (!Number.isSafeInteger(length) || length < 0) return null;
  const bodyStart = headerEnd + 4;
  return message.length >= bodyStart + length
    ? message.subarray(bodyStart, bodyStart + length)
    : null;
}

function withoutObservedClockOffset(config: string) {
  return config.replace(/^server_time_offset_ms = -?\d+\n/m, "");
}

function listening(server: net.Server) {
  return new Promise<void>((resolve) => server.once("listening", resolve));
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs: number,
  failureMessage?: () => string,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  expect(predicate(), failureMessage?.()).toBe(true);
}

function closeServer(server: net.Server) {
  return new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
