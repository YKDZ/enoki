import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";

import * as root from "@enoki/proto/generated/ts/enoki_pb.js";
import { serve } from "@hono/node-server";
import { afterEach, expect, it } from "vitest";

import { createHubApp } from "../src/app";
import { initializeHubDatabase } from "../src/database/index";
import { buildProductionBundle } from "./probe-registration-production-recovery-bundle-test-support";
import {
  docker,
  runCommand,
} from "./probe-registration-production-recovery-command-test-support";
import {
  createOldProductionInstall,
  installCommandEnrollment,
  loginOwner,
  publishProductionFixtureConfiguration,
  registrationFixture,
  replacementLifecycleRequest,
  runLifecycleCompanion,
  runProbe,
  withoutObservedClockOffset,
} from "./probe-registration-production-recovery-fixture-test-support";
import {
  closeServer,
  expectPersistedReportIdentitiesExactlyOnce,
  hasFullThenTwoCompactReplays,
  listening,
  redactedReportExchangeSummary,
  reportIdentityKey,
  reportMetricIdentities,
  reportObservationIdentities,
  startResponseLossProxy,
  waitFor,
} from "./probe-registration-production-recovery-report-test-support";
import {
  currentDockerBridgeAddress,
  expectProcFactsHiddenInCanonicalServices,
  overwriteContainerFile,
  runDockerAcquirer,
  startSystemdContainer,
  waitForConfigRenameCrashAndDisarm,
} from "./probe-registration-production-recovery-systemd-test-support";
import { writeSignedProbeAssetSet } from "./probe-release-transition-fixture";
import { createTestProbeIdentity } from "./probe-test-auth";

const probeBinary = process.env.ENOKI_PRODUCTION_PROBE_BINARY;
const lifecycleCompanionBinary =
  process.env.ENOKI_PRODUCTION_LIFECYCLE_COMPANION_BINARY;
const systemdImage = process.env.ENOKI_PRODUCTION_SYSTEMD_IMAGE;
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
