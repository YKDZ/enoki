import { describe, expect, it } from "vitest";

import { createEnrollmentRoutes } from "../src/enrollment/routes";

function app(
  status: "online" | "stale" | "offline" | null,
  creationResult?: "existing_host_verifying",
) {
  const calls: unknown[] = [];
  const routes = createEnrollmentRoutes({
    enrollments: {
      createPending(input) {
        if (creationResult) {
          return { kind: creationResult };
        }
        if (input.target.kind === "existing_host" && status !== "offline") {
          return { kind: "existing_host_unavailable" };
        }
        calls.push(input);
        return {
          enrollment: {
            createdAtMs: input.createdAtMs,
            enrollmentId: input.enrollmentId,
            expiredAtMs: null,
            expiresAtMs: input.expiresAtMs,
            hostId:
              input.target.kind === "existing_host"
                ? input.target.hostId
                : null,
            id: 1,
            readyAtMs: null,
            rejectedAtMs: null,
            rejectionCode: null,
            rejectionMessage: null,
            status: "pending",
            targetHostId:
              input.target.kind === "existing_host"
                ? input.target.hostId
                : null,
            targetKind: input.target.kind,
            tokenHash: input.tokenHash,
            usedAtMs: null,
            verificationDeadlineAtMs: null,
          } as any,
          kind: "created",
        };
      },
      inspectPending: () => null,
      readStatus: () => null,
      registerNewHost: () => null,
      rejectInstallation: () => null,
      resolveStartupReport: () => null,
    },
    now: () => 1_725_000_000_000,
  });
  return { calls, routes };
}

describe("Existing Host Enrollment API", () => {
  it("creates a persisted existing_host pending Enrollment only for an offline active Host", async () => {
    const { calls, routes } = app("offline");
    const response = await routes.request("/", {
      body: JSON.stringify({
        target: { hostId: 7, kind: "existing_host" },
      }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    expect(response.status).toBe(201);
    await expect(response.json()).resolves.toEqual(
      expect.objectContaining({
        status: "pending",
        target: { hostId: 7, kind: "existing_host" },
      }),
    );
    expect(calls).toEqual([
      expect.objectContaining({ target: { hostId: 7, kind: "existing_host" } }),
    ]);
  });

  it("reports a verifying ExistingHost re-enrollment conflict without creating another Enrollment", async () => {
    const { calls, routes } = app("offline", "existing_host_verifying");
    const response = await routes.request("/", {
      body: JSON.stringify({
        target: { hostId: 7, kind: "existing_host" },
      }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      error: "existing_host_reenrollment_verifying",
    });
    expect(calls).toEqual([]);
  });

  it("rejects malformed JSON enrollment targets without creating an Enrollment", async () => {
    const { calls, routes } = app("offline");
    const response = await routes.request("/", {
      body: "{",
      headers: { "content-type": "application/json" },
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_enrollment_target",
    });
    expect(calls).toEqual([]);
  });

  it("keeps a valid JSON request without target compatible with NewHost Enrollment", async () => {
    const { calls, routes } = app("offline");
    const response = await routes.request("/", {
      body: JSON.stringify({}),
      headers: { "content-type": "application/json" },
      method: "POST",
    });

    expect(response.status).toBe(201);
    expect(calls).toEqual([
      expect.objectContaining({ target: { kind: "new_host" } }),
    ]);
  });

  for (const status of [null, "online", "stale"] as const) {
    it(`rejects ${status ?? "missing"} Hosts without creating an Enrollment`, async () => {
      const { calls, routes } = app(status);
      const response = await routes.request("/existing-host/7", {
        method: "POST",
      });
      expect(response.status).toBe(409);
      expect(calls).toEqual([]);
    });
  }
});
