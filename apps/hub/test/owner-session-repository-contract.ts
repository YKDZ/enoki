import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import type { OwnerSessionRepository } from "../src/auth/owner-session-repository";
import { createMemoryPasswordVerificationBudget } from "../src/auth/password-verification-budget";
import { createOwnerAuth } from "../src/auth/routes";

const ownerPassword = "correct horse battery staple";
const sessionCookieName = "enoki_owner_session";
const sessionDurationMs = 7 * 24 * 60 * 60 * 1000;

type RepositoryFactory = () => OwnerSessionRepository;

export function ownerSessionRepositoryContract(
  name: string,
  createRepository: RepositoryFactory,
) {
  describe(name, () => {
    it("stores only the digest and bounded metadata for an opaque token", async () => {
      const repository = createRepository();
      const auth = createContractAuth(repository);

      const cookie = await login(auth);
      const token = sessionToken(cookie);

      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(repository.list()).toEqual([
        expect.objectContaining({
          createdAtMs: 1_725_000_000_000,
          expiresAtMs: 1_725_000_000_000 + sessionDurationMs,
          sequence: 0,
          tokenDigest: createHash("sha256").update(token).digest("hex"),
        }),
      ]);
      expect(JSON.stringify(repository.list())).not.toContain(token);
      expect(repository.findByTokenDigest(token)).toBeNull();
    });

    it("removes expired sessions before issuance and notifies their revocation", async () => {
      let nowMs = 1_725_000_000_000;
      const invalidated: string[] = [];
      const repository = createRepository();
      const auth = createContractAuth(repository, {
        now: () => nowMs,
        onSessionInvalidated: (sessionId) => invalidated.push(sessionId),
      });

      const expiredCookie = await login(auth);
      const expiredDigest = digestCookie(expiredCookie);
      nowMs += sessionDurationMs + 1;
      await login(auth);

      expect(repository.list()).toHaveLength(1);
      expect(invalidated).toEqual([expiredDigest]);
      await expectSession(auth, expiredCookie, false);
    });

    it("concurrently issues at most eight sessions and deterministically revokes the oldest", async () => {
      const invalidated: string[] = [];
      const repository = createRepository();
      const auth = createContractAuth(repository, {
        onSessionInvalidated: (sessionId) => invalidated.push(sessionId),
      });

      const cookies = await Promise.all(
        Array.from({ length: 20 }, async () => login(auth)),
      );

      expect(repository.list()).toHaveLength(8);
      expect(
        repository
          .list()
          .map((session) => session.sequence)
          .sort(),
      ).toEqual([12, 13, 14, 15, 16, 17, 18, 19]);
      expect(invalidated).toEqual(cookies.slice(0, 12).map(digestCookie));
      for (const [index, cookie] of cookies.entries()) {
        await expectSession(auth, cookie, index >= 12);
      }
    });

    it("notifies the exact revoked session so its WebSockets can be closed", async () => {
      const invalidated: string[] = [];
      const repository = createRepository();
      const auth = createContractAuth(repository, {
        onSessionInvalidated: (sessionId) => invalidated.push(sessionId),
      });
      const cookies: string[] = [];
      for (let index = 0; index < 8; index += 1) {
        cookies.push(await login(auth));
      }

      await login(auth);

      expect(invalidated).toEqual([digestCookie(cookies[0] ?? "")]);
      expect(invalidated).not.toContain(digestCookie(cookies[1] ?? ""));
    });

    it("invalidates a session on logout without affecting another session", async () => {
      const invalidated: string[] = [];
      const repository = createRepository();
      const auth = createContractAuth(repository, {
        onSessionInvalidated: (sessionId) => invalidated.push(sessionId),
      });
      const firstCookie = await login(auth);
      const secondCookie = await login(auth);

      const response = await auth.routes.request("/logout", {
        headers: { cookie: firstCookie },
        method: "POST",
      });

      expect(response.status).toBe(200);
      expect(invalidated).toEqual([digestCookie(firstCookie)]);
      await expectSession(auth, firstCookie, false);
      await expectSession(auth, secondCookie, true);
    });

    it("does not carry sessions into a fresh repository after restart, password replacement, or restore", async () => {
      const original = createContractAuth(createRepository());
      const cookie = await login(original);

      for (const password of [
        ownerPassword,
        "replacement password",
        ownerPassword,
      ]) {
        const replacement = createContractAuth(
          createRepository(),
          {},
          password,
        );
        await expectSession(replacement, cookie, false);
      }
    });

    it("deletes one digest without affecting another and can clear all records", () => {
      const repository = createRepository();
      repository.save(sessionRecord("digest-one", 1));
      repository.save(sessionRecord("digest-two", 2));

      expect(repository.deleteByTokenDigest("digest-one")).toBe(true);
      expect(repository.deleteByTokenDigest("digest-one")).toBe(false);
      expect(repository.list()).toEqual([
        expect.objectContaining({ tokenDigest: "digest-two" }),
      ]);
      expect(repository.clear()).toEqual([
        expect.objectContaining({ tokenDigest: "digest-two" }),
      ]);
      expect(repository.list()).toEqual([]);
    });
  });
}

function createContractAuth(
  ownerSessions: OwnerSessionRepository,
  services: Partial<Parameters<typeof createOwnerAuth>[1]> = {},
  password = ownerPassword,
) {
  return createOwnerAuth(
    {
      failureDelayMs: 0,
      ownerPassword: password,
      sessionCookieName,
    },
    {
      now: () => 1_725_000_000_000,
      ownerSessions,
      passwordVerificationBudget: createMemoryPasswordVerificationBudget({
        capacity: 20,
      }),
      ...services,
    },
  );
}

async function login(auth: ReturnType<typeof createOwnerAuth>) {
  const response = await auth.routes.request("/login", {
    body: JSON.stringify({ password: ownerPassword }),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  expect(response.status).toBe(200);
  return response.headers.get("set-cookie") ?? "";
}

async function expectSession(
  auth: ReturnType<typeof createOwnerAuth>,
  cookie: string,
  authenticated: boolean,
) {
  const response = await auth.routes.request("/session", {
    headers: { cookie },
  });
  await expect(response.json()).resolves.toEqual({ authenticated });
}

function sessionToken(cookie: string) {
  return cookie.match(/enoki_owner_session=([^;]+)/)?.[1] ?? "";
}

function digestCookie(cookie: string) {
  return createHash("sha256").update(sessionToken(cookie)).digest("hex");
}

function sessionRecord(tokenDigest: string, sequence: number) {
  return {
    createdAtMs: 100 + sequence,
    expiresAtMs: 200 + sequence,
    sequence,
    tokenDigest,
  };
}
