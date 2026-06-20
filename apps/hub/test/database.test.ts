import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { initializeHubDatabase } from "../src/database/index";

const tempRoots: string[] = [];

describe("Hub database", () => {
  afterEach(async () => {
    await Promise.all(
      tempRoots
        .splice(0)
        .map((root) => rm(root, { force: true, recursive: true })),
    );
  });

  it("applies migrations to a real SQLite file before audit events are stored", async () => {
    const dataRoot = await mkdtemp(path.join(os.tmpdir(), "enoki-hub-db-"));
    tempRoots.push(dataRoot);
    const database = initializeHubDatabase({
      dataRoot,
      sqlitePath: path.join(dataRoot, "enoki.db"),
    });

    const event = database.audit.record({
      action: "owner.login",
      actor: "owner",
      occurredAtMs: 1_725_000_000_000,
      outcome: "success",
    });

    expect(event.id).toBeGreaterThan(0);
    expect(database.audit.recent()).toEqual([
      expect.objectContaining({
        action: "owner.login",
        actor: "owner",
        outcome: "success",
      }),
    ]);

    database.close();
  });
});
