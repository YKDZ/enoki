import { mkdir } from "node:fs/promises";
import path from "node:path";

import { request, type FullConfig } from "@playwright/test";

import {
  defaultOwnerPassword,
  ownerStorageStatePath,
} from "./owner-auth-state";

export default async function globalSetup(config: FullConfig) {
  const project = config.projects.find(
    ({ name }) => name === "chromium" || name === "candidate-chromium",
  );
  if (!project) {
    throw new Error("The E2E config must define a chromium project");
  }
  const baseURL = project.use.baseURL;
  if (typeof baseURL !== "string") {
    throw new Error("The chromium E2E project must define a baseURL");
  }
  const ownerPassword =
    project.name === "candidate-chromium"
      ? process.env.ENOKI_RELEASE_UI_OWNER_PASSWORD
      : defaultOwnerPassword;
  if (!ownerPassword) {
    throw new Error("The candidate E2E project must define its Owner password");
  }

  const ownerRequest = await request.newContext({
    baseURL,
    extraHTTPHeaders: { origin: baseURL },
  });
  try {
    const response = await ownerRequest.post("/api/web/auth/login", {
      data: { password: ownerPassword },
    });
    if (!response.ok()) {
      throw new Error(
        `Owner E2E setup login failed with HTTP ${response.status()}: ${await response.text()}`,
      );
    }

    await mkdir(path.dirname(ownerStorageStatePath), { recursive: true });
    await ownerRequest.storageState({ path: ownerStorageStatePath });
  } finally {
    await ownerRequest.dispose();
  }
}
