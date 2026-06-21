import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

const webHubUrl = trimTrailingSlash(
  process.env.ENOKI_WEB_HUB_URL ?? "http://localhost:3000",
);
const probeHubUrl = trimTrailingSlash(
  process.env.ENOKI_HUB_URL ?? "http://localhost:3001",
);
const ownerPassword =
  process.env.ENOKI_OWNER_PASSWORD ?? process.env.OWNER_PASSWORD;
let enrollmentToken = process.env.ENOKI_ENROLLMENT_TOKEN;

if (!enrollmentToken) {
  if (!ownerPassword) {
    console.error(
      [
        "ENOKI_OWNER_PASSWORD or OWNER_PASSWORD is required unless ENOKI_ENROLLMENT_TOKEN is provided.",
        "",
        "Examples:",
        "  ENOKI_OWNER_PASSWORD='dev-password' pnpm dev:probe",
        "  OWNER_PASSWORD='dev-password' pnpm dev:probe",
        "  export ENOKI_OWNER_PASSWORD='dev-password'",
        "  pnpm dev:probe",
        "",
        "Note: `env ENOKI_OWNER_PASSWORD=...` by itself only prints an environment for that one command; it does not export the variable to your shell.",
      ].join("\n"),
    );
    process.exit(1);
  }

  enrollmentToken = await createEnrollmentToken(webHubUrl, ownerPassword);
}

const probeRoot = await mkdtemp(path.join(tmpdir(), "enoki-dev-probe-"));
const bootstrapConfigPath = path.join(probeRoot, "probe-bootstrap.toml");

await writeFile(
  bootstrapConfigPath,
  [
    `hub_url = ${tomlString(probeHubUrl)}`,
    `enrollment_token = ${tomlString(enrollmentToken)}`,
    `state_dir = ${tomlString(probeRoot)}`,
    "",
  ].join("\n"),
  {
    mode: 0o600,
  },
);

console.log(`Starting temporary Enoki Probe against ${probeHubUrl}`);
console.log(`Probe bootstrap config: ${bootstrapConfigPath}`);

const child = spawn(
  "cargo",
  ["run", "-p", "enoki-probe", "--", "run", "--config", bootstrapConfigPath],
  {
    stdio: "inherit",
  },
);

let cleanedUp = false;

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.once(signal, () => {
    child.kill(signal);
  });
}

child.once("exit", async (code, signal) => {
  if (!cleanedUp) {
    cleanedUp = true;
    await rm(probeRoot, {
      force: true,
      recursive: true,
    });
  }

  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code ?? 0);
});

async function createEnrollmentToken(baseUrl, password) {
  const loginResponse = await fetch(`${baseUrl}/api/web/auth/login`, {
    body: JSON.stringify({
      password,
    }),
    headers: {
      "content-type": "application/json",
    },
    method: "POST",
  });

  if (!loginResponse.ok) {
    throw new Error(
      `Owner login failed with HTTP ${loginResponse.status}. Check ENOKI_OWNER_PASSWORD/OWNER_PASSWORD and ENOKI_WEB_HUB_URL.`,
    );
  }

  const cookie = loginResponse.headers.get("set-cookie")?.split(";")[0];

  if (!cookie) {
    throw new Error("Owner login did not return a session cookie.");
  }

  const enrollmentResponse = await fetch(`${baseUrl}/api/web/enrollments`, {
    headers: {
      cookie,
    },
    method: "POST",
  });

  if (!enrollmentResponse.ok) {
    throw new Error(
      `Enrollment creation failed with HTTP ${enrollmentResponse.status}.`,
    );
  }

  const body = await enrollmentResponse.json();

  if (typeof body.enrollmentToken !== "string" || !body.enrollmentToken) {
    throw new Error("Enrollment response did not include an enrollment token.");
  }

  return body.enrollmentToken;
}

function trimTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

function tomlString(value) {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}
