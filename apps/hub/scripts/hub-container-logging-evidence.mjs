import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const image = readImage(process.argv.slice(2));
const runId = randomUUID().replaceAll("-", "").slice(0, 16);
const names = {
  fatal: `enoki-hub-logging-fatal-${runId}`,
  runtime: `enoki-hub-logging-runtime-${runId}`,
};
const secret = `seeded-secret-${runId}-never-log`;
const ownerPassword = `owner-password-${secret}`;

try {
  await requireDocker();
  await proveRuntimeLogging();
  await proveFatalLogging();
  console.log("Hub container logging evidence passed.");
} finally {
  await Promise.all(Object.values(names).map((name) => removeContainer(name)));
}

function readImage(args) {
  const imageIndex = args.findIndex((argument) => argument === "--image");
  const value = imageIndex === -1 ? undefined : args[imageIndex + 1];

  if (!value || value.startsWith("-")) {
    throw new Error("Usage: --image <production-hub-image>");
  }

  return value;
}

async function proveRuntimeLogging() {
  await startContainer(names.runtime, []);
  await Promise.all([
    waitForHealth(names.runtime, 3000),
    waitForHealth(names.runtime, 3001),
  ]);

  const managementResponse = await request(
    names.runtime,
    3000,
    "/api/web/auth/login",
    {
      body: JSON.stringify({ password: ownerPassword }),
      headers: secretHeaders("management-client-request-id"),
      method: "POST",
    },
  );
  assertStatus(managementResponse, 200, "management login");

  const probeResponse = await request(
    names.runtime,
    3001,
    "/api/probe/register",
    {
      body: new Uint8Array(),
      headers: secretHeaders("probe-client-request-id"),
      method: "POST",
    },
  );
  assertClientError(probeResponse, "Probe registration rejection");

  const managementError = await request(names.runtime, 3000, "/api/unknown", {
    headers: secretHeaders("management-error-client-id"),
  });
  const probeError = await request(names.runtime, 3001, "/api/unknown", {
    headers: secretHeaders("probe-error-client-id"),
  });
  assertStatus(managementError, 404, "management unknown route");
  assertStatus(probeError, 404, "Probe unknown route");

  await run("stop runtime Hub", ["kill", "--signal=SIGTERM", names.runtime]);
  await waitForContainerExit(names.runtime);

  const logs = await readLogs(names.runtime);
  assertEqual(logs.stderr, "", "healthy runtime only writes stdout");
  const events = parseJsonLines(logs.stdout, "runtime stdout");
  assertSafeEvents(events, "runtime");
  assertNoSecret(events, "runtime");
  assertRuntimeEvents(events, {
    managementRequestId: requestId(managementResponse, "management login"),
    managementErrorRequestId: requestId(
      managementError,
      "management unknown route",
    ),
    probeErrorRequestId: requestId(probeError, "Probe unknown route"),
    probeRequestId: requestId(probeResponse, "Probe registration rejection"),
  });
}

async function proveFatalLogging() {
  await startContainer(names.fatal, ["--env", "PORT=not-a-port"]);
  await waitForContainerExit(names.fatal);

  const logs = await readLogs(names.fatal);
  const stdoutEvents = parseJsonLines(logs.stdout, "fatal stdout");
  const stderrEvents = parseJsonLines(logs.stderr, "fatal stderr");
  assertSafeEvents([...stdoutEvents, ...stderrEvents], "fatal");
  assertNoSecret([...stdoutEvents, ...stderrEvents], "fatal");
  assert(
    stderrEvents.filter((event) => event.event === "process.fatal").length ===
      1,
    "fatal startup is logged exactly once on stderr",
  );
  assert(
    stderrEvents.every((event) => event.level === "error"),
    "stderr contains only error-level JSON events",
  );
  assert(
    stdoutEvents.some((event) => event.event === "process.shutdown.started"),
    "fatal startup begins a bounded shutdown on stdout",
  );
  assert(
    stdoutEvents.some((event) => event.event === "process.shutdown.completed"),
    "fatal startup completes a bounded shutdown on stdout",
  );
}

async function startContainer(name, extraArgs) {
  await run("start production Hub", [
    "run",
    "--detach",
    "--name",
    name,
    "--mount",
    "type=tmpfs,destination=/data,tmpfs-mode=0700",
    "--env",
    `OWNER_PASSWORD=${ownerPassword}`,
    "--env",
    "ENOKI_HUB_LOG_LEVEL=debug",
    "--env",
    "ENOKI_MANAGEMENT_ORIGIN=http://127.0.0.1",
    "--env",
    "ENOKI_PROBE_API_ORIGIN=http://127.0.0.1",
    "--env",
    "ENOKI_METRICS_ARCHIVE_ENABLED=false",
    ...extraArgs,
    image,
  ]);
}

function secretHeaders(clientRequestId) {
  return {
    authorization: `Bearer ${secret}`,
    cookie: `session=${secret}`,
    "content-type": "application/json",
    origin: "http://127.0.0.1",
    "user-agent": secret,
    "x-request-id": clientRequestId,
  };
}

async function request(name, port, path, options = {}) {
  const result = await execInContainer(name, {
    body: typeof options.body === "string" ? options.body : "",
    headers: options.headers ?? {},
    method: options.method ?? "GET",
    url: `http://127.0.0.1:${port}${path}?seed=${secret}`,
  });
  return result;
}

async function waitForHealth(name, port) {
  const deadline = Date.now() + 30_000;

  while (Date.now() < deadline) {
    try {
      const response = await execInContainer(name, {
        method: "GET",
        url: `http://127.0.0.1:${port}/api/health`,
      });
      if (response.status === 200) return;
    } catch {
      // The process is still starting.
    }
    await delay(200);
  }

  throw new Error("Hub listener did not become healthy within 30 seconds.");
}

async function execInContainer(name, request) {
  const script = [
    "const response = await fetch(process.env.ENOKI_EVIDENCE_URL, {",
    "  body: process.env.ENOKI_EVIDENCE_BODY || undefined,",
    "  headers: JSON.parse(process.env.ENOKI_EVIDENCE_HEADERS || '{}'),",
    "  method: process.env.ENOKI_EVIDENCE_METHOD,",
    "});",
    "console.log(JSON.stringify({ requestId: response.headers.get('x-request-id'), status: response.status }));",
  ].join("\n");
  const result = await run("send HTTP request to Hub listener", [
    "exec",
    "--env",
    `ENOKI_EVIDENCE_BODY=${request.body ?? ""}`,
    "--env",
    `ENOKI_EVIDENCE_HEADERS=${JSON.stringify(request.headers ?? {})}`,
    "--env",
    `ENOKI_EVIDENCE_METHOD=${request.method}`,
    "--env",
    `ENOKI_EVIDENCE_URL=${request.url}`,
    name,
    "node",
    "--input-type=module",
    "--eval",
    script,
  ]);

  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error("Hub listener did not return a bounded HTTP response.");
  }
}

async function waitForContainerExit(name) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const state = await run("inspect Hub container state", [
      "inspect",
      "--format",
      "{{.State.Running}}",
      name,
    ]);
    if (state.stdout.trim() === "false") return;
    await delay(100);
  }

  throw new Error("Hub container did not stop within 30 seconds.");
}

async function readLogs(name) {
  return run("read Hub container console logs", ["logs", name]);
}

async function removeContainer(name) {
  await run("remove Hub container", ["rm", "--force", "--volumes", name], {
    allowFailure: true,
  });
}

async function requireDocker() {
  const version = await run(
    "check Docker",
    ["version", "--format", "{{.Server.Version}}"],
    {
      allowFailure: true,
    },
  );
  if (version.code !== 0) {
    throw new Error(
      "Docker Engine is required for Hub container logging evidence.",
    );
  }
}

function run(label, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", () => {
      reject(new Error(`Unable to ${label}.`));
    });
    child.once("close", (code) => {
      const result = { code: code ?? 1, stderr, stdout };
      if (result.code !== 0 && !options.allowFailure) {
        reject(new Error(`Unable to ${label}.`));
        return;
      }
      resolve(result);
    });
  });
}

function parseJsonLines(output, source) {
  const lines = output.split("\n").filter(Boolean);
  assert(lines.length > 0, `${source} contains at least one JSON log event`);
  return lines.map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new Error(`${source} contains only JSON Lines.`);
    }
  });
}

function assertSafeEvents(events, source) {
  const allowedKeys = new Set([
    "component",
    "configurationMessage",
    "durationMs",
    "event",
    "level",
    "listener",
    "method",
    "outcome",
    "requestId",
    "routeId",
    "status",
  ]);
  const components = new Set([
    "hub",
    "management-listener",
    "metrics-archive",
    "probe-listener",
  ]);
  const eventNames = new Set([
    "background.completed",
    "background.failed",
    "configuration.warning",
    "listener.started",
    "process.fatal",
    "process.shutdown.completed",
    "process.shutdown.started",
    "request.completed",
  ]);
  const levels = new Set(["debug", "info", "warn", "error"]);

  for (const event of events) {
    assert(
      event && typeof event === "object" && !Array.isArray(event),
      `${source} log line is an object`,
    );
    assert(
      Object.keys(event).every((key) => allowedKeys.has(key)),
      `${source} log event uses only the Hub allowlist`,
    );
    assert(
      components.has(event.component),
      `${source} component is allowlisted`,
    );
    assert(eventNames.has(event.event), `${source} event name is allowlisted`);
    assert(levels.has(event.level), `${source} level is allowlisted`);
    if (event.requestId !== undefined) {
      assert(
        /^[A-Za-z0-9_-]{8,64}$/.test(event.requestId),
        `${source} request IDs are bounded Hub identifiers`,
      );
    }
  }
}

function assertRuntimeEvents(events, requestIds) {
  assertEvent(events, {
    component: "management-listener",
    event: "listener.started",
    listener: "management",
    outcome: "listening",
  });
  assertEvent(events, {
    component: "probe-listener",
    event: "listener.started",
    listener: "probe",
    outcome: "listening",
  });
  assertEvent(events, {
    component: "management-listener",
    event: "request.completed",
    listener: "management",
    method: "POST",
    outcome: "ok",
    requestId: requestIds.managementRequestId,
    routeId: "web_auth_login",
    status: 200,
  });
  assertEvent(events, {
    component: "probe-listener",
    event: "request.completed",
    listener: "probe",
    method: "POST",
    requestId: requestIds.probeRequestId,
    routeId: "probe_registration",
  });
  assertEvent(events, {
    component: "management-listener",
    event: "request.completed",
    listener: "management",
    outcome: "http_404",
    requestId: requestIds.managementErrorRequestId,
    routeId: "unknown",
    status: 404,
  });
  assertEvent(events, {
    component: "probe-listener",
    event: "request.completed",
    listener: "probe",
    outcome: "http_404",
    requestId: requestIds.probeErrorRequestId,
    routeId: "unknown",
    status: 404,
  });
  assertEvent(events, {
    component: "hub",
    event: "process.shutdown.started",
    outcome: "graceful_shutdown",
  });
  assertEvent(events, {
    component: "hub",
    event: "process.shutdown.completed",
    outcome: "graceful_shutdown",
  });
  assert(
    events.filter((event) => event.event === "process.fatal").length === 0,
    "ordinary runtime requests do not create fatal logs",
  );
}

function assertEvent(events, expected) {
  assert(
    events.some((event) =>
      Object.entries(expected).every(([key, value]) => event[key] === value),
    ),
    `missing expected ${expected.event} event`,
  );
}

function requestId(response, label) {
  const value = response.requestId;
  assert(typeof value === "string", `${label} returns a Hub request ID`);
  assert(
    !value.includes("client-request-id") && !value.includes("client-id"),
    `${label} does not return the caller request ID`,
  );
  return value;
}

function assertNoSecret(events, source) {
  assert(
    !JSON.stringify(events).includes(secret),
    `${source} logs do not expose seeded secrets, headers, or query values`,
  );
}

function assertStatus(response, expected, label) {
  assert(response.status === expected, `${label} returns HTTP ${expected}`);
}

function assertClientError(response, label) {
  assert(
    response.status >= 400 && response.status < 500,
    `${label} is an expected client rejection`,
  );
}

function assertEqual(actual, expected, message) {
  assert(actual === expected, message);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
