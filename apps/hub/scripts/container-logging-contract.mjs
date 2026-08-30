const allowedEventKeys = new Set([
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

const allowedComponents = new Set([
  "hub",
  "management-listener",
  "metrics-archive",
  "probe-listener",
]);
const allowedEvents = new Set([
  "background.completed",
  "background.failed",
  "configuration.warning",
  "listener.started",
  "process.fatal",
  "process.shutdown.completed",
  "process.shutdown.started",
  "request.completed",
]);
const allowedLevels = new Set(["debug", "info", "warn", "error"]);

export function parseContainerJsonLines(output) {
  const lines = output.split("\n").filter(Boolean);
  assert(lines.length > 0, "容器控制台至少包含一条 JSON Lines 日志。");

  return lines.map((line) => {
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      throw new Error("容器控制台只包含 JSON Lines 日志。");
    }

    assert(
      event && typeof event === "object" && !Array.isArray(event),
      "每条容器日志都是 JSON 对象。",
    );
    assert(
      Object.keys(event).every((key) => allowedEventKeys.has(key)),
      "容器日志只使用 Hub 字段白名单。",
    );
    assert(
      allowedComponents.has(event.component),
      "容器日志 component 使用 Hub 白名单。",
    );
    assert(allowedEvents.has(event.event), "容器日志 event 使用 Hub 白名单。");
    assert(allowedLevels.has(event.level), "容器日志 level 使用 Hub 白名单。");
    if (event.requestId !== undefined) {
      assert(
        typeof event.requestId === "string" &&
          /^[A-Za-z0-9_-]{8,64}$/.test(event.requestId),
        "容器日志 requestId 是 Hub 生成的有界标识符。",
      );
    }
    return event;
  });
}

export function assertListenerConsoleEvidence(events) {
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
  assertRequestEvent(events, "management");
  assertRequestEvent(events, "probe");
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
}

function assertRequestEvent(events, listener) {
  const component =
    listener === "management" ? "management-listener" : "probe-listener";
  const event = events.find(
    (candidate) =>
      candidate.component === component &&
      candidate.event === "request.completed" &&
      candidate.listener === listener &&
      candidate.method === "GET" &&
      candidate.outcome === "ok" &&
      candidate.routeId === "health" &&
      candidate.status === 200,
  );

  assert(event, `${listener} listener 的普通健康请求已写入容器日志。`);
  assert(
    typeof event.durationMs === "number" && event.durationMs >= 0,
    `${listener} listener 日志包含有界请求耗时。`,
  );
}

function assertEvent(events, expected) {
  assert(
    events.some((event) =>
      Object.entries(expected).every(([key, value]) => event[key] === value),
    ),
    `缺少预期的 ${expected.event} 容器日志事件。`,
  );
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
