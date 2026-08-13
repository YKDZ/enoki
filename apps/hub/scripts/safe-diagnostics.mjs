export function formatFailureDiagnostic(error, containers, options = {}) {
  const limitBytes = options.limitBytes ?? 8 * 1024;
  const redactions = options.redactions ?? [];
  const headings = ["Hub container logging evidence failed:"];
  const values = [safeErrorMessage(error)];

  for (const container of containers) {
    headings.push(`container ${container.name}`);
    values.push(
      `state: ${container.state ?? "unavailable"}`,
      `stdout: ${container.stdout ?? "unavailable"}`,
      `stderr: ${container.stderr ?? "unavailable"}`,
    );
  }

  const headingBytes = Buffer.byteLength(headings.join("\n") + "\n");
  const valueBudget = Math.max(
    0,
    Math.floor((limitBytes - headingBytes) / values.length),
  );
  const lines = [
    headings[0],
    truncate(redact(values[0], redactions), valueBudget),
  ];
  let valueIndex = 1;

  for (const container of containers) {
    lines.push(`container ${container.name}`);
    for (let field = 0; field < 3; field += 1) {
      lines.push(truncate(redact(values[valueIndex], redactions), valueBudget));
      valueIndex += 1;
    }
  }

  return truncate(lines.join("\n"), limitBytes);
}

function safeErrorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function redact(value, redactions) {
  return redactions
    .filter((secret) => typeof secret === "string" && secret.length > 0)
    .reduce((safe, secret) => safe.split(secret).join("[REDACTED]"), value);
}

function truncate(value, limitBytes) {
  if (Buffer.byteLength(value) <= limitBytes) return value;
  if (limitBytes <= 3) return ".".repeat(limitBytes);
  return `${Buffer.from(value)
    .subarray(0, limitBytes - 3)
    .toString("utf8")}...`;
}
