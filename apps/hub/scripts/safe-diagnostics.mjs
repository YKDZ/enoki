import { redactAndTruncate } from "./safe-output.mjs";

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
    redactAndTruncate(values[0], redactions, valueBudget),
  ];
  let valueIndex = 1;

  for (const container of containers) {
    lines.push(`container ${container.name}`);
    for (let field = 0; field < 3; field += 1) {
      lines.push(
        redactAndTruncate(values[valueIndex], redactions, valueBudget),
      );
      valueIndex += 1;
    }
  }

  return redactAndTruncate(lines.join("\n"), redactions, limitBytes);
}

function safeErrorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
