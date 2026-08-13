const redactionMarker = "[REDACTED]";

export function createRedactingBoundedBuffer(limitBytes, redactions = []) {
  if (!Number.isSafeInteger(limitBytes) || limitBytes < 0) {
    throw new Error("A non-negative output limit is required.");
  }

  const secrets = redactions
    .filter((secret) => typeof secret === "string" && secret.length > 0)
    .sort((left, right) => right.length - left.length);
  const overlapLength = Math.max(
    0,
    ...secrets.map((secret) => secret.length - 1),
  );
  let output = "";
  let pending = "";
  let finalized = false;

  return {
    append(chunk) {
      if (finalized) throw new Error("Cannot append finalized safe output.");
      pending += chunk;
      drain(false);
    },
    bufferedBytes() {
      return Buffer.byteLength(output) + Buffer.byteLength(pending);
    },
    value() {
      if (!finalized) {
        drain(true);
        finalized = true;
      }
      return output;
    },
  };

  function drain(final) {
    while (pending.length > 0 && (final || pending.length > overlapLength)) {
      const secret = secrets.find((candidate) => pending.startsWith(candidate));
      if (secret) {
        appendOutput(redactionMarker);
        pending = pending.slice(secret.length);
        continue;
      }

      const [character] = pending;
      appendOutput(character);
      pending = pending.slice(character.length);
    }
  }

  function appendOutput(value) {
    if (Buffer.byteLength(output) >= limitBytes) return;
    output = truncateUtf8(`${output}${value}`, limitBytes);
  }
}

export function redactAndTruncate(value, redactions, limitBytes) {
  const buffer = createRedactingBoundedBuffer(limitBytes, redactions);
  buffer.append(value);
  return buffer.value();
}

export function truncateUtf8(value, limitBytes) {
  if (Buffer.byteLength(value) <= limitBytes) return value;
  const bytes = Buffer.from(value);
  for (let end = Math.min(limitBytes, bytes.length); end >= 0; end -= 1) {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(
        bytes.subarray(0, end),
      );
    } catch {
      // Move to the preceding complete UTF-8 code point.
    }
  }
  return "";
}
