export function createContainerFetchSource(timeoutMs) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error("A positive HTTP timeout is required.");
  }

  return [
    "const response = await fetch(process.env.ENOKI_EVIDENCE_URL, {",
    "  body: process.env.ENOKI_EVIDENCE_BODY || undefined,",
    "  headers: JSON.parse(process.env.ENOKI_EVIDENCE_HEADERS || '{}'),",
    "  method: process.env.ENOKI_EVIDENCE_METHOD,",
    `  signal: AbortSignal.timeout(${timeoutMs}),`,
    "});",
    "console.log(JSON.stringify({ requestId: response.headers.get('x-request-id'), status: response.status }));",
  ].join("\n");
}
