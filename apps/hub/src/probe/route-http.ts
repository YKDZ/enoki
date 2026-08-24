import { getConnInfo } from "@hono/node-server/conninfo";
import type { Context } from "hono";

import { deriveObservedIp, type TrustedProxyCidr } from "../network.js";

export async function readCappedRequestBody(
  request: Request,
  maxBytes: number,
) {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export function parseProbeOperationId(operationId: string | null | undefined) {
  return operationId && /^[1-9]\d*$/.test(operationId)
    ? Number(operationId)
    : null;
}

export function observedIpFromContext(
  context: Context,
  trustedProxyCidrs: TrustedProxyCidr[] | undefined,
) {
  let directPeer: string | null = null;
  try {
    const address = getConnInfo(context).remote.address;
    directPeer = address?.startsWith("::ffff:")
      ? address.slice(7)
      : (address ?? null);
  } catch {
    directPeer = null;
  }
  return deriveObservedIp({
    directPeer,
    trustedProxyCidrs: trustedProxyCidrs ?? [],
    xForwardedFor: context.req.raw.headers.get("x-forwarded-for"),
  });
}

export function probeJsonError(
  error: string,
  status: 400 | 401 | 403 | 404 | 409 | 413 | 415 | 429 | 503,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify({ error }), {
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json",
      ...headers,
    },
    status,
  });
}
