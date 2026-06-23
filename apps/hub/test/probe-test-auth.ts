import {
  createHash,
  createSign,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";

export type TestProbeIdentity = {
  privateKeyPem: string;
  publicKeyPem: string;
};

export type RegisteredTestProbe = {
  privateKeyPem: string;
  probeId: string;
  probeSecret?: string;
};

export function createTestProbeIdentity(): TestProbeIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  return {
    privateKeyPem: privateKey.export({
      format: "pem",
      type: "pkcs8",
    }) as string,
    publicKeyPem: publicKey.export({
      format: "pem",
      type: "spki",
    }) as string,
  };
}

export function signedProbeHeaders(input: {
  body: Uint8Array;
  method?: string;
  pathAndQuery: string;
  privateKeyPem: string;
  probeId: string;
  timestampMs?: string;
  nonce?: string;
}) {
  const bodySha256 = createHash("sha256").update(input.body).digest("hex");
  const timestampMs = input.timestampMs ?? String(Date.now());
  const nonce = input.nonce ?? randomHex(16);
  const payload = [
    (input.method ?? "POST").toUpperCase(),
    input.pathAndQuery,
    timestampMs,
    nonce,
    bodySha256,
  ].join("\n");
  const signer = createSign("RSA-SHA256");
  signer.update(payload);
  signer.end();

  return {
    "content-type": "application/x-protobuf",
    "x-enoki-body-sha256": bodySha256,
    "x-enoki-nonce": nonce,
    "x-enoki-probe-id": input.probeId,
    "x-enoki-signature": signer.sign(input.privateKeyPem).toString("hex"),
    "x-enoki-timestamp-ms": timestampMs,
  };
}

export function signedJsonProbeHeaders(input: {
  body: string;
  pathAndQuery: string;
  privateKeyPem: string;
  probeId: string;
  timestampMs?: string;
  nonce?: string;
}) {
  return {
    ...signedProbeHeaders({
      body: new TextEncoder().encode(input.body),
      nonce: input.nonce,
      pathAndQuery: input.pathAndQuery,
      privateKeyPem: input.privateKeyPem,
      probeId: input.probeId,
      timestampMs: input.timestampMs,
    }),
    "content-type": "application/json",
  };
}

export function signedJsonProbeRequest(
  registration: RegisteredTestProbe,
  pathAndQuery: string,
  body: string,
): RequestInit {
  return {
    body,
    headers: signedJsonProbeHeaders({
      body,
      pathAndQuery,
      privateKeyPem: registration.privateKeyPem,
      probeId: registration.probeId,
    }),
    method: "POST",
  };
}

export function signedProbeRequest(
  registration: RegisteredTestProbe,
  pathAndQuery: string,
  body: Uint8Array,
): RequestInit {
  return {
    body,
    headers: signedProbeHeaders({
      body,
      pathAndQuery,
      privateKeyPem: registration.privateKeyPem,
      probeId: registration.probeId,
    }),
    method: "POST",
  };
}

function randomHex(byteCount: number) {
  return randomBytes(byteCount).toString("hex");
}
