import { generateKeyPairSync } from "node:crypto";

const identities = new Map();

export function rsa4096TestKeyPair(slot) {
  if (typeof slot !== "string" || slot.length === 0) {
    throw new Error("RSA-4096 test key slot is required");
  }
  let identity = identities.get(slot);
  if (!identity) {
    identity = Object.freeze(
      generateKeyPairSync("rsa", {
        modulusLength: 4096,
        privateKeyEncoding: { format: "pem", type: "pkcs8" },
        publicKeyEncoding: { format: "pem", type: "spki" },
      }),
    );
    identities.set(slot, identity);
  }
  return identity;
}
