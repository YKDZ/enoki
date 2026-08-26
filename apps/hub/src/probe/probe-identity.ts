import { Buffer } from "node:buffer";
import { createPublicKey, createVerify } from "node:crypto";

export function verifyProbeRequestSignature(
  publicKeyPem: string,
  payload: string,
  signature: string,
) {
  try {
    const verifier = createVerify("RSA-SHA256");
    verifier.update(payload);
    verifier.end();
    return verifier.verify(publicKeyPem, Buffer.from(signature, "hex"));
  } catch {
    return false;
  }
}

export function validProbePublicKeyPem(
  publicKeyPem: string | null | undefined,
) {
  if (!publicKeyPem) {
    return false;
  }

  try {
    const publicKey = createPublicKey(publicKeyPem);
    return (
      publicKey.asymmetricKeyType === "rsa" &&
      (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048
    );
  } catch {
    return false;
  }
}
