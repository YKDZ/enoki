export function createSignedLegacyProbeAssetSetFixture(input: {
  privateKeyPem: string | Buffer;
  publicKeyPem: string | Buffer;
}): Promise<{
  assetDir: string;
  assets: Array<{ name: string; sha256: string; size: number }>;
  cleanup: () => Promise<void>;
  probeComponents: Array<{
    file: "enoki-probe";
    role: "probe";
    sha256: string;
    target: string;
  }>;
}>;

export function createGenericReleaseTransitionContractFixture(input: {
  authority: { privateKey: string | Buffer; publicKey: string | Buffer };
  manifest: Buffer;
  sourceVersion: string;
  transition: "compatible" | "replacement-required";
  sourceProbeComponents: Array<{
    file: string;
    role: string;
    sha256: string;
    target: string;
  }>;
}): { bytes: Buffer; signature: Buffer };
