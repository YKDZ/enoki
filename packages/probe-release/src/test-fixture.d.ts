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
