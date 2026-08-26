import { readFile } from "node:fs/promises";

type RootFileReader = (path: string) => Promise<Buffer>;

const probeDistributionRootPublicKeyPath =
  "/app/probe-distribution-root/root-key.pem";

export async function readProbeDistributionRootPublicKeyFromImage(
  options: { readFile?: RootFileReader } = {},
): Promise<Buffer | null> {
  try {
    return await (options.readFile ?? readFile)(
      probeDistributionRootPublicKeyPath,
    );
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return null;
    }
    throw error;
  }
}
