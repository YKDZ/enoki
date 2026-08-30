import { constants } from "node:fs";
import { open } from "node:fs/promises";

export async function readRegularFileSnapshot(filePath, label) {
  let handle;
  try {
    handle = await open(
      filePath,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
  } catch {
    throw new Error(`${label} must be a regular non-symbolic-link file`);
  }
  try {
    const details = await handle.stat();
    if (!details.isFile() || details.nlink > 1) {
      throw new Error(`${label} must be a regular single-link file`);
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength !== details.size) {
      throw new Error(`${label} changed while reading`);
    }
    return { bytes, size: details.size };
  } finally {
    await handle.close();
  }
}
