import { constants } from "node:fs";
import { open } from "node:fs/promises";

export async function readRegularFileSnapshot(
  filePath,
  label,
  { expectedSize, maximumSize },
) {
  if (
    !Number.isSafeInteger(expectedSize) ||
    expectedSize < 0 ||
    !Number.isSafeInteger(maximumSize) ||
    maximumSize < 0 ||
    expectedSize > maximumSize
  ) {
    throw new Error(`${label} expected size is invalid`);
  }
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
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink > 1n) {
      throw new Error(`${label} must be a regular single-link file`);
    }
    if (before.size !== BigInt(expectedSize)) {
      throw new Error(`${label} size does not match`);
    }
    const bytes = Buffer.allocUnsafe(expectedSize);
    let offset = 0;
    while (offset < expectedSize) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        expectedSize - offset,
        offset,
      );
      if (bytesRead === 0) {
        throw new Error(`${label} changed while reading`);
      }
      offset += bytesRead;
    }
    const overflow = Buffer.allocUnsafe(1);
    if ((await handle.read(overflow, 0, 1, expectedSize)).bytesRead !== 0) {
      throw new Error(`${label} changed while reading`);
    }
    const after = await handle.stat({ bigint: true });
    if (
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs
    ) {
      throw new Error(`${label} changed while reading`);
    }
    return { bytes, size: expectedSize };
  } finally {
    await handle.close();
  }
}
