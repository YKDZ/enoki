import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import path from "node:path";
import { Readable } from "node:stream";

import { Hono } from "hono";

export type ProbeAssetRouteOptions = {
  assetDir?: string;
  maxConcurrentPackageStreams?: number;
  maxPackageBytes?: number;
  maxPackageStreamDurationMs?: number;
  maxMetadataBytes?: number;
  packageStreamHighWaterMark?: number;
};

const defaultAssetDir = "/app/probe-assets";
const assetFileNamePattern = /^[A-Za-z0-9._-]+$/;
const defaultMaxConcurrentPackageStreams = 4;
const defaultMaxPackageBytes = 512 * 1024 * 1024;
const defaultMaxPackageStreamDurationMs = 5 * 60 * 1000;
const defaultMaxMetadataBytes = 256 * 1024;
export const defaultMaxProbeMetadataBytes = defaultMaxMetadataBytes;
export const defaultMaxProbeMetadataSetBytes = 1024 * 1024;

type OpenFile = typeof open;

export async function readBoundedMetadataFilesFromDirectory(input: {
  assetDir: string;
  fileNames: readonly string[];
  maxFileBytes?: number;
  maxTotalBytes?: number;
  openFile?: OpenFile;
}): Promise<Record<string, Buffer> | null> {
  const snapshot = await readBoundedMetadataSnapshotFromDirectory({
    ...input,
    requiredFileNames: input.fileNames,
  });
  if (!snapshot) return null;
  return Object.fromEntries(
    Object.entries(snapshot).map(([fileName, file]) => [fileName, file!]),
  );
}

export async function readBoundedMetadataSnapshotFromDirectory(input: {
  assetDir: string;
  optionalFileNames?: readonly string[];
  requiredFileNames: readonly string[];
  maxFileBytes?: number;
  maxTotalBytes?: number;
  openFile?: OpenFile;
}): Promise<Record<string, Buffer | null> | null> {
  const assetDir = path.resolve(input.assetDir);
  const maxFileBytes = positiveSafeInteger(
    input.maxFileBytes ?? defaultMaxProbeMetadataBytes,
    "maxFileBytes",
  );
  const maxTotalBytes = positiveSafeInteger(
    input.maxTotalBytes ?? defaultMaxProbeMetadataSetBytes,
    "maxTotalBytes",
  );
  const files: Record<string, Buffer | null> = {};
  let totalBytes = 0;

  for (const [fileName, required] of [
    ...input.requiredFileNames.map((fileName) => [fileName, true] as const),
    ...(input.optionalFileNames ?? []).map(
      (fileName) => [fileName, false] as const,
    ),
  ]) {
    if (!assetFileNamePattern.test(fileName)) return null;
    const file = await readExistingSmallFile(
      path.join(assetDir, fileName),
      Math.min(maxFileBytes, maxTotalBytes - totalBytes),
      input.openFile,
    );
    if (!file) {
      if (required) return null;
      files[fileName] = null;
      continue;
    }
    totalBytes += file.byteLength;
    if (totalBytes > maxTotalBytes) return null;
    files[fileName] = file;
  }

  return files;
}

export function createProbeAssetRoutes(options: ProbeAssetRouteOptions = {}) {
  const app = new Hono();
  const assetDir = path.resolve(options.assetDir ?? defaultAssetDir);
  const packageStreams = createPackageStreamGate(
    options.maxConcurrentPackageStreams ?? defaultMaxConcurrentPackageStreams,
  );
  const packageStreamDurationMs = positiveSafeInteger(
    options.maxPackageStreamDurationMs ?? defaultMaxPackageStreamDurationMs,
    "maxPackageStreamDurationMs",
  );
  const maxPackageBytes = positiveSafeInteger(
    options.maxPackageBytes ?? defaultMaxPackageBytes,
    "maxPackageBytes",
  );
  const packageStreamHighWaterMark = options.packageStreamHighWaterMark
    ? positiveSafeInteger(
        options.packageStreamHighWaterMark,
        "packageStreamHighWaterMark",
      )
    : undefined;
  const maxMetadataBytes = positiveSafeInteger(
    options.maxMetadataBytes ?? defaultMaxMetadataBytes,
    "maxMetadataBytes",
  );

  app.get("/assets/:file", async (context) => {
    if (context.req.header("range")) {
      return context.text("Probe assets do not support Range requests.", 416);
    }
    const fileName = context.req.param("file");

    if (!assetFileNamePattern.test(fileName)) {
      return context.text("Probe asset not found.", 404);
    }

    const assetPath = path.resolve(assetDir, fileName);
    if (!isPathInsideDirectory(assetPath, assetDir)) {
      return context.text("Probe asset not found.", 404);
    }

    if (isProbePackage(fileName)) {
      const lease = packageStreams.tryAcquire();
      if (!lease) {
        return context.text(
          "Probe package stream capacity is unavailable.",
          503,
          {
            "retry-after": "1",
          },
        );
      }
      const streamed = await openPackageStream({
        filePath: assetPath,
        highWaterMark: packageStreamHighWaterMark,
        lease,
        maxBytes: maxPackageBytes,
        maxDurationMs: packageStreamDurationMs,
      });
      if (!streamed) {
        lease.release();
        return context.text("Probe asset not found.", 404);
      }
      return new Response(streamed.body, {
        headers: {
          "accept-ranges": "none",
          "cache-control": "public, max-age=31536000, immutable",
          "content-length": String(streamed.size),
          "content-type": contentTypeForProbeAsset(fileName),
        },
      });
    }

    const file = await readExistingSmallFile(assetPath, maxMetadataBytes);
    if (!file) return context.text("Probe asset not found.", 404);
    return new Response(file, {
      headers: {
        "cache-control":
          fileName === "manifest.json"
            ? "no-cache"
            : "public, max-age=31536000, immutable",
        "content-type": contentTypeForProbeAsset(fileName),
      },
    });
  });

  return app;
}

function isPathInsideDirectory(filePath: string, directoryPath: string) {
  const relativePath = path.relative(directoryPath, filePath);

  return (
    relativePath !== "" &&
    !relativePath.startsWith("..") &&
    !path.isAbsolute(relativePath)
  );
}

async function readExistingSmallFile(
  filePath: string,
  maxBytes: number,
  openFile: OpenFile = open,
) {
  if (maxBytes < 1) return null;
  const opened = await openRegularFile(filePath, maxBytes, openFile);
  if (!opened) return null;

  try {
    return await readBoundedFile(opened.file, opened.size);
  } catch (error) {
    if (isUnavailable(error)) return null;
    throw error;
  } finally {
    await opened.file.close().catch(() => undefined);
  }
}

async function openRegularFile(
  filePath: string,
  maxBytes: number,
  openFile: OpenFile = open,
) {
  let file: FileHandle;
  try {
    file = await openFile(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (isUnavailable(error)) return null;
    throw error;
  }

  try {
    const details = await file.stat();
    if (!details.isFile() || details.size > maxBytes) {
      await file.close();
      return null;
    }
    return { file, size: details.size };
  } catch (error) {
    await file.close().catch(() => undefined);
    if (isUnavailable(error)) return null;
    throw error;
  }
}

async function readBoundedFile(file: FileHandle, size: number) {
  const contents = Buffer.alloc(size);
  let offset = 0;
  while (offset < contents.byteLength) {
    const { bytesRead } = await file.read(
      contents,
      offset,
      contents.byteLength - offset,
      offset,
    );
    if (bytesRead === 0) return null;
    offset += bytesRead;
  }
  return contents;
}

function isProbePackage(fileName: string) {
  return fileName.endsWith(".tar.gz");
}

function createPackageStreamGate(limit: number) {
  const validatedLimit = positiveSafeInteger(
    limit,
    "maxConcurrentPackageStreams",
  );
  let active = 0;
  return {
    tryAcquire() {
      if (active >= validatedLimit) return null;
      active += 1;
      let released = false;
      return {
        release() {
          if (!released) {
            released = true;
            active -= 1;
          }
        },
      };
    },
  };
}

async function openPackageStream({
  filePath,
  highWaterMark,
  lease,
  maxBytes,
  maxDurationMs,
}: {
  filePath: string;
  highWaterMark: number | undefined;
  lease: { release: () => void };
  maxBytes: number;
  maxDurationMs: number;
}) {
  const opened = await openRegularFile(filePath, maxBytes);
  if (!opened || opened.size === 0) {
    await opened?.file.close();
    return null;
  }
  const { file, size } = opened;

  const stream = file.createReadStream({
    autoClose: false,
    end: size - 1,
    highWaterMark,
  });
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let closed = false;
  const release = () => {
    if (timeout) clearTimeout(timeout);
    if (!closed) {
      closed = true;
      void file.close().catch(() => undefined);
    }
    lease.release();
  };
  stream.once("close", release);
  stream.once("error", release);
  timeout = setTimeout(() => {
    stream.destroy(new Error("Probe package stream duration exceeded"));
  }, maxDurationMs);
  timeout.unref();

  const source = Readable.toWeb(stream) as ReadableStream<Uint8Array>;
  const reader = source.getReader();
  return {
    body: new ReadableStream<Uint8Array>({
      async cancel(reason) {
        try {
          await reader.cancel(reason);
        } finally {
          release();
        }
      },
      async pull(controller) {
        try {
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
            release();
          } else {
            controller.enqueue(value);
          }
        } catch (error) {
          controller.error(error);
          release();
        }
      },
    }),
    size,
  };
}

function positiveSafeInteger(value: number, name: string) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

function isUnavailable(error: unknown) {
  return (
    error instanceof Error &&
    "code" in error &&
    ((error as NodeJS.ErrnoException).code === "ENOENT" ||
      (error as NodeJS.ErrnoException).code === "ENOTDIR" ||
      (error as NodeJS.ErrnoException).code === "ELOOP")
  );
}

function contentTypeForProbeAsset(fileName: string) {
  if (fileName === "manifest.json") {
    return "application/json; charset=utf-8";
  }
  if (fileName.endsWith(".pem")) {
    return "application/x-pem-file; charset=utf-8";
  }
  if (fileName.endsWith(".sig")) {
    return "application/octet-stream";
  }
  if (fileName.endsWith(".tar.gz")) {
    return "application/gzip";
  }

  return "application/octet-stream";
}
