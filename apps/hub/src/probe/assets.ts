import { lstat, readFile } from "node:fs/promises";
import path from "node:path";

import { Hono } from "hono";

export type ProbeAssetRouteOptions = {
  assetDir?: string;
  installScriptPath?: string;
};

const defaultAssetDir = "/app/probe-assets";
const defaultInstallScriptPath = "/app/probe-assets/install-probe.sh";
const assetFileNamePattern = /^[A-Za-z0-9._-]+$/;

export function createProbeAssetRoutes(options: ProbeAssetRouteOptions = {}) {
  const app = new Hono();
  const assetDir = path.resolve(options.assetDir ?? defaultAssetDir);
  const installScriptPath = path.resolve(
    options.installScriptPath ?? defaultInstallScriptPath,
  );
  const canServeInstallScript = isPathInsideDirectory(
    installScriptPath,
    assetDir,
  );

  app.get("/install.sh", async (context) => {
    if (!canServeInstallScript) {
      return context.text("Probe installer is not available.", 404);
    }

    const file = await readExistingFile(installScriptPath);
    if (!file) {
      return context.text("Probe installer is not available.", 404);
    }

    return new Response(file, {
      headers: {
        "cache-control": "no-store",
        "content-type": "text/x-shellscript; charset=utf-8",
      },
    });
  });

  app.get("/assets/:file", async (context) => {
    const fileName = context.req.param("file");

    if (!assetFileNamePattern.test(fileName)) {
      return context.text("Probe asset not found.", 404);
    }

    const assetPath = path.resolve(assetDir, fileName);
    if (!isPathInsideDirectory(assetPath, assetDir)) {
      return context.text("Probe asset not found.", 404);
    }

    const file = await readExistingFile(assetPath);
    if (!file) {
      return context.text("Probe asset not found.", 404);
    }

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

async function readExistingFile(filePath: string) {
  try {
    const details = await lstat(filePath);
    if (!details.isFile()) {
      return null;
    }

    return await readFile(filePath);
  } catch (error) {
    if (error instanceof Error && "code" in error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") {
        return null;
      }
    }

    throw error;
  }
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
