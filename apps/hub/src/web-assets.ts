import { readFile, stat } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";

import type { Context } from "hono";

const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);

export function createWebAssetHandler(webDistPath: string) {
  const webRoot = resolve(webDistPath);

  return async (context: Context) => {
    const url = new URL(context.req.url);

    if (url.pathname.startsWith("/api/")) {
      return context.notFound();
    }

    const candidate = safeResolveWebAsset(webRoot, url.pathname);
    const assetPath =
      candidate && (await isFile(candidate))
        ? candidate
        : resolve(webRoot, "index.html");

    if (!(await isFile(assetPath))) {
      return context.notFound();
    }

    const body = await readFile(assetPath);
    return new Response(body, {
      headers: {
        "content-type": contentTypeFor(assetPath),
      },
    });
  };
}

function safeResolveWebAsset(webRoot: string, pathname: string) {
  const relativePath = decodeURIComponent(pathname).replace(/^\/+/, "");
  const assetPath = resolve(webRoot, relativePath || "index.html");

  if (assetPath !== webRoot && !assetPath.startsWith(`${webRoot}${sep}`)) {
    return null;
  }

  return assetPath;
}

async function isFile(path: string) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function contentTypeFor(path: string) {
  return contentTypes.get(extname(path)) ?? "application/octet-stream";
}
