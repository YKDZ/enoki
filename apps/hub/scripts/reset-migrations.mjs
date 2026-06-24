import { execFileSync } from "node:child_process";
import { rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

await Promise.all([
  rm(resolve(root, "drizzle"), { force: true, recursive: true }),
  rm(resolve(root, "drizzle-official-metrics"), {
    force: true,
    recursive: true,
  }),
]);

execFileSync("pnpm", ["run", "db:generate"], {
  cwd: root,
  stdio: "inherit",
});
