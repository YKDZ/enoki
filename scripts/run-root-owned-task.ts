import { spawnSync } from "node:child_process";

const task = process.argv[2];
const command =
  task === "format:check"
    ? ["exec", "oxfmt", "--list-different", "--config", "oxfmt.config.ts", "."]
    : task === "format:write"
      ? ["exec", "oxfmt", "--write", "--config", "oxfmt.config.ts", "."]
      : task === "lint"
        ? ["exec", "oxlint", "--quiet", "--config", "oxlint.config.ts", "."]
        : task === "lint:fix"
          ? ["exec", "oxlint", "--config", "oxlint.config.ts", ".", "--fix"]
          : undefined;

if (command === undefined) {
  throw new Error(`Unknown root-owned task: ${task ?? "(missing)"}`);
}

// 冷 CI 上 better-tailwindcss 插件等待 synckit worker 会超过其 30 秒默认预算；
// 这里只把两个 lint 入口的等待上限放宽到有限的 120 秒，调用者显式设置保持原样，
// 到期仍按原错误有限传播。format 任务与其余参数不变。
const result = spawnSync("pnpm", command, {
  stdio: "inherit",
  ...(task === "lint" || task === "lint:fix"
    ? {
        env: {
          ...process.env,
          SYNCKIT_TIMEOUT: process.env.SYNCKIT_TIMEOUT ?? "120000",
        },
      }
    : {}),
});
if (result.error !== undefined) throw result.error;
process.exitCode = result.status ?? 1;
