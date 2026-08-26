import { spawn } from "node:child_process";

export function docker(container: string, command: string[]) {
  return runCommand("docker", ["exec", container, ...command]);
}

export async function requireCommand(
  program: string,
  args: string[],
  options: { cwd?: string; env?: Record<string, string> } = {},
) {
  const result = await runCommand(program, args, undefined, options);
  if (result.code !== 0) {
    throw new Error(
      `${program} ${args.join(" ")} failed (${result.code}):\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result;
}

export async function runCommand(
  program: string,
  args: string[],
  input?: string,
  options: { cwd?: string; env?: Record<string, string> } = {},
) {
  return await new Promise<{
    code: number | null;
    stderr: string;
    stdout: string;
  }>((resolve, reject) => {
    const child = spawn(program, args, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout!.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr!.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stderr, stdout }));
    if (input !== undefined) child.stdin?.end(input);
  });
}
