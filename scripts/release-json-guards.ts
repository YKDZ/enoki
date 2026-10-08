// Runtime guards for unknown Release evidence and artifact Manifest JSON. These
// narrow untrusted input by checking it, and are shared by the typed Release
// maintenance modules so each check has a single implementation.
// 维护 CLI 的共享参数守卫也在此，供类型化入口与尚未迁移的存量命令壳使用同一实现。

export type CommandLineOptions = Map<string, string>;

export type ParsedCommandLine = {
  command: string | undefined;
  options: CommandLineOptions;
};

export function parseCommandLine(
  arguments_: readonly string[],
): ParsedCommandLine {
  const [command, ...tokens] = arguments_;
  const options: CommandLineOptions = new Map();

  for (let index = 0; index < tokens.length; index += 2) {
    const name = tokens[index];
    const value = tokens[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`invalid command-line argument: ${name ?? "<missing>"}`);
    }
    if (options.has(name)) {
      throw new Error(`duplicate command-line argument: ${name}`);
    }
    options.set(name, value);
  }

  return { command, options };
}

export function requiredOption(
  options: CommandLineOptions,
  name: string,
): string {
  const value = options.get(name);
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

export function assertAllowedOptions(
  command: string | undefined,
  options: CommandLineOptions,
  allowedNames: readonly string[],
): void {
  const allowed = new Set(allowedNames);
  for (const name of options.keys()) {
    if (!allowed.has(name)) {
      throw new Error(`unknown option for ${command}: ${name}`);
    }
  }
}

export type UnknownRecord = Record<string, unknown>;

export function isUnknownRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isUnknownArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

export function isSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value);
}

export function isFiniteNumber(value: unknown): value is number {
  return Number.isFinite(value);
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

export function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

export function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

// 与 RegExp.test(value ?? "") 的 JavaScript 强制转换完全一致：只有 null/undefined 变为空串。
export function regexInput(value: unknown): string {
  return value == null ? "" : String(value);
}

export function assertPlainObject(
  value: unknown,
  description: string,
): asserts value is UnknownRecord {
  if (!isUnknownRecord(value)) {
    throw new Error(`${description} must be an object`);
  }
}

export function objectView(value: unknown): UnknownRecord {
  return isUnknownRecord(value) ? value : {};
}
