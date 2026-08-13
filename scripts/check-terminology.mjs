import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

export const managedTerminologyRules = [
  { pattern: /\bOwner\b/g, phrase: "Owner", replacement: "管理员" },
  { pattern: /\bHost\b/g, phrase: "Host", replacement: "主机" },
  {
    pattern: /\bHost Profile\b/g,
    phrase: "Host Profile",
    replacement: "主机概况",
  },
  { pattern: /\bMetrics\b/g, phrase: "Metrics", replacement: "指标" },
  {
    pattern: /\bProbe Repair\b/g,
    phrase: "Probe Repair",
    replacement: "探针修复",
  },
  {
    pattern: /\bProbe Upgrade\b/g,
    phrase: "Probe Upgrade",
    replacement: "探针升级",
  },
  {
    pattern: /\bProbe Configuration\b/g,
    phrase: "Probe Configuration",
    replacement: "探针配置",
  },
  {
    pattern: /\bProbe Asset Set\b/g,
    phrase: "Probe Asset Set",
    replacement: "探针安装包",
  },
  {
    pattern: /\bProbe Asset Bundle\b/g,
    phrase: "Probe Asset Bundle",
    replacement: "探针安装包",
  },
  { pattern: /\bProbe API\b/g, phrase: "Probe API", replacement: "探针 API" },
  { pattern: /\bProbe\b/g, phrase: "Probe", replacement: "探针" },
  { pattern: /主机信息/g, phrase: "主机信息", replacement: "主机元数据" },
  {
    pattern: /主机资料/g,
    phrase: "主机资料",
    replacement: "主机概况或主机元数据",
  },
  { pattern: /中心端/g, phrase: "中心端", replacement: "Hub" },
  {
    pattern: /服务端记录/g,
    phrase: "服务端记录",
    replacement: "Hub 中的主机",
  },
  { pattern: /探针自我更新/g, phrase: "探针自我更新", replacement: "探针升级" },
  { pattern: /探针更新/g, phrase: "探针更新", replacement: "探针升级" },
  { pattern: /自删除/g, phrase: "自删除", replacement: "卸载探针" },
  {
    pattern: /卸载并删除/g,
    phrase: "卸载并删除",
    replacement: "卸载探针并删除主机",
  },
  { pattern: /探针资产/g, phrase: "探针资产", replacement: "探针安装包" },
];

const displayCopyTypeScriptModules = new Set([
  "apps/web/src/lib/enrollment-dialog-state.ts",
  "apps/web/src/lib/login-errors.ts",
  "apps/web/src/lib/probe-upgrade-toast.ts",
]);

export function findTerminologyViolations(source, text) {
  return managedTerminologyRules.flatMap((rule) => {
    const matches = [...text.matchAll(rule.pattern)];

    return matches.map((match) => ({
      column: match.index - text.lastIndexOf("\n", match.index),
      line: text.slice(0, match.index).split("\n").length,
      phrase: rule.phrase,
      replacement: rule.replacement,
      source,
    }));
  });
}

export function findUserFacingTerminologyViolations(source, text) {
  return findTerminologyViolations(source, userFacingCopyFor(source, text));
}

export async function checkRepositoryTerminology(root = process.cwd()) {
  const sourcePaths = [
    "README.md",
    ...(await findVueFiles(path.join(root, "apps/web/src"))).map((file) =>
      path.relative(root, file),
    ),
    ...(await findFeedbackPolicyTypeScriptModules(root)),
    ...displayCopyTypeScriptModules,
  ];
  const violations = [];

  for (const source of sourcePaths) {
    const text = await readFile(path.join(root, source), "utf8");
    violations.push(...findUserFacingTerminologyViolations(source, text));
  }

  return violations;
}

export async function findFeedbackPolicyTypeScriptModules(root) {
  const featureRoot = path.join(root, "apps/web/src/features");
  const files = await findFiles(featureRoot, (name) =>
    name.endsWith("-feedback-policy.ts"),
  );

  return files
    .map((file) => path.relative(root, file).split(path.sep).join("/"))
    .sort();
}

function userFacingCopyFor(source, text) {
  const normalizedSource = source.split(path.sep).join("/");

  if (normalizedSource.endsWith(".vue")) {
    const template = vueTemplateCopy(text);
    return [template, vueScriptSetupDisplayCopy(text, template)].join("\n");
  }

  if (normalizedSource.endsWith(".md")) {
    return markdownProseCopy(text);
  }

  if (isFeedbackPolicyModule(normalizedSource)) {
    return feedbackPolicyDisplayCopy(text);
  }

  if (displayCopyTypeScriptModules.has(normalizedSource)) {
    return typeScriptStringLiterals(text);
  }

  return text;
}

function isFeedbackPolicyModule(source) {
  return (
    source.startsWith("apps/web/src/features/") &&
    source.endsWith("-feedback-policy.ts")
  );
}

function feedbackPolicyDisplayCopy(text) {
  const sourceFile = ts.createSourceFile(
    "feedback-policy.ts",
    text,
    ts.ScriptTarget.Latest,
    false,
    ts.ScriptKind.TS,
  );
  const literals = [];

  const visit = (node) => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text.endsWith("Presentations") &&
      node.initializer
    ) {
      collectStringLiterals([node.initializer], literals);
      return;
    }
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "display"
    ) {
      collectStringLiterals(node.arguments, literals);
      return;
    }
    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return literals.join("\n");
}

function markdownProseCopy(text) {
  return text.replace(/```[\s\S]*?```/g, "").replace(/`[^`]*`/g, "");
}

function vueTemplateCopy(text) {
  return [...text.matchAll(/<template\b[^>]*>([\s\S]*?)<\/template>/g)]
    .map((match) => match[1] ?? "")
    .join("\n");
}

function vueScriptSetupDisplayCopy(text, template) {
  const templateIdentifiers = new Set(
    [...template.matchAll(/\b[$A-Z_a-z][$\w]*\b/g)].map((match) => match[0]),
  );

  return [...text.matchAll(/<script\s+setup\b[^>]*>([\s\S]*?)<\/script>/g)]
    .flatMap((match) =>
      scriptSetupDisplayStringLiterals(match[1] ?? "", templateIdentifiers),
    )
    .join("\n");
}

function scriptSetupDisplayStringLiterals(text, templateIdentifiers) {
  const sourceFile = ts.createSourceFile(
    "script-setup.ts",
    text,
    ts.ScriptTarget.Latest,
    false,
    ts.ScriptKind.TS,
  );
  const literals = [];

  const visit = (node) => {
    if (ts.isCallExpression(node) && isExplicitDisplaySinkCall(node)) {
      collectStringLiterals(node.arguments, literals);
      return;
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      isTemplateBoundRefValue(node.left, templateIdentifiers)
    ) {
      collectStringLiterals([node.right], literals);
      return;
    }
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      templateIdentifiers.has(node.name.text) &&
      node.initializer
    ) {
      collectStringLiterals([node.initializer], literals);
      return;
    }
    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return literals;
}

function isTemplateBoundRefValue(node, templateIdentifiers) {
  return (
    ts.isPropertyAccessExpression(node) &&
    node.name.text === "value" &&
    ts.isIdentifier(node.expression) &&
    templateIdentifiers.has(node.expression.text)
  );
}

function isExplicitDisplaySinkCall(node) {
  if (
    !ts.isPropertyAccessExpression(node.expression) ||
    !ts.isIdentifier(node.expression.expression)
  ) {
    return false;
  }

  const receiver = node.expression.expression.text;
  return (
    receiver === "dialog" ||
    (receiver === "toast" &&
      ["error", "info", "success", "warning"].includes(
        node.expression.name.text,
      ))
  );
}

function collectStringLiterals(nodes, literals) {
  for (const node of nodes) {
    const visit = (child) => {
      if (
        ts.isStringLiteral(child) ||
        ts.isNoSubstitutionTemplateLiteral(child)
      ) {
        literals.push(child.text);
        return;
      }
      if (ts.isTemplateExpression(child)) {
        literals.push(child.head.text);
        literals.push(...child.templateSpans.map((span) => span.literal.text));
        return;
      }
      ts.forEachChild(child, visit);
    };
    visit(node);
  }
}

function typeScriptStringLiterals(text) {
  const sourceFile = ts.createSourceFile(
    "display-copy.ts",
    text,
    ts.ScriptTarget.Latest,
    false,
    ts.ScriptKind.TS,
  );
  const literals = [];

  const visit = (node) => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      literals.push(node.text);
    }
    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return literals.join("\n");
}

async function findVueFiles(directory) {
  return findFiles(directory, (name) => name.endsWith(".vue"));
}

async function findFiles(directory, matches) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const entryPath = path.join(directory, entry.name);

      if (entry.isDirectory()) {
        return findFiles(entryPath, matches);
      }

      return entry.isFile() && matches(entry.name) ? [entryPath] : [];
    }),
  );

  return nested.flat();
}

async function main() {
  const violations = await checkRepositoryTerminology();

  if (violations.length === 0) {
    process.stdout.write("Terminology check passed.\n");
    return;
  }

  for (const violation of violations) {
    process.stderr.write(
      `${violation.source}:${violation.line}:${violation.column} ${violation.phrase} → ${violation.replacement}\n`,
    );
  }
  process.exitCode = 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
