import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

import ts from "typescript";
import { describe, expect, it } from "vitest";
import { parse } from "vue/compiler-sfc";

describe("Sonner feedback boundary", () => {
  it("imports the Toast library only through the Web Feedback adapter", () => {
    const sourceRoot = join(process.cwd(), "src");
    const importers = sourceFiles(sourceRoot).filter((file) =>
      staticModuleSpecifiers(file).includes("vue-sonner"),
    );
    expect(importers.map((file) => relative(sourceRoot, file))).toEqual([
      "feedback/sonner-feedback-adapter.ts",
    ]);
  });

  it("finds an import in a Vue script despite script-shaped template text", () => {
    const source = `<template><span title="<script>//">x</span></template><script setup lang="ts">import { toast } from "vue-sonner";</script>`;

    expect(staticModuleSpecifiersForSource("decoy.vue", source)).toContain(
      "vue-sonner",
    );
  });
});

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return /\.(?:ts|tsx|js|jsx|vue)$/.test(entry.name) ? [path] : [];
  });
}

function staticModuleSpecifiers(file: string): string[] {
  return staticModuleSpecifiersForSource(file, readFileSync(file, "utf8"));
}

function staticModuleSpecifiersForSource(
  file: string,
  source: string,
): string[] {
  const script = file.endsWith(".vue") ? vueScripts(source) : source;
  const ast = ts.createSourceFile(file, script, ts.ScriptTarget.Latest, true);
  const specifiers: string[] = [];
  const visit = (node: ts.Node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      specifiers.push(node.moduleSpecifier.text);
    }
    if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword
    ) {
      const argument = node.arguments.at(0);
      if (argument && ts.isStringLiteral(argument))
        specifiers.push(argument.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  return specifiers;
}

function vueScripts(source: string) {
  const descriptor = parse(source).descriptor;
  return [descriptor.script?.content, descriptor.scriptSetup?.content]
    .filter((script): script is string => Boolean(script))
    .join("\n");
}
