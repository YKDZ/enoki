import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  findTerminologyViolations,
  findUserFacingTerminologyViolations,
  checkRepositoryTerminology,
  findFeedbackPolicyTypeScriptModules,
} from "./check-terminology.mjs";

describe("Chinese product terminology", () => {
  const managedAliases = [
    ["Owner", "管理员"],
    ["Host", "主机"],
    ["Host Profile", "主机概况"],
    ["Metrics", "指标"],
    ["Probe Repair", "探针修复"],
    ["Probe Upgrade", "探针升级"],
    ["Probe Configuration", "探针配置"],
    ["Probe Asset Set", "探针安装包"],
    ["Probe Asset Bundle", "探针安装包"],
    ["Probe API", "探针 API"],
    ["Probe", "探针"],
    ["主机信息", "主机元数据"],
    ["主机资料", "主机概况或主机元数据"],
    ["中心端", "Hub"],
    ["服务端记录", "Hub 中的主机"],
    ["探针自我更新", "探针升级"],
    ["探针更新", "探针升级"],
    ["自删除", "卸载探针"],
    ["卸载并删除", "卸载探针并删除主机"],
    ["探针资产", "探针安装包"],
  ];

  it.each(managedAliases)(
    "reports the user-facing alias %s as %s",
    (alias, replacement) => {
      expect(
        findTerminologyViolations("display copy", `请处理 ${alias}。`),
      ).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ phrase: alias, replacement }),
        ]),
      );
    },
  );

  it("scans Vue template and script-setup display copy, not TypeScript identifiers", () => {
    const vueViolations = findUserFacingTerminologyViolations(
      "apps/web/src/App.vue",
      [
        '<script setup lang="ts">',
        "type Host = { latestMetrics: number };",
        'const internal = "Probe";',
        'toast.error("Owner");',
        "</script>",
        "<template><p>管理员</p></template>",
      ].join("\n"),
    );
    expect(vueViolations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          phrase: "Owner",
          replacement: "管理员",
        }),
      ]),
    );
    expect(vueViolations.map((violation) => violation.phrase)).not.toContain(
      "Host",
    );
    expect(vueViolations.map((violation) => violation.phrase)).not.toContain(
      "Probe",
    );

    expect(
      findUserFacingTerminologyViolations(
        "apps/web/src/lib/enrollment-dialog-state.ts",
        [
          "type Host = { latestMetrics: number };",
          'const internal = "Probe";',
          'export const copy = { title: "Probe Repair" };',
        ].join("\n"),
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ phrase: "Probe", replacement: "探针" }),
        expect.objectContaining({
          phrase: "Probe Repair",
          replacement: "探针修复",
        }),
      ]),
    );
  });

  it("reports managed aliases assigned to App display state", async () => {
    const appSource = await readFile("apps/web/src/App.vue", "utf8");
    const sourceWithAlias = appSource.replace(
      "无法保存主机元数据",
      "无法保存主机信息",
    );

    expect(
      findUserFacingTerminologyViolations(
        "apps/web/src/App.vue",
        sourceWithAlias,
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          phrase: "主机信息",
          replacement: "主机元数据",
        }),
      ]),
    );
  });

  it("scans template-bound ref display sources without scanning internal refs", () => {
    const violations = findUserFacingTerminologyViolations(
      "apps/web/src/components/Example.vue",
      [
        '<script setup lang="ts">',
        'const displayStatus = ref("Probe Repair");',
        'const internal = ref("Owner");',
        "type Host = { latestMetrics: number };",
        "</script>",
        "<template><p>{{ displayStatus }}</p></template>",
      ].join("\n"),
    );

    expect(violations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          phrase: "Probe Repair",
          replacement: "探针修复",
        }),
      ]),
    );
    expect(violations.map((violation) => violation.phrase)).not.toContain(
      "Host",
    );
    expect(violations.map((violation) => violation.phrase)).not.toContain(
      "Owner",
    );
  });

  it("scans explicit dialog display sinks", () => {
    expect(
      findUserFacingTerminologyViolations(
        "apps/web/src/components/Example.vue",
        [
          '<script setup lang="ts">',
          'dialog.error("Host Profile");',
          "</script>",
          "<template><p>管理员</p></template>",
        ].join("\n"),
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          phrase: "Host Profile",
          replacement: "主机概况",
        }),
      ]),
    );
  });

  it("scans static text in interpolated templates assigned to display refs", () => {
    const violations = findUserFacingTerminologyViolations(
      "apps/web/src/components/Example.vue",
      [
        '<script setup lang="ts">',
        'const displayStatus = ref("");',
        "displayStatus.value = `Probe Repair ${version} 后请检查 Host Profile`;",
        "const internal = `Owner ${ownerId}`;",
        "</script>",
        "<template><p>{{ displayStatus }}</p></template>",
      ].join("\n"),
    );

    expect(violations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ phrase: "Probe Repair" }),
        expect.objectContaining({ phrase: "Host Profile" }),
      ]),
    );
    expect(violations.map((violation) => violation.phrase)).not.toContain(
      "Owner",
    );
  });

  it("scans static text in interpolated templates passed to display sinks", () => {
    expect(
      findUserFacingTerminologyViolations(
        "apps/web/src/components/Example.vue",
        [
          '<script setup lang="ts">',
          "toast.error(`Probe Upgrade ${version}`);",
          "dialog.warning(`${hostName} Host Profile`);",
          "</script>",
          "<template><p>管理员</p></template>",
        ].join("\n"),
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ phrase: "Probe Upgrade" }),
        expect.objectContaining({ phrase: "Host Profile" }),
      ]),
    );
  });

  it("scans feedback policy presentations without treating typed facts as display copy", () => {
    const violations = findUserFacingTerminologyViolations(
      "apps/web/src/features/example/example-feedback-policy.ts",
      [
        'type ExampleFact = { kind: "Owner"; transition: "Probe Upgrade" };',
        "const examplePresentations = {",
        '  failed: { title: "Owner 无法发起 Probe Upgrade" },',
        "};",
        'display("example", "error", examplePresentations.failed.title);',
      ].join("\n"),
    );

    expect(violations.map(({ phrase }) => phrase)).toEqual([
      "Owner",
      "Probe Upgrade",
      "Probe",
    ]);
  });

  it("automatically discovers every feature feedback policy module", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "enoki-terminology-"));
    const policyDirectory = path.join(root, "apps/web/src/features/example");
    await mkdir(policyDirectory, { recursive: true });
    await writeFile(
      path.join(policyDirectory, "new-feedback-policy.ts"),
      'display("example", "error", "Owner Probe Upgrade");',
    );
    await writeFile(
      path.join(policyDirectory, "internal-policy.ts"),
      'type Fact = { kind: "Owner" };',
    );

    try {
      await expect(findFeedbackPolicyTypeScriptModules(root)).resolves.toEqual([
        "apps/web/src/features/example/new-feedback-policy.ts",
      ]);
    } finally {
      await rm(root, { recursive: true });
    }
  });

  it("includes every existing feature feedback policy in repository scans", async () => {
    await expect(
      findFeedbackPolicyTypeScriptModules(process.cwd()),
    ).resolves.toEqual(
      expect.arrayContaining([
        "apps/web/src/features/enrollment/enrollment-feedback-policy.ts",
        "apps/web/src/features/host/host-feedback-policy.ts",
        "apps/web/src/features/probe-upgrade/probe-upgrade-feedback-policy.ts",
      ]),
    );
  });

  it("leaves README commands, environment variables, and header names outside prose checks", () => {
    expect(
      findUserFacingTerminologyViolations(
        "README.md",
        "运行 `docker run -e ENOKI_PROBE_PORT -H X-Forwarded-Host`。",
      ),
    ).toEqual([]);
  });

  it("keeps README and Web user-facing copy free of managed-term aliases", async () => {
    await expect(checkRepositoryTerminology()).resolves.toEqual([]);
  });
});
