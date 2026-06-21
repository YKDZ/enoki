import { renderToString } from "@vue/server-renderer";
import { describe, expect, it } from "vitest";
import { createSSRApp } from "vue";

import LoginPanel from "./LoginPanel.vue";

describe("Login panel", () => {
  it("renders Hub unavailable as a distinct error hero", async () => {
    const html = await renderToString(
      createSSRApp(LoginPanel, {
        isSubmitting: false,
        loginError: "无法连接 Hub，请检查服务是否正在运行。",
        loginErrorKind: "hub_unavailable",
        password: "",
      }),
    );

    expect(html).toContain("Hub 暂不可用");
    expect(html).toContain("无法连接 Hub，请检查服务是否正在运行。");
    expect(html).toContain("重试连接");
    expect(html).toContain("lucide-server-crash");
    expect(html).not.toContain("登录");
  });

  it("renders password errors as field feedback with a visibility toggle", async () => {
    const html = await renderToString(
      createSSRApp(LoginPanel, {
        isSubmitting: false,
        loginError: "密码不正确，请稍后再试。",
        loginErrorKind: "credentials",
        password: "",
      }),
    );

    expect(html).toContain("密码不正确，请稍后再试。");
    expect(html).not.toContain("Hub 暂不可用");
    expect(html).toContain('data-slot="input-group"');
    expect(html).toContain('type="password"');
    expect(html).toContain('aria-label="显示密码"');
  });
});
