import { describe, expect, it } from "vitest";

import {
  hubUnavailableLoginError,
  loginErrorForResponse,
} from "./login-errors";

describe("login error classification", () => {
  it("treats 401 as an invalid owner password", () => {
    expect(loginErrorForResponse(401)).toEqual({
      kind: "credentials",
      message: "密码不正确，请稍后再试。",
    });
  });

  it("treats proxy and server failures as Hub unavailable", () => {
    expect(loginErrorForResponse(502)).toEqual(hubUnavailableLoginError());
    expect(loginErrorForResponse(500)).toEqual(hubUnavailableLoginError());
  });
});
