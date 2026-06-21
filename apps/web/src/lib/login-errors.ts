export type LoginErrorKind = "" | "credentials" | "hub_unavailable";

export function loginErrorForResponse(status: number): {
  kind: LoginErrorKind;
  message: string;
} {
  if (status === 401) {
    return {
      kind: "credentials",
      message: "密码不正确，请稍后再试。",
    };
  }

  return hubUnavailableLoginError();
}

export function hubUnavailableLoginError() {
  return {
    kind: "hub_unavailable" as const,
    message: "无法连接 Hub，请检查服务是否正在运行。",
  };
}
