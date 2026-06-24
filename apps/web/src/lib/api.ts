import type { ProbeConfiguration, ProbeConfigurationResponse } from "../types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
  });

  if (!response.ok) {
    throw new ApiError(`Request failed: ${response.status}`, response.status);
  }

  return (await response.json()) as T;
}

export async function apiMutate<T>(
  path: string,
  options: { body?: unknown; method: "DELETE" | "POST" | "PUT" },
): Promise<T> {
  const response = await fetch(path, {
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    credentials: "same-origin",
    headers:
      options.body === undefined
        ? undefined
        : {
            "content-type": "application/json",
          },
    method: options.method,
  });

  if (!response.ok) {
    throw new ApiError(
      ((await response.json()) as { error?: string }).error ??
        `Request failed: ${response.status}`,
      response.status,
    );
  }

  return (await response.json()) as T;
}

export async function saveConfiguration(
  path: string,
  configuration: ProbeConfiguration,
): Promise<ProbeConfigurationResponse> {
  const response = await fetch(path, {
    body: JSON.stringify(configuration),
    credentials: "same-origin",
    headers: {
      "content-type": "application/json",
    },
    method: "PUT",
  });

  if (!response.ok) {
    throw new ApiError(
      ((await response.json()) as { error?: string }).error ??
        `Request failed: ${response.status}`,
      response.status,
    );
  }

  return (await response.json()) as ProbeConfigurationResponse;
}

export function isUnauthorizedError(error: unknown) {
  return error instanceof ApiError && error.status === 401;
}
