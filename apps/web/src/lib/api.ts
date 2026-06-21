import type { ProbeConfiguration } from "../types";

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

export async function saveConfiguration(
  path: string,
  configuration: ProbeConfiguration,
) {
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

  return (await response.json()) as { configuration: ProbeConfiguration };
}

export function isUnauthorizedError(error: unknown) {
  return error instanceof ApiError && error.status === 401;
}
