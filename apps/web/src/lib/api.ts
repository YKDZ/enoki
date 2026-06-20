import type { ProbeConfiguration } from "../types";

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
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
    throw new Error(((await response.json()) as { error?: string }).error);
  }

  return (await response.json()) as { configuration: ProbeConfiguration };
}
