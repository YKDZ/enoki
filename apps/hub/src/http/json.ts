export type JsonBodyResult =
  | {
      ok: true;
      value: unknown;
    }
  | {
      ok: false;
    };

export async function readJsonBody(request: { json: () => Promise<unknown> }) {
  try {
    return {
      ok: true,
      value: await request.json(),
    } satisfies JsonBodyResult;
  } catch {
    return {
      ok: false,
    } satisfies JsonBodyResult;
  }
}
