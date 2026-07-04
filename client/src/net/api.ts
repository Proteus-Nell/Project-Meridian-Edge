// REST client (CLAUDE.md §0): errors are uniform — callers get a status code
// and a generic message, never server internals.

import { toBase64 } from "../util/base64";

export class ApiError extends Error {
  constructor(public readonly status: number) {
    super("request_failed");
    this.name = "ApiError";
  }
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new ApiError(res.status);
  }
  return (await res.json()) as T;
}

export interface RegisterResponse {
  readonly uid: string;
}

export function register(ikPub: Uint8Array): Promise<RegisterResponse> {
  return postJson<RegisterResponse>("/v1/register", { ik_pub: toBase64(ikPub) });
}
