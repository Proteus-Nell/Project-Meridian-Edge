// REST client (CLAUDE.md §0): errors are uniform — callers get a status code
// and a generic message, never server internals. The session token lives in
// JS memory only and is attached as a bearer header (§2.3).

import { toBase64 } from "../util/base64";

export class ApiError extends Error {
  constructor(public readonly status: number) {
    super("request_failed");
    this.name = "ApiError";
  }
}

async function requestJson<T>(
  method: "GET" | "POST",
  path: string,
  body: unknown,
  token?: string,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) {
    headers["content-type"] = "application/json";
  }
  if (token !== undefined) {
    headers["authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? null : JSON.stringify(body),
  });
  if (!res.ok) {
    throw new ApiError(res.status);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export interface RegisterResponse {
  readonly uid: string;
  readonly recovery_codes: readonly string[];
}

export function register(ikPub: Uint8Array): Promise<RegisterResponse> {
  return requestJson<RegisterResponse>("POST", "/v1/register", { ik_pub: toBase64(ikPub) });
}

export interface ChallengeResponse {
  readonly nonce: string; // hex
  readonly timestamp: number;
  readonly origin: string; // the origin the server bound; signed verbatim
}

export function loginChallenge(uid: string): Promise<ChallengeResponse> {
  return requestJson<ChallengeResponse>("POST", "/v1/login/challenge", { uid });
}

export interface TokenResponse {
  readonly token: string;
}

export function loginVerify(
  uid: string,
  nonce: string,
  signature: Uint8Array,
): Promise<TokenResponse> {
  return requestJson<TokenResponse>("POST", "/v1/login/verify", {
    uid,
    nonce,
    signature: toBase64(signature),
  });
}

export function logout(token: string): Promise<void> {
  return requestJson<void>("POST", "/v1/logout", undefined, token);
}

export function uploadSpk(token: string, pub: Uint8Array, sig: Uint8Array): Promise<void> {
  return requestJson<void>(
    "POST",
    "/v1/keys/spk",
    { spk_pub: toBase64(pub), spk_sig: toBase64(sig) },
    token,
  );
}

export function uploadOpks(
  token: string,
  pubs: readonly Uint8Array[],
  rootSig: Uint8Array,
): Promise<void> {
  return requestJson<void>(
    "POST",
    "/v1/keys/opks",
    { opks: pubs.map(toBase64), root_sig: toBase64(rootSig) },
    token,
  );
}

export interface KeysStatusResponse {
  readonly spk_uploaded_at: number | null;
  readonly opk_count: number;
}

export function keysStatus(token: string): Promise<KeysStatusResponse> {
  return requestJson<KeysStatusResponse>("GET", "/v1/keys/status", undefined, token);
}
