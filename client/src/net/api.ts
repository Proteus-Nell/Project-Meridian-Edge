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

export interface RecoverResponse {
  readonly uid: string;
  readonly recovery_codes: readonly string[]; // full replacement set, shown once
}

/** Redeem a recovery code and enroll `ikPub` as the account's new identity
 * key (§2.2). The server destroys every artifact of the old identity. */
export function recover(uid: string, code: string, ikPub: Uint8Array): Promise<RecoverResponse> {
  return requestJson<RecoverResponse>("POST", "/v1/recover", {
    uid,
    code,
    ik_pub: toBase64(ikPub),
  });
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

export interface WireBundleOpk {
  readonly pub: string;
  readonly index: number;
  readonly leaf_hashes: readonly string[];
  readonly root_sig: string;
}

export interface WireBundle {
  readonly ik_pub: string;
  readonly spk_pub: string;
  readonly spk_sig: string;
  readonly opk: WireBundleOpk | null;
}

/** consumeOpk=false is the identity-binding path: it must never drain the
 * target's one-time prekeys (ADR 0002). */
export function fetchBundle(token: string, uid: string, consumeOpk = true): Promise<WireBundle> {
  const suffix = consumeOpk ? "" : "?opk=0";
  return requestJson<WireBundle>("GET", `/v1/bundles/${uid}${suffix}`, undefined, token);
}

export function sendMessage(
  token: string,
  recipientUid: string,
  envelope: Uint8Array,
): Promise<void> {
  return requestJson<void>(
    "POST",
    "/v1/messages",
    { recipient_uid: recipientUid, envelope: toBase64(envelope) },
    token,
  );
}

export interface InboxMessage {
  readonly id: number;
  readonly envelope: string;
}

export function fetchMessages(token: string): Promise<{ messages: InboxMessage[] }> {
  return requestJson<{ messages: InboxMessage[] }>("GET", "/v1/messages", undefined, token);
}

export function ackMessages(token: string, ids: readonly number[]): Promise<void> {
  return requestJson<void>("POST", "/v1/messages/ack", { ids }, token);
}
