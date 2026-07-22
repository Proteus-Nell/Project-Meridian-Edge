// Live end-to-end against a running server (CLAUDE.md §3 DoD): Alice
// registers, Bob registers and goes offline, Alice sends, Bob logs in and
// reads, and the queue row is provably deleted after ack.
//
// Skipped unless MERIDIAN_EDGE_E2E=1 (needs uvicorn on 127.0.0.1:8000 with a fresh
// or disposable database):
//   MERIDIAN_EDGE_E2E=1 npx vitest run tests/live.e2e.test.ts

import { beforeAll, describe, expect, it } from "vitest";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { buildLoginMessage } from "../src/crypto/login";
import { initiateKx, respondKx, verifyBundle } from "../src/crypto/kx";
import type { Bundle, PrekeyLookup, PrekeySecret } from "../src/crypto/kx";
import { generateOpkBatch, generateSpk } from "../src/crypto/prekeys";
import { fromBase64, toBase64 } from "../src/util/base64";

const BASE = "http://127.0.0.1:8000";

interface Actor {
  keys: { publicKey: Uint8Array; secretKey: Uint8Array };
  uid: string;
  token: string;
  codes: string[];
  spk: { pub: Uint8Array; sec: Uint8Array; sig: Uint8Array };
  opks: { pub: Uint8Array; sec: Uint8Array }[];
}

async function call<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) {
    headers["content-type"] = "application/json";
  }
  if (token !== undefined) {
    headers["authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? null : JSON.stringify(body),
  });
  expect(res.ok, `${method} ${path} -> ${res.status}`).toBe(true);
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}

async function login(keys: Actor["keys"], uid: string): Promise<string> {
  const challenge = await call<{ nonce: string; timestamp: number; origin: string }>(
    "POST",
    "/v1/login/challenge",
    { uid },
  );
  const signature = ml_dsa65.sign(
    buildLoginMessage(hexToBytes(challenge.nonce), challenge.origin, challenge.timestamp),
    keys.secretKey,
  );
  const verified = await call<{ token: string }>("POST", "/v1/login/verify", {
    uid,
    nonce: challenge.nonce,
    signature: toBase64(signature),
  });
  return verified.token;
}

async function bootstrap(seedByte: number): Promise<Actor> {
  const keys = ml_dsa65.keygen(new Uint8Array(32).fill(seedByte));
  const registered = await call<{ uid: string; recovery_codes: string[] }>("POST", "/v1/register", {
    ik_pub: toBase64(keys.publicKey),
  });
  const uid = registered.uid.replaceAll("-", "");
  const token = await login(keys, uid);

  const spk = generateSpk(keys.secretKey);
  await call("POST", "/v1/keys/spk", { spk_pub: toBase64(spk.pub), spk_sig: toBase64(spk.sig) }, token);
  const batch = generateOpkBatch(keys.secretKey, 5);
  await call(
    "POST",
    "/v1/keys/opks",
    { opks: batch.pubs.map(toBase64), root_sig: toBase64(batch.rootSig) },
    token,
  );
  const opks = batch.pubs.map((pub, i) => ({ pub, sec: batch.secs[i] ?? new Uint8Array() }));
  return { keys, uid, token, codes: registered.recovery_codes, spk, opks };
}

function toLookup(actor: Actor): PrekeyLookup {
  const spkMap = new Map<string, PrekeySecret>([
    [
      bytesToHex(sha512(actor.spk.pub)),
      { pub: actor.spk.pub, sec: actor.spk.sec, storeKey: "spk/e2e" },
    ],
  ]);
  const opkMap = new Map<string, PrekeySecret>(
    actor.opks.map((opk, i) => [
      bytesToHex(sha512(opk.pub)),
      { pub: opk.pub, sec: opk.sec, storeKey: `opk/e2e/${i}` },
    ]),
  );
  return {
    spkByHash: (hash) => spkMap.get(hash) ?? null,
    opkByHash: (hash) => opkMap.get(hash) ?? null,
  };
}

describe.skipIf(process.env["MERIDIAN_EDGE_E2E"] !== "1")("live: offline first message", () => {
  // One actor pair for the whole file: registration is limited to 3/hour/IP.
  let alice: Actor;
  let bob: Actor;

  beforeAll(async () => {
    alice = await bootstrap(0xa1);
    bob = await bootstrap(0xb0);
  }, 120000);

  it("delivers Alice's KX message to an offline Bob and deletes on ack", async () => {
    // Bob goes offline.
    await call("POST", "/v1/logout", undefined, bob.token);

    // Alice fetches Bob's bundle, verifies it, and sends the first message.
    const wire = await call<{
      ik_pub: string;
      spk_pub: string;
      spk_sig: string;
      opk: { pub: string; index: number; leaf_hashes: string[]; root_sig: string } | null;
    }>("GET", `/v1/bundles/${bob.uid}`, undefined, alice.token);
    expect(fromBase64(wire.ik_pub)).toEqual(bob.keys.publicKey);
    expect(wire.opk).not.toBeNull();
    const bundle: Bundle = {
      ikPub: fromBase64(wire.ik_pub),
      spkPub: fromBase64(wire.spk_pub),
      spkSig: fromBase64(wire.spk_sig),
      opk:
        wire.opk === null
          ? null
          : {
              pub: fromBase64(wire.opk.pub),
              index: wire.opk.index,
              leaves: wire.opk.leaf_hashes.map(fromBase64),
              rootSig: fromBase64(wire.opk.root_sig),
            },
    };
    expect(verifyBundle(bundle)).toBe(true);

    const payload = new TextEncoder().encode(
      JSON.stringify({ u: alice.uid, m: "hello bob - first pure-PQC message" }),
    );
    const { envelope, session } = initiateKx(
      alice.keys.publicKey,
      alice.keys.secretKey,
      bundle,
      payload,
    );
    await call(
      "POST",
      "/v1/messages",
      { recipient_uid: bob.uid, envelope: toBase64(envelope) },
      alice.token,
    );

    // Bob comes back online and reads.
    const bobToken = await login(bob.keys, bob.uid);
    const inbox = await call<{ messages: { id: number; envelope: string }[] }>(
      "GET",
      "/v1/messages",
      undefined,
      bobToken,
    );
    expect(inbox.messages).toHaveLength(1);
    const first = inbox.messages[0];
    expect(first).toBeDefined();
    if (first === undefined) {
      return;
    }

    const result = respondKx(bob.keys.publicKey, toLookup(bob), fromBase64(first.envelope));
    expect(result.ok).toBe(true);
    if (result.ok) {
      const parsed = JSON.parse(new TextDecoder().decode(result.plaintext)) as {
        u: string;
        m: string;
      };
      expect(parsed.u).toBe(alice.uid);
      expect(parsed.m).toContain("hello bob");
      expect(Buffer.from(result.session.rk)).toEqual(Buffer.from(session.rk));
      expect(result.consumedOpkStoreKey).not.toBeNull();
    }

    // Ack deletes the row - provably gone.
    await call("POST", "/v1/messages/ack", { ids: [first.id] }, bobToken);
    const after = await call<{ messages: unknown[] }>("GET", "/v1/messages", undefined, bobToken);
    expect(after.messages).toHaveLength(0);
  }, 60000);

  it("a tampered envelope fails on Bob's side, not silently", async () => {
    const wire = await call<{
      ik_pub: string;
      spk_pub: string;
      spk_sig: string;
      opk: { pub: string; index: number; leaf_hashes: string[]; root_sig: string } | null;
    }>("GET", `/v1/bundles/${bob.uid}`, undefined, alice.token);
    const bundle: Bundle = {
      ikPub: fromBase64(wire.ik_pub),
      spkPub: fromBase64(wire.spk_pub),
      spkSig: fromBase64(wire.spk_sig),
      opk:
        wire.opk === null
          ? null
          : {
              pub: fromBase64(wire.opk.pub),
              index: wire.opk.index,
              leaves: wire.opk.leaf_hashes.map(fromBase64),
              rootSig: fromBase64(wire.opk.root_sig),
            },
    };
    const { envelope } = initiateKx(
      alice.keys.publicKey,
      alice.keys.secretKey,
      bundle,
      new TextEncoder().encode('{"u":"x","m":"y"}'),
    );
    const tampered = envelope.slice();
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0xff;
    const result = respondKx(bob.keys.publicKey, toLookup(bob), tampered);
    expect(result).toEqual({ ok: false, reason: "decrypt-failed" });
  }, 60000);

  // Runs last: it retires Alice's key/token, so nothing may follow it.
  it("recovers Alice by code: new key takes the UID, old key/token/codes all die", async () => {
    const oldKeys = alice.keys;
    const oldCodes = [...alice.codes];
    const newKeys = ml_dsa65.keygen(new Uint8Array(32).fill(0xa2));

    const recovered = await call<{ uid: string; recovery_codes: string[] }>(
      "POST",
      "/v1/recover",
      // Mangled on purpose: lowercase, dashes stripped, 0 typed as O - the
      // server's Crockford canonicalization must absorb all of it.
      {
        uid: alice.uid,
        code: (oldCodes[0] ?? "").toLowerCase().replaceAll("-", "").replaceAll("0", "o"),
        ik_pub: toBase64(newKeys.publicKey),
      },
    );
    expect(recovered.uid.replaceAll("-", "")).toBe(alice.uid);
    expect(recovered.recovery_codes).toHaveLength(10);
    expect(recovered.recovery_codes).not.toContain(oldCodes[0]);

    // The pre-recovery session token was revoked in the same transaction.
    const dead = await fetch(`${BASE}/v1/keys/status`, {
      headers: { authorization: `Bearer ${alice.token}` },
    });
    expect(dead.status).toBe(401);

    // The old identity key can no longer complete the login handshake.
    const challenge = await call<{ nonce: string; timestamp: number; origin: string }>(
      "POST",
      "/v1/login/challenge",
      { uid: alice.uid },
    );
    const staleSig = ml_dsa65.sign(
      buildLoginMessage(hexToBytes(challenge.nonce), challenge.origin, challenge.timestamp),
      oldKeys.secretKey,
    );
    const refused = await fetch(`${BASE}/v1/login/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        uid: alice.uid,
        nonce: challenge.nonce,
        signature: toBase64(staleSig),
      }),
    });
    expect(refused.status).toBe(401);

    // The new key logs in, and every old-key artifact is gone server-side.
    const newToken = await login(newKeys, alice.uid);
    const status = await call<{ spk_uploaded_at: number | null; opk_count: number }>(
      "GET",
      "/v1/keys/status",
      undefined,
      newToken,
    );
    expect(status.spk_uploaded_at).toBeNull();
    expect(status.opk_count).toBe(0);

    // A peer that pinned Alice's old key now sees a different one - the
    // client-side section 4.6 key-change warning trigger.
    const wire = await call<{ ik_pub: string }>(
      "GET",
      `/v1/bundles/${alice.uid}?opk=0`,
      undefined,
      bob.token,
    ).catch(() => null);
    if (wire !== null) {
      expect(fromBase64(wire.ik_pub)).toEqual(newKeys.publicKey);
      expect(fromBase64(wire.ik_pub)).not.toEqual(oldKeys.publicKey);
    }

    // Every code from the old set is void; a reissued one redeems.
    const replay = await fetch(`${BASE}/v1/recover`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        uid: alice.uid,
        code: oldCodes[1],
        ik_pub: toBase64(newKeys.publicKey),
      }),
    });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual({ error: "auth_failed" });

    const again = await call<{ recovery_codes: string[] }>("POST", "/v1/recover", {
      uid: alice.uid,
      code: recovered.recovery_codes[0],
      ik_pub: toBase64(ml_dsa65.keygen(new Uint8Array(32).fill(0xa3)).publicKey),
    });
    expect(again.recovery_codes).toHaveLength(10);
  }, 120000);
});
