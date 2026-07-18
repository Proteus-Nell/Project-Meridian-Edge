import { describe, expect, it } from "vitest";

import { buildLoginMessage } from "../src/crypto/login";

describe("buildLoginMessage", () => {
  it("produces nonce || origin || ts_be8, byte-exact", () => {
    const nonce = new Uint8Array(32).map((_, i) => i);
    const origin = "https://meridian-edge.example";
    const timestamp = 1_751_600_000;

    const message = buildLoginMessage(nonce, origin, timestamp);
    const originBytes = new TextEncoder().encode(origin);

    expect(message.length).toBe(32 + originBytes.length + 8);
    expect(Array.from(message.slice(0, 32))).toEqual(Array.from(nonce));
    expect(Array.from(message.slice(32, 32 + originBytes.length))).toEqual(
      Array.from(originBytes),
    );
    // 1751600000 = 0x68674B80 big-endian in the trailing 8 bytes.
    expect(Array.from(message.slice(-8))).toEqual([0, 0, 0, 0, 0x68, 0x67, 0x4b, 0x80]);
  });

  it("handles the empty origin (no Origin header seen by the server)", () => {
    const nonce = new Uint8Array(32);
    const message = buildLoginMessage(nonce, "", 0);
    expect(message.length).toBe(40);
    expect(Array.from(message.slice(-8))).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });
});
