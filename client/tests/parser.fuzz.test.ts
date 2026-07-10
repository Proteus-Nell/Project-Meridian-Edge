// Parser fuzz test (CLAUDE.md §1 definition of done): random bytes and
// mutated valid commands must never throw uncaught and must never yield a
// command outside the static allowlist. Deterministically seeded so CI
// failures are reproducible.

import { describe, expect, it } from "vitest";

import { parseLine } from "../src/terminal/parser";
import type { CommandName } from "../src/terminal/parser";

const ALLOWED_NAMES: ReadonlySet<CommandName> = new Set<CommandName>([
  "register",
  "login",
  "logout",
  "lock",
  "whoami",
  "add",
  "contacts",
  "chat",
  "home",
  "return",
  "verify",
  "verified",
  "ack",
  "timer",
  "purge-set",
  "purge-now",
  "delete",
  "rotate-passphrase",
  "settings-rotation",
  "settings-notify",
  "settings-mask",
  "settings-trust",
  "keys-status",
  "keys-refill",
  "bench",
  "wipe",
  "help",
]);

const RESULT_KINDS = new Set(["empty", "message", "command", "invalid"]);

/** Deterministic PRNG (xorshift32) - test-only; app code uses the CSPRNG. */
function makeRng(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x100000000;
  };
}

function randomCodePoint(rng: () => number): number {
  const roll = rng();
  if (roll < 0.5) {
    return 0x20 + Math.floor(rng() * 0x5f); // printable ASCII
  }
  if (roll < 0.7) {
    return Math.floor(rng() * 0x20); // C0 controls
  }
  if (roll < 0.85) {
    return Math.floor(rng() * 0x800); // Latin + misc BMP
  }
  // anywhere in Unicode, skipping the surrogate range
  let cp = Math.floor(rng() * 0x10ffff);
  if (cp >= 0xd800 && cp <= 0xdfff) {
    cp -= 0x800;
  }
  return cp;
}

function randomString(rng: () => number, maxLen: number): string {
  const len = Math.floor(rng() * maxLen);
  let out = "";
  for (let i = 0; i < len; i += 1) {
    out += String.fromCodePoint(randomCodePoint(rng));
  }
  return out;
}

const VALID_SAMPLES = [
  "/register",
  "/login",
  "/whoami",
  "/add 7Q3KM2VD9XWP4RTBA6HJEZ0123 bob",
  "/chat bob",
  "/text bob",
  "/home",
  "/return",
  "/contacts",
  "/verify bob",
  "/verified bob",
  "/ack bob",
  "/timer bob 1d",
  "/purge set 30m",
  "/purge now",
  "/delete last /s",
  "/rotate passphrase",
  "/settings rotation day friday",
  "/settings notify on",
  "/keys status",
  "/keys refill",
  "/bench b3",
  "/wipe",
  "/help timer",
  "hello there",
  " /escaped message",
];

function mutate(rng: () => number, input: string): string {
  let out = input;
  const mutations = 1 + Math.floor(rng() * 4);
  for (let m = 0; m < mutations; m += 1) {
    const pos = Math.floor(rng() * (out.length + 1));
    const roll = rng();
    if (roll < 0.35) {
      out = out.slice(0, pos) + String.fromCodePoint(randomCodePoint(rng)) + out.slice(pos);
    } else if (roll < 0.6 && out.length > 0) {
      out = out.slice(0, Math.min(pos, out.length - 1)) + out.slice(Math.min(pos, out.length - 1) + 1);
    } else if (roll < 0.8) {
      out = out.slice(0, pos) + out.slice(0, pos) + out.slice(pos); // duplicate prefix
    } else {
      out =
        out.slice(0, pos) +
        out
          .slice(pos)
          .split("")
          .map((c) => (rng() < 0.5 ? c.toUpperCase() : c.toLowerCase()))
          .join("");
    }
    if (out.length > 4096) {
      out = out.slice(0, 4096);
    }
  }
  return out;
}

function assertSafe(input: string): void {
  const result = parseLine(input); // must not throw
  expect(RESULT_KINDS.has(result.kind)).toBe(true);
  if (result.kind === "command") {
    expect(ALLOWED_NAMES.has(result.command.name)).toBe(true);
  }
}

describe("parser fuzz", () => {
  it("survives 10000 random strings", () => {
    const rng = makeRng(0xc0ffee);
    for (let i = 0; i < 10000; i += 1) {
      assertSafe(randomString(rng, 120));
    }
  });

  it("survives 10000 slash-prefixed random strings", () => {
    const rng = makeRng(0xdecafbad);
    for (let i = 0; i < 10000; i += 1) {
      assertSafe(`/${randomString(rng, 120)}`);
    }
  });

  it("survives 10000 mutated valid commands", () => {
    const rng = makeRng(0x5eed);
    for (let i = 0; i < 10000; i += 1) {
      const base = VALID_SAMPLES[Math.floor(rng() * VALID_SAMPLES.length)] ?? "/help";
      assertSafe(mutate(rng, base));
    }
  });
});
