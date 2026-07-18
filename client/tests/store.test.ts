import { describe, expect, it } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import { KeyStore, StoreLockedError } from "../src/crypto/store";
import type { Argon2Params, ThemePrefs } from "../src/crypto/store";

// Weak parameters for test speed; production params are the section-0
// constants and are stored beside the ciphertext either way.
const FAST: Argon2Params = { mKib: 64, t: 1, p: 1 };

const ALL_OFF: ThemePrefs = { emblem: false, scanlines: false, vignette: false, dock: false };

/** Baseline prefs record for tests that only care about one field. */
const BASE = {
  secretMask: "asterisk",
  theme: { emblem: true, scanlines: true, vignette: true, dock: true },
  scheme: "dark",
  emblemGlyph: "globe",
  colorOverrides: {},
} as const;

function freshStore(factory = new IDBFactory()): { store: KeyStore; factory: IDBFactory } {
  return { store: new KeyStore("meridian-edge-test", factory), factory };
}

describe("KeyStore", () => {
  it("creates, stores and retrieves encrypted records", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery", FAST);
    const secret = new Uint8Array([1, 2, 3, 4, 5]);
    await store.putBytes("identity", secret);
    expect(await store.getBytes("identity")).toEqual(secret);
    expect(await store.getBytes("missing")).toBeNull();
  });

  it("survives a reload locked and unlocks with the right passphrase", async () => {
    const factory = new IDBFactory();
    const first = new KeyStore("meridian-edge-test", factory);
    await first.create("correct horse battery", FAST);
    await first.putJson("identity", { uid: "ABC" });
    first.lock();

    // "Reload": a brand-new store instance over the same IndexedDB.
    const second = new KeyStore("meridian-edge-test", factory);
    expect(await second.exists()).toBe(true);
    expect(second.isUnlocked()).toBe(false);
    expect(await second.unlock("correct horse battery")).toBe(true);
    expect(await second.getJson<{ uid: string }>("identity")).toEqual({ uid: "ABC" });
  });

  it("rejects a wrong passphrase", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    await store.create("correct horse battery", FAST);
    store.lock();
    expect(await store.unlock("wrong passphrase!!")).toBe(false);
    expect(store.isUnlocked()).toBe(false);
  });

  it("refuses record access while locked", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery", FAST);
    await store.putBytes("k", new Uint8Array([9]));
    store.lock();
    await expect(store.getBytes("k")).rejects.toBeInstanceOf(StoreLockedError);
    await expect(store.putBytes("k", new Uint8Array([1]))).rejects.toBeInstanceOf(
      StoreLockedError,
    );
  });

  it("a stolen database without the passphrase yields only ciphertext", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    await store.create("correct horse battery", FAST);
    const marker = new TextEncoder().encode("TOP-SECRET-IDENTITY-KEY");
    await store.putBytes("identity", marker);
    store.lock();

    // Thief copies the IndexedDB directory: same factory, no passphrase.
    const raw = await new Promise<unknown>((resolve, reject) => {
      const open = factory.open("meridian-edge-test", 1);
      open.onsuccess = () => {
        const db = open.result;
        const req = db.transaction("vault", "readonly").objectStore("vault").get("identity");
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      };
      open.onerror = () => reject(open.error);
    });
    const record = raw as { ct: Uint8Array };
    const ctText = new TextDecoder("utf-8", { fatal: false }).decode(record.ct);
    expect(ctText).not.toContain("TOP-SECRET");
    // And brute unlock attempts with wrong passphrases fail.
    const thief = new KeyStore("meridian-edge-test", factory);
    expect(await thief.unlock("password")).toBe(false);
    expect(await thief.unlock("")).toBe(false);
  });

  it("rotatePassphrase re-wraps the DEK: old fails, new works, data intact", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    await store.create("old passphrase 1", FAST);
    await store.putJson("identity", { uid: "KEEP" });
    expect(await store.rotatePassphrase("old passphrase 1", "new passphrase 2")).toBe(true);
    store.lock();
    expect(await store.unlock("old passphrase 1")).toBe(false);
    expect(await store.unlock("new passphrase 2")).toBe(true);
    expect(await store.getJson<{ uid: string }>("identity")).toEqual({ uid: "KEEP" });
  });

  it("rotatePassphrase with a wrong current passphrase fails", async () => {
    const { store } = freshStore();
    await store.create("old passphrase 1", FAST);
    expect(await store.rotatePassphrase("guess", "new passphrase 2")).toBe(false);
    store.lock();
    expect(await store.unlock("old passphrase 1")).toBe(true);
  });

  it("wipe destroys everything", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    await store.create("correct horse battery", FAST);
    await store.putBytes("identity", new Uint8Array([1]));
    await store.wipe();
    const after = new KeyStore("meridian-edge-test", factory);
    expect(await after.exists()).toBe(false);
  });

  it("stores display prefs unencrypted, readable before unlock", async () => {
    const factory = new IDBFactory();
    const first = new KeyStore("meridian-edge-test", factory);
    // Default before anything is written.
    expect((await first.getDisplayPrefs()).secretMask).toBe("asterisk");
    await first.setDisplayPrefs({ ...BASE, secretMask: "hidden", theme: ALL_OFF });

    // A fresh instance (reload) reads it back WITHOUT unlocking - the point
    // is the first login prompt honors it.
    const second = new KeyStore("meridian-edge-test", factory);
    expect(second.isUnlocked()).toBe(false);
    expect((await second.getDisplayPrefs()).secretMask).toBe("hidden");
  });

  it("round-trips the theme block and defaults it to all-on", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    // Nothing written yet: every layer defaults on.
    expect((await store.getDisplayPrefs()).theme).toEqual({
      emblem: true,
      scanlines: true,
      vignette: true,
      dock: true,
    });
    await store.setDisplayPrefs({
      ...BASE,
      theme: { emblem: false, scanlines: true, vignette: false, dock: true },
    });
    const reread = new KeyStore("meridian-edge-test", factory);
    expect((await reread.getDisplayPrefs()).theme).toEqual({
      emblem: false,
      scanlines: true,
      vignette: false,
      dock: true,
    });
  });

  it("legacy prefs without a theme block degrade to all-on defaults", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    // Simulate a record written by the pre-theme client: mask only.
    await store.setDisplayPrefs({ secretMask: "hidden" } as unknown as Parameters<
      typeof store.setDisplayPrefs
    >[0]);
    const prefs = await store.getDisplayPrefs();
    expect(prefs.secretMask).toBe("hidden");
    expect(prefs.theme).toEqual({ emblem: true, scanlines: true, vignette: true, dock: true });
  });

  it("keeps display prefs out of vault key listings", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery", FAST);
    await store.setDisplayPrefs({ ...BASE, secretMask: "hidden", theme: ALL_OFF });
    await store.putJson("spk/1", { a: 1 });
    expect(await store.listKeys("")).toEqual(["spk/1"]);
  });

  it("round-trips scheme, emblem glyph, and color overrides; legacy defaults apply", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    // Nothing written: defaults.
    const defaults = await store.getDisplayPrefs();
    expect(defaults.scheme).toBe("dark");
    expect(defaults.emblemGlyph).toBe("globe");
    expect(defaults.colorOverrides).toEqual({});

    await store.setDisplayPrefs({
      ...BASE,
      scheme: "parchment",
      emblemGlyph: "globe",
      colorOverrides: { accent: "#112233" },
    });
    const reread = await new KeyStore("meridian-edge-test", factory).getDisplayPrefs();
    expect(reread.scheme).toBe("parchment");
    expect(reread.emblemGlyph).toBe("globe");
    expect(reread.colorOverrides).toEqual({ accent: "#112233" });

    // Tampered/legacy values degrade to defaults rather than poisoning the UI.
    await store.setDisplayPrefs({
      ...BASE,
      scheme: "neon",
      emblemGlyph: "skull",
      colorOverrides: { accent: "not-a-color", background: "#abcdef", bogus: "#000000" },
    } as unknown as Parameters<typeof store.setDisplayPrefs>[0]);
    const cleaned = await store.getDisplayPrefs();
    expect(cleaned.scheme).toBe("dark");
    expect(cleaned.emblemGlyph).toBe("globe");
    expect(cleaned.colorOverrides).toEqual({ background: "#abcdef" });
  });

  it("lists and deletes prefixed keys", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery", FAST);
    await store.putJson("spk/100", { a: 1 });
    await store.putJson("spk/200", { a: 2 });
    await store.putJson("opk/1/0", { a: 3 });
    expect((await store.listKeys("spk/")).sort()).toEqual(["spk/100", "spk/200"]);
    await store.deleteKey("spk/100");
    expect(await store.listKeys("spk/")).toEqual(["spk/200"]);
  });
});
