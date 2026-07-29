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
  font: "default",
  fontSize: 15,
  accessibility: { screenReader: false, reduceMotion: false },
  customSchemes: [],
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
        req.onerror = () => reject(req.error ?? new Error("indexeddb read failed"));
      };
      open.onerror = () => reject(open.error ?? new Error("indexeddb open failed"));
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
    // Default before anything is written: hidden (sudo-style, no length leak).
    expect((await first.getDisplayPrefs()).secretMask).toBe("hidden");
    await first.setDisplayPrefs({ ...BASE, secretMask: "asterisk", theme: ALL_OFF });

    // A fresh instance (reload) reads it back WITHOUT unlocking - the point
    // is the first login prompt honors it.
    const second = new KeyStore("meridian-edge-test", factory);
    expect(second.isUnlocked()).toBe(false);
    expect((await second.getDisplayPrefs()).secretMask).toBe("asterisk");
  });

  it("round-trips the theme block and defaults it to all-off", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    // Nothing written yet: every layer defaults off (plain terminal).
    expect((await store.getDisplayPrefs()).theme).toEqual({
      emblem: false,
      scanlines: false,
      vignette: false,
      dock: false,
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

  it("legacy prefs without a theme block degrade to all-off defaults", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    // Simulate a record written by the pre-theme client: mask only.
    await store.setDisplayPrefs({ secretMask: "asterisk" } as unknown as Parameters<
      typeof store.setDisplayPrefs
    >[0]);
    const prefs = await store.getDisplayPrefs();
    expect(prefs.secretMask).toBe("asterisk");
    expect(prefs.theme).toEqual({ emblem: false, scanlines: false, vignette: false, dock: false });
  });

  it("keeps display prefs out of vault key listings", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery", FAST);
    await store.setDisplayPrefs({ ...BASE, secretMask: "hidden", theme: ALL_OFF });
    await store.putJson("spk/1", { a: 1 });
    expect(await store.listKeys("")).toEqual(["spk/1"]);
  });

  it("round-trips scheme, emblem glyph, and custom schemes; legacy defaults apply", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    // Nothing written: defaults.
    const defaults = await store.getDisplayPrefs();
    expect(defaults.scheme).toBe("dark");
    expect(defaults.emblemGlyph).toBe("globe");
    expect(defaults.customSchemes).toEqual([]);

    const mine = {
      name: "midnight",
      base: "dark",
      colors: {
        accent: "#112233",
        background: "#000000",
        panel: "#101010",
        text: "#eeeeee",
        muted: "#888888",
      },
    } as const;
    await store.setDisplayPrefs({
      ...BASE,
      scheme: "midnight",
      emblemGlyph: "globe",
      customSchemes: [mine],
    });
    const reread = await new KeyStore("meridian-edge-test", factory).getDisplayPrefs();
    expect(reread.scheme).toBe("midnight");
    expect(reread.emblemGlyph).toBe("globe");
    expect(reread.customSchemes).toEqual([mine]);

    // Tampered/legacy values degrade to defaults rather than poisoning the UI.
    await store.setDisplayPrefs({
      ...BASE,
      scheme: "neon",
      emblemGlyph: "skull",
      customSchemes: [],
    } as unknown as Parameters<typeof store.setDisplayPrefs>[0]);
    const cleaned = await store.getDisplayPrefs();
    expect(cleaned.scheme).toBe("dark");
    expect(cleaned.emblemGlyph).toBe("globe");
  });

  it("drops a stored custom scheme whose colors or name are not trustworthy", async () => {
    const { store } = freshStore();
    const good = {
      name: "mine",
      base: "olive",
      colors: {
        accent: "#112233",
        background: "#000000",
        panel: "#101010",
        text: "#eeeeee",
        muted: "#888888",
      },
    };
    await store.setDisplayPrefs({
      ...BASE,
      customSchemes: [
        good,
        // A CSS-injection attempt in a color value.
        { ...good, name: "inject", colors: { ...good.colors, accent: "red;}body{display:none" } },
        // A prototype-shaped name, and a missing slot.
        { ...good, name: "__proto__" },
        { ...good, name: "constructor" },
        { ...good, name: "gappy", colors: { accent: "#112233" } },
        // A preset name would shadow an immutable scheme.
        { ...good, name: "dark" },
      ],
    } as unknown as Parameters<typeof store.setDisplayPrefs>[0]);

    const prefs = await store.getDisplayPrefs();
    expect(prefs.customSchemes.map((s) => s.name)).toEqual(["mine"]);
    // Nothing tampered survived, so nothing but #rrggbb can reach a CSS var.
    for (const value of Object.values(prefs.customSchemes[0]?.colors ?? {})) {
      expect(value).toMatch(/^#[0-9a-f]{6}$/);
    }
  });

  it("migrates a pre-custom-schemes record into a fork, leaving the preset pristine", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    // A record the old client wrote: overrides smeared over the active preset.
    await store.setDisplayPrefs({
      secretMask: "hidden",
      theme: ALL_OFF,
      scheme: "parchment",
      emblemGlyph: "globe",
      colorOverrides: { accent: "#112233", bogus: "#000000", muted: "not-a-color" },
    } as unknown as Parameters<typeof store.setDisplayPrefs>[0]);

    const prefs = await store.getDisplayPrefs();
    expect(prefs.scheme).toBe("parchment-custom");
    expect(prefs.customSchemes).toHaveLength(1);
    const migrated = prefs.customSchemes[0];
    expect(migrated?.base).toBe("parchment");
    // The one valid override survived; the invalid ones fell back to parchment.
    expect(migrated?.colors.accent).toBe("#112233");
    expect(migrated?.colors.muted).toBe("#5f6d4e");
    expect(migrated?.colors.background).toBe("#e3e7d3");
  });

  it("leaves an empty legacy override map on the pure preset", async () => {
    const { store } = freshStore();
    await store.setDisplayPrefs({
      secretMask: "hidden",
      theme: ALL_OFF,
      scheme: "olive",
      emblemGlyph: "globe",
      colorOverrides: {},
    } as unknown as Parameters<typeof store.setDisplayPrefs>[0]);
    const prefs = await store.getDisplayPrefs();
    expect(prefs.scheme).toBe("olive");
    expect(prefs.customSchemes).toEqual([]);
  });

  it("falls back to the default scheme when the active one no longer exists", async () => {
    const { store } = freshStore();
    await store.setDisplayPrefs({ ...BASE, scheme: "deleted-one", customSchemes: [] });
    expect((await store.getDisplayPrefs()).scheme).toBe("dark");
  });

  // --- duress envelope -------------------------------------------------------
  //
  // The security properties, not just the round trip: an imaged database must
  // not reveal whether the feature is armed, and the envelope must be
  // independent of the DEK so guessing it does not open the vault.

  it("seals and returns a duress payload for its own passphrase only", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery1!", FAST);
    const payload = new TextEncoder().encode('{"uid":"ABC","sec":"AAAA"}');
    await store.armDuress("under the floorboards9!", payload);

    expect(await store.tryDuress("under the floorboards9!")).toEqual(payload);
    expect(await store.tryDuress("correct horse battery1!")).toBeNull();
    expect(await store.tryDuress("something else entirely")).toBeNull();
  });

  it("never unlocks the store with the duress passphrase", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery1!", FAST);
    await store.armDuress("under the floorboards9!", new Uint8Array([1, 2, 3]));
    store.lock();
    // The whole design: it is a trigger, not a second key.
    expect(await store.unlock("under the floorboards9!")).toBe(false);
    expect(store.isUnlocked()).toBe(false);
    expect(await store.unlock("correct horse battery1!")).toBe(true);
  });

  it("writes a decoy of identical shape when disarmed, so the record never says which", async () => {
    const factory = new IDBFactory();
    const armed = new KeyStore("armed", factory);
    const untouched = new KeyStore("untouched", factory);
    await armed.create("correct horse battery1!", FAST);
    await untouched.create("correct horse battery1!", FAST);
    await armed.armDuress("under the floorboards9!", new Uint8Array([7, 7, 7]));

    const read = async (name: string): Promise<Record<string, Uint8Array>> => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const req = factory.open(name, 1);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error("indexeddb error"));
      });
      const tx = db.transaction("vault", "readonly");
      const meta = await new Promise<Record<string, unknown>>((resolve, reject) => {
        const req = tx.objectStore("vault").get("__meta__");
        req.onsuccess = () => resolve(req.result as Record<string, unknown>);
        req.onerror = () => reject(req.error ?? new Error("indexeddb error"));
      });
      db.close();
      return meta.duress as Record<string, Uint8Array>;
    };

    const withSecret = await read("armed");
    const withDecoy = await read("untouched");
    // Same fields, same byte lengths: nothing distinguishes them at rest.
    expect(Object.keys(withDecoy).sort()).toEqual(Object.keys(withSecret).sort());
    for (const field of ["salt", "nonce", "ct"] as const) {
      expect(withDecoy[field]?.length).toBe(withSecret[field]?.length);
    }
    // And the decoy opens for nobody.
    expect(await untouched.tryDuress("under the floorboards9!")).toBeNull();
  });

  it("hides the payload length: two very different payloads seal to one size", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery1!", FAST);
    const sizeOf = async (payload: Uint8Array): Promise<number> => {
      await store.armDuress("under the floorboards9!", payload);
      const opened = await store.tryDuress("under the floorboards9!");
      expect(opened).toEqual(payload);
      return payload.length;
    };
    // Both round-trip exactly, whatever their length.
    expect(await sizeOf(new Uint8Array(1))).toBe(1);
    expect(await sizeOf(new Uint8Array(4000).fill(9))).toBe(4000);
  });

  it("disarms back to a decoy nothing can open", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery1!", FAST);
    await store.armDuress("under the floorboards9!", new Uint8Array([1]));
    await store.disarmDuress();
    expect(await store.tryDuress("under the floorboards9!")).toBeNull();
  });

  it("survives a passphrase rotation untouched", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery1!", FAST);
    const payload = new Uint8Array([4, 2]);
    await store.armDuress("under the floorboards9!", payload);
    expect(await store.rotatePassphrase("correct horse battery1!", "a different one 7?")).toBe(
      true,
    );
    // Own salt, own key: rotating the unlock passphrase does not disturb it.
    expect(await store.tryDuress("under the floorboards9!")).toEqual(payload);
    expect(await store.unlock("a different one 7?")).toBe(true);
  });

  it("recognises its own unlock passphrase without unlocking", async () => {
    const { store } = freshStore();
    await store.create("correct horse battery1!", FAST);
    store.lock();
    expect(await store.isPrimaryPassphrase("correct horse battery1!")).toBe(true);
    expect(await store.isPrimaryPassphrase("under the floorboards9!")).toBe(false);
    expect(store.isUnlocked()).toBe(false);
  });

  it("treats a store predating the feature as unarmed rather than throwing", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("meridian-edge-test", factory);
    await store.create("correct horse battery1!", FAST);
    // Strip the envelope, as a store created by the older client would have.
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = factory.open("meridian-edge-test", 1);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error("indexeddb error"));
    });
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("vault", "readwrite");
      const objectStore = tx.objectStore("vault");
      const get = objectStore.get("__meta__");
      get.onsuccess = () => {
        const meta = get.result as Record<string, unknown>;
        delete meta.duress;
        const put = objectStore.put(meta, "__meta__");
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error ?? new Error("indexeddb error"));
      };
      get.onerror = () => reject(get.error ?? new Error("indexeddb error"));
    });
    db.close();

    expect(await store.tryDuress("under the floorboards9!")).toBeNull();
    expect(await store.unlock("correct horse battery1!")).toBe(true);
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
