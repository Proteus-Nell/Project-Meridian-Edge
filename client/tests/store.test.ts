import { describe, expect, it } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import { KeyStore, StoreLockedError } from "../src/crypto/store";
import type { Argon2Params } from "../src/crypto/store";

// Weak parameters for test speed; production params are the section-0
// constants and are stored beside the ciphertext either way.
const FAST: Argon2Params = { mKib: 64, t: 1, p: 1 };

function freshStore(factory = new IDBFactory()): { store: KeyStore; factory: IDBFactory } {
  return { store: new KeyStore("pqterm-test", factory), factory };
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
    const first = new KeyStore("pqterm-test", factory);
    await first.create("correct horse battery", FAST);
    await first.putJson("identity", { uid: "ABC" });
    first.lock();

    // "Reload": a brand-new store instance over the same IndexedDB.
    const second = new KeyStore("pqterm-test", factory);
    expect(await second.exists()).toBe(true);
    expect(second.isUnlocked()).toBe(false);
    expect(await second.unlock("correct horse battery")).toBe(true);
    expect(await second.getJson<{ uid: string }>("identity")).toEqual({ uid: "ABC" });
  });

  it("rejects a wrong passphrase", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("pqterm-test", factory);
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
    const store = new KeyStore("pqterm-test", factory);
    await store.create("correct horse battery", FAST);
    const marker = new TextEncoder().encode("TOP-SECRET-IDENTITY-KEY");
    await store.putBytes("identity", marker);
    store.lock();

    // Thief copies the IndexedDB directory: same factory, no passphrase.
    const raw = await new Promise<unknown>((resolve, reject) => {
      const open = factory.open("pqterm-test", 1);
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
    const thief = new KeyStore("pqterm-test", factory);
    expect(await thief.unlock("password")).toBe(false);
    expect(await thief.unlock("")).toBe(false);
  });

  it("rotatePassphrase re-wraps the DEK: old fails, new works, data intact", async () => {
    const factory = new IDBFactory();
    const store = new KeyStore("pqterm-test", factory);
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
    const store = new KeyStore("pqterm-test", factory);
    await store.create("correct horse battery", FAST);
    await store.putBytes("identity", new Uint8Array([1]));
    await store.wipe();
    const after = new KeyStore("pqterm-test", factory);
    expect(await after.exists()).toBe(false);
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
