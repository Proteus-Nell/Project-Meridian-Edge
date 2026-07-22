// Encrypted local key store (CLAUDE.md §2.4).
//
// Everything in IndexedDB is ciphertext: a random 256-bit DEK encrypts every
// record with XChaCha20-Poly1305 (random 24-byte nonce per write, record key
// as associated data); the DEK itself is wrapped by a KEK derived from the
// unlock passphrase via Argon2id. Changing the passphrase re-wraps only the
// DEK. Locking zeroizes the DEK - best effort, as JS allows.

import { argon2id } from "@noble/hashes/argon2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEM_KIB,
  ARGON2ID_PARALLELISM,
} from "./constants";

export interface Argon2Params {
  readonly mKib: number;
  readonly t: number;
  readonly p: number;
}

// Stored beside the ciphertext so parameters can be upgraded later (§0).
export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  mKib: ARGON2ID_MEM_KIB,
  t: ARGON2ID_ITERATIONS,
  p: ARGON2ID_PARALLELISM,
};

const STORE_NAME = "vault";
const META_KEY = "__meta__";
const PREFS_KEY = "__prefs__";
const DEK_BYTES = 32;
const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const STORE_VERSION = 1;

interface WrappedRecord {
  readonly nonce: Uint8Array;
  readonly ct: Uint8Array;
}

interface MetaRecord {
  readonly version: number;
  readonly salt: Uint8Array;
  readonly params: Argon2Params;
  readonly wrappedDek: WrappedRecord;
}

import { COLOR_SLOTS, isEmblemName, isSchemeName, normalizeHex } from "../terminal/theme";
import type { ColorSlot, EmblemName, SchemeName } from "../terminal/theme";

/** Toggleable visual atmosphere layers (/settings theme). Purely cosmetic. */
export interface ThemePrefs {
  readonly emblem: boolean;
  readonly scanlines: boolean;
  readonly vignette: boolean;
  readonly dock: boolean;
}

/** Non-secret UI preferences. Stored UNENCRYPTED and deliberately so: they
 * must be readable before the store is unlocked (the passphrase-mask setting
 * governs the very first login prompt, and the theme skins the lock screen
 * too), and they contain nothing an attacker with the raw database could
 * exploit. */
export interface DisplayPrefs {
  readonly secretMask: "asterisk" | "hidden";
  readonly theme: ThemePrefs;
  /** Base color scheme (/settings scheme). */
  readonly scheme: SchemeName;
  /** Medallion glyph (/settings emblem). */
  readonly emblemGlyph: EmblemName;
  /** Per-slot HEX overrides layered on the scheme (/settings color). */
  readonly colorOverrides: Partial<Record<ColorSlot, string>>;
}

// Every atmosphere layer defaults OFF: a clean, plain terminal on first run.
// Users opt into the emblem watermark / scanlines / vignette / dock treatment
// via /settings theme. (The header medallion is separate and unaffected.)
const DEFAULT_THEME: ThemePrefs = { emblem: false, scanlines: false, vignette: false, dock: false };

const DEFAULT_PREFS: DisplayPrefs = {
  // Passphrase entry echoes nothing by default (sudo-style); /settings mask
  // asterisk opts into one '*' per character, which leaks length.
  secretMask: "hidden",
  theme: DEFAULT_THEME,
  scheme: "dark",
  emblemGlyph: "globe",
  colorOverrides: {},
};

export class StoreLockedError extends Error {
  constructor() {
    super("store is locked");
    this.name = "StoreLockedError";
  }
}

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexeddb error"));
  });
}

function deriveKek(passphrase: string, salt: Uint8Array, params: Argon2Params): Uint8Array {
  return argon2id(new TextEncoder().encode(passphrase), salt, {
    m: params.mKib,
    t: params.t,
    p: params.p,
    dkLen: DEK_BYTES,
  });
}

export class KeyStore {
  private dek: Uint8Array | null = null;

  constructor(
    private readonly dbName: string = "meridian-edge",
    private readonly idb: IDBFactory = indexedDB,
  ) {}

  private async openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = this.idb.open(this.dbName, STORE_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error("indexeddb open failed"));
    });
  }

  private async readRaw(key: string): Promise<unknown> {
    const db = await this.openDb();
    try {
      const tx = db.transaction(STORE_NAME, "readonly");
      return await request(tx.objectStore(STORE_NAME).get(key));
    } finally {
      db.close();
    }
  }

  private async writeRaw(key: string, value: unknown): Promise<void> {
    const db = await this.openDb();
    try {
      const tx = db.transaction(STORE_NAME, "readwrite");
      await request(tx.objectStore(STORE_NAME).put(value, key));
    } finally {
      db.close();
    }
  }

  async exists(): Promise<boolean> {
    return (await this.readRaw(META_KEY)) !== undefined;
  }

  /** Non-secret display preferences; readable with or without a passphrase.
   * Field-by-field validation so a legacy or hand-tampered record degrades to
   * defaults instead of poisoning the UI (theme absent → all layers off,
   * mask absent → hidden). */
  async getDisplayPrefs(): Promise<DisplayPrefs> {
    const raw = (await this.readRaw(PREFS_KEY)) as
      | {
          secretMask?: unknown;
          theme?: Partial<Record<keyof ThemePrefs, unknown>>;
          scheme?: unknown;
          emblemGlyph?: unknown;
          colorOverrides?: Record<string, unknown>;
        }
      | undefined;
    if (raw === undefined) {
      return DEFAULT_PREFS;
    }
    const mask = raw.secretMask === "asterisk" ? "asterisk" : "hidden";
    const theme: ThemePrefs = {
      emblem: typeof raw.theme?.emblem === "boolean" ? raw.theme.emblem : DEFAULT_THEME.emblem,
      scanlines:
        typeof raw.theme?.scanlines === "boolean" ? raw.theme.scanlines : DEFAULT_THEME.scanlines,
      vignette:
        typeof raw.theme?.vignette === "boolean" ? raw.theme.vignette : DEFAULT_THEME.vignette,
      dock: typeof raw.theme?.dock === "boolean" ? raw.theme.dock : DEFAULT_THEME.dock,
    };
    const scheme =
      typeof raw.scheme === "string" && isSchemeName(raw.scheme) ? raw.scheme : DEFAULT_PREFS.scheme;
    const emblemGlyph =
      typeof raw.emblemGlyph === "string" && isEmblemName(raw.emblemGlyph)
        ? raw.emblemGlyph
        : DEFAULT_PREFS.emblemGlyph;
    const colorOverrides: Partial<Record<ColorSlot, string>> = {};
    for (const slot of COLOR_SLOTS) {
      const value = raw.colorOverrides?.[slot];
      if (typeof value === "string") {
        const hex = normalizeHex(value);
        if (hex !== null) {
          colorOverrides[slot] = hex;
        }
      }
    }
    return { secretMask: mask, theme, scheme, emblemGlyph, colorOverrides };
  }

  async setDisplayPrefs(prefs: DisplayPrefs): Promise<void> {
    await this.writeRaw(PREFS_KEY, prefs);
  }

  isUnlocked(): boolean {
    return this.dek !== null;
  }

  async create(passphrase: string, params: Argon2Params = DEFAULT_ARGON2_PARAMS): Promise<void> {
    if (await this.exists()) {
      throw new Error("store already exists");
    }
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const dek = crypto.getRandomValues(new Uint8Array(DEK_BYTES));
    const kek = deriveKek(passphrase, salt, params);
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const ct = xchacha20poly1305(kek, nonce, new TextEncoder().encode("meridian-edge-dek")).encrypt(dek);
    kek.fill(0);
    const meta: MetaRecord = {
      version: STORE_VERSION,
      salt,
      params,
      wrappedDek: { nonce, ct },
    };
    await this.writeRaw(META_KEY, meta);
    this.dek = dek;
  }

  /** Returns false on a wrong passphrase; throws if no store exists. */
  async unlock(passphrase: string): Promise<boolean> {
    const meta = (await this.readRaw(META_KEY)) as MetaRecord | undefined;
    if (meta === undefined) {
      throw new Error("no store exists");
    }
    const kek = deriveKek(passphrase, meta.salt, meta.params);
    try {
      this.dek = xchacha20poly1305(kek, meta.wrappedDek.nonce, new TextEncoder().encode("meridian-edge-dek")).decrypt(
        meta.wrappedDek.ct,
      );
      return true;
    } catch {
      return false;
    } finally {
      kek.fill(0);
    }
  }

  lock(): void {
    if (this.dek !== null) {
      this.dek.fill(0);
      this.dek = null;
    }
  }

  private requireDek(): Uint8Array {
    if (this.dek === null) {
      throw new StoreLockedError();
    }
    return this.dek;
  }

  async putBytes(key: string, value: Uint8Array): Promise<void> {
    const dek = this.requireDek();
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const ct = xchacha20poly1305(dek, nonce, new TextEncoder().encode(key)).encrypt(value);
    const record: WrappedRecord = { nonce, ct };
    await this.writeRaw(key, record);
  }

  async getBytes(key: string): Promise<Uint8Array | null> {
    const dek = this.requireDek();
    const record = (await this.readRaw(key)) as WrappedRecord | undefined;
    if (record === undefined) {
      return null;
    }
    return xchacha20poly1305(dek, record.nonce, new TextEncoder().encode(key)).decrypt(record.ct);
  }

  async putJson(key: string, value: unknown): Promise<void> {
    await this.putBytes(key, new TextEncoder().encode(JSON.stringify(value)));
  }

  async getJson<T>(key: string): Promise<T | null> {
    const bytes = await this.getBytes(key);
    if (bytes === null) {
      return null;
    }
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  }

  async deleteKey(key: string): Promise<void> {
    const db = await this.openDb();
    try {
      const tx = db.transaction(STORE_NAME, "readwrite");
      await request(tx.objectStore(STORE_NAME).delete(key));
    } finally {
      db.close();
    }
  }

  async listKeys(prefix: string): Promise<string[]> {
    const db = await this.openDb();
    try {
      const tx = db.transaction(STORE_NAME, "readonly");
      const keys = await request(tx.objectStore(STORE_NAME).getAllKeys());
      return keys
        .filter((k): k is string => typeof k === "string")
        .filter((k) => k !== META_KEY && k !== PREFS_KEY && k.startsWith(prefix));
    } finally {
      db.close();
    }
  }

  /** Verifies the old passphrase, then re-wraps the DEK only (§2.4). */
  async rotatePassphrase(oldPassphrase: string, newPassphrase: string): Promise<boolean> {
    const meta = (await this.readRaw(META_KEY)) as MetaRecord | undefined;
    if (meta === undefined) {
      throw new Error("no store exists");
    }
    const oldKek = deriveKek(oldPassphrase, meta.salt, meta.params);
    let dek: Uint8Array;
    try {
      dek = xchacha20poly1305(oldKek, meta.wrappedDek.nonce, new TextEncoder().encode("meridian-edge-dek")).decrypt(
        meta.wrappedDek.ct,
      );
    } catch {
      return false;
    } finally {
      oldKek.fill(0);
    }
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const newKek = deriveKek(newPassphrase, salt, meta.params);
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const ct = xchacha20poly1305(newKek, nonce, new TextEncoder().encode("meridian-edge-dek")).encrypt(dek);
    newKek.fill(0);
    const next: MetaRecord = {
      version: meta.version,
      salt,
      params: meta.params,
      wrappedDek: { nonce, ct },
    };
    await this.writeRaw(META_KEY, next);
    if (this.dek === null) {
      dek.fill(0);
    } else {
      // Zeroize the superseded in-memory copy before dropping it for GC.
      const previous = this.dek;
      this.dek = dek;
      previous.fill(0);
    }
    return true;
  }

  /** Best-effort overwrite of every record, then database deletion (§2 /wipe). */
  async wipe(): Promise<void> {
    this.lock();
    const db = await this.openDb();
    try {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const keys = await request(store.getAllKeys());
      for (const key of keys) {
        await request(store.put(crypto.getRandomValues(new Uint8Array(64)), key));
      }
      for (const key of keys) {
        await request(store.delete(key));
      }
    } finally {
      db.close();
    }
    await new Promise<void>((resolve, reject) => {
      const req = this.idb.deleteDatabase(this.dbName);
      req.onsuccess = () => resolve();
      req.onblocked = () => resolve();
      req.onerror = () => reject(req.error ?? new Error("delete failed"));
    });
  }
}
