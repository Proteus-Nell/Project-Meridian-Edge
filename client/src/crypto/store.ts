// Encrypted local key store.
//
// Everything in IndexedDB is ciphertext: a random 256-bit DEK encrypts every
// record with XChaCha20-Poly1305 (random 24-byte nonce per write, record key
// as associated data). A KEK, which Argon2id derives from the unlock
// passphrase, then wraps the DEK. Changing the passphrase re-wraps only the
// DEK. Locking zeroizes the DEK, best effort, as JS allows.
//
// The meta record also carries the DURESS envelope: a second, independent
// sealed blob whose key is derived from the duress passphrase (own salt, same
// Argon2id parameters). It is NOT a second wrapper around the DEK - it holds
// only the small payload the purge needs to authenticate its own deletion, so
// cracking it does not open the message history. See armDuress.

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

// Stored beside the ciphertext so parameters can be upgraded later.
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

const DEK_AD = "meridian-edge-dek";
const DURESS_AD = "meridian-edge-duress";
const POLY1305_TAG_BYTES = 16;
/** Duress payloads are zero-padded to a fixed size before sealing, so the
 * envelope is one constant length whatever it carries - and so the disarmed
 * decoy (random bytes of exactly this length) is indistinguishable from a real
 * one. Sized to clear an ML-DSA-65 secret key plus its JSON framing. */
const DURESS_PAYLOAD_BYTES = 8192;
const DURESS_LENGTH_PREFIX_BYTES = 4;
const DURESS_CT_BYTES = DURESS_PAYLOAD_BYTES + POLY1305_TAG_BYTES;

interface WrappedRecord {
  readonly nonce: Uint8Array;
  readonly ct: Uint8Array;
}

/** The duress envelope: its own salt (the passphrase is not the unlock one) and
 * a fixed-length sealed blob. Present on every store created since the feature
 * shipped, holding random bytes while disarmed. */
interface DuressRecord {
  readonly salt: Uint8Array;
  readonly nonce: Uint8Array;
  readonly ct: Uint8Array;
}

interface MetaRecord {
  readonly version: number;
  readonly salt: Uint8Array;
  readonly params: Argon2Params;
  readonly wrappedDek: WrappedRecord;
  /** Absent only on stores created before the duress feature existed. */
  readonly duress?: DuressRecord;
}

/** A decoy duress envelope: uniform random bytes in every field, the exact
 * shape and size a real one has. No passphrase can ever open it (AEAD over
 * random bytes never authenticates), and nothing about it says "disarmed". */
function decoyDuress(): DuressRecord {
  return {
    salt: crypto.getRandomValues(new Uint8Array(SALT_BYTES)),
    nonce: crypto.getRandomValues(new Uint8Array(NONCE_BYTES)),
    ct: crypto.getRandomValues(new Uint8Array(DURESS_CT_BYTES)),
  };
}

/** Length-prefix and zero-pad a payload to the fixed sealed size. */
function padDuressPayload(payload: Uint8Array): Uint8Array {
  if (payload.length > DURESS_PAYLOAD_BYTES - DURESS_LENGTH_PREFIX_BYTES) {
    throw new Error("duress payload too large");
  }
  const padded = new Uint8Array(DURESS_PAYLOAD_BYTES);
  new DataView(padded.buffer).setUint32(0, payload.length, false);
  padded.set(payload, DURESS_LENGTH_PREFIX_BYTES);
  return padded;
}

/** Inverse of padDuressPayload; null if the length prefix is not sane, which
 * means the blob authenticated but was not written by armDuress. */
function unpadDuressPayload(padded: Uint8Array): Uint8Array | null {
  if (padded.length !== DURESS_PAYLOAD_BYTES) {
    return null;
  }
  const length = new DataView(padded.buffer, padded.byteOffset).getUint32(0, false);
  if (length > DURESS_PAYLOAD_BYTES - DURESS_LENGTH_PREFIX_BYTES) {
    return null;
  }
  return padded.slice(DURESS_LENGTH_PREFIX_BYTES, DURESS_LENGTH_PREFIX_BYTES + length);
}

import {
  COLOR_SLOTS,
  DEFAULT_ACCESSIBILITY,
  DEFAULT_EMBLEM,
  DEFAULT_FONT,
  DEFAULT_FONT_SIZE,
  DEFAULT_LETTER_SPACING,
  DEFAULT_LINE_HEIGHT,
  DEFAULT_SCHEME,
  FORK_SUFFIX,
  clampFontSize,
  clampLetterSpacing,
  clampLineHeight,
  isEmblemName,
  isFontName,
  isValidCustomSchemeName,
  isSchemeName,
  normalizeHex,
  sanitizeCustomSchemes,
  schemeColorsOf,
  schemeExists,
} from "../terminal/theme";
import type {
  AccessibilityPrefs,
  CustomScheme,
  EmblemName,
  FontName,
  SchemeColors,
} from "../terminal/theme";

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
  /** Active color scheme (/settings scheme): a preset name or one of
   * customSchemes. */
  readonly scheme: string;
  /** Medallion glyph (/settings emblem). */
  readonly emblemGlyph: EmblemName;
  /** Stamp each conversation line with the time it was sent or received, and
   * open each new day with a dated divider (/settings timestamps). On by
   * default: a transcript that says only what was said, and never when, is the
   * harder one to reason about after the fact. Purely local presentation -
   * nothing here is transmitted, and both readings come from the message
   * record's own `ts`. */
  readonly messageTimestamps: boolean;
  /** Monospace stack (/settings font) and its size in px (/settings fontsize).
   * A name from the fixed allowlist, never a raw family string. */
  readonly font: FontName;
  readonly fontSize: number;
  /** Extra px between characters, and the line box as a multiple of the font
   * size (/settings spacing). Readability controls; see theme.ts. */
  readonly letterSpacing: number;
  readonly lineHeight: number;
  /** Opt-in accessibility switches (/settings a11y). */
  readonly accessibility: AccessibilityPrefs;
  /** User-defined schemes (/settings scheme new, /settings color). An array,
   * not a name-keyed object: this record is untrusted input and a keyed one
   * would give a hand-written "__proto__" entry a path into Object.prototype.
   * Validated on every read by theme.ts::sanitizeCustomSchemes. */
  readonly customSchemes: readonly CustomScheme[];
}

// The emblem watermark is ON out of the box, so the medallion
// (theme.ts::DEFAULT_EMBLEM) is actually seen on a first run rather than
// waiting behind a setting nobody knows to look for. It sits behind the text at
// low opacity and pauses while idle, so it costs the transcript nothing.
// Scanlines, vignette and dock stay OFF: those restyle the terminal itself, and
// a plain terminal is still the right thing to meet first. All four are
// /settings theme.
const DEFAULT_THEME: ThemePrefs = { emblem: true, scanlines: false, vignette: false, dock: false };

const DEFAULT_PREFS: DisplayPrefs = {
  // Passphrase entry echoes nothing by default (sudo-style); /settings mask
  // asterisk opts into one '*' per character, which leaks length.
  secretMask: "hidden",
  theme: DEFAULT_THEME,
  scheme: DEFAULT_SCHEME,
  emblemGlyph: DEFAULT_EMBLEM,
  messageTimestamps: true,
  font: DEFAULT_FONT,
  fontSize: DEFAULT_FONT_SIZE,
  letterSpacing: DEFAULT_LETTER_SPACING,
  lineHeight: DEFAULT_LINE_HEIGHT,
  accessibility: DEFAULT_ACCESSIBILITY,
  customSchemes: [],
};

/** Carry a pre-custom-schemes prefs record forward. `colorOverrides` used to be
 * a single slot map smeared over whichever preset was active - the very thing
 * that made presets un-revertable. Anything set there becomes a real custom
 * scheme forked from the preset it was sitting on, so the user's colors survive
 * the upgrade and the preset goes back to being pristine. */
function migrateLegacyOverrides(
  scheme: string,
  raw: Record<string, unknown> | undefined,
): { scheme: string; customSchemes: CustomScheme[] } | null {
  if (raw === undefined) {
    return null;
  }
  const base = isSchemeName(scheme) ? scheme : DEFAULT_SCHEME;
  const colors: SchemeColors = schemeColorsOf(base, []);
  let changed = false;
  for (const slot of COLOR_SLOTS) {
    const value = raw[slot];
    const hex = typeof value === "string" ? normalizeHex(value) : null;
    if (hex !== null) {
      colors[slot] = hex;
      changed = true;
    }
  }
  if (!changed) {
    return null; // an empty override map is just the pure preset
  }
  const name = `${base}${FORK_SUFFIX}`;
  return isValidCustomSchemeName(name)
    ? { scheme: name, customSchemes: [{ name, base, colors }] }
    : null;
}

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
    // Default derivation cost for create(); overridable so tests can use fast
    // parameters for flows (like /recover) that create the store internally.
    private readonly defaultParams: Argon2Params = DEFAULT_ARGON2_PARAMS,
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
          messageTimestamps?: unknown;
          font?: unknown;
          fontSize?: unknown;
          letterSpacing?: unknown;
          lineHeight?: unknown;
          accessibility?: Partial<Record<keyof AccessibilityPrefs, unknown>>;
          customSchemes?: unknown;
          /** Retired in favour of customSchemes; still read once, to migrate. */
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
    const emblemGlyph =
      typeof raw.emblemGlyph === "string" && isEmblemName(raw.emblemGlyph)
        ? raw.emblemGlyph
        : DEFAULT_PREFS.emblemGlyph;
    // Absent means a record written before this setting existed, which is the
    // same thing as never having chosen: the default applies.
    const messageTimestamps =
      typeof raw.messageTimestamps === "boolean"
        ? raw.messageTimestamps
        : DEFAULT_PREFS.messageTimestamps;
    const storedScheme = typeof raw.scheme === "string" ? raw.scheme : DEFAULT_PREFS.scheme;
    let customSchemes = sanitizeCustomSchemes(raw.customSchemes);
    let scheme = storedScheme;
    if (customSchemes.length === 0) {
      const migrated = migrateLegacyOverrides(storedScheme, raw.colorOverrides);
      if (migrated !== null) {
        ({ scheme, customSchemes } = migrated);
      }
    }
    const font =
      typeof raw.font === "string" && isFontName(raw.font) ? raw.font : DEFAULT_FONT;
    const fontSize =
      typeof raw.fontSize === "number" ? clampFontSize(raw.fontSize) : DEFAULT_FONT_SIZE;
    const letterSpacing =
      typeof raw.letterSpacing === "number"
        ? clampLetterSpacing(raw.letterSpacing)
        : DEFAULT_LETTER_SPACING;
    const lineHeight =
      typeof raw.lineHeight === "number" ? clampLineHeight(raw.lineHeight) : DEFAULT_LINE_HEIGHT;
    const accessibility: AccessibilityPrefs = {
      screenReader:
        typeof raw.accessibility?.screenReader === "boolean"
          ? raw.accessibility.screenReader
          : DEFAULT_ACCESSIBILITY.screenReader,
      reduceMotion:
        typeof raw.accessibility?.reduceMotion === "boolean"
          ? raw.accessibility.reduceMotion
          : DEFAULT_ACCESSIBILITY.reduceMotion,
    };
    // A scheme that no longer exists (deleted, or dropped by validation) must
    // not leave the page unpainted.
    return {
      secretMask: mask,
      theme,
      scheme: schemeExists(scheme, customSchemes) ? scheme : DEFAULT_SCHEME,
      emblemGlyph,
      messageTimestamps,
      font,
      fontSize,
      letterSpacing,
      lineHeight,
      accessibility,
      customSchemes,
    };
  }

  async setDisplayPrefs(prefs: DisplayPrefs): Promise<void> {
    await this.writeRaw(PREFS_KEY, prefs);
  }

  isUnlocked(): boolean {
    return this.dek !== null;
  }

  async create(passphrase: string, params: Argon2Params = this.defaultParams): Promise<void> {
    if (await this.exists()) {
      throw new Error("store already exists");
    }
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const dek = crypto.getRandomValues(new Uint8Array(DEK_BYTES));
    const kek = deriveKek(passphrase, salt, params);
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const ct = xchacha20poly1305(kek, nonce, new TextEncoder().encode(DEK_AD)).encrypt(dek);
    kek.fill(0);
    const meta: MetaRecord = {
      version: STORE_VERSION,
      salt,
      params,
      wrappedDek: { nonce, ct },
      // Written from the start, holding random bytes: a store with the duress
      // passphrase disarmed must look exactly like one with it armed.
      duress: decoyDuress(),
    };
    await this.writeRaw(META_KEY, meta);
    this.dek = dek;
  }

  private async readMeta(): Promise<MetaRecord> {
    const meta = (await this.readRaw(META_KEY)) as MetaRecord | undefined;
    if (meta === undefined) {
      throw new Error("no store exists");
    }
    return meta;
  }

  /** Unwrap the DEK with `passphrase`, or null when it is not the unlock
   * passphrase. Shared by unlock, rotatePassphrase and isPrimaryPassphrase so
   * all three agree on what "the right passphrase" means. */
  private unwrapDek(passphrase: string, meta: MetaRecord): Uint8Array | null {
    const kek = deriveKek(passphrase, meta.salt, meta.params);
    try {
      return xchacha20poly1305(
        kek,
        meta.wrappedDek.nonce,
        new TextEncoder().encode(DEK_AD),
      ).decrypt(meta.wrappedDek.ct);
    } catch {
      return null;
    } finally {
      kek.fill(0);
    }
  }

  /** Returns false on a wrong passphrase; throws if no store exists. */
  async unlock(passphrase: string): Promise<boolean> {
    const dek = this.unwrapDek(passphrase, await this.readMeta());
    if (dek === null) {
      return false;
    }
    this.dek = dek;
    return true;
  }

  /** True when `candidate` is this store's unlock passphrase. Used to refuse a
   * duress passphrase that is simply the real one, which would turn a login
   * into an unannounced wipe. Nothing is unlocked and no state changes. */
  async isPrimaryPassphrase(candidate: string): Promise<boolean> {
    const dek = this.unwrapDek(candidate, await this.readMeta());
    if (dek === null) {
      return false;
    }
    dek.fill(0);
    return true;
  }

  // ----- duress envelope -----------------------------------------------------

  /** Seal `payload` under a key derived from `passphrase`, replacing whatever
   * the duress envelope held. The payload is padded to a constant size, so the
   * stored record is byte-for-byte the same shape as the disarmed decoy.
   *
   * Deliberately independent of the DEK: arming does not create a second key
   * to the vault, only to this one small blob. Whatever the caller seals here
   * is readable by anyone who guesses the duress passphrase, so it must hold
   * the minimum the purge needs and nothing more. */
  async armDuress(passphrase: string, payload: Uint8Array): Promise<void> {
    const meta = await this.readMeta();
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const kek = deriveKek(passphrase, salt, meta.params);
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const padded = padDuressPayload(payload);
    const ct = xchacha20poly1305(kek, nonce, new TextEncoder().encode(DURESS_AD)).encrypt(padded);
    kek.fill(0);
    padded.fill(0);
    await this.writeRaw(META_KEY, { ...meta, duress: { salt, nonce, ct } } satisfies MetaRecord);
  }

  /** Overwrite the duress envelope with a fresh decoy. Indistinguishable from
   * arming to anyone reading the database. */
  async disarmDuress(): Promise<void> {
    const meta = await this.readMeta();
    await this.writeRaw(META_KEY, { ...meta, duress: decoyDuress() } satisfies MetaRecord);
  }

  /** The sealed payload when `passphrase` is the duress passphrase, else null.
   * Costs exactly one Argon2id derivation whether or not the feature is armed
   * (a store predating it derives against a throwaway salt), so the work done
   * on a failed unlock never says which. */
  async tryDuress(passphrase: string): Promise<Uint8Array | null> {
    const meta = await this.readMeta();
    const record = meta.duress ?? decoyDuress();
    const kek = deriveKek(passphrase, record.salt, meta.params);
    try {
      return unpadDuressPayload(
        xchacha20poly1305(kek, record.nonce, new TextEncoder().encode(DURESS_AD)).decrypt(
          record.ct,
        ),
      );
    } catch {
      return null;
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

  /** Verifies the old passphrase, then re-wraps the DEK only. The duress
   * envelope has its own salt and key and is carried across untouched: rotating
   * the unlock passphrase leaves the duress one exactly as it was. */
  async rotatePassphrase(oldPassphrase: string, newPassphrase: string): Promise<boolean> {
    const meta = await this.readMeta();
    const dek = this.unwrapDek(oldPassphrase, meta);
    if (dek === null) {
      return false;
    }
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const newKek = deriveKek(newPassphrase, salt, meta.params);
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const ct = xchacha20poly1305(newKek, nonce, new TextEncoder().encode(DEK_AD)).encrypt(dek);
    newKek.fill(0);
    const next: MetaRecord = { ...meta, salt, wrappedDek: { nonce, ct } };
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

  /** Best-effort overwrite of every record, then database deletion (/wipe). */
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
