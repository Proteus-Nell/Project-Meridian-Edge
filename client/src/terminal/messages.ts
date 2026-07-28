// The error-message catalog: every user-facing failure has a stable E-code
// and one canonical text builder, rendered as `[E###] text` (no glyph) by
// Renderer.error. Codes are grouped by cause family:
//
//   E1xx  input / command usage
//   E2xx  authentication, session, identity
//   E3xx  network / server responses
//   E4xx  local encrypted store
//   E5xx  contacts, messaging, decryption
//
// docs/MESSAGES.md is the human table (message, cause, remedy) and a drift
// test (messages.test.ts) fails the build when the two disagree. Codes are
// append-only: never renumber a shipped code, retire it instead.
//
// Warnings, security events, and info lines keep their glyph prefixes and
// are catalogued in the same table without codes.

export const ERRORS = {
  // E1xx input / command usage. E101/E102 pass the parser's own composed
  // detail through; the code marks the family, the text stays specific.
  E101: (detail: string) => detail, // unknown command: /<word>
  E102: (detail: string) => detail, // bad arguments for a known command
  E103: () => "invalid UID (26 Crockford Base32 chars, dashes optional)",
  E104: () => "invalid recovery code (16 Crockford Base32 chars, dashes optional)",
  E105: () => "unknown suite - use b1, b2, b3, b4, or all (omit for all)",
  // E106-E109 cover the color-scheme namespace, where presets and user-defined
  // schemes share one set of names.
  E106: (name: string) => `unknown color scheme: ${name} - /settings scheme list shows them all`,
  E107: (name: string) =>
    `'${name}' cannot name a custom scheme - use 1-24 characters (a letter, then letters, digits or hyphens) that is not a preset or one of 'new', 'delete', 'list', 'reset'`,
  E108: (max: number) =>
    `custom scheme limit reached (${max}) - /settings scheme delete <name> frees a slot`,
  E109: (name: string) =>
    `a scheme named '${name}' already exists - pick another name, or /settings scheme ${name} then /settings color to edit it`,

  // E2xx authentication, session, identity
  E201: () => "not logged in - /login first",
  E202: () => "session expired or invalid - /login again",
  E203: () => "unlock failed",
  E204: () => "no identity on this device - /register first",
  E205: () => "recovery failed - unknown UID or invalid recovery code",
  E206: (min: number) => `passphrase must be at least ${min} characters`,
  E207: () => "passphrases do not match",
  E208: () => "rotation failed",
  E209: () => "passphrase must include at least one number and one symbol",
  // The server's 401 is deliberately uniform (unknown UID, wrong key, and a
  // stale nonce are indistinguishable), so this names the likely cause without
  // claiming the server said which.
  E210: () =>
    "login rejected - the server does not recognise this device's identity key. If you ran /recover on another device, that replaced the account's key: run /recover here with one of the new codes. Otherwise retry, in case the login challenge expired",
  // Guards both directions: arming a duress passphrase that is already the
  // unlock one, and rotating the unlock passphrase onto the armed duress one.
  // Either would make every ordinary login a silent, unannounced wipe.
  E211: () =>
    "that is already this device's unlock passphrase - a duress passphrase must be different, or every login would silently destroy the account",

  // E3xx network / server responses
  E301: () => "rate limit reached - try again later",
  E302: () => "request failed - is the server running?",
  E303: () => "recipient keys unavailable - unknown UID",
  E304: () => "recipient keys unavailable - unknown UID or no prekeys published",

  // E4xx local encrypted store
  E401: () => "store is locked - /login to unlock",
  E402: () => "store is corrupt: no identity record",
  E403: () => "contacts live in the encrypted store - /login first",
  E404: () => "store is locked - /login first (settings live encrypted)",
  E405: () => "store is locked - /login first (trust setting lives encrypted)",
  E406: () => "store is locked - /login first (the duress passphrase is sealed with the store)",

  // E5xx contacts, messaging, decryption
  E501: (target: string) => `unknown contact: ${target} - /add <uid> [alias] first`,
  E502: (alias: string) => `no known identity key for ${alias} yet - /verify first`,
  E503: (alias: string) =>
    `${alias} has an unacknowledged key change - /ack ${alias} first, then /verify again`,
  E504: () => "message too large after encryption - not sent",
  // E505/E511/E512 are the inbound-discard family. They are shown in the
  // discarded-notice panel rather than inline (chrome.noteDiscarded), because
  // they describe something that happened TO you, not a command that failed.
  // A first-time contact never lands here: that handshake succeeds and shows
  // as a contact request. These mean a session or prekey mismatch instead.
  E505: () =>
    "someone sent you a message this device cannot read - the shared session for that conversation is gone here (removed contact, /wipe, or /recover). Message them first with /chat <alias> to set up a fresh handshake",
  E506: () => "discarded message with malformed payload",
  E507: () => "discarded malformed message",
  E508: () => "could not verify sender identity - message discarded",
  E509: () => "failed to process an incoming message",
  E510: (alias: string) =>
    `the name '${alias}' is already used by another contact - choose a different alias`,
  E511: () =>
    "someone is trying to start a conversation with you, but used sign-up keys this device no longer has (usually after /recover or /wipe). Ask them to /remove you and message again so their app picks up your current keys",
  E512: () => "a damaged or tampered incoming message was discarded",

  // E599 the last-resort catch-all for anything unclassified
  E599: () => "operation failed",
} as const;

export type ErrorCode = keyof typeof ERRORS;

export const ERROR_CODES = Object.keys(ERRORS) as readonly ErrorCode[];
