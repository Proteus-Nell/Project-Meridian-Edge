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
  E105: () => "unknown suite - use b1, b2, b3, or omit for all",

  // E2xx authentication, session, identity
  E201: () => "not logged in - /login first",
  E202: () => "session expired or invalid - /login again",
  E203: () => "unlock failed",
  E204: () => "no identity on this device - /register first",
  E205: () => "recovery failed - unknown UID or invalid recovery code",
  E206: (min: number) => `passphrase must be at least ${min} characters`,
  E207: () => "passphrases do not match",
  E208: () => "rotation failed",

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

  // E5xx contacts, messaging, decryption
  E501: (target: string) => `unknown contact: ${target} - /add <uid> [alias] first`,
  E502: (alias: string) => `no known identity key for ${alias} yet - /verify first`,
  E503: (alias: string) =>
    `${alias} has an unacknowledged key change - /ack ${alias} first, then /verify again`,
  E504: () => "message too large after encryption - not sent",
  E505: (reason: string) => `discarded undecryptable message (${reason})`,
  E506: () => "discarded message with malformed payload",
  E507: () => "discarded malformed message",
  E508: () => "could not verify sender identity - message discarded",
  E509: () => "failed to process an incoming message",
  E510: (alias: string) =>
    `the name '${alias}' is already used by another contact - choose a different alias`,

  // E599 the last-resort catch-all for anything unclassified
  E599: () => "operation failed",
} as const;

export type ErrorCode = keyof typeof ERRORS;

export const ERROR_CODES = Object.keys(ERRORS) as readonly ErrorCode[];
