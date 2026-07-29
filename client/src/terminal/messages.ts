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
//
// House style for every message here: plain sentences, and say what to do.
// State the problem, then the action, as two sentences rather than joining
// them with a dash. "Server might be temporarily down. Please contact the host
// or try again." reads as help; "request failed - is the server running?"
// reads as a log line. Sentence case, no trailing period omitted, and no dash
// used as a connector anywhere in the catalog.

export const ERRORS = {
  // E1xx input / command usage. E101/E102 pass the parser's own composed
  // detail through; the code marks the family, the text stays specific.
  E101: (detail: string) => detail, // unknown command: /<word>
  E102: (detail: string) => detail, // bad arguments for a known command
  E103: () =>
    "That UID is not valid. It should be 26 characters; dashes and capitalisation do not matter.",
  E104: () =>
    "That recovery code is not valid. It should be 16 characters; dashes, spaces and capitalisation do not matter.",
  E105: () => "Unknown benchmark suite. Choose b1, b2, b3, b4, or all, or leave it out to run everything.",
  // E106-E109 cover the color-scheme namespace, where presets and user-defined
  // schemes share one set of names.
  E106: (name: string) =>
    `There is no color scheme called '${name}'. Run /settings scheme list to see the ones you can switch to.`,
  E107: (name: string) =>
    `'${name}' cannot be used as a scheme name. Use 1 to 24 characters starting with a letter, and avoid the preset names and the words new, delete, list and reset.`,
  E108: (max: number) =>
    `You already have the maximum of ${max} custom schemes. Run /settings scheme delete <name> to free a slot.`,
  E109: (name: string) =>
    `A scheme called '${name}' already exists. Choose another name, or switch to it and use /settings color to change it.`,

  // E2xx authentication, session, identity
  E201: () => "You are not logged in. Please run /login first.",
  E202: () => "Your session has expired. Please run /login again.",
  // Deliberately says nothing beyond the failure. This is also what a duress
  // passphrase prints (executor/duress.ts), so it must read exactly like an
  // ordinary mistyped passphrase.
  E203: () => "Unlock failed. Please check your passphrase and try again.",
  E204: () =>
    "There is no identity on this device. Run /register to create one, or /recover to bring an existing account here.",
  E205: () =>
    "Recovery failed. The UID or the code was not accepted, so check both and try another saved code.",
  E206: (min: number) =>
    `That passphrase is too short. Please use at least ${min} characters.`,
  E207: () => "The two passphrases did not match. Please run the command again.",
  E208: () => "Rotation failed. The current passphrase was not correct.",
  E209: () => "That passphrase needs at least one number and one symbol.",
  // The server's 401 is deliberately uniform (unknown UID, wrong key, and a
  // stale nonce are indistinguishable), so this names the likely cause without
  // claiming the server said which.
  E210: () =>
    "The server does not recognise this device's identity key. This usually means /recover was run on another device, which replaces the account key. Run /recover here with one of the new codes, or try again in case the login challenge simply expired.",
  // Guards both directions: arming a duress passphrase that is already the
  // unlock one, and rotating the unlock passphrase onto the armed duress one.
  // Either would make every ordinary login a silent, unannounced wipe.
  E211: () =>
    "That is already this device's unlock passphrase. Your duress passphrase must be a different one, otherwise every login would silently destroy the account.",

  // E3xx network / server responses
  E301: () => "Rate limit reached. Please wait a few minutes and try again.",
  E302: () => "Server might be temporarily down. Please contact the host or try again.",
  E303: () => "Those keys are unavailable. That UID may not exist on this server.",
  E304: () =>
    "The recipient's keys are unavailable. That UID may not exist, or they may not have published any prekeys yet.",

  // E4xx local encrypted store
  E401: () => "The store is locked. Please run /login to unlock it.",
  E402: () =>
    "The store is damaged and holds no identity record. Run /wipe, then /register or /recover.",
  E403: () => "Contacts are kept in the encrypted store. Please run /login first.",
  E404: () => "Settings are kept in the encrypted store. Please run /login first.",
  E405: () => "The trust setting is kept in the encrypted store. Please run /login first.",
  E406: () => "The duress passphrase is sealed with the store. Please run /login first.",

  // E5xx contacts, messaging, decryption
  E501: (target: string) =>
    `There is no contact called '${target}'. Run /contacts to see the ones you have saved, or /add <uid> [alias] to add this one.`,
  E502: (alias: string) =>
    `No identity key is known for ${alias} yet. Please run /verify ${alias} first.`,
  E503: (alias: string) =>
    `${alias} has an unacknowledged key change. Run /ack ${alias}, then verify them again.`,
  E504: () => "That message is too large to send. Please shorten it and try again.",
  // E505/E511/E512 are the inbound-discard family. They are shown in the
  // discarded-notice panel rather than inline (chrome.noteDiscarded), because
  // they describe something that happened TO you, not a command that failed.
  // A first-time contact never lands here: that handshake succeeds and shows
  // as a contact request. These mean a session or prekey mismatch instead.
  E505: () =>
    "Someone sent you a message this device cannot read, because the shared session for that conversation is gone from here. That happens after removing a contact, /wipe, or /recover. Message them first with /chat <alias> to set up a fresh handshake.",
  E506: () => "A message was discarded because its contents were not valid.",
  E507: () => "A malformed message was discarded.",
  E508: () => "The sender's identity could not be verified, so their message was discarded.",
  E509: () =>
    "An incoming message could not be processed. It is still waiting on the server, so run /login again to fetch it.",
  E510: (alias: string) =>
    `The name '${alias}' already belongs to another contact. Please choose a different one.`,
  E511: () =>
    "Someone is trying to start a conversation using sign-up keys this device no longer has, which usually follows a /recover or /wipe. Ask them to /remove you and message again so their app picks up your current keys.",
  E512: () => "A damaged or tampered message was discarded.",
  E513: () =>
    "A group message was discarded because it did not add up: it came from someone who is not a contact, or its member list did not include both you and the sender.",

  // E514-E519 cover the /group surface.
  E514: (name: string) =>
    `There is no group called '${name}' on this device. Run /group list to see the ones you have.`,
  E515: (name: string) =>
    `'${name}' cannot be used as a group name. Use 1 to 32 characters: letters, digits, spaces, underscores or hyphens.`,
  E516: (name: string) =>
    `You already have a group called '${name}'. Choose another name so the two can be told apart.`,
  E517: () => "A group needs at least one other member. Name the contacts to include.",
  E518: (max: number) =>
    `A group can hold at most ${max} members. Every message is sent separately to each one, so the limit keeps a single message from becoming a flood.`,
  E519: (target: string, group: string) => `${target} is not a member of '${group}'.`,

  // E599 the last-resort catch-all for anything unclassified
  E599: () => "Something went wrong. Please try again.",
} as const;

export type ErrorCode = keyof typeof ERRORS;

export const ERROR_CODES = Object.keys(ERRORS) as readonly ErrorCode[];
