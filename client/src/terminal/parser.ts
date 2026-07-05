// Command parser (CLAUDE.md §1.2): a line starting with "/" is tokenized
// against a static allowlist; anything else is message text for the active
// conversation. The parser is total — it never throws on any input — and
// returns a typed discriminated union consumed by a switch in the executor.

import { CROCKFORD_ALPHABET, UID_CHARS } from "../crypto/constants";

export type DurationUnit = "m" | "h" | "d" | "w";

export type Duration =
  | { readonly kind: "off" }
  | { readonly kind: "for"; readonly amount: number; readonly unit: DurationUnit };

export const WEEKDAYS = [
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
  "sunday",
] as const;
export type Weekday = (typeof WEEKDAYS)[number];

export type RotationSetting =
  | { readonly kind: "on" }
  | { readonly kind: "off" }
  | { readonly kind: "day"; readonly day: Weekday };

export type Command =
  | { readonly name: "register" }
  | { readonly name: "login" }
  | { readonly name: "logout" }
  | { readonly name: "lock" }
  | { readonly name: "whoami" }
  | { readonly name: "add"; readonly uid: string; readonly alias: string | undefined }
  | { readonly name: "chat"; readonly target: string }
  | { readonly name: "verify"; readonly alias: string }
  | { readonly name: "verified"; readonly alias: string }
  | { readonly name: "ack"; readonly alias: string }
  | { readonly name: "timer"; readonly alias: string; readonly duration: Duration }
  | { readonly name: "purge-set"; readonly duration: Duration }
  | { readonly name: "purge-now"; readonly alias: string | undefined }
  | { readonly name: "rotate-passphrase" }
  | { readonly name: "settings-rotation"; readonly setting: RotationSetting }
  | { readonly name: "settings-notify"; readonly enabled: boolean }
  | { readonly name: "settings-mask"; readonly mask: "asterisk" | "hidden" }
  | { readonly name: "keys-status" }
  | { readonly name: "keys-refill" }
  | { readonly name: "bench"; readonly suite: string | undefined }
  | { readonly name: "wipe" }
  | { readonly name: "help"; readonly topic: CommandWord | undefined };

export type CommandName = Command["name"];

export type ParseResult =
  | { readonly kind: "empty" }
  | { readonly kind: "message"; readonly text: string }
  | { readonly kind: "command"; readonly command: Command }
  | { readonly kind: "invalid"; readonly error: string; readonly usage: string | undefined };

// The static allowlist: every slash word the terminal accepts, with usage.
// No dynamic dispatch happens off this map — it gates membership only.
export const COMMAND_USAGE = {
  register: "/register",
  login: "/login",
  logout: "/logout",
  lock: "/lock",
  whoami: "/whoami",
  add: "/add <uid> [alias]",
  chat: "/chat <alias|uid>",
  verify: "/verify <alias>",
  verified: "/verified <alias>",
  ack: "/ack <alias>",
  timer: "/timer <alias> <duration|off>  (duration: 30m, 1h, 1d, 1w, ...)",
  purge: "/purge set <duration|off>  |  /purge now [alias]",
  rotate: "/rotate passphrase",
  settings:
    "/settings rotation <on|off|day <weekday>>  |  /settings notify <on|off>  |  /settings mask <asterisk|hidden>",
  keys: "/keys status  |  /keys refill",
  bench: "/bench [suite]",
  wipe: "/wipe",
  help: "/help [command]",
} as const;

export type CommandWord = keyof typeof COMMAND_USAGE;

export function isCommandWord(word: string): word is CommandWord {
  return Object.prototype.hasOwnProperty.call(COMMAND_USAGE, word);
}

const ALIAS_RE = /^[A-Za-z0-9_-]{1,32}$/;
const DURATION_RE = /^(\d{1,4})([mhdw])$/;
const SUITE_RE = /^[A-Za-z0-9_-]{1,16}$/;

/** Canonicalize a UID: strip dashes, uppercase, Crockford ambiguity mapping
 * (O→0, I/L→1). Returns null unless exactly 26 canonical chars remain. */
export function normalizeUid(raw: string): string | null {
  const cleaned = raw
    .toUpperCase()
    .replace(/-/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  if (cleaned.length !== UID_CHARS) {
    return null;
  }
  for (const ch of cleaned) {
    if (!CROCKFORD_ALPHABET.includes(ch)) {
      return null;
    }
  }
  return cleaned;
}

/** Group a canonical 26-char UID for display: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX. */
export function formatUid(uid: string): string {
  const groups: string[] = [];
  for (let i = 0; i < uid.length; i += 4) {
    groups.push(uid.slice(i, i + 4));
  }
  return groups.join("-");
}

function parseAlias(token: string): string | null {
  return ALIAS_RE.test(token) ? token : null;
}

function parseDuration(token: string): Duration | null {
  if (token === "off") {
    return { kind: "off" };
  }
  const match = DURATION_RE.exec(token);
  if (match === null) {
    return null;
  }
  const amount = Number(match[1]);
  if (amount < 1) {
    return null;
  }
  return { kind: "for", amount, unit: match[2] as DurationUnit };
}

function parseWeekday(token: string): Weekday | null {
  const lower = token.toLowerCase();
  return (WEEKDAYS as readonly string[]).includes(lower) ? (lower as Weekday) : null;
}

function invalid(error: string, usage?: string): ParseResult {
  return { kind: "invalid", error, usage };
}

function command(cmd: Command): ParseResult {
  return { kind: "command", command: cmd };
}

function clip(word: string): string {
  return word.length > 32 ? `${word.slice(0, 32)}…` : word;
}

export function parseLine(line: string): ParseResult {
  if (line.trim().length === 0) {
    return { kind: "empty" };
  }
  if (line.startsWith(" ")) {
    // A leading space escapes a literal "/" at message start (CLAUDE.md §1.2).
    return { kind: "message", text: line.slice(1) };
  }
  if (!line.startsWith("/")) {
    return { kind: "message", text: line };
  }
  const tokens = line
    .slice(1)
    .split(/\s+/)
    .filter((t) => t.length > 0);
  const head = tokens[0];
  if (head === undefined) {
    return invalid("empty command", COMMAND_USAGE.help);
  }
  const word = head.toLowerCase();
  if (!isCommandWord(word)) {
    return invalid(`unknown command: /${clip(word)}`, "type /help for the command list");
  }
  return parseCommand(word, tokens.slice(1));
}

function parseCommand(word: CommandWord, args: readonly string[]): ParseResult {
  const usage = COMMAND_USAGE[word];
  switch (word) {
    case "register":
    case "login":
    case "logout":
    case "lock":
    case "whoami":
    case "wipe": {
      if (args.length !== 0) {
        return invalid(`/${word} takes no arguments`, usage);
      }
      return command({ name: word });
    }
    case "add": {
      if (args.length < 1 || args.length > 2) {
        return invalid("expected a UID and an optional alias", usage);
      }
      const uid = normalizeUid(args[0] ?? "");
      if (uid === null) {
        return invalid("invalid UID (26 Crockford Base32 chars, dashes optional)", usage);
      }
      const aliasToken = args[1];
      if (aliasToken === undefined) {
        return command({ name: "add", uid, alias: undefined });
      }
      const alias = parseAlias(aliasToken);
      if (alias === null) {
        return invalid("invalid alias (1-32 chars: letters, digits, _ or -)", usage);
      }
      return command({ name: "add", uid, alias });
    }
    case "chat": {
      const token = args[0];
      if (args.length !== 1 || token === undefined) {
        return invalid("expected an alias or UID", usage);
      }
      const uid = normalizeUid(token);
      if (uid !== null) {
        return command({ name: "chat", target: uid });
      }
      const alias = parseAlias(token);
      if (alias === null) {
        return invalid("not a valid alias or UID", usage);
      }
      return command({ name: "chat", target: alias });
    }
    case "verify":
    case "verified":
    case "ack": {
      const token = args[0];
      if (args.length !== 1 || token === undefined) {
        return invalid("expected an alias", usage);
      }
      const alias = parseAlias(token);
      if (alias === null) {
        return invalid("invalid alias", usage);
      }
      return command({ name: word, alias });
    }
    case "timer": {
      const aliasToken = args[0];
      const durationToken = args[1];
      if (args.length !== 2 || aliasToken === undefined || durationToken === undefined) {
        return invalid("expected an alias and a duration", usage);
      }
      const alias = parseAlias(aliasToken);
      if (alias === null) {
        return invalid("invalid alias", usage);
      }
      const duration = parseDuration(durationToken);
      if (duration === null) {
        return invalid("invalid duration (e.g. 30m, 1h, 1d, 1w, or off)", usage);
      }
      return command({ name: "timer", alias, duration });
    }
    case "purge": {
      const sub = args[0];
      if (sub === "set") {
        const token = args[1];
        if (args.length !== 2 || token === undefined) {
          return invalid("expected a duration", usage);
        }
        const duration = parseDuration(token);
        if (duration === null) {
          return invalid("invalid duration (e.g. 30m, 1h, 1d, 1w, or off)", usage);
        }
        return command({ name: "purge-set", duration });
      }
      if (sub === "now") {
        if (args.length > 2) {
          return invalid("expected at most one alias", usage);
        }
        const aliasToken = args[1];
        if (aliasToken === undefined) {
          return command({ name: "purge-now", alias: undefined });
        }
        const alias = parseAlias(aliasToken);
        if (alias === null) {
          return invalid("invalid alias", usage);
        }
        return command({ name: "purge-now", alias });
      }
      return invalid("expected 'set' or 'now'", usage);
    }
    case "rotate": {
      if (args.length !== 1 || args[0] !== "passphrase") {
        return invalid("expected 'passphrase'", usage);
      }
      return command({ name: "rotate-passphrase" });
    }
    case "settings": {
      const sub = args[0];
      if (sub === "rotation") {
        const value = args[1];
        if (value === "on" && args.length === 2) {
          return command({ name: "settings-rotation", setting: { kind: "on" } });
        }
        if (value === "off" && args.length === 2) {
          return command({ name: "settings-rotation", setting: { kind: "off" } });
        }
        if (value === "day" && args.length === 3) {
          const day = parseWeekday(args[2] ?? "");
          if (day === null) {
            return invalid("invalid weekday (monday..sunday)", usage);
          }
          return command({ name: "settings-rotation", setting: { kind: "day", day } });
        }
        return invalid("expected on, off, or day <weekday>", usage);
      }
      if (sub === "notify") {
        const value = args[1];
        if ((value === "on" || value === "off") && args.length === 2) {
          return command({ name: "settings-notify", enabled: value === "on" });
        }
        return invalid("expected on or off", usage);
      }
      if (sub === "mask") {
        const value = args[1];
        if ((value === "asterisk" || value === "hidden") && args.length === 2) {
          return command({ name: "settings-mask", mask: value });
        }
        return invalid("expected asterisk or hidden", usage);
      }
      return invalid("expected 'rotation', 'notify', or 'mask'", usage);
    }
    case "keys": {
      const sub = args[0];
      if (sub === "status" && args.length === 1) {
        return command({ name: "keys-status" });
      }
      if (sub === "refill" && args.length === 1) {
        return command({ name: "keys-refill" });
      }
      return invalid("expected 'status' or 'refill'", usage);
    }
    case "bench": {
      if (args.length > 1) {
        return invalid("expected at most one suite name", usage);
      }
      const token = args[0];
      if (token === undefined) {
        return command({ name: "bench", suite: undefined });
      }
      if (!SUITE_RE.test(token)) {
        return invalid("invalid suite name", usage);
      }
      return command({ name: "bench", suite: token });
    }
    case "help": {
      if (args.length > 1) {
        return invalid("expected at most one command name", usage);
      }
      const token = args[0];
      if (token === undefined) {
        return command({ name: "help", topic: undefined });
      }
      const topic = token.toLowerCase().replace(/^\//, "");
      if (!isCommandWord(topic)) {
        return invalid(`unknown command: /${clip(topic)}`, "type /help for the command list");
      }
      return command({ name: "help", topic });
    }
  }
}
