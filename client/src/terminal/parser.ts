// Command parser: a line starting with "/" is tokenized
// against a static allowlist; anything else is message text for the active
// conversation. The parser is total - it never throws on any input - and
// returns a typed discriminated union consumed by a switch in the executor.

import { CROCKFORD_ALPHABET, RECOVERY_CODE_CHARS, UID_CHARS } from "../crypto/constants";
import { suggestCommand } from "./suggest";
import { isColorSlot, isEmblemName, normalizeHex } from "./theme";
import type { ColorSlot, EmblemName } from "./theme";

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

export const THEME_ELEMENTS = ["emblem", "scanlines", "vignette", "dock"] as const;
export type ThemeElement = (typeof THEME_ELEMENTS)[number];

/** Scope of a `/delete` of your own (outgoing) messages:
 * the last one, the last N, all in the active conversation, or every one
 * across all conversations ("purge"). */
export type DeleteScope =
  | { readonly kind: "last" }
  | { readonly kind: "count"; readonly count: number }
  | { readonly kind: "all" }
  | { readonly kind: "purge" };

/** Target of a `/remove`: one contact (by alias or UID) or every contact.
 * `all` is a reserved keyword, so a contact aliased "all" is removable only
 * by its UID. */
export type RemoveTarget =
  | { readonly kind: "one"; readonly value: string }
  | { readonly kind: "all" };

export type Command =
  | { readonly name: "register" }
  | { readonly name: "recover" }
  | { readonly name: "login" }
  | { readonly name: "logout"; readonly all: boolean }
  | { readonly name: "sessions" }
  | { readonly name: "lock" }
  | { readonly name: "whoami" }
  | { readonly name: "add"; readonly uid: string; readonly alias: string | undefined }
  | { readonly name: "remove"; readonly target: RemoveTarget; readonly purge: boolean }
  | { readonly name: "rename"; readonly target: string; readonly alias: string }
  | { readonly name: "favourite"; readonly target: string; readonly on: boolean }
  | { readonly name: "chat"; readonly target: string; readonly message: string | undefined }
  | { readonly name: "home" }
  | { readonly name: "return" }
  | { readonly name: "contacts" }
  | { readonly name: "verify"; readonly alias: string }
  | { readonly name: "verified"; readonly alias: string }
  | { readonly name: "ack"; readonly alias: string }
  | { readonly name: "timer"; readonly alias: string; readonly duration: Duration }
  | { readonly name: "purge-set"; readonly duration: Duration }
  | { readonly name: "purge-now"; readonly alias: string | undefined }
  | { readonly name: "delete"; readonly scope: DeleteScope; readonly silent: boolean }
  | { readonly name: "rotate-passphrase" }
  | { readonly name: "settings-rotation"; readonly setting: RotationSetting }
  | { readonly name: "settings-notify"; readonly enabled: boolean }
  | { readonly name: "settings-mask"; readonly mask: "asterisk" | "hidden" }
  | { readonly name: "settings-trust"; readonly mode: "auto" | "manual" }
  | { readonly name: "settings-theme"; readonly element: ThemeElement | "all"; readonly enabled: boolean }
  // The scheme name is free-form here: presets and user-defined schemes share
  // one namespace, and only the executor can see which names exist.
  | { readonly name: "settings-scheme"; readonly scheme: string }
  | { readonly name: "settings-scheme-new"; readonly scheme: string }
  | { readonly name: "settings-scheme-delete"; readonly scheme: string }
  | { readonly name: "settings-scheme-list" }
  | { readonly name: "settings-emblem"; readonly emblem: EmblemName }
  | { readonly name: "settings-color"; readonly slot: ColorSlot; readonly hex: string }
  | { readonly name: "settings-color-reset" }
  | { readonly name: "duress-set" }
  | { readonly name: "duress-off" }
  | { readonly name: "duress-status" }
  | { readonly name: "keys-status" }
  | { readonly name: "keys-refill" }
  | { readonly name: "bench"; readonly suite: string | undefined }
  | { readonly name: "wipe" }
  | { readonly name: "clr" }
  | { readonly name: "help"; readonly topic: CommandWord | undefined };

export type CommandName = Command["name"];

export type ParseResult =
  | { readonly kind: "empty" }
  | { readonly kind: "message"; readonly text: string }
  | { readonly kind: "command"; readonly command: Command }
  | {
      readonly kind: "invalid";
      // E101 = the command word itself is unknown; E102 = a known command
      // with bad arguments (docs/MESSAGES.md).
      readonly code: "E101" | "E102";
      readonly error: string;
      readonly usage: string | undefined;
      // A "did you mean /login?" candidate when the head looked like a typo of a
      // real command; undefined when nothing was close enough.
      readonly suggestion: string | undefined;
    };

// The static allowlist: every slash word the terminal accepts, with usage.
// No dynamic dispatch happens off this map - it gates membership only.
export const COMMAND_USAGE = {
  register: "/register",
  recover: "/recover",
  login: "/login",
  logout: "/logout [all]  (all = sign out every other device, keep this one)",
  sessions: "/sessions",
  lock: "/lock",
  whoami: "/whoami",
  add: "/add <uid> [alias]",
  remove: "/remove <alias|uid> [purge]  |  /remove all [purge]  (purge = also delete message history)",
  rename: "/rename <alias|uid> <new-alias>",
  favourite: "/favourite <alias|uid> [off]  (favourites sort to the top of your contact list)",
  contacts: "/contacts",
  chat: "/chat <alias|uid> [message]",
  home: "/home",
  return: "/return",
  verify: "/verify <alias>",
  verified: "/verified <alias>",
  ack: "/ack <alias>",
  timer: "/timer <alias> <duration|off>  (duration: 30m, 1h, 1d, 1w, ...)",
  purge: "/purge set <duration|off>  |  /purge now [alias]",
  delete: "/delete <last|N|all|purge> [/s]  (delete your own messages on both sides; purge = all contacts; /s = silent)",
  rotate: "/rotate passphrase",
  settings:
    "/settings rotation <on|off|day <weekday>>  |  /settings notify <on|off>  |  /settings mask <asterisk|hidden>  |  /settings trust <auto|manual>  |  /settings theme <emblem|scanlines|vignette|dock|all> <on|off>  |  /settings scheme <name>  |  /settings scheme new <name>  |  /settings scheme delete <name>  |  /settings scheme list  |  /settings emblem <globe|tree>  |  /settings color <accent|background|panel|text|muted> <#rrggbb>  |  /settings color reset",
  duress:
    "/duress set  |  /duress off  |  /duress status  (a passphrase that silently destroys this device and the account)",
  keys: "/keys status  |  /keys refill",
  bench: "/bench [b1|b2|b3|b4|all]",
  wipe: "/wipe",
  clr: "/clr",
  help: "/help [command]",
} as const;

export type CommandWord = keyof typeof COMMAND_USAGE;

export function isCommandWord(word: string): word is CommandWord {
  return Object.prototype.hasOwnProperty.call(COMMAND_USAGE, word);
}

/** Alternate spellings that execute a canonical command. Resolved in
 * parseLine before the allowlist check, so `/text bob` behaves exactly like
 * `/chat bob` (arguments and validation are identical). Kept to non-destructive
 * commands by design - never `/wipe` or `/delete`. The autosuggest dropdown
 * still lists only canonical names; these are simply accepted when typed. */
export const COMMAND_ALIASES: Record<string, CommandWord> = {
  signup: "register",
  "sign-up": "register",
  restore: "recover",
  signin: "login",
  "sign-in": "login",
  logon: "login",
  signout: "logout",
  "sign-out": "logout",
  text: "chat",
  msg: "chat",
  message: "chat",
  dm: "chat",
  clear: "clr",
  cls: "clr",
  back: "return",
  // Both spellings of the same word, plus the short form people actually type.
  favorite: "favourite",
  fav: "favourite",
  star: "favourite",
};

/** Resolve a typed word to a canonical command word: itself if it is one, its
 * alias target if it is an alias, otherwise null. */
export function resolveCommandWord(word: string): CommandWord | null {
  if (isCommandWord(word)) {
    return word;
  }
  return COMMAND_ALIASES[word] ?? null;
}

const ALIAS_RE = /^[A-Za-z0-9_-]{1,32}$/;
const DURATION_RE = /^(\d{1,4})([mhdw])$/;
const SUITE_RE = /^[A-Za-z0-9_-]{1,16}$/;
/** Shape of any scheme name the grammar will carry. Whether the name exists,
 * and whether it may be created, is the executor's call (theme.ts owns those
 * rules); this only keeps junk - whitespace, escapes, absurd lengths - from
 * travelling any further. */
const SCHEME_NAME_RE = /^[A-Za-z][A-Za-z0-9-]{0,23}$/;

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

/** Canonicalize a typed recovery code: strip dashes and spaces, uppercase,
 * Crockford ambiguity mapping (O to 0, I/L to 1) - the mirror of the server's
 * canonicalize_recovery_code. Returns null unless exactly RECOVERY_CODE_CHARS
 * canonical chars remain. */
export function normalizeRecoveryCode(raw: string): string | null {
  const cleaned = raw
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  if (cleaned.length !== RECOVERY_CODE_CHARS) {
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

/** The verbatim remainder of `line` after its first `skip` whitespace-delimited
 * tokens, preserving the message's own internal spacing (the tokenizer collapses
 * runs of whitespace, which would corrupt message text). Returns undefined when
 * only whitespace follows. Used to carry the optional `/chat <target> [message]`
 * message exactly as typed. */
function rawRemainder(line: string, skip: number): string | undefined {
  let i = 0;
  for (let t = 0; t < skip; t += 1) {
    while (i < line.length && /\s/.test(line[i] ?? "")) i += 1; // leading whitespace
    while (i < line.length && !/\s/.test(line[i] ?? "")) i += 1; // the token itself
  }
  while (i < line.length && /\s/.test(line[i] ?? "")) i += 1; // whitespace before the remainder
  const rest = line.slice(i);
  return rest.length === 0 ? undefined : rest;
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

function invalid(
  error: string,
  usage?: string,
  suggestion?: string,
  code: "E101" | "E102" = "E102",
): ParseResult {
  return { kind: "invalid", code, error, usage, suggestion };
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
    // A leading space escapes a literal "/" at message start.
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
  const resolved = resolveCommandWord(word);
  if (resolved === null) {
    return invalid(
      `unknown command: /${clip(word)}`,
      "type /help for the command list",
      suggestCommand(word) ?? undefined,
      "E101",
    );
  }
  return parseCommand(resolved, tokens.slice(1), line);
}

function parseCommand(word: CommandWord, args: readonly string[], rawLine: string): ParseResult {
  const usage = COMMAND_USAGE[word];
  switch (word) {
    case "register":
    case "recover":
    case "login":
    case "sessions":
    case "lock":
    case "whoami":
    case "home":
    case "return":
    case "contacts":
    case "clr":
    case "wipe": {
      if (args.length !== 0) {
        return invalid(`/${word} takes no arguments`, usage);
      }
      return command({ name: word });
    }
    case "logout": {
      // Optional single argument "all": sign out every other session.
      if (args.length === 0) {
        return command({ name: "logout", all: false });
      }
      if (args.length === 1 && (args[0] ?? "").toLowerCase() === "all") {
        return command({ name: "logout", all: true });
      }
      return invalid("/logout takes an optional 'all' (sign out other devices)", usage);
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
    case "remove": {
      // /remove <alias|uid|all> [purge]. `all` is a reserved keyword; an
      // optional trailing `purge` also deletes the local message history.
      const first = args[0];
      if (args.length < 1 || args.length > 2 || first === undefined) {
        return invalid("expected a contact (or 'all') and an optional 'purge'", usage);
      }
      const purge = args[1] === "purge";
      if (args.length === 2 && !purge) {
        return invalid("the only extra argument is 'purge'", usage);
      }
      if (first === "all") {
        return command({ name: "remove", target: { kind: "all" }, purge });
      }
      const value = normalizeUid(first) ?? parseAlias(first);
      if (value === null) {
        return invalid("not a valid alias or UID", usage);
      }
      return command({ name: "remove", target: { kind: "one", value }, purge });
    }
    case "rename": {
      const targetToken = args[0];
      const aliasToken = args[1];
      if (args.length !== 2 || targetToken === undefined || aliasToken === undefined) {
        return invalid("expected a contact and a new alias", usage);
      }
      const target = normalizeUid(targetToken) ?? parseAlias(targetToken);
      if (target === null) {
        return invalid("not a valid alias or UID", usage);
      }
      const alias = parseAlias(aliasToken);
      if (alias === null) {
        return invalid("invalid alias (1-32 chars: letters, digits, _ or -)", usage);
      }
      return command({ name: "rename", target, alias });
    }
    case "chat": {
      const token = args[0];
      if (args.length < 1 || token === undefined) {
        return invalid("expected an alias or UID", usage);
      }
      const target = normalizeUid(token) ?? parseAlias(token);
      if (target === null) {
        return invalid("not a valid alias or UID", usage);
      }
      // Anything after the target is an optional inline message, taken verbatim
      // (skip 2 tokens: the command word and the target) so `/chat bob hey there`
      // switches to bob and sends "hey there" in one line.
      const message = rawRemainder(rawLine, 2);
      return command({ name: "chat", target, message });
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
    case "delete": {
      // A trailing "/s" (the only token that can begin with a slash mid-line,
      // since the leading slash was already the command word) requests a silent
      // deletion with no confirmation output.
      const rest = [...args];
      let silent = false;
      if (rest[rest.length - 1] === "/s") {
        silent = true;
        rest.pop();
      }
      const scopeToken = rest[0];
      if (rest.length !== 1 || scopeToken === undefined) {
        return invalid("expected last, a count, all, or purge (optionally /s)", usage);
      }
      if (scopeToken === "last") {
        return command({ name: "delete", scope: { kind: "last" }, silent });
      }
      if (scopeToken === "all") {
        return command({ name: "delete", scope: { kind: "all" }, silent });
      }
      if (scopeToken === "purge") {
        return command({ name: "delete", scope: { kind: "purge" }, silent });
      }
      if (/^\d{1,4}$/.test(scopeToken)) {
        const count = Number(scopeToken);
        if (count >= 1) {
          return command({ name: "delete", scope: { kind: "count", count }, silent });
        }
      }
      return invalid("expected last, a positive count, all, or purge (optionally /s)", usage);
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
      if (sub === "trust") {
        const value = args[1];
        if ((value === "auto" || value === "manual") && args.length === 2) {
          return command({ name: "settings-trust", mode: value });
        }
        return invalid("expected auto or manual", usage);
      }
      if (sub === "theme") {
        const element = args[1];
        const value = args[2];
        const known =
          element === "all" || (THEME_ELEMENTS as readonly string[]).includes(element ?? "");
        if (known && (value === "on" || value === "off") && args.length === 3) {
          return command({
            name: "settings-theme",
            element: element as ThemeElement | "all",
            enabled: value === "on",
          });
        }
        return invalid("expected <emblem|scanlines|vignette|dock|all> <on|off>", usage);
      }
      if (sub === "scheme") {
        // /settings scheme list | new <name> | delete <name> | <name>
        if (args[1] === "list" && args.length === 2) {
          return command({ name: "settings-scheme-list" });
        }
        const verb = args[1];
        if (verb === "new" || verb === "delete") {
          const nameToken = args[2];
          if (args.length !== 3 || nameToken === undefined) {
            return invalid(`expected a scheme name after '${verb}'`, usage);
          }
          if (!SCHEME_NAME_RE.test(nameToken)) {
            return invalid(
              "invalid scheme name (1-24 characters: a letter, then letters, digits or hyphens)",
              usage,
            );
          }
          const scheme = nameToken.toLowerCase();
          return command(
            verb === "new"
              ? { name: "settings-scheme-new", scheme }
              : { name: "settings-scheme-delete", scheme },
          );
        }
        if (verb !== undefined && args.length === 2 && SCHEME_NAME_RE.test(verb)) {
          return command({ name: "settings-scheme", scheme: verb.toLowerCase() });
        }
        return invalid("expected a scheme name, or 'list', 'new <name>', 'delete <name>'", usage);
      }
      if (sub === "emblem") {
        const value = args[1];
        if (value !== undefined && isEmblemName(value) && args.length === 2) {
          return command({ name: "settings-emblem", emblem: value });
        }
        return invalid("expected pq, globe, or tree", usage);
      }
      if (sub === "color") {
        if (args[1] === "reset" && args.length === 2) {
          return command({ name: "settings-color-reset" });
        }
        const slotToken = args[1];
        const hexToken = args[2];
        if (
          slotToken !== undefined &&
          isColorSlot(slotToken) &&
          hexToken !== undefined &&
          args.length === 3
        ) {
          const hex = normalizeHex(hexToken);
          if (hex === null) {
            return invalid("invalid color (use a 6-digit hex like #1a2b3c)", usage);
          }
          return command({ name: "settings-color", slot: slotToken, hex });
        }
        return invalid(
          "expected <accent|background|panel|text|muted> <#rrggbb>, or 'reset'",
          usage,
        );
      }
      return invalid(
        "expected 'rotation', 'notify', 'mask', 'trust', 'theme', 'scheme', 'emblem', or 'color'",
        usage,
      );
    }
    case "duress": {
      const sub = args[0];
      if (args.length !== 1) {
        return invalid("expected 'set', 'off', or 'status'", usage);
      }
      if (sub === "set") {
        return command({ name: "duress-set" });
      }
      if (sub === "off") {
        return command({ name: "duress-off" });
      }
      if (sub === "status") {
        return command({ name: "duress-status" });
      }
      return invalid("expected 'set', 'off', or 'status'", usage);
    }
    case "favourite": {
      // /favourite <alias|uid> [off] - `off` unstars, mirroring the
      // <value|off> shape /timer and /purge set already use.
      const token = args[0];
      if (args.length < 1 || args.length > 2 || token === undefined) {
        return invalid("expected a contact and an optional 'off'", usage);
      }
      const on = args[1] === undefined;
      if (!on && args[1] !== "off") {
        return invalid("the only extra argument is 'off'", usage);
      }
      const target = normalizeUid(token) ?? parseAlias(token);
      if (target === null) {
        return invalid("not a valid alias or UID", usage);
      }
      return command({ name: "favourite", target, on });
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
      const raw = token.toLowerCase().replace(/^\//, "");
      const topic = resolveCommandWord(raw);
      if (topic === null) {
        return invalid(
          `unknown command: /${clip(raw)}`,
          "type /help for the command list",
          suggestCommand(raw) ?? undefined,
          "E101",
        );
      }
      return command({ name: "help", topic });
    }
  }
}
