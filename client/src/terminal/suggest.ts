// Autosuggest + typo correction for the command line. Pure and
// total: no DOM, no throws. `commandSuggestions` drives the live dropdown while
// the user is typing a slash word; `suggestCommand` powers the "did you mean …?"
// hint when an unknown command is entered. Both read the same static allowlist
// (`COMMAND_USAGE`) the parser gates on, so suggestions can never name a command
// the parser would reject.

import { A11Y_FEATURES, COMMAND_USAGE, WEEKDAYS, isCommandWord } from "./parser";
import type { CommandWord } from "./parser";
import { EVENT_COLOR_SLOTS, FONT_NAMES, SCHEME_NAMES } from "./theme";

// Resolved lazily, not at module load: parser.ts imports this module and this
// module imports parser.ts, so touching COMMAND_USAGE at top level would read it
// before parser.ts finishes initialising when parser is the first-loaded side of
// the cycle. Every caller runs at parse-time, well after both modules are ready.
let cachedWords: CommandWord[] | null = null;
function commandWords(): CommandWord[] {
  if (cachedWords === null) {
    cachedWords = Object.keys(COMMAND_USAGE) as CommandWord[];
  }
  return cachedWords;
}

/** Common alternates a user might type for a real command. Checked before the
 * fuzzy fallback so intentional synonyms (sign-up, logon, msg) map crisply
 * rather than landing on whatever happens to be nearest by edit distance. */
const SYNONYMS: Record<string, CommandWord> = {
  signup: "register",
  "sign-up": "register",
  create: "register",
  join: "register",
  recovery: "recover",
  restore: "recover",
  signin: "login",
  "sign-in": "login",
  logon: "login",
  "log-in": "login",
  auth: "login",
  signout: "logout",
  "sign-out": "logout",
  "log-out": "logout",
  exit: "logout",
  quit: "logout",
  message: "chat",
  msg: "chat",
  text: "chat",
  dm: "chat",
  talk: "chat",
  open: "chat",
  clear: "clr",
  cls: "clr",
};

/** The fixed keyword choices for the *next* argument of `word`, given the
 * argument tokens already typed. Returns [] where the next argument is free-form
 * (a UID, alias, duration, hex colour, message count) so the dropdown stays
 * quiet rather than guessing. This is the same shape the parser validates, so a
 * suggestion can never name an argument the parser would reject. */
function nextArgOptions(word: CommandWord, priorArgs: readonly string[]): string[] {
  const n = priorArgs.length;
  const first = priorArgs[0];
  switch (word) {
    case "settings": {
      if (n === 0) {
        return [
          "rotation",
          "notify",
          "mask",
          "theme",
          "scheme",
          "emblem",
          "color",
          "trust",
          "font",
          "fontsize",
          "a11y",
        ];
      }
      switch (first) {
        case "rotation":
          if (n === 1) return ["on", "off", "day"];
          if (n === 2 && priorArgs[1] === "day") return [...WEEKDAYS];
          return [];
        case "notify":
          return n === 1 ? ["on", "off"] : [];
        case "mask":
          return n === 1 ? ["asterisk", "hidden"] : [];
        case "trust":
          return n === 1 ? ["auto", "manual"] : [];
        case "theme":
          if (n === 1) return ["emblem", "scanlines", "vignette", "dock", "all"];
          if (n === 2) return ["on", "off"];
          return [];
        case "scheme":
          // Presets and the sub-verbs only: the user's own scheme names live in
          // the display prefs, which this pure function cannot read.
          return n === 1 ? [...SCHEME_NAMES, "new", "delete", "list"] : [];
        case "emblem":
          return n === 1 ? ["globe", "tree"] : [];
        case "font":
          return n === 1 ? [...FONT_NAMES, "list"] : [];
        case "a11y":
          if (n === 1) return [...A11Y_FEATURES];
          if (n === 2) return ["on", "off"];
          return [];
        case "color":
          if (n === 1) {
            return ["accent", "background", "panel", "text", "muted", "event", "reset"];
          }
          if (n === 2 && priorArgs[1] === "event") {
            return [...EVENT_COLOR_SLOTS];
          }
          return [];
        default:
          return [];
      }
    }
    case "remove":
      // The target (first arg) is a free-form alias/uid, but `all` is a
      // reserved keyword worth surfacing; `purge` is the only second arg.
      if (n === 0) return ["all"];
      if (n === 1) return ["purge"];
      return [];
    case "logout":
      // Optional "all": sign out every other device.
      return n === 0 ? ["all"] : [];
    case "duress":
      return n === 0 ? ["set", "off", "status"] : [];
    case "favourite":
      // The contact (first arg) is a free-form alias/uid; `off` unstars.
      return n === 1 ? ["off"] : [];
    case "keys":
      return n === 0 ? ["status", "refill"] : [];
    case "purge":
      return n === 0 ? ["set", "now"] : [];
    case "delete":
      if (n === 0) return ["last", "all", "purge"];
      if (n === 1 && first !== "/s") return ["/s"];
      return [];
    case "bench":
      return n === 0 ? ["b1", "b2", "b3", "b4", "all"] : [];
    case "rotate":
      return n === 0 ? ["passphrase"] : [];
    case "help":
      return n === 0 ? [...commandWords()] : [];
    default:
      return [];
  }
}

/** Live dropdown contents for the command line. While the command word is being
 * typed it prefix-matches slash words ("/lo" → /lock /login /logout). Once past
 * the word it suggests the next argument's fixed keyword choices (e.g. "/settings"
 * → its subcommands, "/settings theme " → the layers), always as a full
 * ready-to-fill line. Returns [] for free-form argument positions and non-command
 * lines. `input` includes the leading "/". */
export function commandSuggestions(input: string): string[] {
  if (!input.startsWith("/")) {
    return [];
  }
  const endsWithSpace = /\s$/.test(input);
  const tokens = input
    .slice(1)
    .split(/\s+/)
    .filter((t) => t.length > 0);
  const head = tokens[0];
  if (head === undefined) {
    return commandWords().map((c) => `/${c}`); // a lone "/"
  }
  const word = head.toLowerCase();
  if (tokens.length === 1 && !endsWithSpace) {
    // Still choosing the command word: prefix-match the allowlist.
    return commandWords()
      .filter((c) => c.startsWith(word))
      .map((c) => `/${c}`);
  }
  if (!isCommandWord(word)) {
    return []; // arguments to an unknown command - nothing to offer
  }
  // Completing an argument. The partial (if any) is the last token unless the
  // line ends in a space, in which case a fresh argument is beginning.
  const argTokens = tokens.slice(1);
  const priorArgs = endsWithSpace ? argTokens : argTokens.slice(0, -1);
  const partial = (endsWithSpace ? "" : (argTokens[argTokens.length - 1] ?? "")).toLowerCase();
  const options = nextArgOptions(word, priorArgs);
  const base = `/${word}${priorArgs.length > 0 ? ` ${priorArgs.join(" ")}` : ""}`;
  return options.filter((o) => o.toLowerCase().startsWith(partial)).map((o) => `${base} ${o}`);
}

/** Longest common prefix of a set of "/word" suggestions - the safe amount to
 * fill on Tab (fish-style): unambiguous characters only, never a guess. */
export function longestCommonPrefix(words: readonly string[]): string {
  const first = words[0];
  if (first === undefined) {
    return "";
  }
  let prefix = first;
  for (const w of words) {
    while (!w.startsWith(prefix)) {
      prefix = prefix.slice(0, -1);
      if (prefix === "") {
        return "";
      }
    }
  }
  return prefix;
}

/** "did you mean …?" for an unknown command word. A synonym map wins first, then
 * the nearest command word within a length-scaled edit distance (short words get
 * a tighter bound so random input does not attract a suggestion). Accepts the
 * word with or without a leading "/". Returns a "/word" string, or null when
 * nothing is close enough. */
export function suggestCommand(word: string): string | null {
  const w = word.toLowerCase().replace(/^\//, "");
  if (w.length === 0) {
    return null;
  }
  const synonym = SYNONYMS[w];
  if (synonym !== undefined) {
    return `/${synonym}`;
  }
  let best: CommandWord | null = null;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const cmd of commandWords()) {
    const distance = levenshtein(w, cmd);
    if (distance < bestDistance) {
      bestDistance = distance;
      best = cmd;
    }
  }
  const threshold = w.length <= 4 ? 1 : 2;
  return best !== null && bestDistance <= threshold ? `/${best}` : null;
}

/** Classic iterative Levenshtein edit distance (two-row DP, O(m·n) time,
 * O(n) space). */
export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) {
    return n;
  }
  if (n === 0) {
    return m;
  }
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array<number>(n + 1).fill(0);
  for (let i = 1; i <= m; i += 1) {
    curr[0] = i;
    for (let j = 1; j <= n; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const deletion = (prev[j] ?? 0) + 1;
      const insertion = (curr[j - 1] ?? 0) + 1;
      const substitution = (prev[j - 1] ?? 0) + cost;
      curr[j] = Math.min(deletion, insertion, substitution);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n] ?? 0;
}
