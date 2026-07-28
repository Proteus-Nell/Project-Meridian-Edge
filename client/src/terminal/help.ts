// Help text rendering. Pure and total: returns plain lines the renderer prints
// as-is. Text-only (no ANSI): the renderer sanitizes plain output, which would
// strip escape codes anyway, and app-generated help never needs markup. That
// also rules out real tab characters, which sanitizeText drops as C0 controls -
// every column here is made of spaces.
//
// Two layouts, chosen by the terminal's actual width:
//
//   Wide   `/lock ................ locks the store now`
//          One row per command, descriptions aligned in a column per section.
//          The dot leaders exist because the command column is as wide as the
//          longest entry in its section, which can leave a short command like
//          /lock two dozen spaces away from its description - far enough that
//          the eye loses the row.
//   Narrow The command on its own row, the description indented beneath it.
//          Below ~56 columns a two-column layout has nothing left for the
//          description, and xterm hard-wraps mid-word rather than reflowing.
//
// `/help <command>` prints the usage line plus a paragraph explaining what the
// command is FOR: usage alone answers "how do I type it", which is the smaller
// half of the question.

import { COMMAND_ALIASES, COMMAND_USAGE } from "./parser";
import type { CommandWord } from "./parser";

/** Fallback when the caller cannot report a real terminal width. */
export const DEFAULT_HELP_COLUMNS = 80;

/** Never lay out wider than this even on a very wide terminal: long full-width
 * lines are harder to scan than a fixed measure. */
const MAX_LAYOUT_COLUMNS = 96;

/** Below this, the two-column layout leaves too little room for a description
 * and the stacked layout takes over. */
const NARROW_COLUMNS = 56;

/** Smallest width the layout will reason about, so arithmetic stays sane on a
 * terminal reporting something absurd. */
const MIN_LAYOUT_COLUMNS = 32;

interface HelpEntry {
  readonly cmd: string;
  readonly blurb: string;
}

interface HelpSection {
  readonly title: string;
  readonly entries: readonly HelpEntry[];
}

const SECTIONS: readonly HelpSection[] = [
  {
    title: "Identity & session",
    entries: [
      { cmd: "/register", blurb: "create an identity (prints your UID + recovery codes)" },
      { cmd: "/recover", blurb: "regain your account with a recovery code (new device / lost passphrase)" },
      { cmd: "/login", blurb: "unlock the local store and connect" },
      { cmd: "/logout", blurb: "revoke this session and lock" },
      { cmd: "/logout all", blurb: "sign out every other device (this one stays logged in)" },
      { cmd: "/sessions", blurb: "list where this account is signed in" },
      { cmd: "/lock", blurb: "lock the store now" },
      { cmd: "/whoami", blurb: "show your UID and identity-key fingerprint" },
      { cmd: "/rotate passphrase", blurb: "re-wrap the store under a new passphrase" },
      { cmd: "/keys status", blurb: "signed-prekey age and one-time-prekey count" },
      { cmd: "/keys refill", blurb: "replenish one-time prekeys" },
      { cmd: "/wipe", blurb: "destroy the local store (double confirm)" },
      { cmd: "/duress set", blurb: "arm a passphrase that silently destroys this device AND the account" },
      { cmd: "/duress off", blurb: "disarm the duress passphrase" },
      { cmd: "/duress status", blurb: "whether a duress passphrase is armed" },
    ],
  },
  {
    title: "Contacts & trust",
    entries: [
      { cmd: "/add <uid> [alias]", blurb: "add a contact (alias is local-only)" },
      { cmd: "/remove <alias|uid> [purge]", blurb: "remove a contact (purge = also delete history); /remove all clears everyone" },
      { cmd: "/rename <alias|uid> <new>", blurb: "give a contact a new local alias" },
      { cmd: "/favourite <alias|uid> [off]", blurb: "pin a contact to the top of your contact list" },
      { cmd: "/contacts", blurb: "list saved contacts with their UIDs and trust state" },
      { cmd: "/chat <alias|uid>", blurb: "open a conversation (focused view - hides everything else)" },
      { cmd: "/home", blurb: "back to the home dashboard of all conversations" },
      { cmd: "/return", blurb: "toggle back to the previous screen" },
      { cmd: "/verify <alias>", blurb: "show the safety number to compare out-of-band" },
      { cmd: "/verified <alias>", blurb: "mark a contact trusted" },
      { cmd: "/ack <alias>", blurb: "acknowledge a blocking security warning" },
    ],
  },
  {
    title: "Messages",
    entries: [
      { cmd: "/timer <alias> <dur|off>", blurb: "mutual disappearing-message timer" },
      { cmd: "/delete <last|N|all|purge> [/s]", blurb: "delete your own messages on both sides (/s = silent)" },
      { cmd: "/purge set <dur|off>", blurb: "local retention cap (never transmitted)" },
      { cmd: "/purge now [alias]", blurb: "delete local history immediately" },
      { cmd: "/clr", blurb: "clear the screen (also Ctrl+L)" },
    ],
  },
  {
    title: "Appearance",
    entries: [
      { cmd: "/settings scheme <name>", blurb: "switch scheme: dark | parchment | olive | one of yours" },
      { cmd: "/settings scheme list", blurb: "every scheme you can switch to" },
      { cmd: "/settings scheme new <name>", blurb: "copy the current colors into a scheme of your own" },
      { cmd: "/settings scheme delete <name>", blurb: "delete one of your schemes (presets cannot be)" },
      { cmd: "/settings color <slot> <#hex>", blurb: "edit a color; on a preset this forks it, leaving it intact" },
      { cmd: "/settings color event <slot> <#hex>", blurb: "recolor the [✓] [!] [*] [E###] markers and peer names" },
      { cmd: "/settings color reset", blurb: "put your scheme back to its base preset's colors" },
      { cmd: "/settings emblem <name>", blurb: "medallion glyph: globe | tree" },
      { cmd: "/settings theme <layer> <on|off>", blurb: "toggle atmosphere layers" },
    ],
  },
  {
    title: "Preferences",
    entries: [
      { cmd: "/settings trust <auto|manual>", blurb: "auto-verify contacts (TOFU) or verify by hand" },
      { cmd: "/settings mask <asterisk|hidden>", blurb: "passphrase echo style" },
      { cmd: "/settings rotation <on|off|day>", blurb: "weekly passphrase-rotation prompt" },
      { cmd: "/settings notify <on|off>", blurb: "toast notifications" },
    ],
  },
  {
    title: "Other",
    entries: [
      { cmd: "/bench [b1|b2|b3|b4|all]", blurb: "run the PQC-vs-classical benchmarks (omit = all)" },
      { cmd: "/help [command]", blurb: "this list, or a full explanation of one command" },
    ],
  },
];

/** What each command is FOR, in prose: the part a usage line cannot carry.
 * Keyed by the canonical command word, so `/help <alias>` resolves to the same
 * entry the alias executes. Written to be read by someone who has not read the
 * README, which for a terminal-only app is most people. */
const EXPLANATIONS: Record<CommandWord, string> = {
  register:
    "Creates a brand-new identity on this device. You choose a passphrase, which never leaves the device: it derives the key that encrypts everything stored here, so it is the only thing protecting your messages if someone copies the database. The server hands back your UID (your address, which you share out-of-band) and ten recovery codes, shown once and never again. Write the codes down before you do anything else; without them, a forgotten passphrase means the account is gone.",
  recover:
    "Takes your account back onto this device using one recovery code, for a lost passphrase or a new device. It enrolls a fresh identity key and the server destroys everything bound to the old one, then reissues the whole code set. The costs are real: message history, contacts and sessions do not survive, because they only ever existed inside the old encrypted store. Your contacts still pin your old key, so your next message triggers their identity-key-change warning and they should re-verify your safety number.",
  login:
    "Unlocks the local store with your passphrase and authenticates to the server by signing a challenge with your identity key. No password is ever sent. Afterwards your session token lives only in memory, so a page reload always brings you back locked, and it expires after 15 minutes idle.",
  logout:
    "Revokes this session on the server and locks the local store, zeroizing key material from memory. Your data stays on the device, encrypted. `/logout all` is different: it signs out every OTHER device and keeps this one, for when you left yourself logged in somewhere.",
  sessions:
    "Lists everywhere this account is currently signed in, one line each, marking the device you are on. Sessions are anonymous by design: the server stores no device name or user agent, so a session is described only by how long ago it started and when it was last active. Use it to notice a session you do not recognise, then `/logout all`.",
  lock:
    "Locks the store immediately and wipes key material from memory. The same thing happens automatically after 10 minutes idle. Your session token may still be valid, so `/login` re-opens without a round trip through registration.",
  whoami:
    "Prints your UID, which is the address you give people so they can add you, and the fingerprint of your identity key. There is no directory to search, so the UID has to travel out-of-band: read it aloud, send it over another channel, whatever you trust.",
  add: "Saves a contact by UID. The alias is yours alone: it is stored encrypted on this device, never transmitted, and so cannot be used to impersonate anyone. If that person already messaged you and is waiting as a contact request, this accepts it and shows the message that was held back.",
  remove:
    "Ends the relationship locally: deletes the contact and tears down the shared ratchet session, so a later message from them arrives as a fresh contact request. Message history is kept unless you add `purge`. `/remove all` clears everyone and asks first. Nothing is signalled to the other side; removal is purely local.",
  rename:
    "Changes a contact's local alias. History is stored by UID, so it survives the rename untouched. A name another contact already uses is rejected, since aliases have to stay unique on this device.",
  favourite:
    "Pins a contact to the top of `/contacts` and the home dashboard, marked with an asterisk. Favourites sort first, then everyone else alphabetically. Like the alias, it is a local sort preference: it never leaves the device and the contact is never told.",
  contacts:
    "Lists every saved contact with its alias, full UID and trust state, plus any contact requests still waiting for `/add`. This is where you read a UID off to check it. Purely informational: it does not change which conversation you are in.",
  chat: "Focuses one conversation. The transcript switches to just that conversation's history, the prompt changes to show whose it is, and plain text you type from then on is sent to them. `/chat <alias> <message>` does both at once. `/home` brings back everything else.",
  home: "Returns to the home dashboard: every conversation at a glance, with unread counts, trust state, timers and any waiting contact requests. This is the screen `/chat` hides.",
  return:
    "Toggles back to the screen you were on before this one, and toggling again brings you back, like a back/forward button. Useful for flicking between two conversations, or between a conversation and the dashboard.",
  verify:
    "Fetches the contact's current identity key and prints a 60-digit safety number. Compare it with them over a channel the server does not control, in person or by voice. Matching numbers mean no one is sitting in the middle. This only shows the number; `/verified` is what records the result.",
  verified:
    "Records that you compared safety numbers out-of-band and they matched. The contact is then marked verified. If their key ever changes afterwards, this is revoked automatically and loudly, because a key change is exactly what a machine-in-the-middle attack looks like.",
  ack: "Clears a blocking identity-key-change warning so the conversation is usable again. It does NOT mean you trust the new key: the contact stays UNVERIFIED until you `/verify` and `/verified` it. Acknowledge only once you understand why the key changed, since the honest explanations (they recovered their account, they reinstalled) look identical to an attack.",
  timer:
    "Sets a disappearing-message timer for one conversation. It is mutual: the value is carried to the other side over the encrypted channel and applied on both. Deletion is at-rest and cooperative, so it depends on their client honouring it, and nothing stops a screenshot.",
  purge:
    "`/purge set` is your own retention cap, applied to every conversation, never transmitted, and free to be stricter than any mutual timer. `/purge now` deletes stored messages immediately, all conversations or just one. Both are local. Deleting from browser storage is not forensic erasure.",
  delete:
    "Deletes your OWN messages from both sides: they go from your history, and a request to remove them goes to the other client over the encrypted channel. Their incoming messages are never touched. Add `/s` to do it without a notice on either end. Cooperative, not guaranteed: a client that ignores the request keeps its copy.",
  rotate:
    "Re-wraps the store's encryption key under a new passphrase. Local and instant: only the wrapper changes, so nothing is re-encrypted and nothing is sent anywhere. Worth doing if you suspect someone watched you type the old one. It does not change an armed duress passphrase.",
  settings:
    "Preferences, in two groups that are stored differently on purpose. Security posture (trust mode, the rotation reminder) lives encrypted, so it needs an unlocked store. Appearance (scheme, colors, emblem, atmosphere layers, passphrase echo) lives unencrypted, so it can apply to the lock screen before you have unlocked anything. Run `/help` for the full list of subcommands.",
  duress:
    "Arms a second passphrase that DESTROYS this device's store and deletes your account from the server, instead of unlocking anything. There is no confirmation and no undo: the screen shows the same 'unlock failed' a typo produces, because looking unremarkable is the whole point. Off by default. `/duress set` prints the full warning and makes you type yes before anything is armed. The passphrase must differ from your real one, and it needs the same strength, because it seals a copy of your identity key.",
  keys: "`/keys status` shows how old your signed prekey is and how many one-time prekeys the server still holds for you. Those are what let people start a conversation with you while you are offline. They refill automatically when they run low; `/keys refill` tops them up by hand.",
  bench:
    "Runs the post-quantum-versus-classical benchmark suites in this browser and prints the tables: primitive latency, size overhead, and protocol-level timings. A research tool, not part of messaging.",
  wipe: "Destroys the local store: identity, keys, contacts, history, everything on this device. Irreversible unless you still have a recovery code. It asks you to repeat it within 30 seconds. Your account continues to exist on the server; this only clears this device.",
  clr: "Clears the transcript, the delivery ticks, and the discarded-notice panel. Ctrl+L does the same. Cosmetic only: nothing stored is touched, and anything cleared here is still in your history.",
  help: "With no argument, lists every command grouped by what it is for. With one, prints that command's usage and explains what it actually does and what it costs. Aliases resolve to the real command, so `/help msg` explains `/chat`.",
};

/** Break `text` into lines no wider than `width`, keeping whole words. A word
 * longer than the whole measure is emitted on its own line rather than being
 * cut, so a URL or a UID is never silently chopped. */
export function wrapText(text: string, width: number): string[] {
  const limit = Math.max(1, width);
  const lines: string[] = [];
  let current = "";
  for (const word of text.split(/\s+/).filter((w) => w.length > 0)) {
    if (current.length === 0) {
      current = word;
    } else if (current.length + 1 + word.length <= limit) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current.length > 0) {
    lines.push(current);
  }
  return lines;
}

/** Clamp a reported terminal width into the range the layout reasons about. */
function layoutWidth(columns: number): number {
  const usable = Number.isFinite(columns) ? Math.floor(columns) : DEFAULT_HELP_COLUMNS;
  return Math.max(MIN_LAYOUT_COLUMNS, Math.min(usable, MAX_LAYOUT_COLUMNS));
}

/** One command's rows in the wide layout: the command, dot leaders out to the
 * shared description column, then the description, wrapped with a hanging
 * indent so a continuation lines up under the first word rather than under the
 * leaders. */
function wideEntry(entry: HelpEntry, cmdWidth: number, width: number): string[] {
  const indent = 2;
  // Layout of a row: indent, command, space, leaders, space, description. The
  // description column is fixed for the whole section, so the leader run is
  // whatever is left over - and the +1 guarantees even the longest command in
  // the section gets one dot rather than being pushed out of alignment.
  const descColumn = indent + cmdWidth + 3;
  const descWidth = Math.max(16, width - descColumn);
  const leaders = ".".repeat(Math.max(1, cmdWidth - entry.cmd.length + 1));
  const [first = "", ...rest] = wrapText(entry.blurb, descWidth);
  const head = `${" ".repeat(indent)}${entry.cmd} ${leaders} ${first}`.trimEnd();
  return [head, ...rest.map((line) => `${" ".repeat(descColumn)}${line}`)];
}

/** One command's rows in the narrow layout: the command alone, its description
 * indented beneath. */
function narrowEntry(entry: HelpEntry, width: number): string[] {
  const rows = [`  ${entry.cmd}`];
  for (const line of wrapText(entry.blurb, Math.max(16, width - 6))) {
    rows.push(`      ${line}`);
  }
  return rows;
}

/** The full grouped command reference as plain lines, laid out for `columns`. */
export function renderHelp(columns: number = DEFAULT_HELP_COLUMNS): string[] {
  const width = layoutWidth(columns);
  const narrow = width < NARROW_COLUMNS;
  const lines: string[] = [];
  for (const line of wrapText(
    "Meridian Edge commands - anything not starting with / is a message to the active chat",
    width,
  )) {
    lines.push(line);
  }
  for (const section of SECTIONS) {
    lines.push("");
    lines.push(section.title);
    // Per-section column width, so a short section is not stretched out by the
    // longest command in some other section.
    const cmdWidth = Math.max(...section.entries.map((entry) => entry.cmd.length));
    for (const entry of section.entries) {
      lines.push(...(narrow ? narrowEntry(entry, width) : wideEntry(entry, cmdWidth, width)));
    }
  }
  lines.push("");
  lines.push(...wrapText(aliasLine(), width));
  lines.push("");
  lines.push(...wrapText("/help <command> explains any one of these in full.", width));
  lines.push(
    ...wrapText(
      "tip: Tab completes, up/down recalls history, and a leading space escapes a message that starts with /",
      width,
    ),
  );
  return lines;
}

/** A one-line summary of the command aliases, grouped by their canonical target
 * and generated from COMMAND_ALIASES so it never drifts from what executes. */
function aliasLine(): string {
  const byCanonical = new Map<string, string[]>();
  for (const [alias, canonical] of Object.entries(COMMAND_ALIASES)) {
    const list = byCanonical.get(canonical) ?? [];
    list.push(`/${alias}`);
    byCanonical.set(canonical, list);
  }
  const parts = [...byCanonical.entries()].map(
    ([canonical, aliases]) => `${aliases.join(" ")} -> /${canonical}`,
  );
  return `aliases: ${parts.join(" · ")}`;
}

/** `/help <command>`: what it does and what it costs, then how to type it.
 * The explanation leads, because someone asking about a command they have not
 * run yet needs to know what it is before they need its argument order. */
export function renderCommandHelp(
  word: CommandWord,
  columns: number = DEFAULT_HELP_COLUMNS,
): string[] {
  const width = layoutWidth(columns);
  const lines = [`  /${word}`, ""];
  for (const line of wrapText(EXPLANATIONS[word], Math.max(16, width - 2))) {
    lines.push(`  ${line}`);
  }
  lines.push("");
  // A usage string may enumerate several forms joined by "  |  "; one per line
  // keeps them readable at any width.
  const forms = COMMAND_USAGE[word].split("  |  ");
  lines.push(forms.length > 1 ? "  usage:" : `  usage: ${forms[0] ?? ""}`);
  if (forms.length > 1) {
    for (const form of forms) {
      lines.push(`    ${form}`);
    }
  }
  return lines;
}
