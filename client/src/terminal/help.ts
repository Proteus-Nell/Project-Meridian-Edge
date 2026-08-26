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
      { cmd: "/remove <alias|uid> [purge]", blurb: "remove a contact (purge also deletes history); /remove all clears everyone" },
      { cmd: "/rename <alias|uid> <new>", blurb: "give a contact a new local alias" },
      { cmd: "/favourite <alias|uid> [off]", blurb: "pin a contact to the top of your contact list" },
      { cmd: "/contacts", blurb: "list saved contacts with their UIDs and trust state" },
      { cmd: "/group new <name> <who>...", blurb: "create a group and invite its members" },
      { cmd: "/group list", blurb: "every group on this device" },
      { cmd: "/group open <name>", blurb: "focus a group conversation" },
      { cmd: "/group info <name>", blurb: "its roster and member-list fingerprint" },
      { cmd: "/group add <name> <who>", blurb: "add a member (everyone is told)" },
      { cmd: "/group remove <name> <who>", blurb: "remove a member (everyone is told)" },
      { cmd: "/group leave <name>", blurb: "leave a group" },
      { cmd: "/group sync <name>", blurb: "add members you have no contact for, so you can reach them" },
      { cmd: "/group purge <name>", blurb: "delete a group and its local history" },
      { cmd: "/chat <alias|uid>", blurb: "open a conversation (a focused view that hides everything else)" },
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
      { cmd: "/settings scheme <name>", blurb: "switch scheme: dark | parchment | olive | contrast | one of yours" },
      { cmd: "/settings scheme list", blurb: "every scheme you can switch to" },
      { cmd: "/settings scheme new <name>", blurb: "copy the current colors into a scheme of your own" },
      { cmd: "/settings scheme delete <name>", blurb: "delete one of your schemes (presets cannot be)" },
      { cmd: "/settings color <slot> <#hex>", blurb: "edit a color; on a preset this forks it, leaving it intact" },
      { cmd: "/settings color event <slot> <#hex>", blurb: "recolor the [✓] [!] [*] [E###] markers and peer names" },
      { cmd: "/settings color reset", blurb: "put your scheme back to its base preset's colors" },
      { cmd: "/settings font <name>", blurb: "monospace stack: default | system | classic | wide | compact" },
      { cmd: "/settings font list", blurb: "the stacks, and what each one is for" },
      { cmd: "/settings fontsize <10-28>", blurb: "terminal size in px; the terminal re-fits itself" },
      { cmd: "/settings spacing letter <0-4>", blurb: "extra space between characters, in px" },
      { cmd: "/settings spacing line <1-2.5>", blurb: "line height as a multiple of the font size" },
      { cmd: "/settings emblem <name>", blurb: "medallion glyph: globe | tree | gaia" },
      { cmd: "/settings theme <layer> <on|off>", blurb: "toggle atmosphere layers" },
    ],
  },
  {
    title: "Preferences",
    entries: [
      { cmd: "/settings trust <auto|manual>", blurb: "auto-verify contacts (TOFU) or verify by hand" },
      { cmd: "/settings mask <asterisk|hidden>", blurb: "passphrase echo style" },
      { cmd: "/settings rotation <on|off|day>", blurb: "weekly passphrase-rotation prompt" },
      { cmd: "/settings notify <on|off>", blurb: "desktop notification when a message arrives in the background" },
      { cmd: "/settings a11y screenreader <on|off>", blurb: "mirror terminal output into an ARIA live region" },
      { cmd: "/settings a11y motion <on|off>", blurb: "force reduced motion, whatever your OS says" },
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
 * entry the alias executes.
 *
 * Kept to what the reader needs before running the command: what it does, and
 * any cost that is not obvious from the name. Background, rationale and the
 * full threat model belong in the README, not in a terminal pager. */
const EXPLANATIONS: Record<CommandWord, string> = {
  register:
    "Creates a new identity on this device. You choose a passphrase, which never leaves the device and is the only thing protecting your stored messages. Prints your UID and ten recovery codes, shown once. Write the codes down before doing anything else.",
  recover:
    "Takes your account back onto this device using one recovery code, after a lost passphrase or on a new device. Message history, contacts and sessions do not survive, and your contacts will see an identity-key-change warning on your next message.",
  login:
    "Unlocks the local store with your passphrase and signs in by signing a server challenge. No password is ever sent. The session lives in memory only and expires after 15 minutes idle.",
  logout:
    "Revokes this session on the server and locks the local store. Your data stays on the device, encrypted. `/logout all` instead signs out every other device and keeps this one.",
  sessions:
    "Lists everywhere this account is signed in, marking the device you are on. Sessions are anonymous by design, so each shows only when it started and when it was last active.",
  lock: "Locks the store and wipes key material from memory. Happens automatically after 10 minutes idle.",
  whoami:
    "Prints your UID, the address people need to add you, and your identity-key fingerprint. There is no directory, so the UID has to travel out-of-band.",
  add: "Saves a contact by UID. The alias is local only and never transmitted. Also accepts a waiting contact request, showing the message that was held back.",
  remove:
    "Deletes a contact and tears down the shared session, so a later message from them arrives as a fresh request. Keeps message history unless you add `purge`. Purely local; the other side is never told.",
  rename:
    "Changes a contact's local alias. History is keyed by UID, so it survives untouched. A name another contact already uses is rejected.",
  favourite:
    "Pins a contact to the top of `/contacts` and the home dashboard, marked with an asterisk. Local only, and the contact is never told.",
  contacts:
    "Lists every saved contact with its alias, full UID and trust state, plus any contact requests still waiting for `/add`.",
  group:
    "Group conversations. Each message is sent separately to every member over the ratchet you already share with them, so there is no group key and the server sees only ordinary traffic. Membership is not cryptographically agreed: a member list that disagrees with yours is reported, not prevented. Removing someone stops future messages and takes back nothing.",
  chat: "Focuses one conversation: the transcript shows only its history, and plain text you type is sent to them. `/chat <alias> <message>` does both at once.",
  home: "Returns to the home dashboard: every conversation at a glance, with unread counts, trust state, timers and waiting contact requests.",
  return:
    "Toggles back to the screen you were on before this one. Toggling again returns, like a back/forward button.",
  verify:
    "Fetches the contact's current identity key and prints a 60-digit safety number to compare with them out-of-band. Only shows the number; `/verified` records the result.",
  verified:
    "Marks a contact trusted after their safety number matched. Revoked automatically if their key ever changes.",
  ack: "Clears a blocking identity-key-change warning so the conversation is usable again. It does not mean you trust the new key: the contact stays UNVERIFIED until you `/verify` and `/verified` it.",
  timer:
    "Sets a disappearing-message timer for one conversation. Mutual: it is carried to the other side and applied on both. Cooperative, and nothing stops a screenshot.",
  purge:
    "`/purge set` is your own retention cap, never transmitted and free to be stricter than any mutual timer. `/purge now` deletes stored messages immediately. Both are local only.",
  delete:
    "Deletes your own messages from both sides: yours locally, and a removal request to the other client. Their messages are never touched. Add `/s` for no notice on either end.",
  rotate:
    "Re-wraps the store's key under a new passphrase. Local and instant, since only the wrapper changes. Does not affect an armed duress passphrase.",
  settings:
    "Preferences. Security posture lives encrypted and needs an unlocked store; appearance lives unencrypted so it can apply to the lock screen. Run `/help` for the full list of subcommands.",
  duress:
    "Arms a second passphrase that destroys this device's store and deletes your account, instead of unlocking anything. No confirmation, no undo, and the screen shows only the usual 'unlock failed'. Off by default; `/duress set` warns in full first.",
  keys: "Shows how old your signed prekey is and how many one-time prekeys the server holds, which is what lets people start conversations while you are offline. They refill automatically; `/keys refill` tops them up by hand.",
  bench:
    "Runs the post-quantum versus classical benchmark suites in this browser and prints the tables. A research tool, not part of messaging.",
  wipe: "Destroys the local store: identity, keys, contacts, history. Irreversible without a recovery code, and it asks you to repeat it within 30 seconds. Your account still exists on the server.",
  clr: "Clears the transcript, the delivery ticks, and the discarded-notice panel. Cosmetic only; nothing stored is touched.",
  help: "With no argument, lists every command grouped by purpose. With one, explains that command and prints its usage. Aliases resolve to the real command, so `/help msg` explains `/chat`.",
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
    "Meridian Edge commands. Anything not starting with / is a message to the active chat.",
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
