// Help text rendering. Pure and total: returns plain lines the
// renderer prints as-is. Grouped into sections with the command names aligned
// in a column, so `/help` reads as a tidy reference rather than a flat dump.
// Text-only (no ANSI): the renderer sanitizes plain output, which would strip
// escape codes anyway, and app-generated help never needs markup.

import { COMMAND_ALIASES, COMMAND_USAGE } from "./parser";
import type { CommandWord } from "./parser";

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
      { cmd: "/help [command]", blurb: "this list, or the usage for one command" },
    ],
  },
];

/** The full grouped command reference as plain lines. */
export function renderHelp(): string[] {
  const width = Math.max(
    ...SECTIONS.flatMap((section) => section.entries.map((entry) => entry.cmd.length)),
  );
  const lines: string[] = [
    "Meridian Edge commands  -  anything not starting with / is a message to the active chat",
  ];
  for (const section of SECTIONS) {
    lines.push("");
    lines.push(`${section.title}`);
    for (const entry of section.entries) {
      lines.push(`  ${entry.cmd.padEnd(width)}  ${entry.blurb}`);
    }
  }
  lines.push("");
  lines.push(aliasLine());
  lines.push("tip: Tab completes · ↑/↓ recall history · lead a message with a space to escape /");
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
  const parts = [...byCanonical.entries()].map(([canonical, aliases]) => `${aliases.join(" ")} → /${canonical}`);
  return `aliases: ${parts.join(" · ")}`;
}

/** Usage for a single command (the `/help <command>` form). */
export function renderCommandHelp(word: CommandWord): string[] {
  return [`  usage: ${COMMAND_USAGE[word]}`];
}
