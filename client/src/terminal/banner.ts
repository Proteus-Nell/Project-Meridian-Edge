// The startup banner: the first thing a new user reads. It leads with
// plain language and a numbered path to a working conversation, because the
// terminal offers no buttons to discover - the only way in is knowing which
// command to type. The cryptography is named at the end as a footnote, not as
// the opening pitch.
//
// Pure and total: returns ANSI-styled lines that main.ts writes into the
// transcript. Widths are kept within BANNER_MAX_COLUMNS so the text does not
// wrap awkwardly on a narrow phone viewport.

/** Visible-width budget for every banner line, chosen so the block survives a
 * ~60-column mobile terminal without mid-word wrapping. */
export const BANNER_MAX_COLUMNS = 60;

const RESET = "\x1b[0m";
const DIM = "\x1b[2m";
const DIM_CYAN = "\x1b[2;36m";
const ACCENT = "\x1b[36m";
const BOLD = "\x1b[1m";

const WORDMARK = "M E R I D I A N   E D G E";

/** Strip ANSI SGR sequences so a line's printed width can be measured. */
export function visibleWidth(line: string): number {
  // The escape character is the point: this matches ANSI colour sequences in
  // order to discount them from the width.
  // eslint-disable-next-line no-control-regex
  return line.replace(/\x1b\[[0-9;]*m/g, "").length;
}

/** The full startup banner, ready to write line by line. */
export function bannerLines(): string[] {
  const rule = "─".repeat(WORDMARK.length + 2);
  return [
    `${DIM_CYAN}╭${rule}╮${RESET}`,
    `${DIM_CYAN}│ ${WORDMARK} │${RESET}`,
    `${DIM_CYAN}╰${rule}╯${RESET}`,
    "",
    "A private messenger. Messages are encrypted on your",
    "device and can only be read by the person you send",
    `them to ${DIM}-${RESET} not by the server, and not by us.`,
    "",
    `${BOLD}New here? Three steps:${RESET}`,
    `  ${ACCENT}1.${RESET} ${BOLD}/register${RESET}      pick a passphrase, then write`,
    `                    down the recovery codes it shows`,
    `  ${ACCENT}2.${RESET} ${BOLD}/whoami${RESET}        shows your UID ${DIM}-${RESET} send it to a`,
    `                    friend so they can add you`,
    `  ${ACCENT}3.${RESET} ${BOLD}/add <uid>${RESET}     add their UID, then`,
    `                    ${BOLD}/chat <name>${RESET} to start talking`,
    "",
    `Type ${BOLD}/help${RESET} at any time for every command.`,
    `${DIM}Tip: text that does not start with / is sent as a${RESET}`,
    `${DIM}message to whoever you are chatting with.${RESET}`,
    "",
    `${DIM}Post-quantum by design: ML-KEM-768 + ML-DSA-65.${RESET}`,
    "",
  ];
}
