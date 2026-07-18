import { Terminal } from "@xterm/xterm";
import type { ITerminalOptions } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import "./style.css";

import { parseLine } from "./terminal/parser";
import { Renderer } from "./terminal/renderer";
import { Shell } from "./terminal/shell";
import { Executor } from "./terminal/executor";
import { Chrome } from "./terminal/chrome";
import { commandSuggestions, longestCommonPrefix } from "./terminal/suggest";

function mount(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (el === null) {
    throw new Error(`missing #${id} in the page shell`);
  }
  return el;
}

// Both terminals run with a TRANSPARENT background (allowTransparency) so the
// page supplies the backdrop — that is what lets the emblem watermark and the
// dock's footer panel show through behind the text (style.css atmosphere
// layers). The page background remains the same #0d1117.
const TRANSPARENT = "#0d111700";

const SHARED: ITerminalOptions = {
  fontFamily: "'Cascadia Mono', 'Fira Mono', Menlo, Consolas, monospace",
  fontSize: 15,
  allowTransparency: true,
  theme: {
    background: TRANSPARENT,
    foreground: "#c9d1d9",
    cursor: "#58a6ff",
  },
};

// Transcript terminal: read-only (disableStdin) so it never competes with the
// command line for keystrokes; its cursor is hidden by making it transparent.
// All output — including untrusted peer/message text via the sanitizing
// renderer — renders here as xterm text cells. allowProposedApi unlocks
// registerDecoration (the right-edge delivery ticks).
const transcriptTerm = new Terminal({
  ...SHARED,
  disableStdin: true,
  cursorBlink: false,
  scrollback: 5000,
  allowProposedApi: true,
  theme: { ...SHARED.theme, cursor: TRANSPARENT },
});
const transcriptFit = new FitAddon();
transcriptTerm.loadAddon(transcriptFit);
transcriptTerm.open(mount("transcript"));
transcriptFit.fit();

// Command-line terminal: a single-row input that the shell drives.
const inputTerm = new Terminal({ ...SHARED, cursorBlink: true, rows: 1 });
const inputFit = new FitAddon();
inputTerm.loadAddon(inputFit);
inputTerm.open(mount("command-line"));
inputFit.fit();

// Re-fit both terminals to their containers on any layout change. A
// ResizeObserver is more reliable than window 'resize' alone (it also catches
// the mobile keyboard shrinking the dvh viewport and device rotation), and the
// minmax(0,1fr) column lets the containers actually shrink so fit() converges.
const refit = (): void => {
  transcriptFit.fit();
  inputFit.fit();
};
const resizeObserver = new ResizeObserver(refit);
resizeObserver.observe(mount("transcript-pane"));
resizeObserver.observe(mount("command-line"));
window.addEventListener("resize", refit);

const chrome = new Chrome(transcriptTerm, inputTerm);

let executor: Executor;
const shell = new Shell(inputTerm, transcriptTerm, (line) => {
  // Parse once: the result styles the echo (messages bright, commands dim) and
  // then drives the executor. Blank lines are no-ops; passphrase/confirm
  // answers go through readSecret/readLine and never reach here, so secrets
  // are never echoed.
  const result = parseLine(line);
  if (line.trim().length > 0) {
    chrome.echoInput(line, result.kind === "message" ? "message" : "command");
  }
  executor.handle(result);
});
const renderer = new Renderer(shell, undefined, chrome);
executor = new Executor(renderer, shell, undefined, undefined, chrome);

// Autosuggest: live dropdown + Tab completion from the pure suggest module,
// arrow/Enter/Esc navigation via the SuggestionNav seam, click-to-fill.
shell.setCompleter((buffer) => {
  const matches = commandSuggestions(buffer);
  if (matches.length === 0) {
    return null;
  }
  const only = matches.length === 1 ? matches[0] : undefined;
  if (only !== undefined) {
    return `${only} `; // unique match: complete it and move past the command word
  }
  const prefix = longestCommonPrefix(matches);
  return prefix.length > buffer.length ? prefix : buffer;
});
shell.onInputChange((buffer) => chrome.showSuggestions(commandSuggestions(buffer), buffer));
shell.setSuggestionNav(chrome);
chrome.setOnPick((text) => {
  shell.setBuffer(text);
  inputTerm.focus();
});
shell.setClearHandler(() => chrome.clearScreen());

// Apply persisted display preferences (passphrase-mask style + theme layers)
// before the user reaches the first prompt.
void executor.init();

// Startup banner: a compact boxed wordmark. Widths are derived from the text so
// the frame always aligns, and it stays ≤ 32 columns for a 38-column mobile
// viewport ("MERIDIAN EDGE" in block letters would not fit, so it is spaced).
const DIM_CYAN = "\x1b[2;36m";
const RESET = "\x1b[0m";
const WORDMARK = "M E R I D I A N   E D G E";
const rule = "─".repeat(WORDMARK.length + 2);
for (const row of [`╭${rule}╮`, `│ ${WORDMARK} │`, `╰${rule}╯`]) {
  transcriptTerm.writeln(`${DIM_CYAN}${row}${RESET}`);
}
transcriptTerm.writeln("");
transcriptTerm.writeln("pure post-quantum E2EE messenger");
transcriptTerm.writeln("all asymmetric crypto: ML-KEM-768 / ML-DSA-65. type /help to begin.");
transcriptTerm.writeln("");
chrome.status("info", "Session established - type /help to view all commands.");

shell.attach();

// Keep typing focused on the command line. The transcript is read-only, but a
// click on it (to select/scroll) can move focus there; refocus on the next key
// unless the user is selecting text in the input area.
const commandLineEl = mount("command-line");
inputTerm.focus();
document.addEventListener(
  "keydown",
  () => {
    if (!commandLineEl.contains(document.activeElement)) {
      inputTerm.focus();
    }
  },
  true,
);
