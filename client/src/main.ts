import { Terminal } from "@xterm/xterm";
import type { ITerminalOptions } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import "./style.css";

import { bannerLines } from "./terminal/banner";
import { preloadDisplayStyle } from "./terminal/paint";
import { parseLine } from "./terminal/parser";
import { Renderer } from "./terminal/renderer";
import { Shell } from "./terminal/shell";
import { Executor } from "./terminal/executor";
import { Chrome } from "./terminal/chrome";
import { commandSuggestions, longestCommonPrefix } from "./terminal/suggest";

// FIRST statement of the app: start reading the saved colour scheme before
// anything else, so the IndexedDB round-trip overlaps xterm's construction and
// mount rather than following it. #app is hidden (style.css) until this
// resolves, so no content is ever painted in the default scheme first.
const displayStyleReady = preloadDisplayStyle();

function mount(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (el === null) {
    throw new Error(`missing #${id} in the page shell`);
  }
  return el;
}

// Both terminals run with a TRANSPARENT background (allowTransparency) so the
// page supplies the backdrop - that is what lets the emblem watermark and the
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
// All output - including untrusted peer/message text via the sanitizing
// renderer - renders here as xterm text cells. allowProposedApi unlocks
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

const chrome = new Chrome(transcriptTerm, inputTerm);

// Re-fit both terminals to their containers on any layout change. A
// ResizeObserver is more reliable than window 'resize' alone (it also catches
// the mobile keyboard shrinking the dvh viewport and device rotation), and the
// minmax(0,1fr) column lets the containers actually shrink so fit() converges.
const refit = (): void => {
  transcriptFit.fit();
  inputFit.fit();
  // fit() may have changed the transcript's column count; re-pin the delivery
  // ticks to the new right edge (their decoration x was fixed at the old cols).
  chrome.reflowTicks();
};
const resizeObserver = new ResizeObserver(refit);
resizeObserver.observe(mount("transcript-pane"));
resizeObserver.observe(mount("command-line"));
window.addEventListener("resize", refit);

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
// chrome is both the status strip (StatusSink) and the discarded-notice panel
// (NoticeSink); the renderer routes to each without knowing about the DOM.
const renderer = new Renderer(shell, undefined, chrome, chrome);
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

// Re-apply the persisted display preferences through the executor once the
// terminals exist: same prefs as the preload above (idempotent), but this pass
// also themes the two xterm instances and sets the passphrase mask. Sequenced
// after the preload so the two cannot race on the CSS variables.
void displayStyleReady.then(() => executor.init());

// Startup banner: the boxed wordmark plus a plain-language intro and the
// three-step path to a first conversation (terminal/banner.ts).
for (const row of bannerLines()) {
  transcriptTerm.writeln(row);
}
chrome.status("info", "Ready - type /register to get started, or /help to see every command.");

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
