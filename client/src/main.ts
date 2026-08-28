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
import { mirrorTerminalStyles } from "./terminal/stylemirror";
import { DEFAULT_FONT, DEFAULT_FONT_SIZE, FONT_STACKS } from "./terminal/theme";

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

// The face and size here are only the pre-preferences default: executor.init()
// re-applies the stored /settings font and /settings fontsize once the display
// prefs have been read, and re-fits afterwards because both move the cell box.
const SHARED: ITerminalOptions = {
  fontFamily: FONT_STACKS[DEFAULT_FONT],
  fontSize: DEFAULT_FONT_SIZE,
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
// xterm generates its cell metrics, ANSI palette, attributes and cursor as
// <style> elements, which the production CSP's `style-src 'self'` blocks. Mirror
// them into adopted stylesheets, which are CSSOM and so exempt (stylemirror.ts).
// Inert in dev, where the sheets apply normally. Must run before fit(): without
// the cell metrics the measured character box - and therefore `cols` - is wrong.
mirrorTerminalStyles(mount("transcript"));
transcriptFit.fit();

// Command-line terminal: a single-row input that the shell drives.
const inputTerm = new Terminal({ ...SHARED, cursorBlink: true, rows: 1 });
const inputFit = new FitAddon();
inputTerm.loadAddon(inputFit);
inputTerm.open(mount("command-line"));
mirrorTerminalStyles(mount("command-line"));
inputFit.fit();

const chrome = new Chrome(transcriptTerm, inputTerm);

// Re-fit both terminals to their containers on any layout change. A
// ResizeObserver is more reliable than window 'resize' alone (it also catches
// the mobile keyboard shrinking the dvh viewport and device rotation), and the
// minmax(0,1fr) column lets the containers actually shrink so fit() converges.
//
// Two guards matter here, and both exist because a wrong column count is not a
// cosmetic bug. xterm hard-wraps at `cols`, so if cols ends up LARGER than what
// the container can actually show, every long line is painted partly outside
// the visible area: the row appears to lose a run of characters in the middle
// while the tail turns up on the next row. On a phone that lands on exactly the
// text you cannot afford to lose - the UID at registration, a recovery code.
//
//   1. Never fit against a container that is not laid out. A transient zero
//      size (mobile keyboard opening, rotation, the pane before first paint)
//      makes FitAddon propose its 2x1 floor, and nothing would re-fit
//      afterwards, so that garbage would stick.
//   2. Always fit again on the trailing edge. Mobile viewport changes arrive as
//      a burst mid-transition, so the measurement that matters is the last one,
//      after the layout settles.
const MIN_FITTABLE_PX = 24;

const fitTerminals = (): void => {
  const pane = mount("transcript-pane");
  if (pane.clientWidth < MIN_FITTABLE_PX || pane.clientHeight < MIN_FITTABLE_PX) {
    return; // mid-transition or not yet laid out: measuring now would lie
  }
  transcriptFit.fit();
  inputFit.fit();
  // fit() may have changed the transcript's column count; re-pin the delivery
  // ticks to the new right edge (their decoration x was fixed at the old cols).
  chrome.reflowTicks();
};

let settleTimer: ReturnType<typeof setTimeout> | null = null;
const refit = (): void => {
  fitTerminals();
  if (settleTimer !== null) {
    clearTimeout(settleTimer);
  }
  settleTimer = setTimeout(() => {
    settleTimer = null;
    fitTerminals();
  }, 120);
};
// A font or size change moves the cell box exactly as a resize does, so the
// chrome re-fits through the same debounced path rather than its own.
chrome.setRefit(refit);
const resizeObserver = new ResizeObserver(refit);
resizeObserver.observe(mount("transcript-pane"));
resizeObserver.observe(mount("command-line"));
window.addEventListener("resize", refit);
window.addEventListener("orientationchange", refit);

// The first fit above ran against whatever font the browser had resolved at
// that instant. None of the preferred families ship on Android or iOS, so a
// phone falls back to its generic monospace, and if that swap lands after the
// initial measurement the cell width - and therefore the column count - is
// wrong. Re-fit once the font set is settled.
if (typeof document.fonts !== "undefined") {
  void document.fonts.ready.then(refit);
}

// Declared before the shell and assigned after it: the shell's submit callback
// closes over the executor, and the executor needs the shell, so one of the two
// has to be filled in second. The callback only runs on user input, long after
// the assignment below.
// eslint-disable-next-line prefer-const
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
// The renderer owns which day the transcript is on; the chrome writes the echo
// of a message you send, and needs to open a new day for it (renderer.DayMarker).
chrome.setDayMarker(renderer);
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
chrome.status("info", "Ready. Type /register to get started, or /help to see every command.");

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
