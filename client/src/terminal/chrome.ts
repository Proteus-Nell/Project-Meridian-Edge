// DOM chrome around the two terminals (CLAUDE.md §1): the footer status strip
// (transient event + persistent chat context), the keyboard-navigable
// autosuggest dropdown, the right-edge "sent" tick marks, and the toggleable
// atmosphere layers (/settings theme). This is the only DOM-building module in
// the client. It never renders untrusted content - message and peer text stay
// in the xterm transcript via the sanitizing renderer - and it only ever
// assigns through textContent / createElement / classList, never a
// markup-parsing sink, so the strict CSP and the CI audit (scripts/audit.py)
// remain satisfied. No new dependency: markers/decorations are xterm's own API.

import type { IDecoration, IMarker, Terminal } from "@xterm/xterm";

import { COMMAND_USAGE, isCommandWord } from "./parser";
import type { EventLevel } from "./renderer";
import type { SuggestionNav } from "./shell";
import type { EmblemState } from "./executor";
import { EMBLEM_NAMES } from "./theme";
import type { EmblemName, ResolvedScheme } from "./theme";
import type { ThemePrefs } from "../crypto/store";

const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

/** DOM-side mirror of the renderer's ANSI event prefixes. Failures carry
 * their E-code inside the text itself (Renderer.error), so they get no
 * glyph here. */
const GLYPH: Record<EventLevel, string> = {
  success: "[✓]",
  warning: "[!]",
  failure: "",
  info: "[*]",
  security: "[SECURITY]",
};

/** How long the transient status stays at full brightness before dimming. */
const STATUS_STALE_MS = 6000;

/** Rows kept in the discarded-notice panel. Oldest are evicted past this so a
 * flood of undecryptable envelopes cannot grow the DOM without bound. */
const MAX_DISCARDED_ROWS = 50;

/** How a submitted line is echoed: commands stay dim log-furniture, message
 * text renders at full brightness so conversations stand out. */
export type EchoKind = "command" | "message";

/** A right-edge delivery tick: the marker pinning it to its message row, the
 * glyph/classes to paint, and the live decoration (null until pinned, replaced
 * on each reflow). Retained so ticks can be re-pinned to the edge on resize. */
interface TickSpec {
  readonly marker: IMarker;
  readonly glyph: string;
  readonly className: string;
  decoration: IDecoration | null;
}

/**
 * Owns everything on the page that is not one of the two terminals.
 * Constructed with the transcript terminal (so it can pin tick decorations to
 * message rows) and looks up its static hosts from the shell skeleton in
 * index.html. Also implements the shell's SuggestionNav seam so arrow keys can
 * drive the dropdown highlight.
 */
export class Chrome implements SuggestionNav {
  private readonly statusEventEl: HTMLElement;
  private readonly statusContextEl: HTMLElement;
  private readonly suggestEl: HTMLElement;
  private readonly sidePanelEl: HTMLElement;
  private readonly discardedListEl: HTMLElement;
  private readonly discardedCountEl: HTMLElement;
  /** Total notices this session, including rows already evicted by the cap. */
  private discardedTotal = 0;
  private lastSentMarker: IMarker | null = null;
  private readonly markers: IMarker[] = [];
  // Each delivery tick keeps its anchoring marker + glyph so it can be
  // re-pinned to the new right edge on resize (a decoration's column x is
  // fixed at creation - see reflowTicks). `decoration` is the live xterm
  // handle, replaced whenever we re-register.
  private readonly ticks: TickSpec[] = [];
  private staleTimer: ReturnType<typeof setTimeout> | null = null;

  // Autosuggest state: the words currently shown, the highlighted row
  // (-1 = none, so Enter still submits the typed line), the input the list was
  // built for, and - after Esc - the input to stay suppressed for until it changes.
  private words: readonly string[] = [];
  private activeIndex = -1;
  private lastInput = "";
  private suppressedFor: string | null = null;
  private onPickCb: ((text: string) => void) | null = null;

  constructor(
    private readonly transcript: Terminal,
    private readonly input: Terminal | null = null,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.statusEventEl = requireEl("status-event");
    this.statusContextEl = requireEl("status-context");
    this.suggestEl = requireEl("autosuggest");
    this.sidePanelEl = requireEl("side-panel");
    this.discardedListEl = requireEl("side-panel-list");
    this.discardedCountEl = requireEl("side-panel-count");
  }

  // ----- discarded-notice panel ----------------------------------------------

  /** Record an inbound message that could not be delivered (renderer.NoticeSink).
   * Opens the right-hand panel on the first notice and appends a row; the list
   * is capped, and the count reflects every notice this session. App-generated
   * text only, assigned through textContent. */
  noteDiscarded(code: string, text: string): void {
    this.discardedTotal += 1;

    const row = document.createElement("div");
    row.className = "dropped-row";
    const head = document.createElement("div");
    head.className = "dropped-head";
    const codeEl = document.createElement("span");
    codeEl.className = "dropped-code";
    codeEl.textContent = code;
    const time = document.createElement("span");
    time.textContent = this.timestamp();
    head.append(codeEl, time);
    const body = document.createElement("span");
    body.className = "dropped-text";
    body.textContent = text;
    row.append(head, body);
    this.discardedListEl.appendChild(row);

    while (this.discardedListEl.childElementCount > MAX_DISCARDED_ROWS) {
      const oldest = this.discardedListEl.firstChild;
      if (oldest === null) {
        break;
      }
      this.discardedListEl.removeChild(oldest);
    }

    this.discardedCountEl.textContent = String(this.discardedTotal);
    this.sidePanelEl.classList.add("open");
    this.discardedListEl.scrollTop = this.discardedListEl.scrollHeight;
  }

  // ----- status strip --------------------------------------------------------

  /** Latest transient status: timestamp, level glyph, then the text,
   * overwritten in place and faded to dim after a few seconds so a stale
   * status does not read as current. Security events never fade. Implements
   * renderer.StatusSink structurally; only textContent assignment, never
   * markup. */
  status(level: EventLevel, text: string): void {
    if (this.staleTimer !== null) {
      clearTimeout(this.staleTimer);
      this.staleTimer = null;
    }
    this.clearChildren(this.statusEventEl);
    this.statusEventEl.classList.remove("stale");
    this.statusEventEl.className = `status-event status-${level}`;

    const time = document.createElement("span");
    time.className = "status-time";
    time.textContent = this.timestamp();
    const body = document.createElement("span");
    body.className = "status-text";
    body.textContent = text;
    if (GLYPH[level] === "") {
      this.statusEventEl.append(time, body);
    } else {
      const glyph = document.createElement("span");
      glyph.className = "status-glyph";
      glyph.textContent = GLYPH[level];
      this.statusEventEl.append(time, glyph, body);
    }

    if (level !== "security") {
      this.staleTimer = setTimeout(() => {
        this.statusEventEl.classList.add("stale");
      }, STATUS_STALE_MS);
    }
  }

  /** Persistent right-hand context: `[chatting with: bob (UNVERIFIED)] [timer: 1h]`
   * (spec §1.5). Never fades; null clears it. App-generated text only. */
  setChatContext(text: string | null): void {
    this.statusContextEl.textContent = text ?? "";
  }

  // ----- transcript echo + delivery ticks ------------------------------------

  /** Echo a submitted line into the transcript and remember its row, so a
   * following confirmSent()/rejectSent() can pin a tick to it. Commands render
   * fully dim; message text renders bright after a dim `> ` so conversations
   * stand out from command chatter. The marker is registered in the write
   * callback (xterm.write is asynchronous) one row above the cursor. */
  echoInput(line: string, kind: EchoKind = "command"): void {
    const rendered =
      kind === "message" ? `${DIM}> ${RESET}${line}` : `${DIM}> ${line}${RESET}`;
    this.transcript.write(`${rendered}\r\n`, () => {
      const marker = this.transcript.registerMarker(-1) ?? null;
      this.lastSentMarker = marker;
      if (marker !== null) {
        this.markers.push(marker);
      }
    });
  }

  /** Pin a delivered tick at the right edge of the most recently echoed line. */
  confirmSent(): void {
    this.tick("✓", "tick");
  }

  /** Pin a failed tick at the right edge of the most recently echoed line.
   * The reason is left to the transcript/status the executor already emitted,
   * so this only marks the row - keeping the UiChrome contract argument-free. */
  rejectSent(): void {
    this.tick("✗", "tick tick-fail");
  }

  private tick(glyph: string, className: string): void {
    const marker = this.lastSentMarker;
    if (marker === null || marker.line < 0) {
      return; // nothing to anchor to (e.g. the row scrolled out of scrollback)
    }
    const spec: TickSpec = { marker, glyph, className, decoration: null };
    this.ticks.push(spec);
    this.pinTick(spec);
  }

  /** Register (or re-register) a tick's decoration at the CURRENT right edge.
   * A decoration's column x is read once at creation and can't be mutated, so
   * this is also the re-pin path used by reflowTicks after a resize. */
  private pinTick(spec: TickSpec): void {
    if (spec.marker.line < 0) {
      return; // row scrolled out of scrollback since it was echoed
    }
    const decoration = this.transcript.registerDecoration({
      marker: spec.marker,
      x: Math.max(0, this.transcript.cols - 1),
      width: 1,
    });
    if (decoration === undefined) {
      return;
    }
    spec.decoration = decoration;
    decoration.onRender((el) => {
      // onRender may fire repeatedly (scroll/resize); these ops are idempotent.
      // ADD our classes rather than replacing className - xterm's own decoration
      // class carries `position: absolute`, which anchors the glyph to the cell.
      el.textContent = spec.glyph;
      for (const cls of spec.className.split(" ")) {
        el.classList.add(cls);
      }
    });
  }

  /** Re-pin every delivery tick to the right edge after the terminal reflows.
   * fit() on resize changes the column count, but each decoration's x was fixed
   * at the old cols-1, so the ticks would otherwise drift inward from the edge
   * (and be wrong from the very first fit if the terminal opened at a default
   * width). Disposing and re-registering against the retained markers is cheap
   * (ticks are few) and idempotent; markers scrolled out of view are skipped by
   * pinTick. Wired to the ResizeObserver/refit path in main.ts. */
  reflowTicks(): void {
    for (const spec of this.ticks) {
      spec.decoration?.dispose();
      spec.decoration = null;
      this.pinTick(spec);
    }
  }

  // ----- autosuggest dropdown -------------------------------------------------

  /** Called on a suggestion row pick (click or Enter/Tab via the nav seam);
   * wired by main.ts to fill the shell's input buffer. */
  setOnPick(cb: (text: string) => void): void {
    this.onPickCb = cb;
  }

  /** Render the dropdown for the current input, or hide it when there is
   * nothing to show. After an Esc close, stays hidden until the input changes. */
  showSuggestions(words: readonly string[], forInput = ""): void {
    this.lastInput = forInput;
    if (this.suppressedFor !== null) {
      if (this.suppressedFor === forInput) {
        this.render([]);
        return;
      }
      this.suppressedFor = null;
    }
    this.render(words);
  }

  hideSuggestions(): void {
    this.render([]);
  }

  private render(words: readonly string[]): void {
    this.words = words;
    this.activeIndex = -1;
    this.clearChildren(this.suggestEl);
    if (words.length === 0) {
      this.suggestEl.classList.remove("open");
      return;
    }
    for (const word of words) {
      const row = document.createElement("div");
      row.className = "suggestion";
      const name = document.createElement("span");
      name.className = "suggestion-name";
      name.textContent = word;
      row.appendChild(name);
      const key = word.slice(1);
      if (isCommandWord(key)) {
        const args = COMMAND_USAGE[key].slice(word.length);
        if (args.length > 0) {
          const hint = document.createElement("span");
          hint.className = "suggestion-hint";
          hint.textContent = args;
          row.appendChild(hint);
        }
      }
      // pointerdown (not click) + preventDefault keeps focus on the input
      // terminal while the pick lands in its buffer.
      row.addEventListener("pointerdown", (e) => {
        e.preventDefault();
        this.onPickCb?.(`${word} `);
        this.render([]);
      });
      this.suggestEl.appendChild(row);
    }
    this.suggestEl.classList.add("open");
  }

  // SuggestionNav (driven by the shell's arrow/Enter/Tab/Esc routing) ---------

  isOpen(): boolean {
    return this.suggestEl.classList.contains("open");
  }

  move(delta: 1 | -1): void {
    if (this.words.length === 0) {
      return;
    }
    const len = this.words.length;
    this.activeIndex =
      this.activeIndex === -1
        ? delta === 1
          ? 0
          : len - 1
        : (this.activeIndex + delta + len) % len;
    const rows = this.suggestEl.children;
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row !== undefined) {
        row.classList.toggle("active", i === this.activeIndex);
        if (i === this.activeIndex) {
          row.scrollIntoView({ block: "nearest" });
        }
      }
    }
  }

  /** The highlighted completion (with a trailing space), or null when no row
   * has been navigated to - Enter then submits the typed line as usual. */
  accept(): string | null {
    const word = this.activeIndex === -1 ? undefined : this.words[this.activeIndex];
    if (word === undefined) {
      return null;
    }
    this.render([]);
    return `${word} `;
  }

  /** Esc: hide and stay hidden until the input buffer changes. */
  close(): void {
    this.suppressedFor = this.lastInput;
    this.render([]);
  }

  // ----- atmosphere layers ----------------------------------------------------

  /** Toggle the CSS-driven visual layers (emblem medallion, scanlines,
   * vignette, footer dock) via body classes. Persisted by the executor in the
   * unencrypted display prefs so the choice applies before unlock too. */
  applyTheme(theme: ThemePrefs): void {
    const body = document.body;
    body.classList.toggle("th-emblem", theme.emblem);
    body.classList.toggle("th-scanlines", theme.scanlines);
    body.classList.toggle("th-vignette", theme.vignette);
    body.classList.toggle("th-dock", theme.dock);
  }

  /** Drive the medallion's animation state: paused when idle, a slow 9s spin
   * while a session is live, and the fast spin + pulse ring while something
   * awaits acknowledgement. The alert state keeps is-playing set - is-tx only
   * shortens the animation, so it must also be running. */
  setEmblemState(state: EmblemState): void {
    document.body.classList.toggle("is-playing", state !== "idle");
    document.body.classList.toggle("is-tx", state === "alert");
  }

  /** Apply a resolved color scheme: the five slot values become CSS custom
   * properties on :root (everything in style.css derives from them), and both
   * terminals get matching xterm themes - transparent backgrounds preserved so
   * the atmosphere layers keep showing through, transcript cursor kept
   * invisible, ANSI overrides applied for light schemes. */
  applyScheme(scheme: ResolvedScheme): void {
    const root = document.documentElement.style;
    root.setProperty("--accent", scheme.accent);
    root.setProperty("--bg", scheme.background);
    root.setProperty("--panel", scheme.panel);
    root.setProperty("--text", scheme.text);
    root.setProperty("--muted", scheme.muted);

    const shared = {
      background: `${scheme.background}00`, // fully transparent, page paints it
      foreground: scheme.text,
      cursor: scheme.accent,
      selectionBackground: `${scheme.muted}66`,
      ...(scheme.ansi ?? {}),
    };
    this.transcript.options.theme = { ...shared, cursor: `${scheme.background}00` };
    if (this.input !== null) {
      this.input.options.theme = shared;
    }
  }

  /** Select which glyph the medallion shows (the ring framing is shared). */
  applyEmblem(name: EmblemName): void {
    for (const emblem of EMBLEM_NAMES) {
      document.body.classList.toggle(`em-${emblem}`, emblem === name);
    }
  }

  // ----- screen clear ---------------------------------------------------------

  /** /clr and Ctrl+L: wipe the transcript, its tick decorations, the strip, and
   * the discarded-notice panel (the only way to dismiss it, so a screen clear
   * genuinely resets what is on screen).
   * `announce` (default true) posts a "screen cleared" status; the conversation
   * redraw after a /delete passes false so the wipe is silent before it reprints. */
  clearScreen(announce = true): void {
    for (const spec of this.ticks) {
      spec.decoration?.dispose();
    }
    for (const marker of this.markers) {
      marker.dispose();
    }
    this.ticks.length = 0;
    this.markers.length = 0;
    this.lastSentMarker = null;
    this.transcript.clear();
    this.clearChildren(this.discardedListEl);
    this.discardedTotal = 0;
    this.discardedCountEl.textContent = "0";
    this.sidePanelEl.classList.remove("open");
    if (announce) {
      this.status("info", "screen cleared");
    }
  }

  private timestamp(): string {
    const d = this.now();
    const pad = (n: number): string => n.toString().padStart(2, "0");
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  private clearChildren(el: HTMLElement): void {
    while (el.firstChild !== null) {
      el.removeChild(el.firstChild);
    }
  }
}

function requireEl(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (el === null) {
    throw new Error(`missing #${id} in the page shell`);
  }
  return el;
}
