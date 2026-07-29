// Shared fakes for the executor integration tests. Each executor-*.test.ts used
// to hand-declare its own FakeShell / CaptureSink / FakeChrome; those were near
// duplicates, so they live here once. The classes are supersets - they record
// everything any single test asserts on, which is harmless to tests that ignore
// the extra fields.
//
// The api mock (vi.mock("../src/net/api", ...)) deliberately stays in each test
// file: vi.mock is hoisted per-file and its factory path is resolved relative to
// the test, so it cannot be centralised here.

import type { LineSink } from "../../src/terminal/renderer";
import type { ShellIO } from "../../src/terminal/shell";
import type { EmblemState, UiChrome } from "../../src/terminal/executor/context";
import type { ThemePrefs } from "../../src/crypto/store";
import type {
  AccessibilityPrefs,
  EmblemName,
  FontName,
  ResolvedScheme,
} from "../../src/terminal/theme";

/** Scripted shell: push answers onto `secrets` (passphrases) and `lines`
 * (confirmations) in the order the flow consumes them; an empty queue yields
 * null, which reads as a Ctrl+C / cancelled prompt. `masks` records
 * setSecretMask calls for the /settings mask tests. */
export class FakeShell implements ShellIO {
  secrets: (string | null)[] = [];
  lines: (string | null)[] = [];
  /** Prompt text passed to each readLine call, so a test can assert which
   * confirmation was shown (e.g. "rotate anyway? (y/N): "). */
  lineQueries: string[] = [];
  /** Command-line prompt strings set via setPrompt, so a test can assert the
   * active-chat prompt (e.g. "[ali] > "). */
  prompts: string[] = [];
  masks: string[] = [];
  readSecret(): Promise<string | null> {
    return Promise.resolve(this.secrets.shift() ?? null);
  }
  readLine(promptText = ""): Promise<string | null> {
    this.lineQueries.push(promptText);
    return Promise.resolve(this.lines.shift() ?? null);
  }
  setPrompt(prompt = ""): void {
    this.prompts.push(prompt);
  }
  setSecretMask(mask: string): void {
    this.masks.push(mask);
  }
}

/** Collects rendered lines. `text()` joins them with ANSI styling stripped, so
 * assertions match the visible characters rather than the color codes
 * peerMessage and friends emit. */
export class CaptureSink implements LineSink {
  lines: string[] = [];
  printLine(line: string): void {
    this.lines.push(line);
  }
  text(): string {
    // eslint-disable-next-line no-control-regex
    return this.lines.join("\n").replace(/\x1b\[[0-9;]*m/g, "");
  }
}

/** Records every UiChrome interaction so tests can assert on delivery ticks,
 * the chat-context segment, discard notices, echoes, and the theme/scheme/
 * emblem application calls. */
export class FakeChrome implements UiChrome {
  confirms = 0;
  rejects = 0;
  clears = 0;
  context: string | null = null;
  emblem: EmblemState | "unset" = "unset";
  echoes: Array<{ line: string; kind: string }> = [];
  discarded: Array<{ code: string; text: string }> = [];
  themes: ThemePrefs[] = [];
  schemes: ResolvedScheme[] = [];
  glyphs: EmblemName[] = [];
  /** Transcript width reported to width-aware output (/help). Assignable so a
   * test can render the same command at a phone width and a desktop one. */
  width = 80;
  fonts: Array<{ font: FontName; fontSize: number }> = [];
  accessibility: AccessibilityPrefs[] = [];
  echoInput(line: string, kind: "command" | "message" = "command"): void {
    this.echoes.push({ line, kind });
  }
  confirmSent(): void {
    this.confirms += 1;
  }
  rejectSent(): void {
    this.rejects += 1;
  }
  noteDiscarded(code: string, text: string): void {
    this.discarded.push({ code, text });
  }
  clearScreen(): void {
    this.clears += 1;
  }
  setChatContext(text: string | null): void {
    this.context = text;
  }
  applyTheme(theme: ThemePrefs): void {
    this.themes.push(theme);
  }
  setEmblemState(state: EmblemState): void {
    this.emblem = state;
  }
  applyScheme(scheme: ResolvedScheme): void {
    this.schemes.push(scheme);
  }
  applyEmblem(name: EmblemName): void {
    this.glyphs.push(name);
  }
  columns(): number {
    return this.width;
  }
  applyFont(font: FontName, fontSize: number): void {
    this.fonts.push({ font, fontSize });
  }
  applyAccessibility(prefs: AccessibilityPrefs): void {
    this.accessibility.push(prefs);
  }
}
