import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import "./style.css";

import { parseLine } from "./terminal/parser";
import { Renderer } from "./terminal/renderer";
import { Shell } from "./terminal/shell";
import { Executor } from "./terminal/executor";

const container = document.getElementById("terminal");
if (container === null) {
  throw new Error("terminal container missing");
}

const term = new Terminal({
  cursorBlink: true,
  fontFamily: "'Cascadia Mono', 'Fira Mono', Menlo, Consolas, monospace",
  fontSize: 15,
  theme: {
    background: "#0d1117",
    foreground: "#c9d1d9",
  },
});
const fit = new FitAddon();
term.loadAddon(fit);
term.open(container);
fit.fit();
window.addEventListener("resize", () => fit.fit());

let executor: Executor;
const shell = new Shell(term, (line) => {
  executor.handle(parseLine(line));
});
const renderer = new Renderer(shell);
executor = new Executor(renderer, shell);
// Apply persisted display preferences (e.g. passphrase-mask style) before
// the user reaches the first prompt.
void executor.init();

term.writeln("PQTerm - pure post-quantum E2EE messenger (W1 prototype)");
term.writeln("all asymmetric crypto: ML-KEM-768 / ML-DSA-65. type /help to begin.");
term.writeln("");
shell.attach();
term.focus();
