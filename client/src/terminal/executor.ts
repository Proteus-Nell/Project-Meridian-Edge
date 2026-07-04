// Command executor: consumes the parser's typed union in one switch
// (CLAUDE.md §1.2). W1 implements /register, /whoami, /add, /chat and /help;
// later-segment commands respond with their scheduled segment so the surface
// is honest about what exists.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { register as apiRegister, ApiError } from "../net/api";
import type { Command, ParseResult } from "./parser";
import { COMMAND_USAGE, formatUid, normalizeUid } from "./parser";
import type { Renderer } from "./renderer";
import type { Shell } from "./shell";

interface Identity {
  readonly uid: string; // formatted for display
  readonly publicKey: Uint8Array;
  // TODO(W2): move into the Argon2id-wrapped IndexedDB store; zeroize on lock.
  readonly secretKey: Uint8Array;
}

interface Contact {
  readonly uid: string; // canonical 26-char form
  readonly alias: string;
}

const SEGMENT_OF: Partial<Record<Command["name"], string>> = {
  login: "W2 (identity & key store)",
  logout: "W2 (identity & key store)",
  lock: "W2 (identity & key store)",
  "rotate-passphrase": "W2 (identity & key store)",
  "settings-rotation": "W2 (identity & key store)",
  "keys-status": "W2 (identity & key store)",
  "keys-refill": "W2 (identity & key store)",
  wipe: "W2 (identity & key store)",
  verify: "W4 (ratchet & trust)",
  verified: "W4 (ratchet & trust)",
  timer: "W5 (lifecycle & hardening)",
  "purge-set": "W5 (lifecycle & hardening)",
  "purge-now": "W5 (lifecycle & hardening)",
  bench: "W6 (benchmarks)",
  "settings-notify": "W6 (could-have)",
};

export class Executor {
  private identity: Identity | null = null;
  private contacts = new Map<string, Contact>(); // key: alias
  private active: Contact | null = null;
  private registering = false;

  constructor(
    private readonly renderer: Renderer,
    private readonly shell: Shell,
  ) {}

  handle(result: ParseResult): void {
    switch (result.kind) {
      case "empty":
        return;
      case "invalid": {
        this.renderer.event("failure", result.error);
        if (result.usage !== undefined) {
          this.renderer.plain(`    usage: ${result.usage}`);
        }
        return;
      }
      case "message": {
        this.handleMessage(result.text);
        return;
      }
      case "command": {
        this.handleCommand(result.command);
        return;
      }
    }
  }

  private handleMessage(text: string): void {
    if (this.active === null) {
      this.renderer.event("warning", "no active conversation - use /chat <alias|uid> first");
      return;
    }
    void text;
    this.renderer.event(
      "warning",
      `not sent to ${this.active.alias}: messaging arrives in W3 (handshake + delivery queue)`,
    );
  }

  private handleCommand(cmd: Command): void {
    switch (cmd.name) {
      case "help": {
        this.printHelp(cmd.topic);
        return;
      }
      case "register": {
        void this.doRegister();
        return;
      }
      case "whoami": {
        if (this.identity === null) {
          this.renderer.event("warning", "no identity yet - run /register");
          return;
        }
        const fingerprint = bytesToHex(sha512(this.identity.publicKey).slice(0, 16));
        this.renderer.event("info", `UID: ${this.identity.uid}`);
        this.renderer.event("info", `identity-key fingerprint (SHA-512/128): ${fingerprint}`);
        return;
      }
      case "add": {
        const alias = cmd.alias ?? cmd.uid;
        this.contacts.set(alias, { uid: cmd.uid, alias });
        this.renderer.event(
          "success",
          `added contact ${alias} (${formatUid(cmd.uid)}) - alias is local-only`,
        );
        return;
      }
      case "chat": {
        const contact = this.resolveContact(cmd.target);
        if (contact === null) {
          this.renderer.event("failure", `unknown contact: ${cmd.target} - use /add <uid> [alias]`);
          return;
        }
        this.active = contact;
        this.renderer.event("info", `chatting with: ${contact.alias} (UNVERIFIED)`);
        this.shell.setPrompt(`[${contact.alias}] > `);
        return;
      }
      case "ack": {
        this.renderer.event("info", `nothing to acknowledge for ${cmd.alias}`);
        return;
      }
      default: {
        const segment = SEGMENT_OF[cmd.name] ?? "a later segment";
        this.renderer.event("info", `/${cmd.name} is not implemented yet - scheduled for ${segment}`);
        return;
      }
    }
  }

  private resolveContact(target: string): Contact | null {
    const byAlias = this.contacts.get(target);
    if (byAlias !== undefined) {
      return byAlias;
    }
    const uid = normalizeUid(target);
    if (uid === null) {
      return null;
    }
    for (const contact of this.contacts.values()) {
      if (contact.uid === uid) {
        return contact;
      }
    }
    return null;
  }

  private async doRegister(): Promise<void> {
    if (this.identity !== null) {
      this.renderer.event("warning", "an identity already exists in this session");
      return;
    }
    if (this.registering) {
      this.renderer.event("warning", "registration already in progress");
      return;
    }
    this.registering = true;
    try {
      this.renderer.event("info", "generating ML-DSA-65 identity keypair...");
      const seed = crypto.getRandomValues(new Uint8Array(32));
      const keys = ml_dsa65.keygen(seed);
      const response = await apiRegister(keys.publicKey);
      this.identity = {
        uid: response.uid,
        publicKey: keys.publicKey,
        secretKey: keys.secretKey,
      };
      this.renderer.event("success", `registered - your UID is ${response.uid}`);
      this.renderer.event("info", "share your UID out-of-band; there is no directory to search");
      this.renderer.event(
        "warning",
        "passphrase-protected key store and recovery codes arrive in W2 - this identity lives in memory only",
      );
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        this.renderer.event("failure", "registration rate limit reached - try again later");
      } else {
        this.renderer.event("failure", "registration failed - is the server running?");
      }
    } finally {
      this.registering = false;
    }
  }

  private printHelp(topic: keyof typeof COMMAND_USAGE | undefined): void {
    if (topic !== undefined) {
      this.renderer.plain(`  ${COMMAND_USAGE[topic]}`);
      return;
    }
    this.renderer.plain("commands (anything else is message text for the active conversation):");
    for (const usage of Object.values(COMMAND_USAGE)) {
      this.renderer.plain(`  ${usage}`);
    }
    this.renderer.plain("  (escape a leading / in a message with a space)");
  }
}
