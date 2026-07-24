import { describe, expect, it } from "vitest";

import { formatUid, normalizeUid, parseLine } from "../src/terminal/parser";

const UID = "7Q3KM2VD9XWP4RTBA6HJEZ0123";
const UID_DASHED = "7Q3K-M2VD-9XWP-4RTB-A6HJ-EZ01-23";

describe("message vs command discrimination", () => {
  it("treats plain text as a message", () => {
    expect(parseLine("hello world")).toEqual({ kind: "message", text: "hello world" });
  });

  it("treats a leading space as an escape for a literal /", () => {
    expect(parseLine(" /register")).toEqual({ kind: "message", text: "/register" });
  });

  it("returns empty for blank input", () => {
    expect(parseLine("")).toEqual({ kind: "empty" });
    expect(parseLine("   ")).toEqual({ kind: "empty" });
  });

  it("rejects unknown commands without executing them", () => {
    const result = parseLine("/frobnicate now");
    expect(result.kind).toBe("invalid");
  });

  it("rejects a bare slash", () => {
    expect(parseLine("/").kind).toBe("invalid");
    expect(parseLine("/   ").kind).toBe("invalid");
  });
});

describe("zero-arg commands", () => {
  it.each(
    ["register", "login", "sessions", "lock", "whoami", "home", "return", "contacts", "wipe"] as const,
  )(
    "parses /%s",
    (name) => {
      expect(parseLine(`/${name}`)).toEqual({ kind: "command", command: { name } });
    },
  );

  it("rejects extra arguments instead of guessing", () => {
    expect(parseLine("/register please").kind).toBe("invalid");
    expect(parseLine("/home now").kind).toBe("invalid");
    expect(parseLine("/sessions now").kind).toBe("invalid");
  });

  it("is case-insensitive on the command word", () => {
    expect(parseLine("/REGISTER")).toEqual({ kind: "command", command: { name: "register" } });
  });
});

describe("/logout [all]", () => {
  it("parses bare /logout as this-device sign-out", () => {
    expect(parseLine("/logout")).toEqual({
      kind: "command",
      command: { name: "logout", all: false },
    });
  });

  it("parses /logout all as sign-out-everywhere-else", () => {
    expect(parseLine("/logout all")).toEqual({
      kind: "command",
      command: { name: "logout", all: true },
    });
  });

  it("is case-insensitive on the argument", () => {
    expect(parseLine("/logout ALL")).toEqual({
      kind: "command",
      command: { name: "logout", all: true },
    });
  });

  it("rejects any other argument rather than guessing", () => {
    expect(parseLine("/logout everywhere").kind).toBe("invalid");
    expect(parseLine("/logout all now").kind).toBe("invalid");
  });
});

describe("UID validation (/add)", () => {
  it("accepts a canonical UID", () => {
    expect(parseLine(`/add ${UID} bob`)).toEqual({
      kind: "command",
      command: { name: "add", uid: UID, alias: "bob" },
    });
  });

  it("accepts dashes and lowercase, normalizing Crockford ambiguity", () => {
    const messy = UID_DASHED.toLowerCase().replace("0", "o").replace("1", "l");
    const result = parseLine(`/add ${messy}`);
    expect(result).toEqual({
      kind: "command",
      command: { name: "add", uid: UID, alias: undefined },
    });
  });

  it("rejects wrong length and bad alphabet", () => {
    expect(parseLine("/add SHORT").kind).toBe("invalid");
    expect(parseLine(`/add ${UID.slice(0, 25)}U`).kind).toBe("invalid"); // U not in alphabet
  });

  it("rejects bad aliases", () => {
    expect(parseLine(`/add ${UID} "quoted alias"`).kind).toBe("invalid");
    expect(parseLine(`/add ${UID} ${"x".repeat(33)}`).kind).toBe("invalid");
  });
});

describe("/remove", () => {
  it("removes a single contact by alias or UID", () => {
    expect(parseLine("/remove bob")).toEqual({
      kind: "command",
      command: { name: "remove", target: { kind: "one", value: "bob" }, purge: false },
    });
    expect(parseLine(`/remove ${UID_DASHED}`)).toEqual({
      kind: "command",
      command: { name: "remove", target: { kind: "one", value: UID }, purge: false },
    });
  });

  it("takes an optional trailing 'purge' to also delete history", () => {
    expect(parseLine("/remove bob purge")).toEqual({
      kind: "command",
      command: { name: "remove", target: { kind: "one", value: "bob" }, purge: true },
    });
  });

  it("treats 'all' as the reserved every-contact keyword", () => {
    expect(parseLine("/remove all")).toEqual({
      kind: "command",
      command: { name: "remove", target: { kind: "all" }, purge: false },
    });
    expect(parseLine("/remove all purge")).toEqual({
      kind: "command",
      command: { name: "remove", target: { kind: "all" }, purge: true },
    });
  });

  it("rejects a missing target or an unknown trailing word", () => {
    expect(parseLine("/remove").kind).toBe("invalid");
    expect(parseLine("/remove bob keep").kind).toBe("invalid");
    expect(parseLine("/remove bob purge extra").kind).toBe("invalid");
    expect(parseLine('/remove "bad alias"').kind).toBe("invalid");
  });
});

describe("/rename", () => {
  it("renames a contact by alias or UID", () => {
    expect(parseLine("/rename bob robert")).toEqual({
      kind: "command",
      command: { name: "rename", target: "bob", alias: "robert" },
    });
    expect(parseLine(`/rename ${UID} robert`)).toEqual({
      kind: "command",
      command: { name: "rename", target: UID, alias: "robert" },
    });
  });

  it("rejects a missing new alias or a malformed one", () => {
    expect(parseLine("/rename bob").kind).toBe("invalid");
    expect(parseLine("/rename bob a b").kind).toBe("invalid");
    expect(parseLine(`/rename bob ${"x".repeat(33)}`).kind).toBe("invalid");
  });
});

describe("durations (/timer, /purge set)", () => {
  it("parses valid durations", () => {
    expect(parseLine("/timer bob 1d")).toEqual({
      kind: "command",
      command: { name: "timer", alias: "bob", duration: { kind: "for", amount: 1, unit: "d" } },
    });
    expect(parseLine("/purge set 30m")).toEqual({
      kind: "command",
      command: { name: "purge-set", duration: { kind: "for", amount: 30, unit: "m" } },
    });
    expect(parseLine("/timer bob off")).toEqual({
      kind: "command",
      command: { name: "timer", alias: "bob", duration: { kind: "off" } },
    });
  });

  it("rejects malformed durations", () => {
    for (const bad of ["1", "d", "0m", "1x", "-1h", "1h2m", "99999m", "offf"]) {
      expect(parseLine(`/timer bob ${bad}`).kind, bad).toBe("invalid");
    }
  });
});

describe("subcommands", () => {
  it("parses /settings rotation variants", () => {
    expect(parseLine("/settings rotation off")).toEqual({
      kind: "command",
      command: { name: "settings-rotation", setting: { kind: "off" } },
    });
    expect(parseLine("/settings rotation day friday")).toEqual({
      kind: "command",
      command: { name: "settings-rotation", setting: { kind: "day", day: "friday" } },
    });
    expect(parseLine("/settings rotation day someday").kind).toBe("invalid");
  });

  it("parses /settings theme variants and rejects bad values", () => {
    expect(parseLine("/settings theme scanlines off")).toEqual({
      kind: "command",
      command: { name: "settings-theme", element: "scanlines", enabled: false },
    });
    expect(parseLine("/settings theme all on")).toEqual({
      kind: "command",
      command: { name: "settings-theme", element: "all", enabled: true },
    });
    expect(parseLine("/settings theme glow on").kind).toBe("invalid");
    expect(parseLine("/settings theme emblem maybe").kind).toBe("invalid");
    expect(parseLine("/settings theme emblem").kind).toBe("invalid");
    expect(parseLine("/settings theme").kind).toBe("invalid");
  });

  it("parses /settings scheme, emblem, and color variants", () => {
    expect(parseLine("/settings scheme parchment")).toEqual({
      kind: "command",
      command: { name: "settings-scheme", scheme: "parchment" },
    });
    expect(parseLine("/settings scheme neon").kind).toBe("invalid");
    expect(parseLine("/settings emblem globe")).toEqual({
      kind: "command",
      command: { name: "settings-emblem", emblem: "globe" },
    });
    expect(parseLine("/settings emblem skull").kind).toBe("invalid");
    expect(parseLine("/settings color accent #1A2B3C")).toEqual({
      kind: "command",
      command: { name: "settings-color", slot: "accent", hex: "#1a2b3c" },
    });
    expect(parseLine("/settings color background e3e7d3")).toEqual({
      kind: "command",
      command: { name: "settings-color", slot: "background", hex: "#e3e7d3" },
    });
    expect(parseLine("/settings color reset")).toEqual({
      kind: "command",
      command: { name: "settings-color-reset" },
    });
    expect(parseLine("/settings color accent red").kind).toBe("invalid");
    expect(parseLine("/settings color glow #112233").kind).toBe("invalid");
    expect(parseLine("/settings color accent").kind).toBe("invalid");
  });

  it("parses /settings trust variants and rejects bad values", () => {
    expect(parseLine("/settings trust auto")).toEqual({
      kind: "command",
      command: { name: "settings-trust", mode: "auto" },
    });
    expect(parseLine("/settings trust manual")).toEqual({
      kind: "command",
      command: { name: "settings-trust", mode: "manual" },
    });
    expect(parseLine("/settings trust off").kind).toBe("invalid");
    expect(parseLine("/settings trust").kind).toBe("invalid");
  });

  it("parses /settings mask variants and rejects bad values", () => {
    expect(parseLine("/settings mask hidden")).toEqual({
      kind: "command",
      command: { name: "settings-mask", mask: "hidden" },
    });
    expect(parseLine("/settings mask asterisk")).toEqual({
      kind: "command",
      command: { name: "settings-mask", mask: "asterisk" },
    });
    expect(parseLine("/settings mask off").kind).toBe("invalid");
    expect(parseLine("/settings mask").kind).toBe("invalid");
    expect(parseLine("/settings wat").kind).toBe("invalid");
  });

  it("parses /keys and /rotate strictly", () => {
    expect(parseLine("/keys status")).toEqual({ kind: "command", command: { name: "keys-status" } });
    expect(parseLine("/keys hax").kind).toBe("invalid");
    expect(parseLine("/rotate passphrase")).toEqual({
      kind: "command",
      command: { name: "rotate-passphrase" },
    });
    expect(parseLine("/rotate keys").kind).toBe("invalid");
  });

  it("parses /purge now with optional alias", () => {
    expect(parseLine("/purge now")).toEqual({
      kind: "command",
      command: { name: "purge-now", alias: undefined },
    });
    expect(parseLine("/purge now bob")).toEqual({
      kind: "command",
      command: { name: "purge-now", alias: "bob" },
    });
    expect(parseLine("/purge everything").kind).toBe("invalid");
  });
});

describe("/delete (own-message deletion)", () => {
  it("parses last / all / purge scopes", () => {
    expect(parseLine("/delete last")).toEqual({
      kind: "command",
      command: { name: "delete", scope: { kind: "last" }, silent: false },
    });
    expect(parseLine("/delete all")).toEqual({
      kind: "command",
      command: { name: "delete", scope: { kind: "all" }, silent: false },
    });
    expect(parseLine("/delete purge")).toEqual({
      kind: "command",
      command: { name: "delete", scope: { kind: "purge" }, silent: false },
    });
  });

  it("parses a positive count", () => {
    expect(parseLine("/delete 5")).toEqual({
      kind: "command",
      command: { name: "delete", scope: { kind: "count", count: 5 }, silent: false },
    });
  });

  it("accepts a trailing /s for silent deletion on every scope", () => {
    expect(parseLine("/delete last /s")).toEqual({
      kind: "command",
      command: { name: "delete", scope: { kind: "last" }, silent: true },
    });
    expect(parseLine("/delete 3 /s")).toEqual({
      kind: "command",
      command: { name: "delete", scope: { kind: "count", count: 3 }, silent: true },
    });
    expect(parseLine("/delete purge /s")).toEqual({
      kind: "command",
      command: { name: "delete", scope: { kind: "purge" }, silent: true },
    });
  });

  it("rejects a missing or malformed scope", () => {
    expect(parseLine("/delete").kind).toBe("invalid");
    expect(parseLine("/delete 0").kind).toBe("invalid");
    expect(parseLine("/delete -1").kind).toBe("invalid");
    expect(parseLine("/delete everything").kind).toBe("invalid");
    expect(parseLine("/delete last extra").kind).toBe("invalid");
    expect(parseLine("/delete /s").kind).toBe("invalid");
  });
});

describe("/help", () => {
  it("accepts a known topic with or without slash", () => {
    expect(parseLine("/help timer")).toEqual({
      kind: "command",
      command: { name: "help", topic: "timer" },
    });
    expect(parseLine("/help /timer")).toEqual({
      kind: "command",
      command: { name: "help", topic: "timer" },
    });
  });

  it("rejects unknown topics", () => {
    expect(parseLine("/help frobnicate").kind).toBe("invalid");
  });
});

describe("uid helpers", () => {
  it("round-trips format/normalize", () => {
    expect(formatUid(UID)).toBe(UID_DASHED);
    expect(normalizeUid(UID_DASHED)).toBe(UID);
  });
});

describe("/clr and did-you-mean suggestions", () => {
  it("parses /clr with no arguments", () => {
    expect(parseLine("/clr")).toEqual({ kind: "command", command: { name: "clr" } });
  });

  it("rejects /clr with arguments", () => {
    expect(parseLine("/clr now").kind).toBe("invalid");
  });

  it("suggests the nearest command for a typo", () => {
    const r = parseLine("/loing");
    expect(r.kind).toBe("invalid");
    if (r.kind === "invalid") {
      expect(r.suggestion).toBe("/login");
    }
  });

  it("suggests /register for a near-miss typo", () => {
    const r = parseLine("/registr");
    if (r.kind !== "invalid") throw new Error("expected invalid");
    expect(r.suggestion).toBe("/register");
  });

  it("leaves suggestion undefined for far-off input", () => {
    const r = parseLine("/zzzzzzzz now");
    if (r.kind !== "invalid") throw new Error("expected invalid");
    expect(r.suggestion).toBeUndefined();
  });
});

describe("command aliases (execute the canonical command)", () => {
  it("routes every /chat alias to chat with the same target", () => {
    for (const alias of ["text", "msg", "message", "dm"]) {
      expect(parseLine(`/${alias} bob`)).toEqual({
        kind: "command",
        command: { name: "chat", target: "bob", message: undefined },
      });
    }
  });

  it("routes the login / register / logout / clr / return aliases", () => {
    expect(parseLine("/signin")).toEqual({ kind: "command", command: { name: "login" } });
    expect(parseLine("/sign-in")).toEqual({ kind: "command", command: { name: "login" } });
    expect(parseLine("/logon")).toEqual({ kind: "command", command: { name: "login" } });
    expect(parseLine("/signup")).toEqual({ kind: "command", command: { name: "register" } });
    expect(parseLine("/sign-up")).toEqual({ kind: "command", command: { name: "register" } });
    expect(parseLine("/signout")).toEqual({
      kind: "command",
      command: { name: "logout", all: false },
    });
    expect(parseLine("/clear")).toEqual({ kind: "command", command: { name: "clr" } });
    expect(parseLine("/cls")).toEqual({ kind: "command", command: { name: "clr" } });
    expect(parseLine("/back")).toEqual({ kind: "command", command: { name: "return" } });
  });

  it("is case-insensitive and validates aliased args like the canonical command", () => {
    expect(parseLine("/TEXT bob")).toEqual({
      kind: "command",
      command: { name: "chat", target: "bob", message: undefined },
    });
    expect(parseLine("/text").kind).toBe("invalid"); // /chat needs a target, so /text does too
    expect(parseLine("/back now").kind).toBe("invalid"); // zero-arg alias rejects extra args
  });

  it("resolves aliases in /help topics", () => {
    expect(parseLine("/help text")).toEqual({
      kind: "command",
      command: { name: "help", topic: "chat" },
    });
  });
});

describe("/chat inline message (/chat <target> [message])", () => {
  it("parses a bare target with no message", () => {
    expect(parseLine("/chat bob")).toEqual({
      kind: "command",
      command: { name: "chat", target: "bob", message: undefined },
    });
  });

  it("captures a trailing message verbatim, preserving its internal spacing", () => {
    expect(parseLine("/chat bob hey  there   friend")).toEqual({
      kind: "command",
      command: { name: "chat", target: "bob", message: "hey  there   friend" },
    });
  });

  it("preserves message case and a literal slash inside the message", () => {
    expect(parseLine("/chat bob Hello /not-a-command")).toEqual({
      kind: "command",
      command: { name: "chat", target: "bob", message: "Hello /not-a-command" },
    });
  });

  it("treats trailing-only whitespace as no message", () => {
    expect(parseLine("/chat bob   ")).toEqual({
      kind: "command",
      command: { name: "chat", target: "bob", message: undefined },
    });
  });

  it("normalizes a UID target and still captures the message", () => {
    const r = parseLine(`/chat ${"A".repeat(26)} hi`);
    expect(r.kind).toBe("command");
    if (r.kind === "command" && r.command.name === "chat") {
      expect(r.command.target).toBe("A".repeat(26));
      expect(r.command.message).toBe("hi");
    }
  });

  it("carries the message through a /chat alias like /dm", () => {
    expect(parseLine("/dm bob ping")).toEqual({
      kind: "command",
      command: { name: "chat", target: "bob", message: "ping" },
    });
  });

  it("still requires a target", () => {
    expect(parseLine("/chat").kind).toBe("invalid");
  });
});
