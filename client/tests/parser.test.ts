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
  it.each(["register", "login", "logout", "lock", "whoami", "wipe"] as const)(
    "parses /%s",
    (name) => {
      expect(parseLine(`/${name}`)).toEqual({ kind: "command", command: { name } });
    },
  );

  it("rejects extra arguments instead of guessing", () => {
    expect(parseLine("/register please").kind).toBe("invalid");
  });

  it("is case-insensitive on the command word", () => {
    expect(parseLine("/REGISTER")).toEqual({ kind: "command", command: { name: "register" } });
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
