import { describe, expect, it } from "vitest";

import {
  commandSuggestions,
  levenshtein,
  longestCommonPrefix,
  suggestCommand,
} from "../src/terminal/suggest";

describe("commandSuggestions", () => {
  it("prefix-matches slash words while typing the command", () => {
    expect([...commandSuggestions("/lo")].sort()).toEqual(["/lock", "/login", "/logout"]);
  });

  it("returns every command for a lone slash", () => {
    const all = commandSuggestions("/");
    expect(all).toContain("/register");
    expect(all).toContain("/clr");
    expect(all).toContain("/help");
    expect(all).toContain("/home");
  });

  it("prefix-matches /home and /help under /h", () => {
    expect([...commandSuggestions("/h")].sort()).toEqual(["/help", "/home"]);
    expect(commandSuggestions("/hom")).toEqual(["/home"]);
  });

  it("is empty for free-form argument positions", () => {
    expect(commandSuggestions("/add ")).toEqual([]);
    expect(commandSuggestions("/chat bob")).toEqual([]);
    expect(commandSuggestions("/settings color accent ")).toEqual([]); // hex is free-form
  });

  it("suggests a command's subcommands once the word is complete", () => {
    expect(commandSuggestions("/settings ")).toEqual([
      "/settings rotation",
      "/settings notify",
      "/settings mask",
      "/settings theme",
      "/settings scheme",
      "/settings emblem",
      "/settings timestamps",
      "/settings color",
      "/settings trust",
      "/settings font",
      "/settings fontsize",
      "/settings spacing",
      "/settings a11y",
    ]);
    expect(commandSuggestions("/keys ")).toEqual(["/keys status", "/keys refill"]);
    expect(commandSuggestions("/delete ")).toEqual([
      "/delete last",
      "/delete all",
      "/delete purge",
    ]);
  });

  it("prefix-matches a partially typed argument", () => {
    expect(commandSuggestions("/settings the")).toEqual(["/settings theme"]);
    expect(commandSuggestions("/settings trust m")).toEqual(["/settings trust manual"]);
  });

  it("continues into nested argument slots", () => {
    expect(commandSuggestions("/settings theme ")).toEqual([
      "/settings theme emblem",
      "/settings theme scanlines",
      "/settings theme vignette",
      "/settings theme dock",
      "/settings theme all",
    ]);
    expect(commandSuggestions("/settings theme dock ")).toEqual([
      "/settings theme dock on",
      "/settings theme dock off",
    ]);
  });

  it("offers /s after a delete scope", () => {
    expect(commandSuggestions("/delete all ")).toEqual(["/delete all /s"]);
  });

  it("is empty for a non-command line", () => {
    expect(commandSuggestions("hello")).toEqual([]);
    expect(commandSuggestions("")).toEqual([]);
  });
});

describe("longestCommonPrefix", () => {
  it("returns the shared prefix", () => {
    expect(longestCommonPrefix(["/login", "/logout", "/lock"])).toBe("/lo");
  });
  it("returns a single element unchanged", () => {
    expect(longestCommonPrefix(["/login"])).toBe("/login");
  });
  it("returns empty for no matches", () => {
    expect(longestCommonPrefix([])).toBe("");
  });
});

describe("suggestCommand", () => {
  it("maps known synonyms", () => {
    expect(suggestCommand("logon")).toBe("/login");
    expect(suggestCommand("signin")).toBe("/login");
    expect(suggestCommand("sign-up")).toBe("/register");
    expect(suggestCommand("signout")).toBe("/logout");
    expect(suggestCommand("msg")).toBe("/chat");
    expect(suggestCommand("cls")).toBe("/clr");
  });

  it("corrects single-character typos by edit distance", () => {
    expect(suggestCommand("registr")).toBe("/register");
    expect(suggestCommand("loing")).toBe("/login");
    expect(suggestCommand("verifed")).toBe("/verified");
  });

  it("tolerates a leading slash", () => {
    expect(suggestCommand("/logon")).toBe("/login");
  });

  it("returns null when nothing is close enough", () => {
    expect(suggestCommand("zzzzzzzz")).toBeNull();
    expect(suggestCommand("")).toBeNull();
  });
});

describe("levenshtein", () => {
  it("computes edit distance", () => {
    expect(levenshtein("", "")).toBe(0);
    expect(levenshtein("abc", "abc")).toBe(0);
    expect(levenshtein("abc", "")).toBe(3);
    expect(levenshtein("kitten", "sitting")).toBe(3);
    expect(levenshtein("login", "logon")).toBe(1);
  });
});
