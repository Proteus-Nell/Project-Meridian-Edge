// Group chats: the wire envelope, the roster rules, and the checks that make
// this design's limitations visible rather than silent.
//
// The properties worth failing a build over are the ones in the header of
// executor/groups.ts: a group message is authenticated by the pairwise ratchet
// it arrived on, a roster is never adopted from an unsolicited message, and a
// divergent roster is reported rather than merged.

import { describe, expect, it } from "vitest";

import {
  MAX_GROUP_MEMBERS,
  decodeAppPayload,
  decodeGroupEnvelope,
  encodeAppPayload,
  isGroupId,
  isGroupName,
  sanitizeRoster,
} from "../src/terminal/executor/payload";
import type { AppPayload, GroupEnvelope } from "../src/terminal/executor/payload";
import {
  applyAnnouncedChange,
  newGroupId,
  rosterDelta,
  rosterDigest,
} from "../src/terminal/executor/groups";

const UID_A = "A".repeat(26);
const UID_B = "B".repeat(26);
const UID_C = "C".repeat(26);

function payloadWith(group: GroupEnvelope | null, text: string | null = "hello"): AppPayload {
  return { text, timerSeconds: null, mid: null, deletes: null, deleteSilent: false, group };
}

const GROUP: GroupEnvelope = {
  gid: "0123456789abcdef0123456789abcdef",
  name: "book club",
  members: [UID_A, UID_B],
  action: "msg",
  subject: null,
};

describe("group ids", () => {
  it("are 128 random bits of hex, and disclose nothing about the roster", () => {
    const first = newGroupId();
    const second = newGroupId();
    expect(isGroupId(first)).toBe(true);
    expect(first).toHaveLength(32);
    expect(first).not.toBe(second);
  });

  it("reject anything that is not exactly that shape", () => {
    for (const bad of ["", "abc", "0".repeat(31), "0".repeat(33), "Z".repeat(32), "0123456789ABCDEF0123456789ABCDEF"]) {
      expect(isGroupId(bad), bad).toBe(false);
    }
  });
});

describe("group names", () => {
  it("accept ordinary labels", () => {
    for (const name of ["book club", "team-1", "a", "x".repeat(32)]) {
      expect(isGroupName(name), name).toBe(true);
    }
  });

  it("reject anything that could disturb an aligned listing or carry an escape", () => {
    for (const name of ["", "x".repeat(33), "tab\there", "new\nline", "[31mred", "semi;colon", "<script>"]) {
      expect(isGroupName(name), JSON.stringify(name)).toBe(false);
    }
  });
});

describe("sanitizeRoster", () => {
  it("canonicalizes, deduplicates and sorts, so two agreeing members match byte for byte", () => {
    const a = sanitizeRoster([UID_B, UID_A, UID_A]);
    const b = sanitizeRoster([UID_A, UID_B]);
    expect(a).toEqual([UID_A, UID_B]);
    expect(a).toEqual(b);
  });

  it("rejects a roster with any unusable entry rather than guessing at the rest", () => {
    // Partly-valid is not a roster worth acting on: silently dropping an entry
    // is indistinguishable from a member being removed.
    expect(sanitizeRoster([UID_A, "not-a-uid"])).toBeNull();
    expect(sanitizeRoster([UID_A, 42])).toBeNull();
    expect(sanitizeRoster([])).toBeNull();
    expect(sanitizeRoster("nope")).toBeNull();
    expect(sanitizeRoster(null)).toBeNull();
  });

  it("caps the roster, since every member costs one send against the rate limit", () => {
    const many = Array.from({ length: MAX_GROUP_MEMBERS + 1 }, (_, i) =>
      String.fromCharCode(65 + (i % 26)).repeat(26),
    );
    expect(sanitizeRoster(many)).toBeNull();
  });
});

describe("the group envelope on the wire", () => {
  it("round-trips through the encrypted payload", () => {
    const decoded = decodeAppPayload(encodeAppPayload(payloadWith(GROUP)));
    expect(decoded?.group).toEqual(GROUP);
    expect(decoded?.text).toBe("hello");
  });

  it("round-trips a membership action with its subject", () => {
    const add: GroupEnvelope = { ...GROUP, action: "add", subject: UID_C };
    const decoded = decodeAppPayload(encodeAppPayload(payloadWith(add, null)));
    expect(decoded?.group).toEqual(add);
  });

  it("leaves an ordinary one-to-one payload with no group at all", () => {
    const decoded = decodeAppPayload(encodeAppPayload(payloadWith(null)));
    expect(decoded?.group).toBeNull();
    expect(decoded?.text).toBe("hello");
  });

  it("drops a group envelope whose every field is not valid", () => {
    // Everything here is peer-supplied. Failing to null means the message is
    // handled as ordinary text rather than as group state, which is the safe
    // direction.
    const cases: Record<string, unknown>[] = [
      { g: "short", gn: "ok", gm: [UID_A], ga: "msg" },
      { g: GROUP.gid, gn: "bad\nname", gm: [UID_A], ga: "msg" },
      { g: GROUP.gid, gn: "ok", gm: ["nope"], ga: "msg" },
      { g: GROUP.gid, gn: "ok", gm: [UID_A], ga: "explode" },
      { g: GROUP.gid, gn: "ok", gm: [UID_A] },
      { gn: "ok", gm: [UID_A], ga: "msg" },
    ];
    for (const record of cases) {
      expect(decodeGroupEnvelope(record), JSON.stringify(record)).toBeNull();
    }
  });

  it("requires a subject for add/remove and forbids one otherwise", () => {
    const base = { g: GROUP.gid, gn: "ok", gm: [UID_A] };
    expect(decodeGroupEnvelope({ ...base, ga: "add" })).toBeNull();
    expect(decodeGroupEnvelope({ ...base, ga: "remove" })).toBeNull();
    expect(decodeGroupEnvelope({ ...base, ga: "msg", gs: UID_C })).toBeNull();
    expect(decodeGroupEnvelope({ ...base, ga: "add", gs: UID_C })).not.toBeNull();
  });

  it("drops an envelope whose subject does not parse", () => {
    expect(
      decodeGroupEnvelope({ g: GROUP.gid, gn: "ok", gm: [UID_A], ga: "add", gs: "nope" }),
    ).toBeNull();
  });
});

describe("roster digest", () => {
  it("matches for two members who agree, whatever order they hold it in", () => {
    expect(rosterDigest([UID_A, UID_B])).toBe(rosterDigest([UID_B, UID_A]));
  });

  it("differs as soon as one member is added or dropped", () => {
    expect(rosterDigest([UID_A, UID_B])).not.toBe(rosterDigest([UID_A, UID_B, UID_C]));
    expect(rosterDigest([UID_A, UID_B])).not.toBe(rosterDigest([UID_A]));
  });

  it("is short enough to read aloud", () => {
    expect(rosterDigest([UID_A, UID_B])).toMatch(/^[0-9A-F]{8}$/);
  });
});

describe("rosterDelta", () => {
  it("names both directions of a divergence, which is what the warning prints", () => {
    const delta = rosterDelta([UID_A, UID_B], [UID_A, UID_C]);
    expect(delta.onlyTheirs).toEqual([UID_C]);
    expect(delta.onlyMine).toEqual([UID_B]);
  });

  it("is empty when the two agree", () => {
    const delta = rosterDelta([UID_A, UID_B], [UID_B, UID_A]);
    expect(delta.onlyTheirs).toEqual([]);
    expect(delta.onlyMine).toEqual([]);
  });
});

describe("announced-change application", () => {
  // The receiver never adopts a sender's roster wholesale: it applies only the
  // change that was announced, to its own roster. That is what stops one
  // message from rewriting who you think is in a group.
  const envelope = (over: Partial<GroupEnvelope>): GroupEnvelope => ({
    ...GROUP,
    ...over,
  });

  it("leaves the roster untouched for ordinary traffic", () => {
    expect(applyAnnouncedChange([UID_A, UID_B], envelope({ action: "msg" }), UID_A)).toEqual([
      UID_A,
      UID_B,
    ]);
  });

  it("applies exactly the announced add or removal, and nothing else", () => {
    // The envelope claims a roster of [A, B] while announcing "add C". Only the
    // announced delta lands; the claimed roster is not copied over.
    const added = applyAnnouncedChange(
      [UID_A, UID_B],
      envelope({ action: "add", subject: UID_C, members: [UID_A] }),
      UID_A,
    );
    expect(added).toEqual([UID_A, UID_B, UID_C]);

    const removed = applyAnnouncedChange(
      [UID_A, UID_B, UID_C],
      envelope({ action: "remove", subject: UID_C, members: [UID_A, UID_B, UID_C] }),
      UID_A,
    );
    expect(removed).toEqual([UID_A, UID_B]);
  });

  it("drops the sender on a leave", () => {
    expect(
      applyAnnouncedChange([UID_A, UID_B, UID_C], envelope({ action: "leave" }), UID_B),
    ).toEqual([UID_A, UID_C]);
  });
});

describe("divergence is measured after the announced change", () => {
  // A warning that fires on every legitimate operation is a warning people
  // learn to ignore, so a normal add or removal must produce no divergence.
  it("sees no divergence for a legitimate add", () => {
    const mine = [UID_A, UID_B];
    const theirs = [UID_A, UID_B, UID_C]; // sender already applied the add
    const applied = applyAnnouncedChange(
      mine,
      { ...GROUP, action: "add", subject: UID_C, members: theirs },
      UID_A,
    );
    const delta = rosterDelta(applied, theirs);
    expect(delta.onlyMine).toEqual([]);
    expect(delta.onlyTheirs).toEqual([]);
  });

  it("sees no divergence for a legitimate removal", () => {
    const mine = [UID_A, UID_B, UID_C];
    const theirs = [UID_A, UID_B];
    const applied = applyAnnouncedChange(
      mine,
      { ...GROUP, action: "remove", subject: UID_C, members: theirs },
      UID_A,
    );
    expect(rosterDelta(applied, theirs).onlyMine).toEqual([]);
  });

  it("still sees a divergence when a plain message carries a different roster", () => {
    // The case the warning exists for: no change announced, but the rosters
    // disagree anyway.
    const mine = [UID_A, UID_B];
    const theirs = [UID_A, UID_B, UID_C];
    const applied = applyAnnouncedChange(mine, { ...GROUP, action: "msg", members: theirs }, UID_A);
    expect(rosterDelta(applied, theirs).onlyTheirs).toEqual([UID_C]);
  });
});
