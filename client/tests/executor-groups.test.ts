// Regression coverage for the group-chat fixes and the /group command
// surface, driven through the two-executor fixture (client/tests/helpers/
// two-executor.ts): real Executors on both ends, so a property that only
// shows up when a second real device decrypts and applies an incoming
// envelope - a forged sender, a roster carried on the KX first message, a
// stale local copy - is exercised through the real code path
// (processEnvelope / applyIncomingGroup) rather than a hand-rolled payload.
//
// Six fixes are covered here (a stray navigation one, B1, is executor-wide
// rather than group-specific but only reachable through /group open, so it
// lives in this file too):
//   S1 - a group envelope is checked against THIS device's OWN roster, not
//        just the sender's self-reported one.
//   S2 - a group invite carried on the KX first message is not dropped.
//   f  - a sender's roster is never adopted wholesale; only the announced
//        delta is applied (unit-level coverage is in groups.test.ts; this
//        exercises the same rule through applyIncomingGroup on a real peer).
//   B1 - /chat -> /group open -> /return must not leave activeGroup set.
//   B2 - /purge now with no argument also clears gmsg/.
// plus the full /group command surface (new/list/info/open/add/remove/leave/
// sync/purge), including the full-roster invite that /group add sends and
// the confirm/decline behaviour of /group sync.

import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../src/net/api";
import { formatUid } from "../src/terminal/parser";
import { GROUP_MSG_PREFIX, loadGroup, loadGroups, saveGroup } from "../src/terminal/executor/groups";
import {
  addContact,
  createPeer,
  deliver,
  run,
  wireTwoPeerNetwork,
} from "./helpers/two-executor";
import type { OutboxEntry, Peer } from "./helpers/two-executor";

vi.mock("../src/net/api", async () => {
  const actual = await vi.importActual<typeof import("../src/net/api")>("../src/net/api");
  return {
    ApiError: actual.ApiError,
    register: vi.fn(),
    loginChallenge: vi.fn(),
    loginVerify: vi.fn(),
    logout: vi.fn(),
    uploadSpk: vi.fn(),
    uploadOpks: vi.fn(),
    keysStatus: vi.fn(),
    fetchBundle: vi.fn(),
    sendMessage: vi.fn(),
    fetchMessages: vi.fn(),
    ackMessages: vi.fn(),
  };
});

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockReset" in fn) {
      (fn as { mockReset: () => void }).mockReset();
    }
  }
});

/** Assert a value is present and hand it back narrowed - this project's lint
 * config forbids the `!` non-null assertion, and every use below is a value
 * a preceding line already established must exist (an array slot a send just
 * populated, a `find()` this same test already asserted `toBeDefined()`). */
function must<T>(value: T | undefined | null, label = "value"): T {
  expect(value, `expected ${label} to be defined`).toBeDefined();
  if (value === undefined || value === null) {
    throw new Error(`expected ${label} to be defined`);
  }
  return value;
}

/** Alice creates 'team' with bob, and bob receives and accepts the invite
 * (which, since neither side had a prior session, rides the KX first message
 * - this is S2's path, exercised as ordinary setup for every test below that
 * does not test S2 itself). Returns the group id and a cleared outbox so a
 * test can look at exactly what its own actions send. */
async function setupAliceBobGroup(): Promise<{
  alice: Peer;
  bob: Peer;
  outbox: OutboxEntry[];
  gid: string;
}> {
  const { outbox } = wireTwoPeerNetwork();
  const alice = await createPeer("alice");
  const bob = await createPeer("bob");
  await addContact(alice, bob, "bob");
  await addContact(bob, alice, "alice");
  await run(alice, "/group new team bob");
  expect(outbox).toHaveLength(1);
  await deliver(bob, must(outbox[0]).envelope);
  const gid = must((await loadGroups(bob.executor))[0]).gid;
  outbox.length = 0;
  return { alice, bob, outbox, gid };
}

describe("S2 - a group invite carried on the KX first message", () => {
  it("creates the group on the receiving side instead of being dropped", async () => {
    const { outbox } = wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");

    // No prior session exists, so this invite has nowhere to ride but the KX
    // first message itself.
    expect(await loadGroups(bob.executor)).toEqual([]);
    await run(alice, "/group new book-club bob");
    expect(outbox).toHaveLength(1);

    await deliver(bob, must(outbox[0]).envelope);

    const groups = await loadGroups(bob.executor);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.name).toBe("book-club");
    expect(groups[0]?.members.slice().sort()).toEqual([alice.uid, bob.uid].sort());
    expect(bob.output.text()).toContain("added you to the group 'book-club'");
    // Before the fix, the group fields were never parsed off the KX first
    // message, so this arrived (and was recorded) as an ordinary, empty text
    // message instead. Confirm that did not happen.
    expect(await bob.store.listKeys(`msg/${alice.uid}/`)).toEqual([]);
  });
});

describe("S1 - an incoming group envelope is checked against THIS device's own roster", () => {
  it("rejects a sender no longer in the local roster, even though he is a full 1:1 contact and his envelope lists him", async () => {
    const { alice, bob, outbox, gid } = await setupAliceBobGroup();

    // Model alice having already removed bob from the group (e.g. via
    // /group remove) while the removal notice never reached him - an
    // attacker suppressing it, or bob simply being offline. Either way, this
    // is the state that matters for the fix: alice's OWN roster excludes
    // bob, independent of anything bob's client believes or sends.
    const alicesGroup = must(await loadGroup(alice.executor, gid));
    await saveGroup(alice.executor, { ...alicesGroup, members: [alice.uid] });

    // Bob's own copy of the group is untouched, so his envelope honestly (from
    // his point of view) lists himself as a member - a lying or stale sender's
    // envelope always agrees with itself. Only checking alice's OWN roster,
    // not the envelope's self-reported one, can catch this.
    await run(bob, "/group open team");
    await run(bob, "still here, apparently");
    expect(outbox).toHaveLength(1);

    await deliver(alice, must(outbox[0]).envelope);

    expect(alice.chrome.discarded.map((d) => d.code)).toContain("E513");
    // The roster is exactly what it was before the forged message: bob is
    // not silently re-admitted just because his envelope says he belongs.
    expect((await loadGroup(alice.executor, gid))?.members).toEqual([alice.uid]);
    expect(alice.output.text()).not.toContain("still here");
  });
});

describe("f - a sender's roster is never adopted wholesale", () => {
  it("applies only the announced delta at applyIncomingGroup, not whatever roster the envelope carries", async () => {
    const { alice, bob, outbox, gid } = await setupAliceBobGroup();
    const carol = await createPeer("carol");

    // Bob's local copy of the group has drifted to include carol - alice
    // never announced any such add. Modelled directly (rather than via a
    // real /group add from a third party) so this test isolates exactly the
    // rule under test: what alice does with a roster she did not ask for.
    const bobsGroup = must(await loadGroup(bob.executor, gid));
    await saveGroup(bob.executor, {
      ...bobsGroup,
      members: [...bobsGroup.members, carol.uid].sort(),
    });

    await run(bob, "/group open team");
    await run(alice, "/group open team"); // focused, so the inbound message renders inline
    await run(bob, "just chatting");
    expect(outbox).toHaveLength(1);
    await deliver(alice, must(outbox[0]).envelope);

    // Ordinary "msg" traffic is not blocked just because the roster disagrees...
    expect(alice.output.text()).toContain("just chatting");
    // ...but carol is not in alice's roster: no action announced her, so
    // applyAnnouncedChange applied nothing, no matter what bob's envelope
    // claimed to have in it.
    expect((await loadGroup(alice.executor, gid))?.members.slice().sort()).toEqual(
      [alice.uid, bob.uid].sort(),
    );
    // The disagreement is still surfaced - that is the detectable half of
    // the design (see the header of groups.ts) - and it names carol.
    expect(alice.output.text()).toContain("different member list");
    expect(alice.output.text()).toContain(formatUid(carol.uid));
  });

  it("does not raise a divergence warning for an ordinary, legitimate add", async () => {
    // A warning that fires on every correct operation is a warning people
    // learn to ignore - this is the "crying wolf" half of the fix, checked
    // here through a real add rather than the unit-level construction in
    // groups.test.ts.
    const { alice, bob, outbox, gid } = await setupAliceBobGroup();
    const carol = await createPeer("carol");
    await addContact(bob, carol, "carol");

    await run(bob, "/group add team carol");
    const toAlice = outbox.find((e) => e.to === alice.uid);
    await deliver(alice, must(toAlice, "notice to alice").envelope);

    expect(alice.output.text()).not.toContain("different member list");
    expect((await loadGroup(alice.executor, gid))?.members.slice().sort()).toEqual(
      [alice.uid, bob.uid, carol.uid].sort(),
    );
  });
});

describe("B1 - /return after /group open must not leave activeGroup set", () => {
  it("routes a message typed after /chat -> /group open -> /return to the contact, never silently into the group", async () => {
    const { outbox } = wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");

    await run(alice, "/chat bob");
    await run(alice, "/group new team bob");
    await run(alice, "/group open team");
    expect(alice.executor.activeGroup).not.toBeNull();

    await run(alice, "/return");
    // The fix: returning to a one-to-one target must clear activeGroup, or
    // handleMessage's `if (this.activeGroup !== null)` check (which runs
    // before the one-to-one path) keeps routing into the group.
    expect(alice.executor.activeGroup).toBeNull();
    expect(alice.executor.active?.uid).toBe(bob.uid);

    outbox.length = 0;
    await run(alice, "hello for real this time");
    expect(outbox).toHaveLength(1);
    expect(outbox[0]?.to).toBe(bob.uid);

    const gid = must((await loadGroups(alice.executor))[0]).gid;
    expect(await alice.store.listKeys(`${GROUP_MSG_PREFIX}${gid}/`)).toEqual([]);
  });
});

describe("B2 - /purge now with no argument", () => {
  it("deletes gmsg/ history alongside msg/, not just the one-to-one side", async () => {
    const { alice } = await setupAliceBobGroup();
    await run(alice, "/chat bob");
    await run(alice, "hi bob"); // msg/ history
    await run(alice, "/group open team");
    await run(alice, "hi group"); // gmsg/ history

    expect(await alice.store.listKeys("msg/")).not.toEqual([]);
    const gid = must((await loadGroups(alice.executor))[0]).gid;
    expect(await alice.store.listKeys(`${GROUP_MSG_PREFIX}${gid}/`)).not.toEqual([]);

    await run(alice, "/purge now");
    expect(alice.output.text()).toContain("Purged");
    expect(await alice.store.listKeys("msg/")).toEqual([]);
    expect(await alice.store.listKeys(`${GROUP_MSG_PREFIX}${gid}/`)).toEqual([]);
  });
});

describe("the /group command surface", () => {
  it("/group new creates the group and invites every named member", async () => {
    const { outbox } = wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(alice, bob, "bob");

    await run(alice, "/group new team bob");
    expect(alice.output.text()).toContain("Created 'team' with 2 members");
    const groups = await loadGroups(alice.executor);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.members.slice().sort()).toEqual([alice.uid, bob.uid].sort());
    expect(outbox).toHaveLength(1);
  });

  it("/group list reports none, then names each group with its member count", async () => {
    wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(alice, bob, "bob");

    await run(alice, "/group list");
    expect(alice.output.text()).toContain("No groups yet");

    await run(alice, "/group new team bob");
    await run(alice, "/group list");
    expect(alice.output.text()).toContain("groups (1)");
    expect(alice.output.text()).toContain("team");
    expect(alice.output.text()).toContain("2 members");
  });

  it("/group info shows the full roster and its fingerprint", async () => {
    const { alice, bob } = await setupAliceBobGroup();
    await run(alice, "/group info team");
    const text = alice.output.text();
    expect(text).toContain("'team': 2 members");
    expect(text).toContain(formatUid(bob.uid));
    expect(text).toContain("member-list fingerprint");
  });

  it("/group open focuses the conversation and sets the chat-context line and prompt", async () => {
    const { alice } = await setupAliceBobGroup();
    await run(alice, "/group open team");
    expect(alice.chrome.context).toBe("[group: team (2 members)]");
    expect(alice.shell.prompts).toContain("[team] > ");
  });

  it("/group add advertises the FULL roster to the new member, not just the two endpoints of that one send", async () => {
    const { alice, bob, outbox, gid } = await setupAliceBobGroup();
    const carol = await createPeer("carol");
    await addContact(bob, carol, "carol");
    await addContact(carol, bob, "bob");

    await run(bob, "/group add team carol");
    // An invite to carol and a membership notice to alice: two sends, one
    // roster (see fanOutToGroup's header comment on recipients vs roster).
    expect(outbox).toHaveLength(2);
    const toCarol = outbox.find((e) => e.to === carol.uid);
    const toAlice = outbox.find((e) => e.to === alice.uid);

    await deliver(carol, must(toCarol, "invite to carol").envelope);
    await deliver(alice, must(toAlice, "notice to alice").envelope);

    // Before the fix, fanOutToGroup derived the advertised roster from the
    // recipient list, so carol's invite named only [bob, carol] - the two
    // ends of that one send - rather than the group she was actually joining.
    expect((await loadGroup(carol.executor, gid))?.members.slice().sort()).toEqual(
      [alice.uid, bob.uid, carol.uid].sort(),
    );
    expect((await loadGroup(alice.executor, gid))?.members.slice().sort()).toEqual(
      [alice.uid, bob.uid, carol.uid].sort(),
    );
  });

  it("/group remove tells the remaining members and updates their local roster", async () => {
    // A remaining member is still listed in the post-removal roster the notice
    // carries, so they take the ordinary path. The removed member's own view is
    // the interesting one and is covered by the test below.
    const { outbox } = wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    const carol = await createPeer("carol");
    await addContact(alice, bob, "bob");
    await addContact(alice, carol, "carol");
    await addContact(bob, alice, "alice");

    await run(alice, "/group new team bob carol");
    const toBob = outbox.find((e) => e.to === bob.uid);
    await deliver(bob, must(toBob, "invite to bob").envelope);
    const gid = must((await loadGroups(bob.executor))[0]).gid;
    outbox.length = 0;

    await run(alice, "/group remove team carol");
    const notice = outbox.find((e) => e.to === bob.uid);
    await deliver(bob, must(notice, "removal notice to bob").envelope);

    expect((await loadGroup(alice.executor, gid))?.members.slice().sort()).toEqual(
      [alice.uid, bob.uid].sort(),
    );
    expect((await loadGroup(bob.executor, gid))?.members.slice().sort()).toEqual(
      [alice.uid, bob.uid].sort(),
    );
    expect(bob.output.text()).toContain("removed");
  });

  it("tells the person removed, whose own roster the notice deliberately omits", async () => {
    // The notice a removal sends carries the roster that exists AFTER the
    // removal, so the one person who most needs it is absent from it. An
    // earlier version discarded it for exactly that reason (E513) and the
    // removed member went on believing they were still in the group, which is
    // the opposite of what the code around it claimed to do.
    const { outbox } = wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");

    await run(alice, "/group new team bob");
    await deliver(bob, must(outbox.find((e) => e.to === bob.uid), "invite").envelope);
    const gid = must((await loadGroups(bob.executor))[0]).gid;
    outbox.length = 0;

    await run(alice, "/group remove team bob");
    await deliver(bob, must(outbox.find((e) => e.to === bob.uid), "removal notice").envelope);

    expect(bob.chrome.discarded.map((d) => d.code)).not.toContain("E513");
    expect(bob.output.text()).toContain("removed you");
    // The group stays readable as history, but is marked inactive so nothing
    // more is sent into it.
    expect((await loadGroup(bob.executor, gid))?.active).toBe(false);
  });

  it("/group leave tells the others and marks the group inactive locally", async () => {
    const { alice, bob, outbox, gid } = await setupAliceBobGroup();

    await run(bob, "/group leave team");
    expect(outbox).toHaveLength(1);
    await deliver(alice, must(outbox[0]).envelope);

    expect((await loadGroup(bob.executor, gid))?.active).toBe(false);
    expect((await loadGroup(alice.executor, gid))?.members).toEqual([alice.uid]);
    expect(alice.output.text()).toContain("left 'team'");
    // A routine departure must not look like an attack. The notice carries the
    // roster as it stands after the leave, so alice applies the change and
    // lands on exactly that roster with nothing left over to warn about. An
    // earlier version sent the pre-leave roster, which made every legitimate
    // departure raise a [SECURITY] divergence warning naming the person who
    // had just left as a member alice could not see.
    expect(alice.output.text()).not.toContain("different member list");
    expect(alice.chrome.discarded.map((d) => d.code)).not.toContain("E513");
  });

  it("a departure still has to come from someone actually in the roster", async () => {
    // Relaxing the roster check for a leave must not become a way in: the gate
    // that matters is that the sender is in THIS device's roster, and that one
    // is unchanged.
    const { alice, bob, outbox, gid } = await setupAliceBobGroup();
    const alicesGroup = must(await loadGroup(alice.executor, gid));
    await saveGroup(alice.executor, { ...alicesGroup, members: [alice.uid] });

    await run(bob, "/group leave team");
    await deliver(alice, must(outbox[0]).envelope);

    expect(alice.chrome.discarded.map((d) => d.code)).toContain("E513");
    expect((await loadGroup(alice.executor, gid))?.members).toEqual([alice.uid]);
  });

  it("/group sync adds the members the confirmation names, and nothing when declined", async () => {
    const { alice, bob, outbox, gid } = await setupAliceBobGroup();
    const carol = await createPeer("carol");
    await addContact(bob, carol, "carol");
    // Bob invites carol; alice only ever learns of carol through the group's
    // membership notice, never adds her as a 1:1 contact directly - exactly
    // the gap /group sync exists to close.
    await run(bob, "/group add team carol");
    const toAlice = outbox.find((e) => e.to === alice.uid);
    await deliver(alice, must(toAlice, "add notice to alice").envelope);
    expect((await loadGroup(alice.executor, gid))?.members).toContain(carol.uid);

    // Decline: nothing added.
    alice.shell.lines.push("no");
    await run(alice, "/group sync team");
    expect(alice.output.text()).toContain("Nothing was added");
    expect(alice.executor.contacts.size).toBe(1); // only bob

    // Accept: carol is added as a (local-only, unverified) contact.
    alice.shell.lines.push("yes");
    await run(alice, "/group sync team");
    expect(alice.output.text()).toContain("Added 1 member(s)");
    const carolAsContact = [...alice.executor.contacts.values()].find((c) => c.uid === carol.uid);
    expect(carolAsContact).toBeDefined();
    expect(carolAsContact?.verified).toBe(false);
  });

  it("/group purge deletes the group and its stored history", async () => {
    const { alice, gid } = await setupAliceBobGroup();
    await run(alice, "/group open team");
    await run(alice, "keepsake");
    expect(await alice.store.listKeys(`${GROUP_MSG_PREFIX}${gid}/`)).not.toEqual([]);

    await run(alice, "/group purge team");
    expect(await loadGroup(alice.executor, gid)).toBeNull();
    expect(await alice.store.listKeys(`${GROUP_MSG_PREFIX}${gid}/`)).toEqual([]);
    expect(alice.executor.activeGroup).toBeNull(); // it was focused, so cleared
  });
});
