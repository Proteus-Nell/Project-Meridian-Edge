# ADR 0003: Safety-number ordering and key-change block semantics

**Status:** accepted · **Date:** 2026-07-05

## Context

MVP_DOC.md §6.5 defines the safety number as
`SN = SHA-512(min(IK_A, IK_B) ‖ max(IK_A, IK_B) ‖ UID_A ‖ UID_B)`. Read
literally, the identity keys are sorted but the UIDs are not - they are
named "A" and "B" as if that assignment were fixed. If each side's client
treats *itself* as "A", Alice and Bob would hash different byte strings and
compute different numbers, defeating the entire mechanism (comparison
requires both parties to arrive at the same digits).

CLAUDE.md §1.4 also describes a general rule that security-critical events
"block the affected conversation until acknowledged with `/ack`", while
MVP_DOC.md §6.5 separately says an identity-key change on a previously
trusted contact "tears down the session ... requiring explicit
re-verification before further sends." Taken together these describe two
gates, not one, and the relationship between them needed a concrete design.

## Decisions

**1. Order both the key and its UID together, not independently.** Pair each
party's `(IK, UID)`, sort the two pairs by identity-key bytes
(lexicographic), and hash `IK_min ‖ IK_max ‖ UID_of_min ‖ UID_of_max`. This
guarantees Alice's and Bob's clients hash byte-identical input regardless of
who initiated, at the cost of being one specific (but symmetric and
deterministic) reading of an ambiguous formula.

**2. One boolean gate, not two.** `Contact.keyChangeBlocked` is set the
moment any identity-key change is detected (on send, on receive, or during
`/verify`), and `Contact.verified` is simultaneously forced to `false`. It
is:
- Checked first in `sendFirstMessage` - sending is refused outright while
  set, satisfying "block sending ... until re-verification."
- Cleared only by `/ack <alias>` - satisfying the general "block until
  acknowledged" rule. Acknowledging does **not** restore `verified`; the
  contact is simply usable again while honestly marked `UNVERIFIED` until
  `/verify` + `/verified` are re-run against the new key.
- Required to be `false` before `/verified` will set `verified = true` -
  so a change can never be silently re-trusted without the user
  consciously acknowledging it happened first.

This was chosen over a stricter design (sending permanently blocked until
`verified` is true again) because CLAUDE.md's own general rule treats `/ack`
as the standard unblock for security events, and because real secure
messengers (Signal included) let a user proceed past a safety-number-change
warning at their own judgment rather than hard-locking the conversation -
the persistent `UNVERIFIED` status is the honesty mechanism, not a hard stop.

## Consequences

- `handleKeyChange()` is the single code path all three detection sites
  (initiate, respond, `/verify`) funnel through, so the block/unverify/
  session-teardown behavior cannot drift between them.
- A previously-`verified` contact whose key changes reverts to `UNVERIFIED`
  and stays that way - visible every time `/chat` is run - until the user
  explicitly re-verifies, which is the property the threat model (A2,
  malicious server) actually needs.
