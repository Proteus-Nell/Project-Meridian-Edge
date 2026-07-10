# Meridian Edge — Engineering & Product Review (W1–W3)

**Date:** 2026-07-05
**Scope:** Implemented surface only (W1 terminal shell/parser/renderer, W2 identity/key
store/prekeys, W3 PQ-KX handshake/queue/WebSocket). This is an *engineering and product*
review — it recommends improvements to what exists, not new milestones. W4 (ratchet, safety
numbers), W5 (hardening, lifecycle) and W6 (benchmarks) are out of scope except where a
W1–W3 change should leave a seam for them.
**Companion:** An OWASP ASVS 4.0.3 L2 audit already exists at
`docs/compliance/asvs-w1w2.md`. This review deliberately does **not** re-litigate its
findings (security-event logging, `Origin` allowlist, CORS middleware, `DEBUG=0` boot
assertion, per-endpoint rate limits, `SECURITY.md`, HSTS placeholder, passphrase min-length
as an ASVS mapping, nonce-uniqueness stress test). Where this review touches passphrase
strength or secret lifetime it does so from a UX/robustness angle the ASVS report did not
cover.
**Method:** Static read of every file in the implemented surface. No server run, no test
execution. Every item cites `file:line`.

All recommendations respect the CLAUDE.md §0 invariants: no new crypto primitives, the three
`@noble` packages remain the only client crypto deps, exact version pins, no `innerHTML`, no
classical crypto in application paths.

---

## Outright bugs (fix regardless of priority)

These are correctness defects in shipped W1–W3 code, not enhancements.

### BUG-1 — Auto-lock can fire mid-flow and corrupt a registration/login, losing the identity
`executor.ts:281-292` arms a single 10-minute `setTimeout` that calls `lockLocal()` (which
nulls `this.identity` and zeroizes `identity.sec`, `executor.ts:294-306`). The timer is reset
only from `handle()` via `touchAutoLock()` (`executor.ts:132-133`). But `doRegister`/`doLogin`
`await this.shell.readSecret(...)` for passphrase entry (`executor.ts:630,638,777`), and
masked-prompt keystrokes go through the shell's `pending` path, **not** through
`handle()` — so they do **not** reset the auto-lock timer. If a user starts `/register`,
then the timer (armed by a prior unlocked session) elapses while they are choosing a
passphrase or writing down recovery codes, `lockLocal()` runs *concurrently* with the flow:
`this.identity` becomes `null` mid-`doRegister`, and the subsequent `this.identity.pub`
dereference (`executor.ts:681`, or `loginWithIdentity` at `:699-702`) throws or, worse, the
keypair is generated and uploaded server-side but never persisted locally — the UID and its
identity key are orphaned with no recovery path short of the printed codes. **Fix:** suspend
the auto-lock timer for the duration of any `run()` task (clear on entry, re-arm in the
`finally`), or have `readSecret`/`readLine` bump the idle timer. **Effort: S.**

### BUG-2 — `rxTail` (WebSocket receive) races the command chain over shared mutable state
Incoming envelopes are processed on `this.rxTail` (`executor.ts:608-618`), a promise chain
that is entirely independent of the `this.tail`/`busy` command chain (`executor.ts:242-253`).
Both mutate the same fields: `this.contacts` (+`saveContacts`), `this.identity`, and the
store. Concretely: a `/logout` or `/wipe` on the command chain calls `lockLocal()` / nulls
`this.token` and `this.identity` while an in-flight `processEnvelope` is between `await`s
(e.g. after `buildPrekeyLookup` at `executor.ts:481` but before the `putJson` writes at
`:533-534`). `processEnvelope` guards its *entry* (`executor.ts:478`) but not its
continuations, so it can call `this.store.putJson(...)` after the store is locked
(→ `StoreLockedError` surfaced as a generic "failed to process an incoming message"), or
overwrite `this.contacts` that `/wipe` just cleared, re-persisting a contact into a store
that is supposed to be gone. **Fix:** funnel `processEnvelope` through the same
serialization as commands (share one `busy`/queue), or re-check `isUnlocked()`/`identity`
after each `await` and abort cleanly. **Effort: M.**

### BUG-3 — `connectWs()` leaks the previous socket on re-login (no auto-relock of WS)
`connectWs()` (`executor.ts:598-625`) unconditionally assigns `this.ws = new WsClient()`
without closing a pre-existing one. `doLogin` calls `connectWs()` every time
(`executor.ts:801`). If a user runs `/login` while already connected (e.g. after a transient
network blip, or simply typing `/login` twice), the old `WsClient`/`WebSocket` is orphaned:
its `onEnvelope` still fires and pushes onto the *old* `rxTail`, and its `onClose(false)`
fires later and prints "live delivery disconnected" even though a newer socket is healthy —
confusing and it double-processes/acks envelopes. `WsClient.connect` self-closes its *own*
prior socket (`ws.ts:22`) but a brand-new `WsClient` instance has none to close. **Fix:**
`this.ws?.close()` before constructing a new client in `connectWs()`. **Effort: S.**

### BUG-4 — `new DataView(out.buffer)` in the envelope encoder assumes offset 0
`envelope.ts:80`: `new DataView(out.buffer).setUint32(offset, ...)`. `out` is a freshly
allocated `Uint8Array` (`envelope.ts:59`) so today `out.byteOffset` is 0 and this is
correct. It is a latent trap: if `encodeKxEnvelope` is ever refactored to write into a
subarray/pooled buffer, `out.buffer` ignores `byteOffset` and silently corrupts the length
prefix. The decoder already does this correctly with the three-arg form
(`envelope.ts:116`). **Fix:** use `new DataView(out.buffer, out.byteOffset, out.byteLength)`
for symmetry and future-proofing. **Effort: S.** (Low urgency, but it is a real
inconsistency between encode and decode.)

---

## Top 10 priority list

Ranked by impact-over-effort on the *existing* surface.

1. **BUG-1: auto-lock fires during passphrase/recovery-code entry, can orphan an identity.**
   `executor.ts:281-292,630-696` — suspend the idle timer inside `run()`. **(S)**
2. **BUG-2: WS receive chain races commands over `contacts`/`identity`/store.**
   `executor.ts:598-625,477-573` — serialize rx with the command chain. **(M)**
3. **No message-history display command — messages are stored but unreadable.**
   `executor.ts:350,432,534` write `msg/<uid>/<ts>`; nothing ever reads them. Add
   `/history [alias]`. **(M)**
4. **Argon2id (64 MiB) runs on the main thread — UI freezes ~0.5–2 s on unlock/create/
   rotate.** `store.ts:64-71` — move `deriveKek` into a Web Worker. **(M)**
5. **BUG-3: `connectWs()` leaks the old socket on re-login, causing double delivery + false
   disconnect lines.** `executor.ts:598-625` — close before reconnect. **(S)**
6. **No automatic WS reconnect; a blip forces a manual `/login` and silent message loss until
   then.** `ws.ts:62-67`, `executor.ts:619-623` — add bounded backoff reconnect reusing the
   in-memory token. **(M)**
7. **The persistent status line from CLAUDE.md §1.5 is unimplemented; `/chat` only prints a
   one-shot line.** `executor.ts:212-225`, `shell.ts:72-75` — add a bottom status region
   (`alias · UNVERIFIED · locked in Xm`). **(M)**
8. **Executor is ~1000 lines mixing dispatch + auth + messaging + maintenance + contacts.**
   `executor.ts` whole file — split into `AuthFlows`, `Messaging`, `KeyMaintenance`,
   `ContactStore` collaborators; this is also the seam W4 ratchet state needs. **(L)**
9. **Executor send/receive/login flows have zero unit coverage — only the opt-in live e2e
   exercises them.** `executor-rotate.test.ts` is the only executor test; `live.e2e.test.ts`
   is `skipIf` gated. Add fake-transport tests for `sendFirstMessage`/`processEnvelope`. **(M)**
10. **`buildPrekeyLookup` decrypts *every* SPK + all ~50 OPK records on *every* inbound
    envelope.** `executor.ts:452-473`, called at `:481` per message — O(N) Argon2-free but
    ~51 XChaCha20 decrypts per message, and the whole map is rebuilt per envelope in a batch
    drain. Cache the lookup per drain / invalidate on refill. **(M)**

---

## Full catalog by dimension

### 1. UX of the terminal flows

**UX-1 — No message-history command (functional gap).** Inbound and outbound messages are
persisted to `msg/<uid>/<ts>` (`executor.ts:350,432,534`) but there is no read path anywhere
(`grep` for `msg/` shows only writes). A user who receives a message, then reloads (which
always returns locked, per README:79), can never see it again — the data is in IndexedDB but
unreachable. *Why:* the store faithfully records history that the product then hides. *How:*
add `/history [alias]` to the parser allowlist + a handler that `listKeys("msg/<uid>/")`,
sorts by timestamp, and renders `dir`-aware lines through the renderer; respect the active
conversation when no alias is given. *Where:* `parser.ts:63-82` (allowlist),
`executor.ts` (new handler). **Effort: M.**

**UX-2 — The persistent status line (CLAUDE.md §1.5) does not exist.** `/chat` prints a
single transient `chatting with: alias (UNVERIFIED)` line (`executor.ts:222`) and changes the
prompt (`:223`), but there is no persistent `[chatting with: … ] [timer] [locked in Xm]`
region. *Why:* §1.5 calls it out explicitly and it is the primary at-a-glance state
indicator; verified/unverified and lock countdown are security-relevant context. *How
(minimal):* reserve the bottom row via xterm.js — on any state change, save cursor, write to
the last row with `\x1b[<rows>;1H`, restore. A minimal v1 needs only `alias`,
`verified|UNVERIFIED`, and `locked in Xm` (derive from the auto-lock deadline). Timer field
can read "off" until W5. *Where:* `shell.ts` (owns the terminal; add a `setStatus(text)`),
`executor.ts:212-225` and `touchAutoLock`. **Effort: M** (S if you settle for repainting a
status line above the prompt rather than a fixed bottom row).

**UX-3 — `/chat` on an unknown contact tells the user to `/add` but not how the request got
there.** `executor.ts:214-219` prints `unknown contact … /add <uid> [alias] first (contacts
load on /login)`. If the user has a *pending request* (`pending/<uid>`) but hasn't `/add`ed,
`/chat` gives no hint that a held message exists. *Why:* the held-request UX
(`executor.ts:561-571`) surfaces once at receive time and is then only discoverable by
remembering. *How:* on `/chat` miss, check for a `pending/` record and point at it; or add a
`/requests` listing. *Where:* `executor.ts:212-225`. **Effort: S.**

**UX-4 — Second message in a conversation is a dead end with a W4 deferral message.**
`sendFirstMessage` refuses if a session exists (`executor.ts:382-389`) with
"continued messaging arrives with the W4 ratchet". Functionally correct, but the user has
already typed and submitted a message that is now silently dropped. *Why:* typing into an
established chat looks like it should send. *How:* keep the guard, but make the message clearly
state the input was **not** sent and there is nothing to retry; consider disabling the send
path visually via the status line's state. *Where:* `executor.ts:377-389`. **Effort: S.**

**UX-5 — `reportError` collapses all non-401/429 API failures to "is the server running?".**
`executor.ts:271` — a 413 (payload too large), 400, or 5xx all render the same "request
failed - is the server running?". *Why:* misleading during a real 413 on an oversized message
or a validation reject. *How:* branch on `err.status` for 413 ("message too large") and a
generic 4xx/5xx split. *Where:* `executor.ts:260-279`. **Effort: S.**

**UX-6 — `/ack` is a stub that always says "nothing to acknowledge".** `executor.ts:226-229`.
CLAUDE.md §1.4 makes `/ack` the mechanism to clear a blocking security event, and the renderer
already has a `security` level (`renderer.ts:16`). Today security events
(`executor.ts:411,419,485,523,553`) print but nothing *blocks*, so `/ack` has nothing to do
and the "block the affected conversation until acknowledged" requirement is unmet. This is
partly W4, but the W3 identity-key-change events (`executor.ts:416-422,521-528`) already exist
and should latch. *Why:* a key-change warning that scrolls off-screen defeats its purpose.
*How:* track a `blockedConversations: Set<uid>`; set on a security event, refuse sends to a
blocked target, clear on `/ack <alias>`. *Where:* `executor.ts:226-229` + the security-event
sites. **Effort: M.**

**UX-7 — No feedback that registration's long steps are progressing.** `doRegister`
(`executor.ts:649-697`) prints "generating … identity keypair" then runs keygen, register,
`store.create` (Argon2id, seconds), login, and a full prekey bundle upload
(1 SPK + 50 OPK keygens + uploads) before the next line. On a slow device this is a multi-
second silent gap after the recovery codes. *Why:* looks hung. *How:* interleave `info`
lines ("uploading prekey bundle…") and/or move Argon2id off-thread (see PERF-1). *Where:*
`executor.ts:663-694,715-722`. **Effort: S.**

**UX-8 — Discoverability: `/help` dumps all 18 usages with no grouping.**
`printHelp` (`executor.ts:990-1000`) prints every `COMMAND_USAGE` value flat, including W4/W5/W6
commands that respond "not implemented yet" (`executor.ts:230-234`). *Why:* a new user can't
tell what actually works today from what's a placeholder. *How:* mark deferred commands in the
listing (they're already in `SEGMENT_OF`, `executor.ts:101-109`) or group by "available now"
vs "coming in Wn". *Where:* `executor.ts:990-1000`, `parser.ts:63-82`. **Effort: S.**

### 2. Robustness / reliability

**REL-1 — Store has a `version` field but no migration/versioning path.** `store.ts:36`
`STORE_VERSION = 1`, written into `MetaRecord.version` (`store.ts:134`) and the IndexedDB
`open(dbName, STORE_VERSION)` (`store.ts:83`), but `onupgradeneeded` only ever creates the one
object store (`store.ts:84-89`) and no code reads `meta.version` to migrate record shapes.
W4 will change `StoredSession` (`executor.ts:69-76`) to hold ratchet state; there is no
mechanism to migrate existing `session/*` records. *Why:* the seam is declared but empty;
the first schema change will silently mis-read old records as new. *How:* add a
`migrate(fromVersion)` dispatch read from `meta.version` on unlock, and bump `STORE_VERSION`
per shape change. *Where:* `store.ts:81-93,144-160`. **Effort: M.**

**REL-2 — `saveContacts` is whole-map last-writer-wins; the rx chain and command chain both
call it.** `saveContacts` serializes the entire `this.contacts` map (`executor.ts:315-317`).
`doAdd` (`:368`), `sendFirstMessage` (`:439`) and `processEnvelope` (`:531`) all mutate the
in-memory map then persist the whole thing. Combined with BUG-2, an rx-side TOFU pin write
(`:530-531`) can clobber a concurrent command-side `/add`. Even single-threaded, a partial
failure between `this.contacts.set(...)` and `saveContacts()` leaves memory and store
divergent. *Why:* no per-contact atomicity, no reconciliation on reload (contacts only load
at login, `:797`). *How:* store contacts per-key (`contact/<uid>`) so writes don't collide,
or gate all contact mutation through one serialized method. *Where:* `executor.ts:310-373,438-439,529-532`.
**Effort: M.**

**REL-3 — No crash-consistency ("write-ahead, then delete superseded") for session/prekey
writes.** CLAUDE.md §4.4 mandates write-ahead-then-delete; `refillOpksInternal`
(`executor.ts:750-769`) writes each OPK then uploads the batch — if the upload throws after
the local writes, local and server OPK sets diverge (local has secrets the server never
advertised: harmless) but `rotateSpkInternal` (`:724-748`) writes the new SPK locally, uploads,
*then* deletes old SPKs — a crash between write and upload leaves a local SPK the peer can't
fetch. The consumed-OPK delete on receive (`:496-498`) happens *before* the session/message
are persisted (`:533-534`); a crash in that window destroys the only copy of the OPK secret
while the message is still queued server-side, making the queued envelope permanently
undecryptable on retry. *Why:* §3.7 says delete the OPK immediately, but §4.4 says persist
state *first*; the ordering here violates the latter for the failure case. *How:* persist the
session + decrypted message, *then* delete the consumed OPK and ack. *Where:*
`executor.ts:495-534`. **Effort: M.**

**REL-4 — Multi-tab: two tabs share one IndexedDB and one identity but have independent
in-memory sessions, and `wipe`'s `deleteDatabase` resolves `onblocked` as success.** Nothing
coordinates tabs. Two tabs both `/login` → two server sessions, two WS connections, two
`rxTail`s draining the same queue and racing acks (double-processing the same envelope before
delete-on-ack lands). `wipe()` treats `onblocked` as resolve (`store.ts:285`) so a second open
tab silently prevents the DB deletion the user asked for, yet `/wipe` reports success
(`executor.ts:987`). *Why:* the product implies one identity per profile (README:120) but
doesn't enforce single-tab. *How:* a `BroadcastChannel` lock (elect one "active" tab for WS
drain), and have `wipe` surface `onblocked` as a warning instead of success. *Where:*
`store.ts:282-287`, `executor.ts:598-625`. **Effort: L** (M for just the `onblocked` honesty
fix).

**REL-5 — `drainInbox` acks a message as processed even when the store is locked.**
`processEnvelope` returns `"skip"` when locked (`executor.ts:478`), and `drainInbox` correctly
only acks non-skips (`:589-591`) — good. But the WS path
(`executor.ts:608-618`) has no such guard visible at the call site: it calls
`processEnvelope`, and only acks on `"ack"`. That's consistent. However, `processEnvelope`
returns `"ack"` for *malformed/undecryptable* messages (`:490-492,512-515`) — a
permanently-poisoned envelope from a buggy/hostile sender is acked and deleted, which is the
right call, but a *transiently* undecryptable one (e.g. `unknown-spk` because the SPK was
rotated+pruned early) is also acked and lost. *Why:* `unknown-spk`/`unknown-opk` are treated
as permanent when they can be transient during rotation windows. *How:* distinguish transient
(`unknown-spk` within the retention window) from permanent reasons and `skip` the transient
ones. *Where:* `executor.ts:483-493`, `kx.ts:174-175`. **Effort: M.**

**REL-6 — `fetchMessages`/REST drain has no retry; a single network error aborts the whole
inbox drain and its acks.** `drainInbox` (`executor.ts:575-596`) awaits `fetchMessages`, loops,
then a single `ackMessages` at the end. If `ackMessages` throws, every message just processed
is re-processed on next login (idempotent for storage, but re-prints and re-runs TOFU checks).
If `fetchBundle` inside `processEnvelope` (`:549`) throws for one unknown sender, that's caught
(`:557`), fine — but a mid-loop `processEnvelope` rejection propagates out of `drainInbox` and
aborts the rest. *Why:* one bad message stops delivery of all later ones. *How:* per-message
try/catch in the drain loop; ack in batches as you go. *Where:* `executor.ts:575-596`.
**Effort: S.**

**REL-7 — WS client has no heartbeat/ping, so a half-open connection is undetected.** The
server answers `ping` with `pong` (`ws.py:128-129`) but `WsClient` never sends `ping`
(`ws.ts`), and there's no idle timer. A dropped-but-not-closed TCP connection (common on
mobile sleep/wake) leaves `isConnected()` reporting OPEN while no messages arrive. *Why:*
silent delivery stall. *How:* client-side heartbeat interval + missed-pong → force close →
(with REL/Top-6) reconnect. *Where:* `ws.ts:21-67`. **Effort: M.**

**REL-8 — `postLoginMaintenance` runs before `drainInbox`, and both can rotate/prune the very
SPK an offline-queued message needs.** `doLogin` order: `postLoginMaintenance` (`:799`, may
rotate SPK if >7d and prune old SPKs via `rotateSpkInternal`) *then* `drainInbox` (`:800`). If
a message was encrypted to an SPK that is now past the retention cutoff
(`rotateSpkInternal` cutoff at `executor.ts:741`), maintenance may delete it moments before the
drain tries to use it. *Why:* ordering makes a narrow but real self-inflicted decryption
failure. *How:* drain the inbox *before* pruning old SPK secrets, or defer SPK pruning until
after a successful drain. *Where:* `executor.ts:799-800,741-747`. **Effort: S.**

### 3. Performance

**PERF-1 — Argon2id (64 MiB, t=3) on the main thread freezes the UI.** `deriveKek`
(`store.ts:64-71`) is synchronous `@noble/hashes` Argon2id, called from `create`
(`:129`), `unlock` (`:149`) and `rotatePassphrase` (`:234,246`). At the §0 params this is
hundreds of ms to seconds and fully blocks the event loop — the terminal is unresponsive and
the cursor stalls during every unlock. *Why:* worst first-impression on `/login`. *How:* run
`deriveKek` in a Web Worker (postMessage passphrase+salt+params, transfer the derived 32
bytes back); `@noble/hashes` runs unmodified in a worker, so no new dependency and no §0
violation. Keep the sync path for tests. *Where:* `store.ts:64-71` and its four callers.
**Effort: M.**

**PERF-2 — `buildPrekeyLookup` rebuilt and fully decrypted per inbound envelope.**
`executor.ts:452-473` lists and decrypts every `spk/*` and every `opk/*` record (≈50+),
opening a fresh IndexedDB connection per `listKeys`/`getJson` (see PERF-3), and it runs once
*per envelope* (`processEnvelope:481`). A batch drain of K messages does K×51 decrypts + K×102
DB connections. *Why:* receive latency scales with (queued messages × prekey count). *How:*
build the lookup once per `drainInbox`/WS burst and pass it in; invalidate when
`refillOpksInternal`/`rotateSpkInternal` runs or a consumed OPK is deleted. *Where:*
`executor.ts:452-473,477-481,575-596`. **Effort: M.**

**PERF-3 — Every store operation opens and closes its own IndexedDB connection.**
`readRaw`/`writeRaw`/`deleteKey`/`listKeys` each call `openDb()` then `db.close()`
(`store.ts:95-113,205-226`). A single receive does ~4 opens for the lookup plus writes; a
login drain multiplies that. IndexedDB `open` is not free and serializes behind
`onupgradeneeded` checks. *Why:* avoidable latency and GC churn, worsens PERF-2. *How:* hold
one open `IDBDatabase` for the store's unlocked lifetime (open on unlock/create, close on
lock/wipe); keep the per-op transaction. *Where:* `store.ts:81-113,162-167`. **Effort: M.**

**PERF-4 — `wipe()` overwrites then deletes every record one awaited request at a time.**
`store.ts:266-288` loops `await request(store.put(...))` then `await request(store.delete())`
serially inside one transaction. For a large history this is slow and the transaction may
auto-close between awaits in strict engines (IndexedDB transactions deactivate when the
microtask queue yields with no pending requests). *Why:* `/wipe` can be slow or, on some
engines, throw "transaction is not active". *How:* issue all `put`s without awaiting each
(collect requests), await once; same for deletes; or accept `deleteDatabase` alone as
sufficient given it's "not forensic erasure" anyway (README:76). *Where:* `store.ts:266-281`.
**Effort: S.**

### 4. Security hardening (beyond ASVS-flagged W1–W3 items)

**SEC-1 — Passphrase policy is a bare 8-char length check with no strength feedback.**
`promptNewPassphrase` (`executor.ts:634`) rejects `< MIN_PASSPHRASE_LENGTH` (8) and nothing
else. The ASVS report notes the *length* mapping; this is the *UX/strength* angle it didn't
cover: there is no zxcvbn-style feedback, no rejection of `"password"`/all-same-char, and the
DEK's entire at-rest security reduces to this passphrase (`store.ts:64-71`). *Why:* a weak
passphrase silently makes the Argon2id wrap brute-forceable offline from a copied IndexedDB.
*How:* add lightweight local entropy heuristics (length + character-class + a small banned
list) with a warning (not a hard block beyond the min), entirely client-side, no new dep.
*Where:* `executor.ts:629-647`. **Effort: S.**

**SEC-2 — Passphrase strings linger as immutable JS `string`s that cannot be zeroized.**
`readSecret` returns a `string` (`shell.ts:46`), passed to `deriveKek`
(`store.ts:65` `new TextEncoder().encode(passphrase)`) and compared via
`secretStringsEqual` (`executor.ts:880`). JS strings are immutable and interned — the
passphrase and its confirm copy remain in the heap until GC, defeating the careful
`Uint8Array.fill(0)` zeroization elsewhere (`store.ts:132,158`, `executor.ts:298`). *Why:* the
codebase zeroizes byte arrays meticulously but the highest-value secret (the passphrase)
escapes it. This is a documented platform limit, but the gap is worth an explicit note and a
narrowing. *How:* read passphrases into a `Uint8Array` in the shell where feasible and pass
bytes to `deriveKek`; at minimum, drop references promptly and document the residual. *Where:*
`shell.ts:44-65`, `store.ts:64-71`, `executor.ts:629-647`. **Effort: M** (S for the doc + prompt-reference
drop; M to thread bytes end-to-end).

**SEC-3 — `KxSession.rk` (64-byte root key) is serialized to the store as base64 and never
zeroized in memory.** `serializeSession` (`executor.ts:1003-1012`) base64-encodes
`session.rk`; the raw `rk` from `initiateKx`/`respondKx` (`kx.ts:142,236`) is never
`.fill(0)`ed by the executor after persistence. The kx module zeroizes `ss1/ss2/messageKey`
(`kx.ts:122-123,128,214-215,226`) but the *root key* survives in the returned object and the
base64 string. *Why:* inconsistent with the module's own zeroization discipline; the RK is the
long-lived secret from which W4 chains derive. *How:* after `putJson(session…)`, `.fill(0)` the
`rk` bytes; treat the serialized-string residue as a known platform limit. *Where:*
`executor.ts:427-431,533,1003-1012`. **Effort: S.**

**SEC-4 — Server nonce/rate-limiter tables grow unbounded in memory (no eviction visible).**
Login nonces are stored server-side until consumed/expired (per README:59) and the rate limiter
is an in-process token bucket (`rate_limit.py`, referenced from
`messages.py:45`). Nothing in the read surface sweeps expired nonces or evicts idle buckets;
an attacker spraying `/login/challenge` (rate-limited to 10/min/IP, but from many IPs) or many
UIDs can grow these maps. *Why:* memory-exhaustion DoS vector distinct from the ASVS
availability note. *How:* periodic sweep of expired nonce rows and LRU/TTL eviction of idle
buckets. *Where:* `rate_limit.py`, nonce storage in `routes/login.py`. **Effort: M.**
(Flagged for confirmation — the limiter file wasn't fully read here.)

**SEC-5 — Executor holds the session token in a plain field and nulls it inconsistently.**
`this.token` (`executor.ts:114`) is cleared on 401 (`:267`), logout (`:855`), wipe (`:981`) and
lock does **not** clear it (`lockLocal` at `:294-306` clears identity + closes WS but leaves
`this.token` set). So after `/lock`, `this.token` is still a live server session usable by any
code path that doesn't check `isUnlocked()` first (e.g. `doKeysStatus` at `:907` only checks
`this.token !== null`). *Why:* `/lock` implies "no more privileged actions" but a stale token
remains actionable in-process. *How:* clear `this.token` in `lockLocal()`; rely on the 15-min
server idle expiry for the server side. *Where:* `executor.ts:294-306`. **Effort: S.**

### 5. Code quality / architecture

**ARCH-1 — `executor.ts` is a ~1000-line god-object.** It owns parser dispatch
(`handleCommand`), auth flows (register/login/logout/rotate), messaging (send/receive/drain),
key maintenance (SPK/OPK), contacts, settings, WS wiring, and async plumbing. *Why:* every W4
change (ratchet state machine, per-conversation state) lands here and the file is already hard
to test in isolation (hence the single narrow `executor-rotate` test). *How:* extract
collaborators behind the existing seams — `AuthFlows` (register/login/logout/rotate,
`:649-905`), `Messaging` (send/receive/drain, `:377-596`), `KeyMaintenance`
(`:715-826`), `ContactStore` (`:308-373`). The executor becomes a thin dispatcher. *Where:*
whole file. **Effort: L.**

**ARCH-2 — Per-conversation state is scattered across ad-hoc store keys with no owning type.**
`session/<uid>`, `msg/<uid>/<ts>`, `pending/<uid>`, and the `contacts` map each live
independently (`executor.ts:349-355,382,431-436,533-534,567`). W4 needs a coherent
per-conversation state machine (uninitialized → reduced-fs → ratcheting → key-changed/blocked).
*Why:* building the ratchet on top of loose keys will duplicate the lookup/serialize logic
already sprawling here. *How:* introduce a `Conversation` aggregate (session + history +
pending + trust flag + block state) with load/save, and route all messaging through it — this
is the natural home for BUG-2's serialization and UX-6's block set. *Where:* new module
consumed by `executor.ts`. **Effort: L.**

**ARCH-3 — Bundle wire↔domain conversion duplicated between executor and the live e2e test.**
`wireToBundle` (`executor.ts:1014-1029`) is re-implemented inline in `live.e2e.test.ts:128-141,201-214`.
*Why:* drift risk; a wire-shape change updates one and not the other. *How:* export
`wireToBundle` and import it in the test. *Where:* `executor.ts:1014-1029`,
`live.e2e.test.ts`. **Effort: S.**

**ARCH-4 — `this.tail` field is declared in the middle of the class, after methods that
reference it.** `executor.ts:240` declares `tail` inside the "async command plumbing" section,
below `handle`/`handleCommand` which are above it, while `rxTail` is declared up top
(`:121`). *Why:* minor readability/consistency wart; two sibling promise-chain fields declared
40 lines apart in different styles. *How:* colocate `tail` and `rxTail` in the field block.
*Where:* `executor.ts:121,240`. **Effort: S.**

**ARCH-5 — `SEGMENT_OF` deferral map and the parser allowlist can drift.** `SEGMENT_OF`
(`executor.ts:101-109`) lists deferred commands by name; `COMMAND_USAGE` (`parser.ts:63-82`) is
the source of truth for command words. A new deferred command added to the parser won't appear
in `SEGMENT_OF` and falls through to the generic "a later segment" (`:231`). *Why:* two lists
to keep in sync. *How:* derive availability from a single table (e.g. annotate `COMMAND_USAGE`
entries with a milestone). *Where:* `parser.ts:63-82`, `executor.ts:101-109`. **Effort: S.**

### 6. Testing

**TEST-1 — Executor messaging/auth flows have no non-live coverage.** Only
`executor-rotate.test.ts` exercises the executor, and only the rotate path; every send/receive
branch (bundle-tamper abort `:408-414`, IK-change block `:416-422`, TOFU pin `:529-531`,
unknown-sender hold `:546-572`, reduced-fs `:442-447`) is covered *only* by the opt-in,
server-required `live.e2e.test.ts` (`skipIf MERIDIAN_EDGE_E2E !== 1`). *Why:* these are the
security-critical decision points and they don't run in normal CI. *How:* the existing
`FakeShell`/`CaptureSink` in `executor-rotate.test.ts:14-36` plus a fake `api`/`WsClient` and
`fake-indexeddb` make a fake-transport executor test straightforward; assert the rendered
security events and store side-effects. *Where:* new `client/tests/executor-messaging.test.ts`.
**Effort: M.**

**TEST-2 — No test for the auto-lock timer behavior (the site of BUG-1).** `touchAutoLock`/
`lockLocal` (`executor.ts:281-306`) have no coverage; the injectable `now`
(`executor.ts:127`) plus fake timers make it testable. *Why:* BUG-1 would have been caught.
*How:* vitest fake timers, advance past `AUTO_LOCK_MS`, assert lock + no mid-flow lock during a
pending `readSecret`. *Where:* new test. **Effort: S.**

**TEST-3 — Envelope encoder/decoder byteOffset asymmetry (BUG-4) is untested.** `envelope.test.ts`
exists but doesn't exercise a non-zero-offset buffer. *How:* encode into a subarray view and
round-trip. *Where:* `client/tests/envelope.test.ts`. **Effort: S.**

### 7. Developer experience

**DX-1 — Live e2e is forced to share one actor pair because registration is 3/hour/IP.**
`live.e2e.test.ts:106-113` bootstraps exactly one Alice+Bob in `beforeAll` and comments that
registration is limited to 3/hour/IP; every test reuses them, so tests can't be independent and
a second run within the hour fails at registration. *Why:* brittle, order-dependent e2e; can't
add tests that need fresh identities. *How:* a dev-only rate-limit relaxation gated behind the
existing `MERIDIAN_EDGE_DEV` flag (raise register capacity when dev mode is on), or a test-only
reset endpoint gated the same way. This mirrors how docs are already dev-gated
(`main.py`, per ASVS V13.3.1). *Where:* register rate-limit config in `main.py`/`rate_limit.py`,
`live.e2e.test.ts:105-113`. **Effort: S.**

**DX-2 — Two-process dev loop with no single command to bring both up.** README:19-29 documents
starting uvicorn and `npm run dev` in two terminals; `.claude/launch.json` only launches the
client (`:5-9`). *Why:* onboarding friction; the client proxies `/v1`→:8000 (`vite.config.ts:9-15`)
so a forgotten backend yields the confusing "is the server running?" line (UX-5). *How:* add a
root `dev` script (or a second launch config) that starts both; or document a one-liner. *Where:*
`.claude/launch.json`, root tooling. **Effort: S.**

**DX-3 — No client-side way to point at a non-default API origin.** `api.ts` uses relative
paths (`/v1/...`) and `ws.ts:25` hardcodes `location.host`. Fine for the proxied dev setup, but
there's no env-driven base URL for testing against a remote/staging backend. *Why:* limits dev
flexibility. *How:* a Vite env var for the API base, defaulting to relative. *Where:* `api.ts`,
`ws.ts:24-25`. **Effort: S.**

---

## Notes / non-issues confirmed during review

- The parser is genuinely total and allowlist-gated (`parser.ts`), consistent with its fuzz
  test; no dynamic dispatch from user input. No change recommended.
- The renderer's control-char stripping (`renderer.ts:21-31`) correctly covers C0/DEL/C1
  including CSI `U+009B`. Solid.
- Delete-on-ack is genuinely transactional server-side (`messages.py:101-115`, `ws.py:130-141`)
  and scoped to the caller's rows. No change.
- WS server ordering (accept → origin → auth → attach) matches §7.11
  (`ws.py:74-118`). No change.
- TOFU identity pinning + IK-change discard on receive (`executor.ts:521-528`) and send-block
  on IK change (`:416-422`) are present and correct for W3; they just need the *blocking/ack*
  UX (UX-6) to fully satisfy §1.4.
