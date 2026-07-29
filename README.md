# Project-Meridian-Edge

Project Meridian Edge is a passion project of mine that stemmed from a coursework assignment during my first year studying Computer Science.

The project builds **Meridian Edge**: a pure post-quantum end-to-end-encrypted
1:1 terminal messenger. Every asymmetric operation uses NIST-standardized PQC,
ML-KEM-768 (FIPS 203) for key establishment and ML-DSA-65 (FIPS 204) for
identity and authentication. No classical public-key crypto exists in the
application layer, and CI enforces that.

- [CODING_GUIDELINES.md](CODING_GUIDELINES.md): the crypto and code invariants, and which of them CI enforces
- [MESSAGES.md](MESSAGES.md): every `[E###]` error code, with its cause and remedy
- [DEPLOY.md](DEPLOY.md): deployment, TLS certificates, and PQC/TLS screening
- [SECURITY.md](SECURITY.md): vulnerability disclosure contact

Licensed under the [GNU AGPL v3.0](LICENSE).

## Quick start

Run the backend, then the terminal client, then open the printed URL in a
browser:

```
# terminal 1: backend (Python >= 3.12)
cd server
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:create_app --factory --reload      # API on :8000

# terminal 2: client (Node >= 22)
cd client
npm ci
npm run dev                                          # terminal UI, proxies /v1 → :8000
```

Everything happens inside the terminal that loads: commands start with `/`,
anything else is (eventually) message text. `/help` lists every command;
`/help <command>` shows its usage.

The dev backend uses SQLite automatically, so there is no database to install.
Add `MERIDIAN_EDGE_DEV=1` before `uvicorn` if you want the `/docs` page.

### Testing with multiple users

Each browser origin has its own encrypted IndexedDB store, so "two users" means
two origins. Run extra client instances on different ports (each still proxies to
the same backend):

```
cd client
PORT=5174 npm run dev   # user B → http://localhost:5174
PORT=5175 npm run dev   # user C → http://localhost:5175
```

`/register` a separate identity in each tab, share UIDs with `/add <uid>`, and
message across. This runs real crypto against the real backend; only TLS and
Postgres are missing versus production.

## Using Meridian Edge today

### Create your identity: `/register`

1. Choose and confirm a **passphrase**: at least 12 characters, including a
   number and a symbol (anything that is not a letter or digit counts, spaces
   included). The input is masked. This passphrase encrypts everything stored
   in this browser and never leaves the device, so its only job is to make an
   offline attack on a copied database expensive.
2. The browser generates an **ML-DSA-65 identity keypair**. It uploads only the
   public key, and the server assigns you a random 26-character UID like
   `7Q3K-M2VD-9XWP-4RTB-A6HJ-EZ01-23`. There is no email, phone number, or
   username.
3. **Ten recovery codes are printed exactly once.** Write them down: the server
   stores only Argon2id hashes and cannot show them again. Losing the passphrase
   *and* the codes makes the identity unrecoverable, by design.
4. You are logged in automatically, and the client uploads a prekey bundle
   (1 signed prekey plus 50 one-time prekeys, all signed by your identity key)
   so others can start encrypted chats with you while you are offline.

Share your UID out-of-band; there is deliberately no directory to search.

### Come back later: `/login`

Enter your passphrase to unlock the local store. The client then proves it
holds your identity key by signing a fresh server challenge (single-use nonce,
60-second expiry, bound to origin and timestamp). No password ever exists
server-side. Login also runs housekeeping: it rotates the signed prekey if it
is older than 7 days, tops the one-time prekeys back up to 50 when they drop
below 20, and on the first unlock on or after your configured day (Friday by
default) reminds you to rotate the passphrase.

### Lost the passphrase or the device: `/recover`

One recovery code takes the account back (alias: `/restore`):

1. Confirm destruction if this browser already holds a store (the old store
   is unreadable without its passphrase, so recovery rebuilds from zero).
2. Enter your **UID** and **one recovery code** (dashes, case, and O/0-style
   typos are forgiven), then choose a new passphrase.
3. A **brand-new identity keypair** replaces the old one server-side. The
   server destroys everything tied to the old key: prekeys, sessions, and any
   queued ciphertext, which the new key could not read anyway. It then prints a
   **fresh set of ten codes**; every old code is void.

Honest costs, by design: message history, contacts, and sessions do not
survive, because they only ever existed inside the old encrypted store. Every
contact still pins your **old** identity key, so your next message triggers
their `[SECURITY]` identity-key-change warning, exactly as if a MITM had
swapped your key. They should re-verify your safety number before
trusting the new one.

### Session & lock commands

| Command | What it does |
|---|---|
| `/whoami` | Your UID and identity-key fingerprint (needs an unlocked store) |
| `/lock` | Locks the store immediately and wipes key material from memory; happens automatically after 10 min idle |
| `/logout` | Revokes this session server-side, then locks |
| `/sessions` | Lists where this account is signed in: one line per live session showing how long ago it started, when it was last active, and which one is this device. Sessions are anonymous by design, so no device name or user agent is stored |
| `/logout all` | Signs out every **other** session and keeps this one (the "I left myself logged in on another device" control). Reports how many were signed out |
| `/rotate passphrase` | Re-wraps the store key under a new passphrase: local only, instant, crash-safe. Warns and asks for confirmation if the new passphrase matches the current one |
| `/settings rotation on\|off\|day <weekday>` | Configure the weekly rotation reminder |
| `/settings mask asterisk\|hidden` | Passphrase echo: `asterisk` shows `*` per character (default); `hidden` shows nothing at all, sudo-style, so it leaks no length to a shoulder-surfer. Persists across reloads and applies from the first login prompt |
| `/keys status` | Signed-prekey age and one-time-prekey count on the server |
| `/keys refill` | Manually top one-time prekeys back up to 50 |
| `/wipe` | Destroys the local store (identity, keys, everything). Asks you to repeat it within 30 s to confirm |
| `/duress set` | Arm a second passphrase that destroys everything instead of unlocking it. Warns first and asks you to type `yes` |
| `/duress off` | Disarm it |
| `/duress status` | Whether one is armed (needs the real passphrase to answer) |

The session token lives only in JS memory and expires after 15 minutes idle, so
a page reload always brings you back locked and logged out. Your data stays
there, encrypted, until you `/wipe` it.

### The duress passphrase

Opt-in and off by default. Once armed, typing it at the `/login` prompt destroys
the local store and deletes the account from the server: prekeys, queued
ciphertext, sessions, recovery codes, and the account row itself. There is no
confirmation, no progress, and no undo.

The screen shows `[E203] Unlock failed.` and nothing else, because that is the
whole point: it has to look like a typo to anyone standing over your shoulder.
`/duress set` prints that warning and makes you type `yes` before anything is
armed, and that warning is the only place the feature ever announces itself.

Some deliberate properties, and their costs:

- **The armed state is invisible at rest.** The sealed envelope sits in the
  store's meta record and is written with random contents from the moment the
  store is created, so an imaged database looks the same either way. The flag
  `/duress status` reads lives *inside* the encrypted store, so only the real
  passphrase can answer the question.
- **It seals a copy of your identity key**, because deleting the account means
  authenticating to the server as its owner. So the duress passphrase gets the
  same strength rules as your real one, and is refused if it *is* your real one
  (as is rotating your real one onto it). It is not a second key to your message
  history: the envelope holds that credential and nothing else.
- **Local destruction happens first**, before any network call, and still
  happens when the server is unreachable. The account deletion is best-effort
  and silent about its failures.
- **It does not clear the transcript already on screen.** A screen that wipes
  itself is exactly the tell this avoids, and anyone watching has already read
  what is on it. What gets destroyed is what is durable.
- **It does not recall messages you already sent.** Those sit in your
  recipients' queues, and reaching into another account's queue is not something
  this server lets anyone do.

- **It only fires from the lock screen**, since that is the only place a
  passphrase is asked for. From an unlocked session, `/lock` first (or wait for
  the 10-minute idle auto-lock), then `/login` and type it.

`/recover` and `/register` rebuild the store from scratch, which leaves the
duress passphrase disarmed; re-arm it afterwards if you want it.

### Contacts & first messages

| Command | What it does |
|---|---|
| `/add <uid> [alias]` | Save a contact. Requires `/login`, since contacts live in the encrypted store. The alias is local only and never transmitted, so it cannot impersonate anyone. Also accepts a held contact request |
| `/remove <alias\|uid> [purge]` | Remove a contact: deletes the contact and tears down the ratchet session, so a later message from them returns as a fresh request. Keeps your message history unless you add `purge`. `/remove all` clears every contact and asks to confirm first. Purely local; the other side is never told |
| `/rename <alias\|uid> <new>` | Give a contact a new local alias. History (keyed by UID) survives; a name another contact already uses is rejected |
| `/favourite <alias\|uid> [off]` | Pin a contact to the top of `/contacts` and the home dashboard, marked `*`. Favourites sort first, then alphabetically. Local only, never transmitted, and the contact is never told. Also spelled `/favorite`, `/fav`, `/star` |
| `/chat <alias\|uid>` | Set the active conversation (prompt changes to `[alias] >`); the status line shows `(verified)` or `(UNVERIFIED)` |
| `/verify <alias>` | Fetch the contact's current identity key and print a 60-digit safety number. Compare it out-of-band, in person or by phone, against what they see on their end |
| `/verified <alias>` | Mark the contact trusted once the safety numbers match |
| `/ack <alias>` | Acknowledge a blocking identity-key-change warning so the conversation is usable again (still `UNVERIFIED` until you `/verify` + `/verified` the new key) |

Typing a plain line sends it: the client fetches the recipient's prekey
bundle, **verifies both prekey signatures against their identity key**
(aborting loudly if the server tampered), runs the ML-KEM-768 PQ-KX
handshake, and ships the message as one AEAD-sealed envelope. It works while
the recipient is offline: the server queues the opaque ciphertext for up to
14 days and deletes it the moment the recipient acknowledges receipt.
Delivery is live over WebSocket while you are logged in, and your session token
rotates on every connect.

What the recipient sees: a message from a known contact prints inline; a
message from a stranger is held behind a `[!] new contact request` line and
only opens after `/add`. If no one-time prekey was available the session is
flagged **reduced-fs** until the ratchet's first key-encapsulation step heals
it. The first message per conversation is the PQ-KX handshake above; every
message after that rides the **KEM double-ratchet**, which derives a fresh
symmetric key per message and re-keys periodically with ML-KEM for
post-compromise security. It encrypts the header too, so an observer of
ciphertexts learns nothing about ratchet state.

**Trust and key changes:** the client pins a contact's identity key the first
time you exchange with them or run `/verify`. If that key ever changes, whether
from a re-issued identity or a malicious server substituting a different
bundle, the client blocks the conversation immediately with a `[SECURITY]`
warning and reverts the contact to `UNVERIFIED`, even if you had verified them
before. `/ack <alias>` clears the block so you can act on it; sending stays
honestly marked `UNVERIFIED` until you `/verify` the new key and `/verified` it
again.

### Groups

| Command | What it does |
|---|---|
| `/group new <name> <contact>...` | Create a group and invite the named contacts |
| `/group list` | Every group on this device |
| `/group open <name>` | Focus a group; typed text goes to all of it |
| `/group info <name>` | The full roster, each member's trust state, and the member-list fingerprint |
| `/group add <name> <contact>` | Add a member. Everyone is told, and they can see it was you |
| `/group remove <name> <contact>` | Remove a member. Everyone is told, including them |
| `/group leave <name>` | Leave, telling the others |
| `/group sync <name>` | Add the members you have no contact entry for, after showing you the list and asking |
| `/group purge <name>` | Delete the group and its local history from this device |

**How it works, and why.** A group message is not a new kind of message. It is N
ordinary messages, each encrypted to one member over the KEM double-ratchet
already established with them, carrying a small group envelope inside the
encrypted payload. There is no group key. The server stores no group object and
sees only what it always sees: opaque envelopes addressed to individual
recipients.

That buys three things for free. Forward secrecy and post-compromise security
are the pairwise ratchet's, unchanged. There is no group key to leak or to
rotate on removal. And sender authentication is inherited: every envelope is
authenticated by its own pairwise ratchet, so **no member can forge a message as
another member**. The cost is O(n) bandwidth per message, which is the right
trade at the scale this app operates at.

*Why not sender keys:* they save bandwidth but add a key-distribution mechanism,
weaken post-compromise security (a leaked sender key exposes everything from
that sender until a rekey), and turn removal into a rekey that is easy to get
wrong.

*Why not MLS.* MLS ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)) is
the standardised answer, and it fixes the exact limitation below: its ratchet
tree, and the signed group context and confirmed transcript hash carried with
every commit, give members cryptographic *agreement* on who is in the group.
TreeKEM is the continuous group key agreement inside it, arranging members as
leaves of a binary tree so an add, remove or key update costs O(log n) instead
of O(n).

Two things stop it being a drop-in here, and the first matters more than the
size:

- **Every ciphersuite RFC 9420 defines is classical.** They are built on HPKE
  with X25519 or the NIST P-curves, and signatures with Ed25519 or ECDSA.
  Adopting MLS as specified would put classical asymmetric cryptography on the
  message path, which contradicts this project's central invariant and is
  grepped for by `scripts/audit.py`. The alternative, inventing a post-quantum
  ciphersuite, runs into the other rule: primitives here are composed, never
  invented. IETF work on PQ and hybrid MLS ciphersuites is ongoing but not
  something to ship against yet.
- **Size.** This whole client is about 11,000 lines. A production MLS stack is
  several times that on its own, before any integration.

So MLS is the direction, not a plan on a shelf: there is no migration design
written for it here beyond this paragraph, and it is blocked on a
post-quantum ciphersuite existing to standardise against.

**What this does not give you.** Two limitations are real, and neither is
papered over in the UI:

1. **Membership is not cryptographically agreed.** Nothing signs the roster, so
   a malicious member can show different member lists to different people. This
   design does not prevent that; it makes it *detectable*. Every message carries
   the sender's full roster, and a recipient whose own roster disagrees gets a
   `[SECURITY]` warning naming exactly who was added or dropped. `/group info`
   prints a short fingerprint of your roster to read out to the others. That
   fingerprint is a convenience for comparing lists, **not** a proof that a list
   is right, and the app says so on screen.
2. **There is no transcript consistency.** A member can send different text to
   different members. Fan-out cannot fix this and neither can sender keys; only
   a protocol with a shared ordered transcript can.

Smaller ones, stated rather than discovered: removing someone stops future
messages and **takes back nothing** they already received; a group discloses
every member's UID to every other member; a fan-out of N sends in quick
succession lets the server infer that those N accounts are probably a group,
which no cheap countermeasure honestly fixes; and group history is swept by
`/purge set` alongside one-to-one history, so the retention cap stays true.

Groups cannot be forced onto you. A group message from someone who is not a
contact is discarded (`E513`), the contact-request gate applies to groups
exactly as it does to direct messages, and a group is only created on an
explicit invite that lists you. Ordinary traffic for a group this device does
not know is reported, never silently joined.

Two consequences of that worth knowing before you use it:

- **You can only send to members you have added.** Encrypting to someone needs a
  session, and a session needs a pinned key. `/group sync` prints the members
  you are missing and adds them once you confirm; it is a command rather than an
  automatic step because adding a contact means accepting a key on trust, and
  doing that silently would let anyone who can invite you write into your
  contact list. Synced contacts are `UNVERIFIED` until you `/verify` them, like
  any other.
- **A roster is never adopted wholesale.** An incoming message can announce a
  change (an add, a removal, a departure) and this device applies exactly that
  change to its own roster. It never copies the sender's list over. A member who
  lies about the roster can therefore disagree with you, which is reported, but
  cannot rewrite what you hold.
- **An invite carrying a name you already use is renamed on arrival**, and the
  rename is announced. Group names are how every `/group` subcommand addresses a
  group, and the name comes from whoever invited you, so a collision would
  otherwise decide where your next message went.

### Message lifecycle

| Command | What it does |
|---|---|
| `/timer <alias> <duration\|off>` | Mutual disappearing-message timer for one conversation. The client carries it encrypted to the peer and applies it on both sides; `off` disables it |
| `/purge set <duration\|off>` | Personal local retention cap. Never transmitted, and may be stricter than the mutual timer |
| `/purge now [alias]` | Delete stored messages immediately, across all conversations or just one |

Deletion is at-rest, local-only, and best-effort. Peer deletion is cooperative,
nothing stops a screenshot, and browser storage deletion is not forensic
erasure.

### Appearance

| Command | What it does |
|---|---|
| `/settings scheme <name>` | Switch scheme: the `dark`, `parchment` and `olive` presets, or one of your own |
| `/settings scheme list` | Everything you can switch to, marking the active one |
| `/settings scheme new <name>` | Copy the colors currently on screen into a scheme of your own and switch to it |
| `/settings scheme delete <name>` | Delete one of yours. Presets cannot be deleted |
| `/settings color <slot> <#rrggbb>` | Set one of the five slots: `accent`, `background`, `panel`, `text`, `muted` |
| `/settings color event <marker> <#rrggbb>` | Recolor a notification marker: `success`, `warning`, `info`, `failure`, `peer` |
| `/settings color reset` | Put your scheme's colors and markers back to its base preset's |
| `/settings emblem <globe\|tree>` | Medallion glyph |
| `/settings theme <layer> <on\|off>` | Atmosphere layers: `emblem`, `scanlines`, `vignette`, `dock`, or `all` |
| `/settings font <name>` | Monospace stack: `default`, `system`, `classic`, `wide`, `compact` |
| `/settings font list` | The stacks, with what each is for |
| `/settings fontsize <10-28>` | Terminal size in px; the terminal re-fits itself |
| `/settings a11y screenreader <on\|off>` | Mirror terminal output into an ARIA live region |
| `/settings a11y motion <on\|off>` | Force reduced motion without changing your OS setting |

**Fonts are monospace-only**, and that is a constraint rather than a taste:
xterm lays the transcript out in fixed cells, and every aligned listing here is
built from padded columns. Each option is a stack of *local* faces ending in the
generic `monospace`. Nothing is ever fetched from a remote origin: the CSP
forbids it, and a webfont is a request to someone else's server on every load.
The stack is chosen by name from a fixed allowlist, so no stored string reaches
a CSS declaration.

**Accessibility.** The `contrast` scheme is a preset whose every slot, including
`muted` and the notification markers, clears WCAG AA against its own background;
the other schemes deliberately let `muted` recede, which is exactly what fails
for a low-vision reader. The footer status strip is a live region, so every
event is announced as a short sentence without following the scrolling
transcript, and a `[SECURITY]` event escalates to assertive so it interrupts
rather than queueing. `screenreader` turns on xterm's own live-region mirror; it
is off by default for the rendering cost, not for any exposure reason, since the
same text is already in the DOM as terminal cells. All of these live with the
unencrypted display preferences, so they apply to the lock screen, which is
where someone who needs them meets the app first.

**Notification markers are yours too.** The `[✓]` `[!]` `[*]` `[E###]` prefixes
in front of every event line, the `[alias]` on an incoming message, and the
status strip just above the command line all default to the ANSI palette. That
palette is tuned for the preset, so a custom scheme can easily land a green
marker on a green background; `/settings color event` is the way out. One
setting moves both surfaces, since the strip reads the same resolved values the
terminal does.

Recoloring is safe, and the design is what makes it safe rather than a promise.
In the transcript the renderer tints **only the marker**: every event's message
text is printed in your scheme's `text` color after the color is closed, so no
setting here can make the words of a warning unreadable. The markers also carry
their meaning as literal text, so `[SECURITY]` still reads as `[SECURITY]` in
any color at all. And the one place where the strip is the only surface a
message reaches, a `[SECURITY]` event, is deliberately excluded: its
white-on-red treatment is fixed and not configurable.

**The three presets are immutable.** Running `/settings color` while one is
active does not modify it: it forks a scheme named `<preset>-custom`, switches
you there, and tells you so. `/settings scheme dark` therefore always means the
palette that shipped, however far you have wandered. Names are limited to 1-24
lowercase letters, digits and hyphens, colors to literal `#rrggbb`, and both are
re-validated on every read, so nothing in that record can reach the page as
anything but a color. Appearance lives unencrypted by design, so it can apply to
the lock screen before you have unlocked anything, which is also why it is
treated as untrusted input.

### Terminal tips

- **`/help`** adapts to the width it is printed at: a two-column reference with
  the descriptions aligned on a desktop, and one command per line with its
  description indented beneath on a phone. **`/help <command>`** explains what
  that command is for and what it costs, then gives its usage
- **↑ / ↓**: command history. It never records passphrases
- **Passphrase echo**: asterisks by default; `/settings mask hidden` shows
  nothing while you type, leaking no length. Both bypass history entirely
- **← / → / Home / End / Backspace / Delete**: line editing
- **Ctrl+L**: clear the screen, keeping what you were typing. **Ctrl+U**: clear
  the line. **Ctrl+C**: abandon the line, or cancel a passphrase prompt
- Escape a message that should *start* with a literal `/` by typing a leading
  space: ` /this is a message, not a command`

### Guardrails you may run into

- Registration is limited to 3 per hour per IP, login challenges to 10 per
  minute, and recovery attempts to 5 per hour. You will see a rate-limit
  failure line (`E301`); wait and retry.
- Wrong passphrase, unknown UID, expired or replayed challenge, and a wrong or
  spent recovery code all produce the same uniform failure. The API leaks
  nothing about which one it was, and nothing lets you ask the server whether a
  UID exists.
- One identity per browser profile. `/register` on a device that already holds
  a store points you to `/login`, or to `/wipe` first; `/recover` offers to
  destroy and rebuild it.
- Every error line carries a stable code (`[E###]`). [MESSAGES.md](MESSAGES.md)
  tables them all with causes and remedies.

### Researcher tools

- **`/bench [b1|b2|b3|b4|all]`**: runs the PQC-versus-classical benchmark suites
  in the browser, covering primitive latency (B1/B2), size overhead (B3), and
  protocol-level timings (B4). Tables print in the terminal; the full JSON and
  Markdown go to the console. `make bench` runs the server-side and footprint
  suites (B5); see [bench/README.md](bench/README.md).

The MVP build order is complete. What remains are documented could-haves
(charts, a rehearsed demo script) and the B4/B5 methodology notes in the bench
README.

## Layout

```
client/          TypeScript + Vite + xterm.js frontend
  src/terminal/  UI, command parser, renderer
  src/crypto/    constants, key store, prekeys, PQ-KX, ratchet, envelope codec
  src/net/       REST + WebSocket clients
server/
  app/           FastAPI: auth, prekeys, bundles, message queue, WS
  tests/
  Dockerfile     production server image
deploy/          nginx reverse-proxy image + config (TLS, CSP, static bundle)
docker-compose.yml, .env.example   reference production topology
SECURITY.md      vulnerability disclosure contact
shared/vectors/  cross-impl test vectors (pyca/OpenSSL ↔ noble)
bench/           benchmark harness (B1–B5)
scripts/         CI audit gates + vector generator
LICENSE          GNU AGPL v3.0
```

## Development checks

```
cd server && ruff check . && mypy --strict app && pytest      # server gates
cd client && npm run lint && npm run typecheck && npm test    # client gates
python scripts/audit.py                                       # classical-crypto / injection greps
```

All of the above plus `npm audit` / `pip-audit` run blocking in CI.

## Status

- **W1** ✓ terminal shell + allowlist parser, FastAPI skeleton,
  server-authoritative UID registration, CI gates.
- **W2** ✓ passwordless identity: ML-DSA-65 challenge–response `/login`
  (single-use origin-bound nonces, verified via pyca `cryptography`),
  memory-only session tokens (SHA-512 at rest, 15 min idle), Argon2id-wrapped
  IndexedDB key store with auto-lock and `/rotate passphrase`, recovery codes
  (Argon2id hashes server-side), signed prekey + batch-signed one-time prekeys
  with low-watermark refill, `/wipe`.
- **W3** ✓ first messages: PQ-KX handshake (ML-KEM-768 to SPK+OPK, ML-DSA-65
  transcript signature, XChaCha20-Poly1305 with the transcript as AD), binary
  envelope v1, offline delivery via a delete-on-ack 14-day-TTL queue, live
  WebSocket push with token rotation, contact requests + TOFU identity
  pinning, cross-implementation vectors in CI.
- **W4** ✓ trust + ratchet: safety numbers, `/verify` + `/verified`,
  key-change teardown; a KEM double-ratchet (direction-split symmetric
  chains, periodic ML-KEM re-keying for FS/PCS, bounded out-of-order
  delivery, encrypted headers) governs every message after the PQ-KX first
  one.
- **W5** ✓ lifecycle + hardening: `/timer`, `/purge set`/`/purge now`;
  per-connection WS rate cap + idle-kill + client heartbeat; a
  production-boot-safety gate that refuses to start with a dev-shaped
  config; a security-gap sweep (CORS/SSRF absence, nonce uniqueness, HSTS); reference
  `docker-compose.yml` + Dockerfiles + `SECURITY.md`.
- **W6** ✓ benchmarks: `/bench` B1–B4 in the browser (primitive latency, size
  overhead, protocol-level) + a server harness (`make bench`) for native B1/B2
  and the B5 footprint. Headline finding: the PQC libraries are *smaller* than
  the classical curves baseline, so the PQC cost is latency and wire size, not
  JS bundle.

## Production deployment

A reference Docker topology lives at the repo root: Postgres, the FastAPI
server, and an nginx edge that serves the built client same-origin and
terminates TLS.

```
cp .env.example .env   # fill in POSTGRES_PASSWORD, MERIDIAN_EDGE_WS_ORIGINS, TLS_CERT_DIR
docker compose build
docker compose up -d
```

**[DEPLOY.md](DEPLOY.md) carries the full instructions:** the three deployment
routes, TLS certificates, shipping updates, passing PQC/TLS screenings,
operations, scaling limits, and troubleshooting.
[Testing with multiple users](#testing-with-multiple-users) above covers running
the dev servers and multi-user local testing. See [SECURITY.md](SECURITY.md) for
the disclosure contact.

> Nobody has build-tested this config against a live Docker daemon. Review it
> before a real deploy.
