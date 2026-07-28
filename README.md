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

The screen shows `[E203] unlock failed` and nothing else, because that is the
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
| `/settings color reset` | Put your scheme's colors back to its base preset's |
| `/settings emblem <globe\|tree>` | Medallion glyph |
| `/settings theme <layer> <on\|off>` | Atmosphere layers: `emblem`, `scanlines`, `vignette`, `dock`, or `all` |

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
