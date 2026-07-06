# Project-Meridian-Edge

Project Meridian Edge is a passion project of mine that stemmed from a coursework assignment during my first year studying Computer Science.

The project builds **PQTerm** — a pure post-quantum end-to-end-encrypted 1:1
terminal messenger. Every asymmetric operation uses NIST-standardized PQC:
ML-KEM-768 (FIPS 203) for key establishment and ML-DSA-65 (FIPS 204) for
identity and authentication. No classical public-key crypto exists in the
application layer, and CI enforces that.

- [MVP_DOC.md](MVP_DOC.md) — the specification (what and why)
- [CLAUDE.md](CLAUDE.md) — the build guide (how), with the security invariants

## Quick start

Run the backend, then the terminal client, then open the printed URL in a
browser:

```
# terminal 1 — backend (Python ≥ 3.12)
cd server
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:create_app --factory --reload      # API on :8000

# terminal 2 — client (Node ≥ 22)
cd client
npm ci
npm run dev                                          # terminal UI, proxies /v1 → :8000
```

Everything happens inside the terminal that loads: commands start with `/`,
anything else is (eventually) message text. `/help` lists every command;
`/help <command>` shows its usage.

## Using PQTerm today (W1-W5)

### Create your identity — `/register`

1. You are asked to choose and confirm a **passphrase** (min 8 characters,
   input is masked). It encrypts everything stored in this browser — it is
   never sent anywhere.
2. An **ML-DSA-65 identity keypair** is generated in the browser. Only the
   public key is uploaded; the server assigns you a random 26-character UID
   like `7Q3K-M2VD-9XWP-4RTB-A6HJ-EZ01-23`. There is no email, phone number,
   or username.
3. **Ten recovery codes are printed exactly once.** Write them down — the
   server stores only Argon2id hashes and cannot show them again. Losing the
   passphrase *and* the codes means the identity is unrecoverable, by design.
4. You are logged in automatically and a prekey bundle (1 signed prekey +
   50 one-time prekeys, all signed by your identity key) is uploaded so
   others can start encrypted chats with you while you are offline (W3).

Share your UID out-of-band; there is deliberately no directory to search.

### Come back later — `/login`

Enter your passphrase to unlock the local store, and the client proves
possession of your identity key by signing a fresh server challenge
(single-use nonce, 60-second expiry, bound to origin and timestamp). No
password ever exists server-side. On login the client also does housekeeping:
rotates the signed prekey if older than 7 days, tops the one-time prekeys
back up to 50 when they drop below 20, and — on the first unlock on/after
your configured day (default Friday) — reminds you to rotate the passphrase.

### Session & lock commands

| Command | What it does |
|---|---|
| `/whoami` | Your UID and identity-key fingerprint (needs an unlocked store) |
| `/lock` | Locks the store immediately and wipes key material from memory; happens automatically after 10 min idle |
| `/logout` | Revokes the session server-side, then locks |
| `/rotate passphrase` | Re-wraps the store key under a new passphrase — local only, instant, crash-safe. Warns and asks for confirmation if the new passphrase is identical to the current one |
| `/settings rotation on\|off\|day <weekday>` | Configure the weekly rotation reminder |
| `/settings mask asterisk\|hidden` | Passphrase echo: `asterisk` shows `*` per character (default); `hidden` shows nothing at all (sudo-style — no length leak to a shoulder-surfer). Persists across reloads and applies from the first login prompt |
| `/keys status` | Signed-prekey age and one-time-prekey count on the server |
| `/keys refill` | Manually top one-time prekeys back up to 50 |
| `/wipe` | Destroys the local store (identity, keys, everything). Asks you to repeat it within 30 s to confirm |

The session token lives only in JS memory and expires after 15 minutes idle —
a page reload always brings you back locked and logged out, and your data is
still there (encrypted) until you `/wipe` it.

### Contacts & first messages (W3)

| Command | What it does |
|---|---|
| `/add <uid> [alias]` | Save a contact (requires `/login` — contacts live in the encrypted store). The alias is local-only — never transmitted, so it can't impersonate anyone. Also accepts a held contact request |
| `/chat <alias\|uid>` | Set the active conversation (prompt changes to `[alias] >`); the status line shows `(verified)` or `(UNVERIFIED)` |
| `/verify <alias>` | Fetch the contact's current identity key and print a 60-digit safety number — compare it out-of-band (in person, by phone) with what they see on their end |
| `/verified <alias>` | Mark the contact trusted once the safety numbers match |
| `/ack <alias>` | Acknowledge a blocking identity-key-change warning so the conversation is usable again (still `UNVERIFIED` until you `/verify` + `/verified` the new key) |

Typing a plain line sends it: the client fetches the recipient's prekey
bundle, **verifies both prekey signatures against their identity key**
(aborting loudly if the server tampered), runs the ML-KEM-768 PQ-KX
handshake, and ships the message as one AEAD-sealed envelope. It works while
the recipient is offline — the server queues the opaque ciphertext for up to
14 days and deletes it the moment the recipient acknowledges receipt.
Delivery is live over WebSocket while you're logged in (your session token
rotates on every connect).

What the recipient sees: a message from a known contact prints inline; a
message from a stranger is held behind a `[!] new contact request` line and
only opens after `/add`. If no one-time prekey was available the session is
flagged **reduced-fs** until the ratchet's first key-encapsulation step heals
it. The first message per conversation is the PQ-KX handshake above; every
message after that rides the **KEM double-ratchet** (W4) — a fresh symmetric
key per message, with periodic ML-KEM re-keying for post-compromise
security, and the header itself encrypted so an observer of ciphertexts
learns nothing about ratchet state.

**Trust and key changes:** the first time you exchange with (or `/verify`)
a contact, their identity key is pinned. If it ever changes — a re-issued
identity, or a malicious server substituting a different bundle — the
conversation is immediately blocked with a `[SECURITY]` warning and the
contact reverts to `UNVERIFIED`, even if you had verified them before.
`/ack <alias>` clears the block so you can act on it; sending stays honestly
marked `UNVERIFIED` until you `/verify` the new key and `/verified` it again.

### Message lifecycle (W5)

| Command | What it does |
|---|---|
| `/timer <alias> <duration\|off>` | Mutual disappearing-message timer for one conversation — carried encrypted to the peer, applies to both sides, `off` disables it |
| `/purge set <duration\|off>` | Personal local retention cap; never transmitted, may be stricter than the mutual timer |
| `/purge now [alias]` | Delete stored messages immediately — all conversations, or just one |

Deletion is at-rest and local-only, best-effort: peer deletion is
cooperative (nothing stops a screenshot), and browser storage deletion is
not forensic erasure.

### Terminal tips

- **↑ / ↓** — command history (passphrases are never recorded in it)
- **Passphrase echo** — asterisks by default; `/settings mask hidden` shows
  nothing while you type (no length leak). Both bypass history entirely
- **← / → / Home / End / Backspace / Delete** — line editing
- **Ctrl+L** — clear screen (keeps what you were typing) · **Ctrl+U** — clear
  the line · **Ctrl+C** — abandon the line, or cancel a passphrase prompt
- A message that should *start* with a literal `/` is escaped with a leading
  space: ` /this is a message, not a command`

### Guardrails you may run into

- Registration is limited to 3 per hour per IP; login challenges to 10 per
  minute. You'll see a rate-limit failure line — wait and retry.
- Wrong passphrase, unknown UID, expired or replayed challenge all produce
  the same uniform failure — the API leaks nothing about which it was, and
  there is no way to ask the server whether a UID exists.
- One identity per browser profile: `/register` on a device that already has
  a store points you to `/login` (or `/wipe` first).

### Not here yet (build order in CLAUDE.md §8)

- **W6** — `/bench` PQC-vs-classical benchmark suite

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
docs/adr/        architecture decision records
docs/compliance/ OWASP ASVS assessment
scripts/         CI audit gates + vector generator
```

## Development checks

```
cd server && mypy --strict app && pytest     # server gates
cd client && npm run typecheck && npm test   # client gates
python scripts/audit.py                      # classical-crypto / injection greps
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
  config; §7 sweep (CORS/SSRF absence, nonce uniqueness, HSTS); reference
  `docker-compose.yml` + Dockerfiles + `SECURITY.md`.
- Next: **W6** the `/bench` PQC-vs-classical benchmark suite.

See CLAUDE.md §8 for the full build order.

## Production deployment

A reference Docker topology lives at the repo root: Postgres, the FastAPI
server, and an nginx edge that serves the built client same-origin and
terminates TLS.

```
cp .env.example .env   # fill in POSTGRES_PASSWORD, PQTERM_WS_ORIGINS, TLS_CERT_DIR
docker compose build
docker compose up -d
```

See `deploy/nginx.conf` for the TLS policy (TLS 1.3, `X25519MLKEM768` hybrid
group — verify your nginx image's OpenSSL supports it before relying on it)
and `SECURITY.md` for the disclosure contact. This config has not been
build-tested against a live Docker daemon — review it before a real deploy.
