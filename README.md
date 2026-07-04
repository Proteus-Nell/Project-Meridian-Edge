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

## Using PQTerm today (W1 + W2)

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
| `/keys status` | Signed-prekey age and one-time-prekey count on the server |
| `/keys refill` | Manually top one-time prekeys back up to 50 |
| `/wipe` | Destroys the local store (identity, keys, everything). Asks you to repeat it within 30 s to confirm |

The session token lives only in JS memory and expires after 15 minutes idle —
a page reload always brings you back locked and logged out, and your data is
still there (encrypted) until you `/wipe` it.

### Contacts (messaging lands in W3)

| Command | What it does |
|---|---|
| `/add <uid> [alias]` | Save a contact. The alias is local-only — it is never transmitted, so it can't be used to impersonate anyone |
| `/chat <alias\|uid>` | Set the active conversation (prompt changes to `[alias] >`) |

Typing a plain line targets the active conversation, but sending is not wired
yet — the PQ-KX handshake, message encryption, and the delivery queue are the
W3 milestone. Today the client tells you so honestly instead of pretending.

### Terminal tips

- **↑ / ↓** — command history (passphrases are never recorded in it)
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

- **W3** — actual messaging: PQ-KX handshake, offline delivery via a
  delete-on-ack queue
- **W4** — the KEM double-ratchet (forward secrecy / post-compromise
  security), `/verify` + `/verified` safety numbers, `/ack`
- **W5** — `/timer` disappearing messages, `/purge`, the hardening sweep
- **W6** — `/bench` PQC-vs-classical benchmark suite

## Layout

```
client/          TypeScript + Vite + xterm.js frontend
  src/terminal/  UI, command parser, renderer
  src/crypto/    constants, key store, prekeys, login message
  src/net/       REST client (WS in W3)
server/
  app/           FastAPI: auth, prekeys, rate limiting
  tests/
shared/vectors/  JSON test vectors (liboqs → TS tests)
bench/           benchmark harness (B1–B5)
docs/adr/        architecture decision records
scripts/         CI audit gates
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
- Next: **W3** PQ-KX handshake, first message, delete-on-ack delivery queue.

See CLAUDE.md §8 for the full build order.
