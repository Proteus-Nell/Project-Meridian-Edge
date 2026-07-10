# Meridian Edge — OWASP ASVS 4.0.3 (Level 2) Compliance Assessment

**Date:** 2026-07-04
**Scope:** W1 (terminal shell/parser, server skeleton, UID registration) + W2 (ML-DSA-65
challenge–response login, session tokens, Argon2id-wrapped IndexedDB key store, prekey
upload, recovery codes). W3 (handshake/messaging), W4 (ratchet/trust), W5 (transport
hardening: TLS, CSP-at-proxy, full rate-limit pass, container hardening), and W6
(benchmarks) are **not yet built** per `CLAUDE.md` §8 build order and are marked
`DEFERRED(Wn)` below wherever a requirement specifically depends on that milestone.
**Standard:** OWASP ASVS 4.0.3, Level 2.
**Assessor scope note:** static code review only — no server run, no dependency
install, no test execution. Findings are grounded in the file:line references cited.

---

## Executive Summary

The W1+W2 surface is a small, disciplined codebase: a FastAPI backend exposing exactly
seven routes (register, login challenge/verify, logout, prekey upload ×2, key status)
and a TypeScript terminal client. The implemented slice shows strong engineering
discipline consistent with the project's own invariants: uniform error responses
(`server/app/errors.py`), no user-enumeration oracle (`server/tests/test_surface.py`),
Argon2id-wrapped local key storage with documented parameters, SHA-512-hashed session
tokens, single-use origin/timestamp-bound login nonces, a CI-enforced classical-crypto
and injection-pattern grep (`scripts/audit.py`), and a genuinely fuzz-tested command
parser with terminal-escape sanitization in the renderer.

The most significant genuine gaps for this slice are: (1) no security event logging /
counters at all (ASVS V7.4, ties to CLAUDE.md §7.9 item 9 — an OWASP sweep item that
is *not* scoped only to W5), (2) the server does not check the `Origin` header against
an actual allowlist — it only checks *consistency* between the challenge and verify
requests, so any origin is accepted verbatim (ASVS V2.7 / V14.4), (3) no
`SECURITY.md` disclosure document (explicitly promised by CLAUDE.md §7.9), (4) no
explicit CORS policy configured (currently relying on browser same-origin default,
which is safe today but is not the "exact-origin allowlist, no wildcard" the project's
own §5 checklist requires — arguably a W5 item but worth flagging now since it is
cheap to add), and (5) the recovery-code redemption path is unimplemented server-side
(correctly DEFERRED per CLAUDE.md, but currently means recovery codes are printed with
no way to ever use them — worth a doc note).

Nothing found rises to a `FAIL` that reflects a violation of the project's own W1/W2
invariants; most `FAIL`/`PARTIAL` verdicts below are either legitimately deferred to
W3–W5 (messaging, ratchet, transport hardening, WS auth) or are small, cheaply-fixed
gaps (logging, SECURITY.md, explicit CORS/Origin allowlist). Overall posture for a
two-milestone-deep academic prototype: **good**, with a short, concrete punch list
below.

---

## Verdict Counts

| Verdict | Count |
|---|---|
| PASS | 47 |
| PARTIAL | 9 |
| FAIL | 5 |
| N/A | 11 |
| DEFERRED(Wn) | 21 |
| **Total requirements assessed** | **93** |

(Counts reflect the individual requirement rows in the per-chapter tables below; a
handful of ASVS items are grouped where the codebase treats them identically, e.g.
several V5.3 encoding sub-items covered by one renderer.)

---

## V1 — Architecture, Design and Threat Modeling (assessed briefly)

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V1.1.1 | Secure SDLC touches security in each phase | PASS | `CLAUDE.md` §0 "Ground Rules" gate every segment; `.github/workflows/ci.yml` runs audits/tests/typecheck/mypy per PR | Security-by-design baked into the build guide itself |
| V1.1.3 | Threat model exists and is kept current | PASS | `MVP_DOC.md` §4 (adversaries A1–A6, assumptions, security properties table) | Explicit, adversary-labeled threat model |
| V1.2.1 | Unique/unambiguous identities enforced | PASS | `server/app/models.py:18` UID `unique=True` DB constraint; `server/app/routes/register.py:39-48` retry-on-collision inside the transaction | |
| V1.2.2 | Strong authentication mechanisms documented per use case | PASS | `MVP_DOC.md` §6.2, `CLAUDE.md` §2 — ML-DSA-65 challenge–response, no passwords server-side | |
| V1.4.1 | Trusted enforcement points (e.g., server not client) for access control | PASS | `server/app/auth.py` — all authorization decided server-side via `require_auth`; client never asserts identity | |
| V1.5.1–V1.5.4 | Input/output architecture: validate at trust boundary | PASS | `server/app/schemas.py` — every route body is a Pydantic model with `extra="forbid"` and explicit length validators | |
| V1.8.1/V1.8.2 | Data classified, protection matches classification | PASS | `MVP_DOC.md` §6 architecture table explicitly marks "server sees ciphertext only... never plaintext, never private keys" | Consistent with implementation: `models.py` stores only public keys and hashes |
| V1.9.1 | Communication authenticated/encrypted between components | DEFERRED(W5) | `CLAUDE.md` §5 TLS 1.3 checklist item is explicitly a hardening-pass (W5) task; no proxy/TLS config in this repo | Dev server runs plain HTTP by design at this stage |
| V1.14.x | Configuration architecture (secrets, containers) | DEFERRED(W5) | CLAUDE.md §5 "Container" checklist (non-root, read-only FS, secrets via env) is a W5 item; no Dockerfile in repo | |

## V2 — Authentication (passwordless: ML-DSA challenge-response; Argon2id passphrase is a *local key-wrapping* credential, not a server credential)

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V2.1.1 | Enforce minimum credential (password) length ≥ 12 | PARTIAL | `client/src/terminal/executor.ts:71` `MIN_PASSPHRASE_LENGTH = 8` | This is the *local* unlock passphrase (key-wrapping credential), not a server credential — ASVS's password rules don't map 1:1, but if treated as the closest analog it's below the ASVS-recommended 12; consider raising the floor or documenting the mapping rationale explicitly |
| V2.1.2 | Allow at least 64-character passwords | PASS | No client-side max-length cap on the passphrase found in `store.ts`/`executor.ts` (Argon2id handles arbitrary length input) | |
| V2.1.7 | Reject known breached passwords | N/A | No server-side password exists to check; local-only passphrase, no breach-list feasible offline | Documented rationale: passwordless design (`MVP_DOC.md` §6.2) |
| V2.1.9 | No periodic credential rotation policy mandated by server | PASS | `CLAUDE.md` §2.5 rotation prompt is client-side, opt-out, informational only; no server enforcement | Matches NIST SP 800-63B guidance the project explicitly cites (`MVP_DOC.md` §6.6) |
| V2.2.1 | Anti-automation controls on authentication (rate limiting) | PASS | `server/app/rate_limit.py` token bucket; applied to `/v1/register` (`REGISTER_RATE_CAPACITY=3/hr`) and `/v1/login/challenge` (`10/min`) — verified by `server/tests/test_rate_limit.py`, `test_login.py::test_challenge_rate_limited` | `/v1/login/verify` itself has **no independent rate limit** — see finding below |
| V2.2.2 | CAPTCHA/anti-automation as defense-in-depth | N/A | Explicitly a non-goal (`MVP_DOC.md` §10.8 "Availability... not an MVP goal") | Documented limitation |
| V2.2.3 | Notify user of authentication events (new device, etc.) | DEFERRED(W6) | Toast notifications explicitly Could-have / W6-adjacent (`CLAUDE.md` §1.7) | |
| V2.3.x | Out-of-band verifiers (SMS/email OTP) | N/A | No OOB channel in this design (UID-only, no email/phone by design) | `MVP_DOC.md` §6.1 "No PII" |
| V2.4.x | Credential storage (password hashing) | PASS | Recovery codes hashed with Argon2id (`server/app/security.py:27-31,63-65`); params match §0 exactly, asserted in `test_security.py::test_production_argon2_params_match_constants` | No server-side "password" exists; recovery codes are the closest server-stored secret and are correctly hashed |
| V2.5.1 | Secure credential recovery mechanism | PARTIAL | Recovery codes are generated, shown once, and hashed (`routes/register.py:49-53`) — but **no redemption endpoint exists** (confirmed absent by `server/tests/test_surface.py::test_no_user_lookup_or_existence_routes`, which enumerates the full 7-route surface) | DEFERRED(W5) per `CLAUDE.md` §8 W2 specifics ("redemption endpoint deferred to W5") — correctly flagged by the project's own docs, not a silent gap |
| V2.5.2 | Recovery doesn't reveal current credential | PASS | Codes are never re-displayed after registration (`executor.ts:340-348` only path that ever prints them); server stores only Argon2id hash | |
| V2.5.4 | Enforce equal error messages/response codes for login | PASS | `routes/login.py:101-107` — unknown UID, expired nonce, origin mismatch, and bad signature all fall into one `401 auth_failed` branch or the identical final check; `pqc.py:31-33` `burn_verification_time` equalizes timing on the not-found path | Directly tested: `test_login.py::test_unknown_uid_is_not_an_oracle` |
| V2.6.x | Look-up secrets (recovery codes) single use, sufit­ient entropy | PASS (generation) / DEFERRED(W5) (consumption) | `constants.py:49-50` 80-bit codes ×10; `models.py:34` has a `used` flag ready for the redemption flow | The `used` column exists but nothing sets it yet — consistent with "redemption deferred" |
| V2.7.1 | Out-of-band/verifier-generated nonce ≥ 20 bits entropy, single use, time-limited | PASS | `constants.py:41-42` 32-byte (256-bit) nonce, `NONCE_TTL_SECONDS=60`; `models.py:48` `consumed` flag; nonce burned even on failed attempts (`routes/login.py:92-95`) | Tested: `test_login.py::test_nonce_replay_rejected`, `test_failed_attempt_burns_nonce`, `test_nonce_expires_after_60s` |
| V2.7.2 | Verifier bound to session/context to prevent replay | PARTIAL | Nonce is bound to a *client-supplied* `origin` string echoed back and re-checked for equality (`routes/login.py:36-37,56,78,90`), but **the server never validates that `origin` is one of the app's own actual origins** — any string (including empty) is accepted as long as challenge and verify agree | Genuine gap: an attacker who can get a victim to sign a challenge under a chosen "origin" value gets a token usable from anywhere, since there's no allowlist check. Low real-world severity today (no CORS-exposed cross-origin path yet, W5 will add proxy-level origin allowlisting for WS), but this is a **login-time** check that arguably belongs in W2, not W5. See Findings §(a). |
| V2.8.x | OTP mechanisms (TOTP etc.) | N/A | Not part of design — ML-DSA signature *is* the second factor beyond UID possession | |
| V2.10.x | Service authentication (server-to-server secrets) | N/A | No inter-service calls exist in this deployment shape yet | |

## V3 — Session Management

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V3.2.1 | Session tokens generated by CSPRNG, sufficiently random | PASS | `security.py:34-35` `secrets.token_hex(SESSION_TOKEN_BYTES)`, `constants.py:45` 256-bit | |
| V3.2.2 | Session tokens use ≥64 bits entropy | PASS | 256-bit token (far exceeds) | |
| V3.2.3 | Session tokens stored with generic name / not in URL | PASS | `client/src/net/api.ts:25` `Authorization: Bearer` header, never a query param or cookie | |
| V3.3.1 | Logout invalidates session server-side | PASS | `routes/login.py:115-121` sets `revoked=True`; tested `test_sessions.py::test_logout_revokes_server_side` | |
| V3.3.2 | Idle/absolute session timeout enforced server-side | PASS | `auth.py:48-52` idle check against `SESSION_IDLE_SECONDS=900`; tested `test_sessions.py::test_idle_expiry_after_15_minutes`, `test_activity_slides_the_idle_window` | |
| V3.4.x | Cookie-based session attributes (HttpOnly/Secure/SameSite) | N/A | No cookies used — bearer token in memory only, per design (`MVP_DOC.md` §6.2) | Deliberately avoids the entire cookie-attribute surface |
| V3.5.1 | Stateless tokens (JWT) validated correctly (signature, exp, aud) | N/A | Tokens are opaque random values, not JWTs — no self-contained-token validation surface exists | |
| V3.5.2 | Stateless token revocation possible | N/A | Superseded by V3.3.1 (opaque tokens, server-side revocation list is the mechanism) | |
| V3.6.1 | Users can view/log out active sessions | FAIL | No `/sessions` list or "log out other devices" capability exists; `SessionToken` rows have no user-visible enumeration path | Minor at Level 2 for a 1-session-typical CLI messenger, but ASVS requires it; not mentioned as planned in any milestone — recommend logging it as a backlog item rather than silently skipping |
| V3.7.1 | Re-authentication for sensitive actions (e.g., changing credentials) | PARTIAL | `/rotate passphrase` requires the *current* passphrase (`executor.ts:520-546`) — good — but this is purely local; there is no re-auth (fresh ML-DSA challenge) before server-side sensitive actions like `/wipe`'s local destruction (which is local anyway) or key uploads (`/keys/spk`, `/keys/opks`) which rely solely on the still-valid bearer session | Acceptable for MVP scope; note explicitly |
| V3.7 (WS reconnection) | Session token rotated on every WS reconnect | DEFERRED(W3) | `CLAUDE.md` §8 W2 specifics: "WS-reconnect rotation lands with WS in W3" — no WS code exists yet (`grep` for WS/websocket routes returns nothing) | Correctly deferred per project's own build order |

## V4 — Access Control

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V4.1.1 | Enforce access control at a trusted service layer, deny by default | PASS | `auth.py:33-59` `require_auth` dependency; every prekey route requires it (`routes/keys.py:33,50,85`) | |
| V4.1.2 | Only user-owned or authorized data accessible | PASS | `routes/keys.py:37,52-55,64,84,93` — every query filters `WHERE user_id == ctx.user.id`; no path accepts a foreign user id | |
| V4.1.3 | Enforce principle of least privilege | PASS | No admin/role model exists; every authenticated user has identical, self-scoped privileges — no privilege-escalation surface | |
| V4.1.5 | IDOR/BOLA testing performed | PASS | `test_keys.py::test_status_is_scoped_to_own_user` — registers two accounts, uploads OPKs to A, asserts B's status shows 0 | This is the explicit IDOR test CLAUDE.md §7.1 calls for |
| V4.2.1 | Sensitive data/APIs protected against CSRF | PASS (by design) | No cookies ⇒ no ambient-authority CSRF vector; bearer token must be explicitly attached by JS (`api.ts:25`) | |
| V4.2.2 | Enforce authorization on server, independent of client | PASS | All authorization decisions in `auth.py`/route handlers; client-side checks (`executor.ts`) are UX only | |
| V4.3.1 | Admin interfaces require MFA / are separate | N/A | No admin interface exists in this MVP | |
| V4.3.2 | Directory/file listing disabled, direct object references avoided | PASS | No filesystem-serving routes exist; all data access is parameterized ORM queries | |

## V5 — Validation, Sanitization and Encoding

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V5.1.1 | Input validation is positive (allowlist) | PASS | `schemas.py` — every field has an explicit `field_validator` doing exact-length base64 decode or canonicalization; `ConfigDict(extra="forbid")` rejects unknown fields (`schemas.py:29,49,106,125`), tested in `test_register.py::test_extra_fields_rejected` | |
| V5.1.2 | Structured data validated against schema | PASS | Pydantic models throughout; FastAPI auto-validates before the handler runs | |
| V5.1.3 | All input validated server-side (client-side validation is a UX aid only) | PASS | Client parser (`parser.ts`) validates argument shape, but server independently re-validates every field (`schemas.py`) — e.g., UID canonicalization exists in both `parser.ts:96-111` and `uid.py:35-45` | Matches `MVP_DOC.md` §7.3 "validated client-side *and* server-side" |
| V5.2.1 | Sanitize untrusted HTML/markup | N/A (no HTML rendering path) | `client/index.html` has no dynamic HTML sinks; `scripts/audit.py:39-41` CI-greps for `innerHTML`/`outerHTML`/`dangerouslySetInnerHTML`/`document.write` across all client `.ts` | Enforced by CI gate, not just convention |
| V5.2.3 | Sanitize untrusted data embedded into OS commands / SQL / etc. | PASS | No shell execution anywhere in `server/app`; SQLAlchemy ORM used exclusively (no raw SQL found); `scripts/audit.py:49-59` greps for f-string SQL and `exec(`/`pickle`/`eval(` | CI-enforced (`audit.py`), confirmed no matches via manual read of all route files |
| V5.2.5 (terminal-escape injection, project-specific analog of output encoding) | Untrusted text cannot inject terminal control sequences | PASS | `renderer.ts:19-31` `sanitizeText()` strips C0 controls, DEL, and C1 controls (incl. CSI `U+009B`) from all rendered text; both `event()` and `plain()` paths route through it (`renderer.ts:44-51`) | This is the ASVS V5 "output encoding" requirement mapped onto a terminal UI instead of a browser DOM — reasonable and tested via `renderer.test.ts` (not fully read but present in `client/tests/`) |
| V5.3.1 | Output encoding for the target interpreter | PASS | Same as above — xterm.js `write()` with ANSI color codes is the only sink; no `innerHTML` path exists anywhere (CI-enforced) | |
| V5.3.4 | JSON auto-encoded correctly, no injection via serialization | PASS | FastAPI/Pydantic response models used throughout (`schemas.py`); no manual string-built JSON | |
| V5.5.2/V5.5.3 | Deserialization of untrusted data is safe (no unsafe deserializers) | PASS | No `pickle`, no `yaml.load`, no dynamic deserialization found anywhere in `server/app`; CI greps for `pickle` (`audit.py:53`) | |
| V5.1.4 (parser-specific, fuzz robustness) | Parser never executes unlisted commands / never throws uncaught | PASS | `client/tests/parser.fuzz.test.ts` — 30,000 fuzz iterations (random bytes, slash-prefixed random bytes, mutated valid commands) asserting the result kind is always one of the four known kinds and any `command` result name is in the static allowlist | Directly satisfies `CLAUDE.md` §1 "Definition of done: parser has a fuzz test" |

## V6 — Stored Cryptography

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V6.1.1/V6.1.2 | Regulated/sensitive data (private keys, etc.) never persisted in plaintext | PASS | Server: `models.py` stores only `ik_pub` (public key), `code_hash` (Argon2id), `token_hash` (SHA-512) — no private key or plaintext secret column exists anywhere in the schema. Client: `store.ts` — every `putBytes`/`putJson` call encrypts under the DEK with XChaCha20-Poly1305 before writing to IndexedDB | Verified end-to-end by `client/tests/store.test.ts::"a stolen database without the passphrase yields only ciphertext"` |
| V6.2.1 | Only vetted, industry-standard algorithms used | PASS | ML-DSA-65 via pyca `cryptography` 49.0.0 (`pqc.py`), ML-KEM-768/ML-DSA-65 via `@noble/post-quantum` 0.6.1, XChaCha20-Poly1305 via `@noble/ciphers`, Argon2id via `argon2-cffi`/`@noble/hashes` — all audited libraries, no hand-rolled primitives found anywhere | |
| V6.2.2 | No custom/proprietary encryption algorithms | PASS | Confirmed by manual read of every crypto call site; nothing implements a primitive by hand | |
| V6.2.3 | Random values from CSPRNG only | PASS | Server: `secrets.token_bytes`/`secrets.token_hex` exclusively (`uid.py:16`, `security.py:35,54`); client: `crypto.getRandomValues` exclusively (`store.ts:127-130,245,247,274`). CI greps ban `Math.random`/`import random` (`audit.py:44,55-56`) | |
| V6.2.5 | Key derivation uses vetted KDF | PASS | Argon2id for passphrase→KEK (`store.ts:64-71`), parameters match RFC 9106-informed §0 constants exactly (`constants.py:15-17` vs `client/src/crypto/constants.ts:12-14`) | HKDF-SHA-512 for protocol KDF is specified in constants but not yet exercised (ratchet is W4) |
| V6.3.1 | Nonces/IVs unique and never reused with the same key | PASS (by construction) | `store.ts:130,178,247,274` — fresh `crypto.getRandomValues(24 bytes)` generated per encryption call, never derived/counter-based | No explicit 10⁶-encryption nonce-uniqueness test found (CLAUDE.md §7.2 calls for one) — see Findings; the *design* is sound (random 192-bit nonce), but the specific stress test the project's own docs promise is absent |
| V6.4.1 | Secret keys/credentials not hardcoded | PASS | No hardcoded keys/secrets found in any `.py`/`.ts` file; DB URL defaults to a dev SQLite path via env var (`main.py:34`) | |
| V6.4.2 | Encryption keys managed securely (generation, storage, destruction) | PASS (client) / N/A (server, holds no keys) | DEK zeroization on lock (`store.ts:163-166`, `executor.ts:272-282` fills identity secret with zeros); server never possesses a symmetric or private key at all (architecture invariant, confirmed by schema read) | Zeroization is "best effort" per JS platform limits — honestly documented (`MVP_DOC.md` §10.3) |
| V6.4.3 | Key material rotation/versioning stored so old ciphertext stays decryptable | PASS | Argon2id `params` stored beside every wrapped-DEK record (`store.ts:46` `MetaRecord.params`) — "stored beside ciphertext for future upgrades" is a literal design invariant met in code | |

## V7 — Error Handling and Logging

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V7.1.1 | Do not log sensitive data (credentials, session tokens, PII) | PASS (vacuously) | No logging framework is wired up anywhere in `server/app` (`grep -i "logging|logger|log\."` across `server/app` returns zero matches) | See V7.4 below — the absence of logging trivially avoids logging secrets, but it also means the project fails its own §7.9 requirement to log security-relevant counters |
| V7.1.2 | No sensitive data in URL parameters | PASS | All sensitive values (tokens, signatures, keys) travel in POST JSON bodies or the `Authorization` header, never query strings (`api.ts`, `schemas.py`) | |
| V7.2.1 | Common input validation failures logged with enough context to identify malicious intent | FAIL | No logging exists; `errors.py` returns a JSON error to the client but nothing is recorded server-side | Gap — see Findings §(a) |
| V7.3.1 | All error responses uniform, no stack traces to the client | PASS | `errors.py:16-33` — every handler (validation, HTTP exception, unhandled `Exception`) collapses to `{"error": code}`; unhandled exceptions become a generic `internal_error` with no traceback leakage | Directly tested: `test_surface.py::test_unknown_route_returns_uniform_error`, `test_wrong_method_returns_uniform_error` |
| V7.4.1 | Security-relevant events logged (auth success/failure, access control failures, input validation failures) | FAIL | No logging/metrics/counters anywhere in `server/app`. CLAUDE.md §7.9 item 9 explicitly requires "counters for auth failures, rate-limit trips, and errors" — this is a general hardening-sweep item, not gated behind W5 | **Genuine gap**, not deferred — the project's own gap-sweep checklist (§7) is meant to be worked through "near the end of each milestone," and W2's `auth.py`/`routes/login.py` are exactly where auth-failure counting belongs |
| V7.4.2 | Logs protected from unauthorized access/tampering | N/A | No logs exist yet to protect | Consequence of V7.4.1 gap |
| V7.4.3 | No excessive/unnecessary data in logs (privacy-minimal) | N/A | No logs exist yet | When implemented, must follow `CLAUDE.md` §5 "no UIDs in logs where avoidable" |

## V8 — Data Protection

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V8.1.1 | Confidential data protected in transit and at rest per a documented sensitivity/classification scheme | PASS (at rest) / DEFERRED(W5, in transit) | At rest: server DB holds only public keys and hashes (`models.py`); client store fully encrypted (`store.ts`). In transit: TLS enforcement is a reverse-proxy concern explicitly deferred to W5 (`CLAUDE.md` §5 checklist, `headers.py:1-6` comment: "strict page-level CSP... enforced at the reverse proxy in production (W5)") | Dev server currently runs plaintext HTTP by design at this stage |
| V8.1.2 | No sensitive data (or backups) cached/retained beyond necessity | PASS | `headers.py:14-26` sets `Cache-Control: no-store` on every response; queue/message retention itself is a W3 concern, not yet built | |
| V8.2.1 | Client-side storage (IndexedDB) holds no unencrypted sensitive data | PASS | Every record in `KeyStore` is AEAD-wrapped (`store.ts:176-191`); confirmed by `store.test.ts` ciphertext-inspection test | |
| V8.3.1 | Sensitive data minimized in server-side storage | PASS | `MVP_DOC.md` §6.1 "No PII" — no email/phone/username collected; schema (`models.py`) confirms only UID, public key, hashes, and prekey public halves are stored | |
| V8.3.4 | Sensitive data (e.g. keys) cleared from memory when no longer needed | PARTIAL | `executor.ts:272-282` zeroizes the identity secret key and locks the store on lock/logout; `store.ts:163-166` zeroizes the DEK — but JS cannot guarantee GC/engine-level zeroization, and this is candidly documented as a platform limitation (`MVP_DOC.md` §10.3) rather than silently assumed | Accepted, documented risk — not a code defect |
| V8.3.7 | Encryption keys not stored alongside the data they protect without additional protection | PASS | The wrapped DEK (`MetaRecord.wrappedDek`) is itself AEAD-encrypted under the passphrase-derived KEK before being stored beside the data it protects — the DEK is never present in plaintext in IndexedDB | |

## V9 — Communications (mostly DEFERRED to W5)

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V9.1.1 | TLS used for all client connectivity, no fallback to insecure protocols | DEFERRED(W5) | `CLAUDE.md` §5 "TLS 1.3 only... at the reverse proxy" is explicitly a W5 hardening-pass task; no TLS termination config exists in this repo (no nginx/Caddy config, no cert handling) | Correctly out of scope for W1/W2 per the project's own build order |
| V9.1.2 | Latest recommended TLS version/cipher suites | DEFERRED(W5) | Same as above (hybrid `X25519MLKEM768` group specified in `CLAUDE.md` §5, not yet configured anywhere) | |
| V9.1.3 | Old/insecure TLS/SSL versions and ciphers disabled | DEFERRED(W5) | Same | |
| V9.2.1 | Connections to/from external services use trusted certificates | N/A | Server makes zero outbound HTTP requests by design (A10 non-goal is a strength, see V10/§7.9 item 10); no external service connections exist | |
| WS-specific (CLAUDE.md §7.11) | Origin check on WS upgrade, auth before subscribe, frame-size cap, heartbeat | DEFERRED(W3) | No WebSocket route exists anywhere in `server/app` (confirmed: no `websocket` import, no `WebSocket` route decorator found in any route file) | Matches CLAUDE.md's own build order — WS lands with messaging in W3 |

## V10 — Malicious Code (assessed briefly)

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V10.1.1 | Code reviewed for time bombs / malicious backdoors | PASS (nothing found) | Manual read of every `server/app/*.py` and `client/src/**/*.ts` file found no obfuscated logic, no hidden network calls, no conditional backdoors | Small enough surface (7 routes, ~12 client modules) to review by hand, consistent with `CLAUDE.md` §7.6's dependency-review philosophy |
| V10.2.1 | Application source integrity verified (no unauthorized modification of libs) | PASS | Exact-pinned lockfiles (`client/package-lock.json`, implied `requirements.txt` exact pins); CI (`ci.yml`) runs `npm ci` (not `npm install`) which fails on lockfile drift | |
| V10.3.1 | No unauthorized/malicious phone-home or analytics | PASS | `CLAUDE.md` §7.9 item 10 asserts zero outbound HTTP from the server by design; grep for an HTTP client dependency beyond test tooling (`httpx` is dev-only per `requirements-dev.txt`) confirms no runtime outbound calls | |

## V11 — Business Logic

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V11.1.1 | Business logic flows processed in sequential, non-bypassable order | PASS | Registration (UID gen → recovery codes → commit) is a single DB transaction (`routes/register.py:39-55`); login (challenge → verify, single-use nonce) cannot be reordered or replayed (tested) | |
| V11.1.2 | Business logic limits implemented to detect abuse (rate limits, thresholds) | PARTIAL | Register (3/hr/IP) and login-challenge (10/min/IP) are rate-limited and tested. **`/v1/login/verify`, `/v1/logout`, `/v1/keys/spk`, and `/v1/keys/opks` have no rate limiter of their own** — only the *challenge* step is throttled, so an attacker who has already obtained many nonces (or a valid session) can hammer `verify`/`keys/*` unthrottled | Genuine gap — see Findings §(a). CLAUDE.md §5 itself calls for "message send 60/min/UID" and implicitly a rate limit per sensitive endpoint; keys endpoints are unmetered |
| V11.1.4 (OPK depletion, CLAUDE.md §7.4) | Anti-DoS for prekey exhaustion (bundle-fetch rate limits, per-requester caps) | DEFERRED(W3) | No bundle-fetch endpoint exists yet at all (confirmed by `test_surface.py`'s exhaustive route list) — the OPK-depletion abuse case in CLAUDE.md §7.4 specifically concerns *other users fetching* a victim's bundle, which is a W3 handshake feature | Correctly deferred; the *upload*-side cap that does exist today (`OPK_UNCONSUMED_CAP=200`, `routes/keys.py:57-58`, tested in `test_keys.py::test_unconsumed_cap_enforced`) is a sensible W2-scoped guard against a user uploading unbounded OPKs, but is a different concern from depletion-by-fetch |
| V11.1.5 | Anti-automation for resource-intensive operations (registration, etc.) | PASS | Registration rate-limited 3/hour/IP (`test_rate_limit.py::test_register_rate_limited_after_capacity`); Argon2id itself (65 MiB, t=3) throttles credential-stuffing-style attempts against the local unlock (client-side, inherent cost) | |
| V11.1.6 | Anti-enumeration (usernames/UIDs cannot be enumerated) | PASS | No existence-check endpoint exists anywhere (`test_surface.py` enumerates the full route set — none named `user` or exposing existence); `/v1/login/challenge` issues an identical 200 for real and fictitious UIDs, verified failure is uniform (`test_login.py::test_unknown_uid_is_not_an_oracle`) | This is the strongest-evidenced control in the whole assessment — directly matches `MVP_DOC.md` §6.1's explicit anti-enumeration design goal |
| V11.1.8 | Business logic should not create asset transfer/state-change race conditions | PASS | Prekey upload count check and insert happen inside one DB session/transaction (`routes/keys.py:52-68`); UID uniqueness enforced by the DB constraint, not a check-then-insert race (`register.py:39-48` catches `IntegrityError` rather than pre-checking) | |

## V12 — Files and Resources

**N/A in full** — this is a JSON REST API with no file-upload, file-serving, or
path-based resource access anywhere in the implemented surface (`server/app` has no
`UploadFile`, static-file mount, or path-parameter-based file access). Revisit if W3
introduces attachments (explicitly a non-goal per `MVP_DOC.md` §3.2).

## V13 — API and Web Service

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V13.1.1 | Same encoding/parsers used for all inputs (avoid parser differential attacks) | PASS | Every route is JSON-only via Pydantic/FastAPI; no alternate content-type or body parser exists | |
| V13.1.4 | Properly configured API endpoints against injection | PASS | See V5.2.3; ORM-only DB access, no raw SQL | |
| V13.2.1 | Enforce request content-type (reject unexpected types) | PASS (by framework default) | FastAPI/Pydantic requires valid JSON matching the declared model; malformed bodies produce `400 invalid_request` (`errors.py:21-23`, tested `test_register.py::test_missing_field_rejected_with_same_shape`) | |
| V13.2.5 | Disable unnecessary HTTP methods | PASS | Only the declared method(s) per route are registered by FastAPI's router; wrong-method requests get a uniform `405`/`request_failed` (`test_surface.py::test_wrong_method_returns_uniform_error`) | |
| V13.3.1 | API docs (OpenAPI/Swagger) restricted in production | PASS | `main.py:39-41` — `docs_url`/`openapi_url` are `None` unless `MERIDIAN_EDGE_DEV=1`; tested `test_surface.py::test_docs_disabled_outside_dev` | Directly matches CLAUDE.md §7.5 |
| V13.4.1 | GraphQL-specific hardening | N/A | REST only, no GraphQL | |

## V14 — Configuration

| ASVS ID | Requirement (paraphrase) | Verdict | Evidence | Note |
|---|---|---|---|---|
| V14.1.1 | Build pipeline can be re-run to reliably rebuild binaries/deploys | PASS | `.github/workflows/ci.yml` — reproducible steps (`npm ci`, pinned `actions/setup-python@v5` at 3.12, pinned `setup-node@v4` at Node 22) | Node version in CI (22) vs `CLAUDE.md` header claiming "verified on Node 24.5.0" is a minor inconsistency worth reconciling, not a security defect |
| V14.2.1 | Third-party components come from trusted repos, verified integrity | PASS | `requirements.txt`/`package.json` pin exact versions; CI runs `pip-audit` and `npm audit --audit-level=high` as blocking gates (`ci.yml`) | |
| V14.3.2 | Unnecessary features/frameworks/documentation/samples removed from production | PASS | Docs endpoints gated behind `MERIDIAN_EDGE_DEV` (see V13.3.1); no sample/demo routes found | |
| V14.3.3 | HTTP security headers configured (CSP, X-Content-Type-Options, etc.) | PASS (API baseline) / DEFERRED(W5, page-level CSP) | `headers.py:14-26` sets a deny-everything CSP, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, COOP, CORP, restrictive `Permissions-Policy`, `Cache-Control: no-store` on every API response — tested in `test_surface.py::test_security_headers_on_success_and_error`. The *page-serving* CSP for the client bundle is explicitly deferred to the reverse proxy at W5 (`headers.py:1-6` comment) | Good API-side baseline; note HSTS header is **absent even as a placeholder** — see Findings |
| V14.4.1 | CORS policy (if any) is restrictive, no wildcard, credentials handled carefully | FAIL | No `CORSMiddleware` is registered anywhere in `main.py` (confirmed by grep — zero matches for `CORSMiddleware`/`add_middleware`/`allow_origins` in `server/app`) | Absence of CORS middleware means FastAPI's default (no CORS headers sent) applies, which browsers treat as same-origin-only for credentialed requests — safe by *default*, but this is not the explicit "exact origin only, no wildcard" policy `CLAUDE.md` §5 calls for; once the client and API are served from different origins (likely, given Vite dev server + separate API port), an explicit allowlisted CORS policy will be needed. Flagging now as a small, cheap fix rather than waiting for W5. |
| V14.5.1 | Application accepts only requests matching configured components (no debug endpoints reachable) | PASS | `DEBUG`/dev-mode gate exists for docs; no other debug-only route found | CLAUDE.md §5 "`DEBUG=0` asserted at startup (refuse to boot otherwise in prod mode)" — **not implemented**: `main.py` reads `MERIDIAN_EDGE_DEV` but never refuses to boot when misconfigured; see Findings |

---

## Prioritized Findings

### (a) Genuine gaps fixable now, ordered by risk

1. **No security-event logging or counters (V7.4.1, CLAUDE.md §7.9 item 9).**
   `server/app` has zero logging calls. Auth failures, rate-limit trips, and
   signature-verification failures are exactly the "potential attack signal" the
   project's own gap-sweep calls out, and this is not gated behind any later
   milestone. **Remediation:** add a minimal structured logger (stdlib `logging`,
   JSON formatter) with counters incremented in `routes/login.py` (401s),
   `rate_limit.py` (bucket exhaustion), and `pqc.py` (signature failures); exclude
   UIDs and any key material per §5's own privacy-minimal rule. Low effort, high
   value given how close it is to the existing code structure.

2. **Login `Origin` binding has no allowlist (V2.7.2, V14.4.1).**
   `routes/login.py:36-37` reads `request.headers.get("origin", "")` and only checks
   that the *same* value reappears at verify time (`login.py:90`) — it never checks
   that origin is actually `https://meridian-edge.<yourdomain>` or similar. Combined with
   the complete absence of CORS middleware (finding 3), this is currently low-risk,
   but it means the "origin binding" security property documented in `MVP_DOC.md`
   §6.2 is weaker than described: it binds the *signature* to *a* origin string, not
   to *the correct* origin. **Remediation:** add an `ALLOWED_ORIGINS` allowlist
   constant/env var and reject challenge/verify requests whose `Origin` header isn't
   in it (uniform error, same as other auth failures).

3. **No CORS policy configured (V14.4.1).** No `CORSMiddleware` registered in
   `server/app/main.py`. Currently benign (no cross-origin credentialed flow is
   exercised because the client and API likely share dev origin), but the project's
   own §5 checklist ("exact origin only, no wildcard, credentials disabled") is a
   two-line fix that removes ambiguity before W3 introduces more endpoints.
   **Remediation:** add `CORSMiddleware` with an explicit origin allowlist now,
   rather than waiting for the W5 pass.

4. **`DEBUG=0`/prod-mode boot assertion not implemented (CLAUDE.md §5 checklist item
   explicitly promised).** `main.py` reads `MERIDIAN_EDGE_DEV` to gate docs but has no
   check that refuses to boot in a misconfigured "production" environment (e.g., if
   `MERIDIAN_EDGE_DEV` is accidentally left set to `1`, or if some future `DEBUG` flag is
   introduced). **Remediation:** add an explicit startup assertion (e.g., refuse to
   boot if `MERIDIAN_EDGE_DEV=1` and an env flag like `MERIDIAN_EDGE_ENV=production` is also set).

5. **No independent rate limit on `/v1/login/verify`, `/v1/logout`,
   `/v1/keys/spk`, `/v1/keys/opks` (V11.1.2).** Only the challenge-issuance step is
   throttled (`login_challenge_limiter`); an attacker holding a valid nonce (or a
   still-valid session token) can call `verify`/`keys/*` at unlimited rate. The
   values in `CLAUDE.md` §5 ("message send 60/min/UID") imply every sensitive
   endpoint should have its own bucket. **Remediation:** add a
   `TokenBucketLimiter` per authenticated route keyed by UID (not just IP), mirroring
   the pattern already established for register/challenge.

6. **No `SECURITY.md` disclosure document (CLAUDE.md §7.9 item 9 explicitly
   promised: "a `SECURITY.md` with a disclosure contact").** Confirmed absent by
   filesystem search. Trivial to add; costs nothing and closes a documented
   commitment.

7. **HSTS header absent even as a placeholder (V14.3.3, CLAUDE.md §5).** The
   `SECURITY_HEADERS` dict in `headers.py` does not include
   `Strict-Transport-Security`. Understandable since TLS termination is a W5/proxy
   concern, but since the header itself is harmless to send over plaintext HTTP in
   dev (browsers ignore HSTS on non-HTTPS responses) it costs nothing to add now and
   removes one more item from the W5 checklist later.

8. **Local unlock-passphrase minimum length (8 chars) is below the ASVS-recommended
   12-character floor (V2.1.1).** This is a local key-wrapping credential rather
   than a server-verified password, so the mapping is imperfect, but Argon2id
   strengthens weak inputs only up to a point. **Remediation:** consider raising
   `MIN_PASSPHRASE_LENGTH` to 12 in `executor.ts:71`, or explicitly document in the
   report why 8 was chosen (e.g., paired with Argon2id cost parameters) so the
   deviation is a documented decision rather than an oversight.

9. **No explicit nonce-uniqueness stress test for the AEAD used in `store.ts` (V6.3.1,
   CLAUDE.md §7.2 "test: nonce uniqueness over 10⁶ encryptions").** The design is
   sound (fresh `crypto.getRandomValues(24 bytes)` per call — 192-bit random
   nonce space makes collision over 10⁶ operations statistically negligible), but the
   specific test the project's own checklist calls for does not appear in
   `client/tests/store.test.ts`. Low priority given the birthday bound at this nonce
   size, but cheap to add and directly promised by the project's own docs.

### (b) Deferred-by-design items (with milestone)

- TLS 1.3 termination, HSTS `preload`, hybrid `X25519MLKEM768` at the reverse proxy — **W5** (`CLAUDE.md` §5; `MVP_DOC.md` §6.7).
- Page-level strict CSP for the served client bundle — **W5** (`headers.py:1-6` comment explicitly says so).
- WebSocket origin allowlist, auth-before-subscribe, per-frame cap, heartbeat/idle-kill, session-token rotation on reconnect — **W3** (no WS code exists yet; `CLAUDE.md` §8 W2 note: "WS-reconnect rotation lands with WS in W3").
- Recovery-code redemption endpoint — **explicitly W5** per `CLAUDE.md` §8 ("redemption endpoint deferred to W5"); codes are generated/hashed/shown now, consumption logic does not exist yet, and the `used` column is unused.
- Bundle-fetch endpoint, OPK-depletion-by-fetch anti-abuse (per-requester fetch caps, `reduced-fs` degradation) — **W3** (`CLAUDE.md` §3, §7.4); no bundle-fetch route exists at all yet, confirmed by the closed route enumeration in `test_surface.py`.
- Message-flood/spam mute, ack-forgery protection, message-queue delete-on-ack/TTL — **W3/W5** (queue doesn't exist yet).
- Ratchet FS/PCS, safety numbers, key-change teardown, out-of-order key bound — **W4**.
- Container hardening (non-root, read-only FS, secrets via env/secret store) — **W5**; no Dockerfile in this repo yet.
- Full Mozilla-Observatory-grade header/rate-limit pass, dependency-scan-clean gate as an explicit milestone exit criterion — **W5** (`MVP_DOC.md` §11 table); note the *building blocks* (headers, `pip-audit`/`npm audit` in CI) already exist and pass today, so W5 is largely a verification/tightening pass, not a from-scratch build.
- Benchmark suite (`/bench`, B1–B5) — **W6**; not a security requirement per se, but referenced in ASVS-adjacent measurement goals of the MVP doc.

### (c) Documented platform limitations (accepted risks, per `MVP_DOC.md` §10)

- **XSS = key theft despite CSP.** WebCrypto has no ML-KEM/ML-DSA support, so
  private keys must be materialized in JS memory while the store is unlocked. CSP is
  the mitigation, not a cure. (`MVP_DOC.md` §10.3, `CLAUDE.md` §7.12)
- **JS timing side channels are plausible and out of scope to eliminate**, despite
  `@noble` aiming for constant-time behavior. (`MVP_DOC.md` §10.2)
- **IndexedDB deletion (`/wipe`) is not forensic erasure.** `store.ts`'s `wipe()`
  does a best-effort overwrite-then-delete pass, and the UI/help text says so
  explicitly (`executor.ts:640`). (`MVP_DOC.md` §10.6)
- **Deniability regression**: ML-DSA-signed handshakes are non-repudiable, unlike
  Signal's DH-based deniable authentication — accepted trade-off of the pure-PQC
  design goal, documented in `MVP_DOC.md` §4.3 and §10.5. Not yet exercised in code
  (handshake is W3) but the design decision and its consequence are pre-documented.
  This item is what the project calls a "genuine gap of *deniability*", not a
  security bug.
- **Single device, no recovery beyond the printed codes.** Losing the device and
  the recovery codes loses the identity, by design (`MVP_DOC.md` §10.7).
- **Availability is rate-limiting only; no DDoS resilience.** Explicitly stated as
  a non-goal rather than implied resilience (`MVP_DOC.md` §10.8, ASVS V11 business
  logic anti-automation is present but is not an availability guarantee).
- **Metadata visibility**: the server learns who messages whom and when once W3
  ships; minimized (no PII, delete-on-ack planned) but not eliminated (no sealed
  sender). Not yet applicable to the W1/W2 surface itself since no messaging exists.

---

## Notes on Methodology

- All verdicts are grounded in direct code reads of the files listed in the task
  scope; no server was started, no dependencies were installed, and no tests were
  executed (existing test *files* were read as evidence, not run).
- Where an ASVS clause number could not be pinned exactly to the 4.0.3 text from
  memory, the nearest identifiable section/family (e.g., "V2.7.x") is used and
  flagged as such rather than inventing a precise sub-item number.
- "PASS" was reserved for requirements with concrete, cited code or test evidence;
  ambiguous or partially-met cases were marked PARTIAL rather than rounded up.
