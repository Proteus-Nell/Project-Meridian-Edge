# PQTerm - MVP Document

**A Pure Post-Quantum End-to-End Encrypted Terminal Messenger**

| | |
|---|---|
| **Version** | 1.0 (MVP specification) |
| **Author** | Mark |
| **Date** | 2 July 2026 |
| **Context** | University internship project - practical application of post-quantum cryptography (PQC) |
| **Timeline** | 4–6 weeks |
| **Status** | Approved for build |

> *"PQTerm" is a working title - rename freely.*

---

## 1. Executive Summary

PQTerm is a web-based, terminal-style, one-to-one messaging application in which **every asymmetric cryptographic operation uses NIST-standardized post-quantum algorithms**: ML-KEM-768 (FIPS 203) for key establishment and ML-DSA-65 (FIPS 204) for identity and authentication. No classical public-key cryptography (RSA, ECDH, Ed25519) appears anywhere in the application layer.

The MVP demonstrates that a pure-PQC secure messenger is buildable today, and **measures what it costs** - in latency, bandwidth, and key sizes - through a dedicated benchmark suite comparing PQC primitives against classical baselines.

The primary threat motivating the design is **Harvest Now, Decrypt Later (HNDL)**: an adversary recording encrypted traffic today to decrypt it once a cryptographically relevant quantum computer exists. The design therefore prioritizes (a) quantum-resistant confidentiality, (b) forward secrecy so past messages stay safe even after key compromise, and (c) data minimization so there is almost nothing at rest to harvest.

**MVP scope in one sentence:** a hardened web app (Python backend, TypeScript frontend) where two users register with CSPRNG-generated IDs, authenticate with ML-DSA signatures, establish sessions via an ML-KEM handshake, exchange messages through a KEM-based double-ratchet with forward secrecy and post-compromise security, verify each other with safety numbers, and control message lifetime with mutual disappearing timers and local purge policies - plus a benchmark suite quantifying the PQC overhead.

---

## 2. Background and Motivation

### 2.1 Why post-quantum, why now

- Shor's algorithm on a cryptographically relevant quantum computer breaks all deployed public-key cryptography based on integer factorization and discrete logarithms (RSA, DH, ECDH, ECDSA, Ed25519).
- **HNDL is a present-tense threat**: ciphertext recorded today is retroactively decryptable. Confidential communications with multi-year secrecy requirements are already exposed.
- NIST finalized the first PQC standards in August 2024: **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, and FIPS 205 (SLH-DSA). A fourth KEM, HQC, was selected in March 2025 as a backup based on different mathematical assumptions.
- **NIST IR 8547** (Transition to Post-Quantum Cryptography Standards) sets the migration clock: quantum-vulnerable algorithms at ~112-bit security are deprecated after **2030** and all quantum-vulnerable public-key algorithms are disallowed after **2035**.
- Industry has moved: Signal deployed the hybrid PQXDH handshake (2023) and the SPQR post-quantum ratchet forming a "Triple Ratchet" (2025); Chrome, Cloudflare, and major CDNs deploy hybrid PQ TLS (X25519MLKEM768) at scale.

### 2.2 Why *pure* PQC (a deliberate, documented choice)

Industry consensus is **hybrid** (classical + PQC combined), hedging against undiscovered weaknesses in the young PQC algorithms. This project deliberately goes **pure PQC** instead, because:

1. The academic question being investigated is *"what does a fully post-quantum messenger cost today?"* - hybridization would blur the measurement.
2. Hybrid deployments are well studied (Signal, TLS); a pure-PQC application-layer protocol with benchmarks is the more novel contribution for an internship report.
3. The risk profile is acceptable for an academic prototype that is explicitly **not production crypto** (see §10).

The report should present this trade-off honestly: pure PQC is the research position; hybrid remains the correct engineering position for production systems in 2026. Defense-in-depth is partially recovered at the transport layer (§6.7), where hybrid PQ TLS wraps the already-PQC application protocol.

### 2.3 Relationship to the Signal Protocol

The original project guideline suggested "possibly using open-source repos like Signal Protocol." Investigation showed that libsignal is **hybrid by design** (X25519 + ML-KEM in PQXDH; classical Ed25519 identity signatures; no ML-DSA anywhere) and has no maintained browser build. Stock libsignal is therefore incompatible with the pure-PQC goal. **Decision: build a custom, deliberately simplified protocol whose architecture mirrors Signal's design** (prekey bundles, asynchronous handshake, double-ratchet structure, safety numbers) but with every asymmetric primitive replaced by its FIPS 203/204 counterpart. Signal's published designs (X3DH, PQXDH, Double Ratchet, SPQR) serve as the reference literature, not as a dependency.

---

## 3. Goals and Non-Goals

### 3.1 Goals

1. **G1 - Pure PQC:** all asymmetric operations use ML-KEM-768 or ML-DSA-65. Zero classical public-key crypto in the application layer.
2. **G2 - Forward secrecy & post-compromise security:** compromise of current keys must not expose past messages (FS), and the session must self-heal after a transient compromise (PCS), via a KEM-based ratchet.
3. **G3 - Untrusted server:** the server never possesses plaintext, private keys, or the ability to silently insert itself into a verified conversation.
4. **G4 - Data minimization:** delete-on-delivery server queue; nothing long-lived to harvest.
5. **G5 - Measured, not asserted:** a benchmark suite quantifies PQC costs against classical baselines.
6. **G6 - Hardened by default:** transport, headers, rate limits, input handling, and dependency hygiene follow current best practice (OWASP ASVS-informed).
7. **G7 - Terminal UX:** all interaction through a command-driven terminal UI.

### 3.2 Non-Goals (explicitly out of MVP scope)

- Group messaging (future: MLS / RFC 9420)
- Mobile apps or PWA packaging (future work)
- Multi-device support and encrypted history sync
- Metadata protection beyond minimization (no sealed sender, no onion routing)
- Media attachments, voice/video
- Federation or third-party client APIs
- Production-grade cryptographic assurance (this is an academic prototype)

---

## 4. Threat Model

### 4.1 Adversaries

| ID | Adversary | Capability | MVP posture |
|----|-----------|------------|-------------|
| A1 | **HNDL passive network adversary** *(primary)* | Records all traffic now; gains a quantum computer later | **Defended.** All key establishment is ML-KEM-768; recorded traffic is not retroactively decryptable by Shor's algorithm. Forward secrecy limits the value of any single future key compromise. |
| A2 | **Compromised / malicious server** | Full control of server code, storage, and delivery | **Largely defended.** E2EE means no plaintext or private keys server-side. Active MITM at handshake time is possible *until* users compare safety numbers (§6.5); after verification it is detectable. Metadata (who talks to whom, when) remains visible - acknowledged limitation (§10). |
| A3 | **Active network MITM** | Intercepts and modifies traffic | **Defended** at two layers: TLS 1.3 (hybrid PQ groups where available) and application-layer E2EE with ML-DSA-authenticated handshakes. |
| A4 | **Device thief (offline)** | Steals device/browser profile while app is logged out | **Defended.** Local key store and message history are encrypted under an Argon2id-derived key from the unlock passphrase (§6.6). Weekly passphrase rotation limits the window of a leaked passphrase. |
| A5 | **Metadata analyst** | Observes traffic patterns, sizes, timing; subpoenas server | **Partially defended.** Data minimization (delete-on-delivery, minimal logs, no phone numbers/emails) shrinks the surface; traffic analysis and server-visible routing metadata remain. Documented as future work. |
| A6 | **Active malware on an unlocked device** | Keylogger, memory scraping, malicious extension | **Out of scope.** No E2EE messenger survives a fully compromised endpoint. PCS (G2) provides healing after *transient* compromise only. |

### 4.2 Assumptions

- The endpoint (browser + OS) is not compromised at registration time.
- Users perform safety-number verification for conversations that matter.
- The `@noble/post-quantum` and server-side PQC implementations correctly implement FIPS 203/204 (Cure53-audited, but not formally verified).
- TLS PKI is used for transport hardening but is **not** relied upon for message confidentiality (the application layer assumes the transport is hostile).

### 4.3 Security properties targeted

| Property | Mechanism |
|----------|-----------|
| Confidentiality (incl. vs. future quantum adversary) | ML-KEM-768 key establishment; XChaCha20-Poly1305 AEAD |
| Integrity & authenticity | AEAD; ML-DSA-65 signatures over identity and prekey bundles; transcript binding in the handshake |
| Forward secrecy | Per-message symmetric KDF chains + periodic KEM ratchet steps; one-time prekeys consumed at handshake |
| Post-compromise security | Fresh ML-KEM encapsulations in the ratchet continually inject new entropy, healing the session after transient key compromise |
| Peer authentication | ML-DSA-signed prekey bundles; out-of-band safety-number verification |
| At-rest confidentiality | Argon2id-wrapped local key store; encrypted local message DB |
| **Deniability - reduced (known trade-off)** | Signal's DH-based designs give deniability; a signature-authenticated handshake produces non-repudiable evidence that a party signed handshake material. Accepted and documented (§10). |

---

## 5. Product Requirements

### 5.1 Personas & core user stories

*Persona: privacy-conscious technical users (students, researchers, journalists' sources) comfortable with a command line.*

1. As a new user, I can register and receive a randomly generated user ID with no email or phone number, so my identity carries no personal data.
2. As a user, I can log in by proving possession of my identity key (no server-side password), unlock my local key store with a passphrase, and be confident a stolen database cannot impersonate me.
3. As a user, I can start an encrypted chat with someone by their UID, even while they are offline (asynchronous handshake via prekeys).
4. As a user, I can verify a contact's safety number out-of-band and be alerted if it ever changes.
5. As a user, I can set a disappearing-message timer that both sides see and honor, and separately purge my own copies sooner.
6. As a user, I am prompted weekly (toggleable, day configurable) to rotate my local unlock passphrase.
7. As the operator/researcher, I can run a benchmark command that produces the PQC-vs-classical measurement tables for the report.

### 5.2 Feature scope (MoSCoW)

**Must have**
- CSPRNG UID generation with server-side collision handling (§6.1)
- ML-DSA-65 identity keys; challenge–response login (§6.2)
- Argon2id-wrapped local key store with unlock passphrase (§6.6)
- PQ-KX asynchronous handshake over ML-KEM-768 prekey bundles (§6.3)
- KEM double-ratchet for 1:1 messaging - FS + PCS (§6.4)
- XChaCha20-Poly1305 message encryption
- Ephemeral server delivery queue: delete-on-ack, 14-day TTL (§6.8)
- Safety numbers + key-change alerts (§6.5)
- Terminal UI with the core command set (§7)
- Transport & platform hardening baseline (§6.7)
- Rate limiting on registration, login, and message endpoints

**Should have**
- Mutual disappearing-message timer per conversation (§6.8)
- Local retention purge policy (§6.8)
- Weekly passphrase-rotation prompt, toggleable, day-configurable (§6.6)
- Delivery acknowledgments (`[✓]` inline)
- One-time prekey replenishment (`/keys refill`, automatic low-watermark)
- Benchmark suite + report tables (§8)

**Could have**
- `/wipe` panic command (secure-as-possible local store destruction)
- Toast notifications for background events (in addition to inline event lines)
- QR-code rendering of safety numbers
- Light/dark terminal themes

**Won't have (this MVP)** - everything in §3.2.

---

## 6. Security Architecture

### 6.1 Identity & UID generation

- **UID:** 128 bits from a CSPRNG (`crypto.getRandomValues` client-side proposal, regenerated server-side authoritatively with `secrets.token_bytes(16)`), encoded as Crockford Base32 (26 characters, e.g. `7Q3K-M2VD-9XWP-4RTB-A6HJ-EZ`), grouped for readability.
- **Collision handling:** the server generates the UID within the registration transaction under a UNIQUE constraint; on the (cryptographically negligible, ~2⁻⁶⁴ birthday bound at even 2⁶⁴ users) collision, it silently regenerates. **There is no "does this UID exist?" endpoint** - the original guideline's client-visible existence check is replaced to eliminate the username-enumeration oracle. Lookups of *other* users' bundles require an authenticated session and are rate-limited.
- **No PII:** no email, phone number, or username is collected. Users share UIDs out-of-band. Display aliases are **local-only** address-book entries, never transmitted, so aliases cannot be used for impersonation.

### 6.2 Authentication (passwordless, PQC-native)

- At registration the client generates an **ML-DSA-65 identity keypair (IK)**. The public key is uploaded; the private key never leaves the device.
- **Login = challenge–response:** server sends a 32-byte CSPRNG nonce bound to a server timestamp and origin; client returns `ML-DSA.Sign(sk_IK, nonce ‖ origin ‖ timestamp)`; server verifies and issues a session token.
- **Session tokens:** opaque 256-bit random tokens, held in memory (not `localStorage`), 15-minute idle expiry, rotated on every WebSocket reconnect, invalidated server-side on `/logout`. This - not password rotation - provides the "fresh credentials each session" property the original guideline aimed at.
- **Recovery:** MVP ships one-time recovery codes generated at registration (printed to terminal once); losing both the device key store and the codes means the identity is unrecoverable - by design, and stated in the UI.
- **Rationale vs. original guideline:** "rotate password prior to log-off" is replaced. A server-side password rotation at log-off fails unsafely (crash/network drop ⇒ no rotation or client–server desync) and mandatory periodic rotation contradicts NIST SP 800-63B. The *intent* - limiting the useful life of stolen credentials - is met better by (a) passwordless ML-DSA auth (nothing phishable), (b) short-lived rotating session tokens, and (c) the local passphrase rotation schedule in §6.6.

### 6.3 PQ-KX: the asynchronous handshake (PQXDH analog, DH removed)

Server stores per user a **prekey bundle**:

| Element | Algorithm | Signed by IK? | Lifetime |
|---|---|---|---|
| Identity key `IK` | ML-DSA-65 (verify key) | - | Long-term |
| Signed prekey `SPK` | ML-KEM-768 (encapsulation key) | Yes | Rotated every 7 days; old SPK kept 7 more days for late handshakes |
| One-time prekeys `OPK₁…ₙ` | ML-KEM-768 (encapsulation keys) | Yes (batch-signed) | Consumed once; low-watermark refill at < 20 |

**Initiator (Alice → offline Bob):**
1. Fetch Bob's bundle (authenticated, rate-limited); verify both prekey signatures against `IK_B`. Abort loudly on failure.
2. `(*ct₁*, ss₁) ← ML-KEM.Encaps(SPK_B)` and `(*ct₂*, ss₂) ← ML-KEM.Encaps(OPK_B)` (if an OPK is available; the handshake proceeds without ss₂ if depleted, at reduced FS for the first flight - flagged in the UI).
3. Root secret: `RK₀ = HKDF-SHA-512(ss₁ ‖ ss₂, info = "PQTerm-v1-KX" ‖ IK_A ‖ IK_B ‖ transcript-hash)`.
4. Alice signs the handshake transcript hash with `sk_IK_A` (authenticates the initiator; this is where the deniability trade-off of §4.3 arises).
5. First message: `ct₁ ‖ ct₂ ‖ IK_A ‖ signature ‖ AEAD(RK₀-derived key, message)`.

**Responder (Bob, on coming online):** decapsulates with his SPK/OPK secrets, verifies Alice's signature over the transcript, derives the same `RK₀`, deletes the consumed OPK secret immediately, and replies through the ratchet (§6.4). Both parties then compute the safety number (§6.5).

### 6.4 KEM double-ratchet (forward secrecy + post-compromise security)

A simplified, SPQR-inspired construction - full ML-KEM keys sent inline (no chunking/erasure coding; the bandwidth cost is a benchmark subject, not an engineering problem at MVP scale):

- **Symmetric chains (per-message FS):** as in Signal's Double Ratchet, sending and receiving chains advance with `HKDF` per message; each message key is deleted after use. Compromise of the current chain key never reveals earlier message keys.
- **KEM ratchet steps (PCS + epoch FS):** whenever a party sends its first message of a new "turn" (or every N = 10 messages, whichever first), it includes a **fresh ML-KEM-768 encapsulation key**. The peer encapsulates to it in its next message; the resulting shared secret is mixed into the root key: `RK_{i+1} = HKDF(RK_i, ss_new)`. New chain keys derive from the new root. This continuous entropy injection heals the session after a transient compromise.
- **Out-of-order delivery:** skipped message keys stored (bounded, max 256) exactly as in the Double Ratchet spec.
- **Header protection:** ratchet headers (counters, epoch IDs, encapsulation keys) are encrypted under a header key derived from `RK`, limiting what an observer of ciphertexts learns about ratchet state.

### 6.5 Trust establishment: safety numbers

- `SN = SHA-512(min(IK_A, IK_B) ‖ max(IK_A, IK_B) ‖ UID_A ‖ UID_B)` truncated and rendered as 60 decimal digits in 12 groups (Signal-style), via `/verify <alias>`.
- Users compare out-of-band (in person, phone call). `/verified <alias>` marks the contact; thereafter **any identity-key change tears down the session and prints a high-visibility warning** requiring explicit re-verification before further sends.
- This is the sole mechanism that defeats an actively malicious server (A2) at handshake time; the UI must make it prominent, not buried.

### 6.6 Local key store & the rotation schedule

- All long-term secrets (`sk_IK`, SPK/OPK secrets, ratchet states, message history) live in IndexedDB **encrypted** under a key derived from the unlock passphrase via **Argon2id** (m = 64 MiB, t = 3, p = 1 - above OWASP minimums; parameters stored alongside for future upgrades), wrapping a random 256-bit data-encryption key (DEK) so passphrase changes only re-wrap the DEK.
- WebCrypto has no ML-DSA/ML-KEM support, so private keys must exist in JS memory while unlocked - an honest web-platform limitation (§10). Keys are zeroized on lock/logout to the extent JS allows.
- **Rotation prompt (adapted from the original guideline):** every Friday (default; day configurable; feature toggleable via `/settings rotation …`) the client prompts the user to change the unlock passphrase. Rotation is **entirely local** - re-wrap the DEK - so it is crash-safe, involves no server round-trip, cannot desync, and does not conflict with NIST SP 800-63B (it is opt-out user-controlled hygiene against device-theft/shoulder-surfing, not a server-mandated password policy).
- Auto-lock after 10 minutes idle; `/lock` locks immediately.

### 6.7 Transport & platform hardening

| Layer | Control |
|---|---|
| TLS | TLS 1.3 only; prefer hybrid group **X25519MLKEM768** (defense-in-depth under the pure-PQC app layer); HSTS (max-age 2 years, preload); WSS for all WebSocket traffic |
| Headers | Strict CSP (`default-src 'self'`; no `unsafe-inline`/`unsafe-eval`; this is also the primary XSS→key-theft mitigation), `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy`, `frame-ancestors 'none'` |
| Input | Terminal input handled by a **strict allowlist command parser** (§7.3) - never `eval`-like paths; all server inputs schema-validated (Pydantic); message payloads treated as opaque ciphertext bytes with size caps |
| Rate limiting | Per-IP + per-UID token buckets on registration, login challenges, bundle fetches, and message sends; exponential backoff on auth failures |
| Logging | No message metadata beyond what delivery requires; logs exclude UIDs where feasible; no third-party analytics; error messages never leak stack traces to clients |
| Dependencies | Lockfiles pinned; `pip-audit` + `npm audit`/Snyk in CI; SRI for any CDN asset (goal: zero CDN assets); Dependabot |
| Server | Non-root container, read-only filesystem, secrets via environment/secret store, CSPRNG from `secrets`/`os.urandom` only |

### 6.8 Data lifecycle: ephemeral queue, timers, purge

- **Server queue:** messages are opaque ciphertext blobs in a per-recipient queue; **deleted immediately on client delivery ack**; undelivered messages expire at **14 days TTL**. Delivered = gone; there is no server-side history, ever. Backups exclude the queue.
- **Mutual disappearing timer** (`/timer <alias> <duration|off>`): a per-conversation setting carried in encrypted headers, visible to both parties, changes announced as inline system lines in both terminals. Countdown starts on read; both clients delete on expiry.
- **Local purge** (`/purge set <duration|off>`, `/purge now`): a personal, never-transmitted retention cap on one's own copies - independent of, and allowed to be stricter than, the mutual timer.
- **Enforcement honesty:** peer-side deletion is cooperative - a modified client can retain everything, and screenshots exist. Browser storage deletion is not forensic erasure. Both facts are stated in the UI help and in this document (§10) rather than implied away.

---

## 7. Terminal UI Specification

### 7.1 Principles

- One interaction surface: a terminal (xterm.js) - commands in, styled text out. Works identically on desktop and mobile browsers (mobile-native app is future work).
- **Events are inline lines, not modal pop-ups** (adapting the original guideline): pop-ups fight the terminal paradigm and train dismissal habits. Format: `[✓]` success, `[!]` warning, `[✗]` failure, `[*]` info, each timestamped. Optional browser toast notifications ("Could have") cover background events only.
- Security-critical events (identity key change, verification failure, SPK rotation failure) render in a high-visibility style and require acknowledgment before the affected conversation continues.

### 7.2 Command set (MVP)

| Command | Action |
|---|---|
| `/register` | Generate identity, receive UID + recovery codes, set unlock passphrase |
| `/login` / `/logout` / `/lock` | Challenge–response login; logout invalidates session server-side; lock encrypts store immediately |
| `/whoami` | Show own UID + safety-number fingerprint of own identity key |
| `/add <uid> [alias]` | Add contact (alias is local-only) |
| `/chat <alias\|uid>` | Open/switch active conversation (plain typed lines send to it) |
| `/verify <alias>` / `/verified <alias>` | Display safety number / mark as verified |
| `/timer <alias> <1h\|1d\|1w\|off>` | Set mutual disappearing timer |
| `/purge set <duration\|off>` / `/purge now [alias]` | Local retention policy / immediate local deletion |
| `/rotate passphrase` | Re-wrap key store under a new passphrase |
| `/settings rotation <on\|off\|day <weekday>>` | Configure the weekly rotation prompt |
| `/keys status` / `/keys refill` | Prekey inventory / manual replenishment |
| `/bench [suite]` | Run benchmark suite (researcher feature, §8) |
| `/wipe` | Panic: destroy local store (double confirmation) |
| `/help [command]` | Usage |

### 7.3 Parser rules (security-relevant)

- Grammar: line starts with `/` ⇒ tokenize against a **static allowlist** of commands and typed arguments; anything else is message text for the active conversation. No dynamic dispatch, no string-built code paths, no HTML injection (all output rendered as text cells, never `innerHTML`).
- Argument validation client-side *and* server-side; UIDs checked against the Base32 alphabet + length before any lookup.
- A leading space escapes a literal `/` at the start of a message.

---

## 8. Benchmark Suite (report evidence)

Run via `/bench` (browser) and `make bench` (server); output as JSON + generated Markdown tables and charts.

| # | Benchmark | Compares | Environments |
|---|---|---|---|
| B1 | Primitive latency: keygen / encaps / decaps | ML-KEM-768 vs X25519 | Browser (`@noble/post-quantum` vs `@noble/curves`); server (liboqs-python vs `cryptography`) |
| B2 | Primitive latency: keygen / sign / verify | ML-DSA-65 vs Ed25519 | Same as B1 |
| B3 | Size overhead | Keys, ciphertexts, signatures; per-registration-bundle, per-handshake, per-ratchet-step bytes | Static analysis + wire capture |
| B4 | Protocol level | Time-to-first-message; messages/sec sustained; handshake under 4× CPU throttling (mobile proxy) | Full app over WSS |
| B5 | Footprint | Frontend bundle-size delta attributable to PQC libs; server memory per session | Build stats / RSS sampling |

**Reference size table (expected values, to be confirmed by B3):**

| Object | Classical | Pure PQC | Factor |
|---|---|---|---|
| KEM/DH public key | 32 B (X25519) | 1,184 B (ML-KEM-768) | ×37 |
| KEM ciphertext / DH share | 32 B | 1,088 B | ×34 |
| Signature | 64 B (Ed25519) | 3,309 B (ML-DSA-65) | ×52 |
| Signature public key | 32 B | 1,952 B | ×61 |

**Methodology:** ≥ 100 warm-up iterations discarded; report median and p95 of ≥ 1,000 iterations for primitives, ≥ 100 for protocol-level; fixed hardware/browser documented; benchmarks run on isolated machine states. Numbers are for *these implementations in these environments*, not the algorithms in the abstract - the browser-JS vs native-C gap is itself a reported finding.

---

## 9. System Architecture

```
┌───────────────────────────┐    WSS + HTTPS (TLS 1.3,
│ Browser (TypeScript)      │     X25519MLKEM768 hybrid)
│ · xterm.js terminal UI    │◄────────────────────┐
│ · command parser          │                     │
│ · protocol engine:        │      ┌──────────────┴────────┐
│   PQ-KX + KEM ratchet     │      │ FastAPI (Python)      │
│   (@noble/post-quantum,   │      │ · ML-DSA challenge    │
│    ciphers, hashes)       │      │   auth                │
│ · key store: IndexedDB,   │      │ · prekey bundle store │
│   Argon2id-wrapped DEK    │      │ · delivery queue      │
│ · local message DB (enc.) │      │   (delete-on-ack,     │
└───────────────────────────┘      │    TTL 14 days)       │
                                   │ · rate limiter        │
  Server sees ciphertext           └──────────────┬────────┘
  only: never plaintext,                          │
  never private keys                  ┌───────────┴─────┐
                                      │ PostgreSQL      │
                                      │ (SQLite in dev) │
                                      └─────────────────┘
```

- **Frontend:** TypeScript, Vite, xterm.js; crypto exclusively from the audited `@noble` family (`post-quantum`, `ciphers`, `hashes`) - no hand-rolled primitives; protocol engine isolated as a dependency-injected module so the benchmark suite and unit tests drive it headlessly.
- **Backend:** Python 3.12 + FastAPI; WebSocket for live delivery, REST for registration/bundles; `liboqs-python` used **only** for server-side benchmark baselines - the server performs no message cryptography because it never has keys. PostgreSQL in deployment, SQLite in development.
- **Crypto duplication note:** because the stack is Python + TS, the protocol is implemented once (client TS); the server is a dumb ciphertext router, which is exactly the trust posture G3 requires. Shared test vectors (JSON) validate the TS implementation against liboqs outputs in CI.

---

## 10. Known Limitations (state these in the report - they are features of honesty, not bugs of the project)

1. **Academic prototype, not production crypto.** The custom protocol is unreviewed by professional cryptographers and unverified formally. Real deployments should use vetted implementations (e.g., libsignal) - this project's value is measurement and demonstration.
2. **JavaScript side channels.** `@noble` aims at constant-time behavior, but JS engines (JIT, GC) cannot guarantee it. Timing side channels are plausible; out of scope to eliminate.
3. **Web-platform key custody.** No WebCrypto support for ML-KEM/ML-DSA ⇒ private keys are materialized in JS memory while unlocked. XSS is therefore a key-theft vector; strict CSP is the mitigation, not a cure.
4. **Metadata.** The server learns who messages whom and when. Minimized, not eliminated (no sealed sender in MVP).
5. **Deniability regression.** ML-DSA-signed handshakes are non-repudiable, unlike Signal's DH-based deniable authentication.
6. **Cooperative deletion.** Disappearing timers and purge cannot bind a malicious peer client; screenshots exist; browser deletion is not forensic erasure.
7. **Single device.** Losing the device + recovery codes loses the identity; no history sync.
8. **Availability.** No DDoS resilience beyond rate limiting; not an MVP goal.

---

## 11. Milestones (6-week plan; 4-week floor = W1–W4 + B3 only)

| Week | Deliverables | Exit criteria |
|---|---|---|
| **W1 - Foundations** ✓ | Repos, CI (lint, tests, `pip-audit`/`npm audit`), FastAPI skeleton, DB schema, UID generation + registration transaction, xterm.js shell + command parser | Register via terminal; UID printed; parser rejects malformed commands; CI green |
| **W2 - Identity & key store** ✓ | ML-DSA keygen, challenge–response login, session tokens, Argon2id-wrapped IndexedDB store, recovery codes, prekey bundle upload (SPK + 50 OPKs, signed) | Login round-trip works; store survives reload locked; bundle visible in DB as ciphertext/keys only |
| **W3 - Handshake & first message** ✓ | PQ-KX end-to-end, AEAD messaging happy path, delivery queue with ack-delete + TTL, offline delivery | Alice → offline Bob → Bob receives on login; server row deleted on ack; signature-verification failure aborts loudly |
| **W4 - Ratchet & trust** | Symmetric chains, KEM ratchet steps, out-of-order handling, header encryption, safety numbers + key-change tear-down | FS/PCS demonstrated by test (leak state → past msgs safe → session heals); `/verify` flow complete |
| **W5 - Lifecycle & hardening** | Disappearing timers, local purge, rotation prompt + `/settings`, full header/CSP/rate-limit pass, dependency scan clean, `/wipe` | OWASP-header scan clean; timers verified on both clients; Snyk/`pip-audit` zero high-severity |
| **W6 - Benchmarks & report** | B1–B5 implemented, charts generated, demo script, README, this document updated to as-built | `/bench` produces the report tables; 15-minute live demo rehearsed; buffer for slip |

**W2 specifics:** Build the local key store + authentication. Client generates ML-DSA-65 keypair at `/register` (done in W1, move to encrypted storage in W2); store all secrets (identity SK, prekey SKs, ratchet state) in IndexedDB encrypted under Argon2id(passphrase) + a random DEK. Implement `/login` (server issues a nonce, client ML-DSA-signs it, server issues session token); `/logout` (invalidates token server-side); `/lock` (immediate encrypt); `/rotate passphrase` (re-wrap DEK locally). Auto-generate SPK (rotated weekly) + 50 OPKs (low-watermark refill at < 20); both batch-signed with IK and uploaded on first login. Print one-time recovery codes at registration. `/settings rotation <on|off|day <weekday>>` configures the weekly passphrase rotation prompt (default: Friday, toggleable, entirely local).

**Scope-cut order if behind schedule:** B4/B5 benchmarks → toasts/QR/themes → `/wipe` → local purge (keep mutual timer) → header encryption. Never cut: ratchet FS/PCS, safety numbers, delete-on-ack queue.

---

## 12. Acceptance Criteria (MVP is "done" when…)

1. Two users on separate machines register, verify safety numbers, and exchange messages; a packet capture shows only TLS; server DB inspection shows only ciphertext, public keys, and queue rows that vanish on delivery.
2. A test harness that exfiltrates one party's full ratchet state cannot decrypt previously captured ciphertexts (FS) and loses access within one round-trip after the leak stops (PCS).
3. Replacing a user's identity key server-side causes the peer's client to refuse to send and display a key-change warning (A2 detection).
4. No classical asymmetric primitive appears in the application dependency graph's crypto paths (checked by an automated grep/import audit in CI).
5. The benchmark suite reproduces the §8 tables on the demo hardware.
6. Registration/login/lookup endpoints hold under the rate-limit test without user enumeration (uniform errors and timing for exists/not-exists paths).
7. Security headers score A on Mozilla Observatory (or equivalent); dependency scans report no high/critical findings.

---

## 13. Future Work (post-MVP roadmap, for the report's outlook section)

1. **SPQR-style chunked KEM ratchet** with erasure coding - direct bandwidth comparison against the MVP's inline-key design.
2. **Sealed sender / metadata protection**, then traffic-analysis resistance.
3. **Group messaging** via MLS (RFC 9420) with PQ ciphersuites.
4. **Mobile PWA**, then native clients.
5. **Multi-device** with encrypted state sync (the key-backup problem).
6. **Formal verification** of PQ-KX and the ratchet in Tamarin or ProVerif.
7. **HQC as a backup KEM** (algorithm-agility demonstration: swap KEMs behind one interface).
8. **Hybrid mode** as a runtime option - enabling a three-way benchmark: classical vs hybrid vs pure PQC.
9. Deniability research: PQ deniable authenticated key exchange (e.g., ring-signature or designated-verifier approaches) to recover Signal-style deniability.

---

## 14. Guideline Disposition (traceability from the original supporting guidelines)

| # | Original guideline | Disposition | Rationale |
|---|---|---|---|
| 1 | Terminal UI for all interaction, web + mobile app | **Adopted (web MVP)** | Terminal UI is the core UX (§7). Mobile-native deferred to future work; the web terminal is responsive on mobile browsers. |
| 2 | Pop-ups to indicate event interactions | **Adapted** | Modal pop-ups replaced with inline event lines (terminal-native, non-dismissable-by-reflex); optional toast notifications for background events. Security-critical events require acknowledgment (§7.1). |
| 3 | CSPRNG UID generation with existence check | **Adapted** | CSPRNG UIDs adopted (§6.1). The *client-visible* existence check is removed as a username-enumeration oracle; uniqueness is enforced silently server-side under a DB constraint. |
| 4 | Rotate password prior to log-off, not log-on | **Replaced** | Server-side rotation at log-off fails unsafely on crash/disconnect and contradicts NIST SP 800-63B. Replaced by: passwordless ML-DSA auth, short-lived rotating session tokens (§6.2), and a weekly *local* unlock-passphrase rotation prompt - toggleable, day-configurable, crash-safe (§6.6). |
| 5 | PQC employment | **Adopted and strengthened** | Pure PQC: ML-KEM-768 + ML-DSA-65 everywhere in the application layer; hybrid PQ TLS underneath as defense-in-depth (§6). |
| 6 | Possibly use open-source repos like Signal Protocol | **Adapted** | libsignal is hybrid-only with no maintained browser build ⇒ incompatible with pure PQC. Signal's published designs (X3DH/PQXDH/Double Ratchet/SPQR) are used as reference architecture; implementation uses audited open-source primitive libraries (`@noble/post-quantum`, liboqs) instead (§2.3, §9). |

---

## Appendix A - Cryptographic parameter summary

| Purpose | Algorithm | Standard | Security category |
|---|---|---|---|
| Key encapsulation (handshake, ratchet) | ML-KEM-768 | FIPS 203 | 3 (~AES-192) |
| Identity & handshake signatures | ML-DSA-65 | FIPS 204 | 3 |
| Message AEAD | XChaCha20-Poly1305 | RFC-draft / libsodium-established | 256-bit symmetric |
| KDF | HKDF-SHA-512 | RFC 5869 / FIPS 180-4 | - |
| Password hashing (local wrap) | Argon2id, m=64 MiB, t=3, p=1 | RFC 9106 | - |
| Randomness | OS CSPRNG (`crypto.getRandomValues`, `secrets`) | - | - |

*Symmetric primitives at 256-bit keys are already considered quantum-resistant (Grover halves the effective exponent; 2¹²⁸ post-quantum work factor remains).*

## Appendix B - Glossary

- **HNDL** - Harvest Now, Decrypt Later: recording ciphertext today for future quantum decryption.
- **ML-KEM / ML-DSA** - Module-Lattice-based KEM (FIPS 203, née Kyber) / Digital Signature Algorithm (FIPS 204, née Dilithium).
- **FS / PCS** - Forward Secrecy (past messages safe after compromise) / Post-Compromise Security (session heals after transient compromise).
- **PQXDH / SPQR** - Signal's post-quantum extended-DH handshake / Sparse Post-Quantum Ratchet (the reference designs for §6.3–6.4).
- **Prekey bundle** - Public keys published to the server enabling handshakes with offline recipients.
- **Safety number** - Human-comparable fingerprint of both parties' identity keys for out-of-band verification.
- **DEK** - Data-encryption key wrapped by the passphrase-derived key.

## Appendix C - Key references

- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) - NIST, August 2024
- NIST IR 8547 - Transition to Post-Quantum Cryptography Standards (deprecation ≈ 2030, disallowance 2035)
- NIST SP 800-63B - Digital Identity Guidelines (password rotation guidance)
- Signal: X3DH, Double Ratchet, PQXDH specifications; "Signal Protocol and Post-Quantum Ratchets" (SPQR), signal.org/blog/spqr
- RFC 9106 (Argon2), RFC 5869 (HKDF), RFC 9420 (MLS - future work)
- `@noble/post-quantum` (Cure53-audited TS ML-KEM/ML-DSA), Open Quantum Safe `liboqs`
- OWASP ASVS & Password Storage Cheat Sheet
                                                                                                                                                                                                                                                                                                                                                                      