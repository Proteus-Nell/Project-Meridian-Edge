# PQTerm deployment guide

How to run PQTerm — for local development and for a hardened production
deployment. It reflects the actual artifacts in this repo (`server/Dockerfile`,
`deploy/`, `docker-compose.yml`); the security rationale behind each choice
lives in [CLAUDE.md](../CLAUDE.md) §5.

> **Honest status.** The Docker/compose/nginx artifacts were authored and
> cross-checked by eye but **not build-tested against a live Docker daemon** in
> the session that produced them. Treat the production path below as a
> reviewed reference, not a turnkey guarantee: run `docker compose build` and
> the smoke tests in [Verify the deployment](#5-verify-the-deployment) before
> trusting it with real users.

---

## Topology

Three containers, one host-facing port surface:

```
                          :443 (https/wss)          (internal docker network)
   browser  ───TLS 1.3──▶  ┌─────────────┐   /v1/*   ┌──────────────┐   ┌────────────┐
   (xterm)                 │    proxy     │ ────────▶ │    server    │ ─▶│     db     │
                           │  nginx edge  │   :8000   │  FastAPI     │   │ PostgreSQL │
   ◀── static client ───── │  + client    │           │  (uvicorn)   │   │            │
                           └─────────────┘           └──────────────┘   └────────────┘
        :80 → 301 https        serves dist/            opaque ciphertext    encrypted
                                                        router only          blobs only
```

- **proxy** — terminates TLS, serves the built client bundle same-origin (zero
  CDN assets, §7.8), reverse-proxies `/v1/*` and `/v1/ws` to the server, and
  sets the page-level CSP + HSTS. Redirects `:80` → `:443`.
- **server** — the FastAPI app. Never sees plaintext, private keys, or symmetric
  keys — it routes opaque envelopes and stores public keys + ciphertext blobs.
- **db** — PostgreSQL. Holds users' public keys, prekey bundles, the per-recipient
  ciphertext queue (delete-on-ack, 14-day TTL), session-token hashes, and
  Argon2id recovery-code hashes. No plaintext, ever.

The trust model does **not** depend on the server or the database being
trustworthy — end-to-end encryption and the safety-number check (§4) are what
protect users. This guide is about running the service reliably, not about
making the server a trusted party (it isn't one).

---

## Prerequisites

**Local development**
- Node ≥ 22, npm
- Python ≥ 3.12
- (SQLite is used automatically in dev — no database to install.)

**Production**
- Docker Engine + the Compose plugin (`docker compose`, v2)
- A domain name pointing at the host
- TLS certificate + private key for that domain (e.g. from Let's Encrypt)
- **An nginx image whose linked OpenSSL supports the `X25519MLKEM768` hybrid
  group** — see [TLS and the hybrid PQ group](#tls-and-the-hybrid-pq-group).
  This is the one prerequisite most likely to need attention.

---

## Local development

Two long-running dev servers: the FastAPI backend and the Vite client. The
client dev server proxies `/v1` to the backend, so you only open the client URL.

```bash
# terminal 1 — backend (API on :8000, SQLite dev DB, docs enabled)
cd server
pip install -r requirements.txt -r requirements-dev.txt
PQTERM_DEV=1 uvicorn app.main:create_app --factory --reload

# terminal 2 — client (terminal UI on :5173, proxies /v1 → :8000)
cd client
npm ci
npm run dev
```

Open <http://localhost:5173> and type `/help`.

### Testing with multiple users locally

Each browser origin has its own encrypted IndexedDB store, so "two users" means
two origins. Run extra client instances on different ports (each still proxies
to the same backend):

```bash
cd client
PORT=5174 npm run dev   # user B → http://localhost:5174
PORT=5175 npm run dev   # user C → http://localhost:5175
```

`.claude/launch.json` already defines `client`, `client2`, `client3`, and
`server` entries if you drive dev servers through that tooling.

`/register` a separate identity in each tab, share UIDs between them with
`/add <uid>`, and message across. Everything is real crypto against the real
backend — only TLS and Postgres are missing versus production.

### Running the checks

```bash
cd server && mypy --strict app && pytest        # server gates
cd client && npm run typecheck && npm test      # client gates
python scripts/audit.py                         # classical-crypto / injection greps
```

---

## Production deployment

### 1. Clone and enter the repo

```bash
git clone <your-fork-url> pqterm && cd pqterm
```

### 2. Provide TLS certificates

Create a directory holding the certificate chain and private key, named exactly
`fullchain.pem` and `privkey.pem` (the names `nginx.conf` expects):

```bash
mkdir -p tls
cp /path/to/fullchain.pem tls/fullchain.pem
cp /path/to/privkey.pem   tls/privkey.pem
chmod 600 tls/privkey.pem
```

`tls/` is git-ignored. With Let's Encrypt, these are the files certbot writes to
`/etc/letsencrypt/live/<domain>/`. Certificate **issuance/renewal is out of
scope** for this compose file — run certbot on the host (or a sidecar) and point
`TLS_CERT_DIR` at its output; the proxy mounts the directory read-only, so a
renewed cert is picked up on the next proxy restart (`docker compose restart
proxy`).

### 3. Write the `.env` file

```bash
cp .env.example .env
```

Fill in every value (the compose file **refuses to start** if any is missing —
see [Configuration reference](#configuration-reference)):

```ini
POSTGRES_PASSWORD=<a long random secret>
PQTERM_WS_ORIGINS=https://pqterm.example      # your exact public origin(s)
TLS_CERT_DIR=./tls
```

`PQTERM_WS_ORIGINS` must be the **exact** origin(s) browsers will connect from
(scheme + host + optional port, comma-separated for more than one). The
WebSocket upgrade is rejected if the `Origin` header doesn't match — a wrong
value here breaks live message delivery.

Never commit `.env`. It's git-ignored.

### 4. Build and start

```bash
docker compose build
docker compose up -d
```

`server` waits for `db` to pass its health check before starting. On boot the
server runs `_assert_production_safe` (because `PQTERM_ENV=production` is set in
compose) and **refuses to start** if the config is dev-shaped — see
[Boot-safety gate](#boot-safety-gate).

### 5. Verify the deployment

```bash
# All three up; db healthy, server/proxy running
docker compose ps

# The API answers uniformly through the proxy over TLS
curl -sS https://pqterm.example/v1/keys/status \
  -H 'Authorization: Bearer not-a-real-token' -i | head -n1
#   → HTTP/2 401        (uniform auth_failed body; the stack is wired)

# Security headers + HSTS are present on a page response
curl -sSI https://pqterm.example/ | grep -iE 'strict-transport|content-security'

# http redirects to https
curl -sSI http://pqterm.example/ | grep -i location

# Then open https://pqterm.example in a browser and /register.
```

A `401` (not a `502`/connection error) on the first curl means the browser →
nginx → server → db path is healthy. `502` means the proxy can't reach the
server; check `docker compose logs server`.

---

## Configuration reference

### Server environment variables

| Variable | Purpose | Dev default | Production |
|---|---|---|---|
| `PQTERM_ENV` | Enables the boot-safety gate when `production` | unset | `production` (set by compose) |
| `PQTERM_DATABASE_URL` | SQLAlchemy URL | `sqlite:///./pqterm_dev.db` | `postgresql+psycopg://…` (from compose) |
| `PQTERM_WS_ORIGINS` | Exact WS `Origin` allowlist, comma-separated | unset (open, dev only) | **required** |
| `PQTERM_DEV` | Enables `/docs` + `/openapi.json` | unset | must stay unset in prod |

In production, `PQTERM_DATABASE_URL` and `PQTERM_WS_ORIGINS` are derived from
`.env` inside `docker-compose.yml`; you normally only touch `.env`.

### Compose / host `.env` variables

| Variable | Used by | Notes |
|---|---|---|
| `POSTGRES_PASSWORD` | db + server URL | any long random secret |
| `PQTERM_WS_ORIGINS` | server | your public origin(s) |
| `TLS_CERT_DIR` | proxy | host dir with `fullchain.pem` + `privkey.pem` |

### Ports

| Host | Container | Service |
|---|---|---|
| 80 | 8080 | proxy (301 → https) |
| 443 | 8443 | proxy (TLS, client + `/v1`) |
| — | 8000 | server (internal only) |
| — | 5432 | db (internal only) |

Only 80 and 443 are published. The server and database are reachable only on the
internal Docker network.

### Boot-safety gate

`_assert_production_safe` (in `server/app/main.py`) runs **only** when
`PQTERM_ENV=production`. It refuses to boot — with an explicit message — if any
of these dev-shaped conditions hold:

- `PQTERM_DEV=1` is set (would expose `/docs`)
- `PQTERM_WS_ORIGINS` is unset (would disable WS origin checking)
- `PQTERM_DATABASE_URL` is a SQLite URL (a dev artifact, never deploy it — §7.5)
- the live Argon2id parameters have drifted from the §0 constants
  (m = 64 MiB, t = 3, p = 1)

If the server container exits immediately on `up`, read `docker compose logs
server` — this gate names exactly what's wrong.

---

## TLS and the hybrid PQ group

`deploy/nginx.conf` requests, in order:

```
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;
```

`X25519MLKEM768` is the hybrid post-quantum key-exchange group (the same one
Chrome and Cloudflare deploy). **nginx refuses to start if its linked OpenSSL
doesn't recognize the named group.** Support for this codepoint landed in
OpenSSL 3.5; a stock `nginx:1.27-alpine` may ship an older OpenSSL.

Before relying on it, check inside the proxy image:

```bash
docker compose run --rm --entrypoint sh proxy -c \
  'openssl version && openssl list -kem-algorithms 2>/dev/null | grep -i mlkem'
```

- If it lists an ML-KEM algorithm, you're set.
- If not, either base `deploy/proxy.Dockerfile` on an nginx image built against
  OpenSSL ≥ 3.5, **or** temporarily drop the hybrid group from `ssl_ecdh_curve`
  (leaving `X25519:secp384r1`) so nginx starts — classical key exchange, with
  the rest of the stack (ML-KEM/ML-DSA end-to-end) unaffected. Treat that as a
  documented downgrade of the *transport* layer only, and restore the hybrid
  group once the image supports it.

The application's post-quantum guarantees (ML-KEM-768 handshake, ML-DSA-65
identity, the ratchet) do **not** depend on the TLS group — they run end-to-end
inside the client. The hybrid TLS group is defense-in-depth for the transport.

---

## Operations

### Logs

```bash
docker compose logs -f server     # auth failures, rate-limit trips, errors only
docker compose logs -f proxy      # access + TLS errors
docker compose logs -f db
```

Server logs are privacy-minimal by design (§5): auth-failure counts, rate-limit
trips, and errors — no message metadata, no UIDs where avoidable. Retain ~30
days per policy.

### Database backups

The only durable state is the `db-data` volume. Back it up with `pg_dump`:

```bash
docker compose exec db pg_dump -U pqterm pqterm > backup-$(date +%F).sql
```

Note what this contains and does **not**: public keys, prekey bundles, session
hashes, and the transient ciphertext queue. It contains **no** plaintext and no
private keys, so a leaked backup does not expose message content. The message
queue is short-lived (delete-on-ack, 14-day TTL) — a backup is a point-in-time
snapshot of undelivered blobs, not a message archive.

### Updating to a new version

```bash
git pull
docker compose build
docker compose up -d          # recreates changed containers
```

**Schema changes need care.** The server currently uses SQLAlchemy
`create_all()` as a stand-in for migrations (it creates missing tables but does
**not** alter existing ones). A release that changes a column will not migrate an
existing Postgres database automatically — introduce a real migration tool
(e.g. Alembic) before shipping a schema change to a database with real users.

### Certificate renewal

Renew on the host (certbot etc.) into `TLS_CERT_DIR`, then:

```bash
docker compose restart proxy
```

---

## Scaling and its limits

This topology is designed for a single server instance. Two pieces of state are
**in-process, per server container**, so naïvely running multiple `server`
replicas breaks them:

- **Rate limiters** (`rate_limit.py`) are in-memory token buckets. With N
  replicas behind a load balancer, each enforces the limit independently, so the
  effective limit is ~N×. Availability/rate-limiting is already documented as the
  only DoS defense and a best-effort one (§7.14).
- **The WebSocket hub** (`WsHub` in `ws.py`) tracks live connections in memory.
  A message enqueued for a user connected to a *different* replica won't be
  live-pushed from this one — it's still delivered (the recipient drains the
  queue on its next connect/poll), just not instantly.

To scale the server horizontally you'd need a shared rate-limit store (e.g.
Redis) and a shared pub/sub or sticky sessions for WS fan-out. Until then, scale
**up** (a bigger single server container) rather than **out**. Postgres and the
proxy scale independently in the usual ways.

---

## What's enforced where

| Control (CLAUDE.md §5) | Enforced by |
|---|---|
| TLS 1.3 only, `X25519MLKEM768` hybrid group | `deploy/nginx.conf` |
| HSTS `max-age=63072000; includeSubDomains; preload` | nginx + server headers |
| Page CSP (`default-src 'none'` → `'self'` script/style, `wss:` connect) | `deploy/nginx.conf` |
| API deny-all CSP + `nosniff`/`Referrer-Policy`/COOP/CORP/Permissions-Policy | `server/app/headers.py` |
| Same-origin bundle, zero CDN assets | proxy serves `dist/` |
| No CORS (no wildcard, no credentials) | server installs no CORS middleware |
| WS origin allowlist, auth-before-subscribe, frame cap, idle-kill, rate cap | `server/app/ws.py` + `PQTERM_WS_ORIGINS` |
| Rate limits (register/login/bundle/message) | `server/app/rate_limit.py` |
| Non-root, read-only fs, no shell, secrets via env | Dockerfiles + compose `read_only`/`tmpfs` |
| `DEBUG=0` / dev-config refused at boot | `_assert_production_safe` |
| Docs/openapi disabled in prod | `PQTERM_DEV` unset → `docs_url=None` |
| No outbound requests (SSRF) | no HTTP client dependency (asserted by test) |

---

## Troubleshooting

**`server` container exits immediately on `up`.**
The boot-safety gate rejected the config. `docker compose logs server` names the
exact problem (docs enabled, missing WS origins, SQLite URL, or drifted Argon2id
params).

**`proxy` won't start / TLS handshake fails on the group.**
Almost always the `X25519MLKEM768` group is unknown to the image's OpenSSL — see
[TLS and the hybrid PQ group](#tls-and-the-hybrid-pq-group). Check
`docker compose logs proxy` for an "unknown curve/group" error.

**`proxy` starts but can't write its pid / cache under read-only fs.**
The proxy runs non-root with a read-only root filesystem; `/var/cache/nginx`,
`/var/run`, and `/tmp` are provided as writable tmpfs by compose. If you edited
the compose tmpfs list or the Dockerfile `chown` targets, nginx may be unable to
write its pid file — re-check that those three paths are tmpfs and writable by
the `pqterm` user. (This is one of the untested interplays flagged at the top —
verify on first build.)

**Browser loads the client but messages never deliver live.**
`PQTERM_WS_ORIGINS` doesn't match the origin the browser uses (scheme/host/port
must be exact). Fix `.env`, `docker compose up -d` to recreate `server`. Messages
still deliver on reconnect; only the live push is affected.

**`curl https://…/v1/…` returns `502 Bad Gateway`.**
The proxy can't reach the server. Check `docker compose ps` (is `server` up?) and
`docker compose logs server`.

**`docker compose up` errors about an unset variable.**
A required `.env` value is missing. The message names it (`POSTGRES_PASSWORD`,
`PQTERM_WS_ORIGINS`, or `TLS_CERT_DIR`).

---

## Known limitations

- The Docker/compose/nginx config is a reviewed reference, **not build-tested**
  end-to-end in the authoring session — `docker compose build` + the smoke tests
  before real use.
- No automated database migrations (`create_all` only) — see
  [Updating](#updating-to-a-new-version).
- Single-server design — see [Scaling and its limits](#scaling-and-its-limits).
- Certificate issuance/renewal is out of scope for the compose file.
- Recovery-code redemption is not yet a server endpoint (deferred).
- Rate limiting is the only DoS defense, by design and best-effort (§7.14) — it
  is not resilience against a resourced attacker.

See [SECURITY.md](../SECURITY.md) for how to report a vulnerability and for the
documented browser-platform limitations.
