# Deploying Meridian Edge

How to stand up a Meridian Edge instance for real users. Three routes are
documented below — pick one:

| Route | Edge | TLS | Best for |
|---|---|---|---|
| **A. Traditional** | nginx (container) | bring-your-own certs | you already run nginx/certbot and want explicit control |
| **B. Caddy** | Caddy (container) | automatic (Let's Encrypt) | most people — simplest path to a hardened HTTPS deploy |
| **C. Single box** | Caddy (host) | automatic | 10–20 users on one small VPS, no container orchestration |

All three keep the CLAUDE.md §5 hardening posture (non-root, read-only
filesystems, TLS 1.3, the exact CSP/HSTS header set, WS origin allowlist).

---

## What you're actually deploying (read this first)

The server is a **zero-knowledge relay**. Every post-quantum operation —
ML-KEM-768 key exchange, ML-DSA-65 signatures, the message ratchet — runs in
the browser. The server only stores and forwards opaque encrypted blobs and
public key bundles; it never sees plaintext, private keys, or symmetric keys.

Two consequences that shape deployment:

- **Load is trivial.** 10–20 users generate almost no server work — the crypto
  cost lives on the clients. A 1 vCPU / 1 GB VPS is comfortable. Don't
  over-provision.
- **The PQ TLS group is defense-in-depth, not the security boundary.** The
  `X25519MLKEM768` hybrid group on the TLS handshake is a nice-to-have extra
  layer. If your edge can't negotiate it, the end-to-end PQ encryption is
  **completely unaffected** — it's in the client, not the transport. So a
  fallback to classical TLS curves degrades transport hardening only, never the
  messenger's actual guarantees. (Route B/C get the PQ group for free; Route A
  depends on your nginx OpenSSL build — see its note.)

### Prerequisites (all routes)

1. A domain and a DNS `A`/`AAAA` record pointing at the host, e.g.
   `chat.example.com`.
2. Docker + Docker Compose (routes A/B) **or** a plain Linux VPS (route C).
3. The production env vars below. The server **refuses to boot** in production
   if any are wrong (`_assert_production_safe`, `server/app/main.py`):

   | Var | Required | Purpose |
   |---|---|---|
   | `MERIDIAN_EDGE_ENV=production` | yes | turns on the boot guard, disables `/docs` |
   | `MERIDIAN_EDGE_WS_ORIGINS` | yes | exact WS `Origin` allowlist, comma-separated (e.g. `https://chat.example.com`) — **must not be empty** |
   | `MERIDIAN_EDGE_DATABASE_URL` | yes | Postgres DSN — a `sqlite://` URL is **rejected** in production |
   | `MERIDIAN_EDGE_DEV` | must be unset/≠1 | `=1` enables `/docs`; refused alongside production |

   Argon2id params are also asserted against the §0 constants at boot.

> **Honest status:** the Dockerfiles / nginx.conf / Caddyfile were authored and
> reviewed by eye but **not build-tested end-to-end** in a session with a Docker
> daemon (noted in CLAUDE.md W5). Run `docker compose build` and the smoke
> checks at the bottom before trusting any of this in front of real users.

---

## Route A — Traditional (nginx reverse proxy)

The reference topology already in the repo: `docker-compose.yml` +
`deploy/nginx.conf` + `deploy/proxy.Dockerfile`. nginx terminates TLS, serves
the built client bundle same-origin, and reverse-proxies `/v1/*` (including the
`/v1/ws` WebSocket) to the FastAPI server. Postgres runs alongside.

**You provide the TLS certificates** (this route does not auto-issue them).

```bash
# 1. Secrets + config
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD (long random), MERIDIAN_EDGE_WS_ORIGINS
# (e.g. https://chat.example.com), and TLS_CERT_DIR (e.g. ./tls)

# 2. Drop certs where the proxy mounts them (read-only) as:
#    ${TLS_CERT_DIR}/fullchain.pem  and  ${TLS_CERT_DIR}/privkey.pem
#    Obtain them however you like, e.g. certbot on the host:
sudo certbot certonly --standalone -d chat.example.com
mkdir -p ./tls
sudo cp /etc/letsencrypt/live/chat.example.com/fullchain.pem ./tls/
sudo cp /etc/letsencrypt/live/chat.example.com/privkey.pem   ./tls/

# 3. Build + run
docker compose up -d --build

### Using a paid CA certificate (instead of certbot)

A standard commercial DV cert is domain-validated, not server-bound, so you can
finalize it before the server exists. Generate the key + CSR yourself:

    openssl req -new -newkey rsa:2048 -nodes \
      -keyout privkey.pem -out meridianedge.csr \
      -subj "/CN=<your-domain>"

In the CA/reseller dashboard, submit the CSR and complete **Domain Control
Validation** by **DNS (TXT)** or **email** — not the HTTP-file method, which
needs a running web server. The CA returns your leaf cert plus an intermediate
chain; assemble the two files this route mounts (leaf first, then the
intermediate(s)):

    cat your_domain.crt intermediate.crt > fullchain.pem   # privkey.pem is from the CSR step
    mkdir -p ./tls && cp fullchain.pem privkey.pem ./tls/   # keep privkey.pem secret, never commit

Then `docker compose up -d --build` as above. **Renewal is manual**: standard
certs last ~1 year — when you re-issue, drop the new `fullchain.pem` /
`privkey.pem` into `TLS_CERT_DIR` and `docker compose restart proxy`.
```

**PQ TLS caveat (route-specific):** `deploy/nginx.conf` asks for
`ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1`. nginx **won't start** if its
linked OpenSSL doesn't know that group. The `nginx:1.27-alpine` base must be
OpenSSL ≥ 3.5 (ML-KEM support). If it isn't, either use a newer base image or
edit the line to `ssl_ecdh_curve X25519:secp384r1` — you lose PQ *transport*
only (see the boundary note above), nothing else.

Certificate renewal is on you (e.g. a certbot cron/systemd timer that re-copies
into `TLS_CERT_DIR`, then `docker compose restart proxy`). If that sounds
tedious, that's exactly what Route B removes.

---

## Route B — Caddy (automatic HTTPS)

Same containerized topology, but the edge is **Caddy** instead of nginx.
Caddy provisions and renews TLS automatically (Let's Encrypt / ZeroSSL), and
Caddy 2.9+ negotiates the `X25519MLKEM768` hybrid group out of the box — no
OpenSSL wrangling, no certbot. For most deployments this is the easiest path.

Files: `docker-compose.caddy.yml`, `deploy/caddy.Dockerfile`, `deploy/Caddyfile`
(the header set mirrors nginx.conf exactly).

```bash
# 1. Secrets + config
cp .env.example .env
# edit .env: POSTGRES_PASSWORD, MERIDIAN_EDGE_WS_ORIGINS (https://chat.example.com),
# and add:
#   MERIDIAN_EDGE_DOMAIN=chat.example.com
#   ACME_EMAIL=you@example.com          # optional but recommended
# (TLS_CERT_DIR is unused on this route — Caddy manages certs itself.)

# 2. Point DNS at this host and make sure ports 80 + 443 are reachable
#    (Caddy needs 80 for the ACME challenge).

# 3. Build + run
docker compose -f docker-compose.caddy.yml up -d --build
```

Caddy stores its ACME account and issued certificates in the persistent
`caddy-data` volume — don't delete it, or you'll re-issue certs (and can hit
Let's Encrypt rate limits) on the next start.

---

## Route C — Single box, no orchestration (10–20 people)

The lightest operationally sane deployment: one small VPS, no Docker, Caddy on
the host for auto-TLS, one `uvicorn` process under systemd, one local Postgres.
Because the server barely works (it's a relay), this handles a small circle of
users on the cheapest tier comfortably.

> Postgres is still required — the production boot guard rejects SQLite by
> design (§7.5). It just runs on the same box here.

```bash
# --- 0. Base packages (Debian/Ubuntu example) ---
sudo apt update && sudo apt install -y python3.12 python3.12-venv postgresql caddy git

# --- 1. Postgres: db + user ---
sudo -u postgres psql <<'SQL'
CREATE USER meridian_edge WITH PASSWORD 'CHANGE_ME_LONG_RANDOM';
CREATE DATABASE meridian_edge OWNER meridian_edge;
SQL

# --- 2. App + Python deps ---
sudo git clone <your-repo-url> /opt/meridian-edge
cd /opt/meridian-edge/server
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt   # psycopg[binary] is pinned, Postgres works as-is

# --- 3. Build the client bundle and hand it to Caddy ---
cd /opt/meridian-edge/client && npm ci && npm run build
sudo mkdir -p /srv/www && sudo cp -r dist/* /srv/www/
```

**systemd unit** — `/etc/systemd/system/meridian-edge.service`:

```ini
[Unit]
Description=Meridian Edge server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
User=www-data
WorkingDirectory=/opt/meridian-edge/server
Environment=MERIDIAN_EDGE_ENV=production
Environment=MERIDIAN_EDGE_WS_ORIGINS=https://chat.example.com
Environment=MERIDIAN_EDGE_DATABASE_URL=postgresql+psycopg://meridian_edge:CHANGE_ME_LONG_RANDOM@localhost/meridian_edge
ExecStart=/opt/meridian-edge/server/.venv/bin/uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000
Restart=on-failure
# Hardening (mirrors the container posture)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**Caddy** — put `MERIDIAN_EDGE_DOMAIN` + `ACME_EMAIL` in `/etc/caddy/env`, point
Caddy's service at it, and reuse the repo's config but serving from `/srv/www`
with the backend on localhost:

```bash
# Reuse deploy/Caddyfile; it already reads MERIDIAN_EDGE_DOMAIN / ACME_EMAIL and
# defaults the backend to server:8000 — override to localhost for the host setup:
export MERIDIAN_EDGE_DOMAIN=chat.example.com ACME_EMAIL=you@example.com
export MERIDIAN_EDGE_BACKEND=127.0.0.1:8000
sudo cp /opt/meridian-edge/deploy/Caddyfile /etc/caddy/Caddyfile
```

```bash
sudo systemctl enable --now meridian-edge
sudo systemctl restart caddy
```

That's the whole stack: Caddy (auto-TLS, PQ TLS group) → uvicorn → Postgres,
all on one host. To update: `git pull`, rebuild the client into `/srv/www`,
`pip install -r requirements.txt`, `systemctl restart meridian-edge`.

---

## After deploying — smoke checks (all routes)

```bash
# 1. Static bundle loads and carries the exact security headers
curl -sI https://chat.example.com | grep -iE 'content-security-policy|strict-transport|x-content-type|referrer-policy|cross-origin'

# 2. API is reachable and returns uniform errors (no stack traces, no /docs)
curl -s  https://chat.example.com/docs -o /dev/null -w '%{http_code}\n'   # expect 404 in production

# 3. WebSocket upgrade is proxied (needs a real client Origin to fully pass)
curl -sI -H 'Connection: Upgrade' -H 'Upgrade: websocket' https://chat.example.com/v1/ws
```

Then load the site in a browser, `/register`, note the UID, and from a second
browser `/add` + `/chat` to confirm an end-to-end message round-trips. Run a
header scan (e.g. Mozilla Observatory) — CLAUDE.md §5 targets grade **A**.

## Operational notes

- **Schema:** first boot auto-creates tables (`Base.metadata.create_all`, the
  W1 migration stand-in). There's no Alembic yet, so plan schema changes
  manually when they come.
- **Backups:** back up the Postgres data volume, but the **message queue is
  intentionally ephemeral** (delete-on-ack + 14-day TTL, §5) — do not add it to
  any archival/backup that would retain delivered ciphertext. Public key
  bundles and account rows are the durable state worth backing up.
- **Secrets:** `.env` and TLS private keys never get committed or baked into
  images. `.env.example` documents the shape; keep the real `.env` out of git.
- **Rate limits** (register/login/bundle/message) and WS frame caps are enforced
  in-app and need no proxy config; the edge only adds `client_max_body_size 64k`
  as belt-and-suspenders against the 64 KiB payload cap.
