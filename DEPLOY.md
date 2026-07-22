# Deploying Meridian Edge

How to stand up a Meridian Edge instance for real users — end to end: how
requests route, how to obtain your TLS certificate (`privkey.pem` /
`fullchain.pem`), and three concrete deployment routes.

Pick one route:

| Route | Edge | TLS certificates | Best for |
|---|---|---|---|
| **A. Traditional** | nginx (container) | **you obtain them** (certbot or a CA) | you already run nginx/certbot and want explicit control |
| **B. Caddy** | Caddy (container) | **automatic** (Let's Encrypt) | most people — simplest path to a hardened HTTPS deploy |
| **C. Single box** | Caddy (host) | **automatic** | 10–20 users on one small VPS, no container orchestration |

All three keep the CLAUDE.md §5 hardening posture (non-root, read-only
filesystems, TLS 1.3, the exact CSP/HSTS header set, WS origin allowlist).

> **Short version:** if you don't want to think about certificates at all, use
> **Route B or C** — Caddy fetches and renews TLS for you. The whole "getting
> the SSL files" section below only applies to **Route A**, where nginx expects
> you to supply `fullchain.pem` + `privkey.pem` yourself.

---

## 1. What you're actually deploying

The server is a **zero-knowledge relay**. Every post-quantum operation —
ML-KEM-768 key exchange, ML-DSA-65 signatures, the message ratchet — runs in
the browser. The server only stores and forwards opaque encrypted blobs and
public-key bundles; it never sees plaintext, private keys, or symmetric keys.

Two consequences that shape deployment:

- **Load is trivial.** 10–20 users generate almost no server work — the crypto
  cost lives on the clients. A 1 vCPU / 1 GB VPS is comfortable. Don't
  over-provision.
- **The PQ TLS group is defense-in-depth, not the security boundary.** The
  `X25519MLKEM768` hybrid group on the TLS handshake is a nice-to-have extra
  layer. If your edge can't negotiate it, the end-to-end PQ encryption is
  **completely unaffected** — it lives in the client, not the transport. A
  fallback to classical TLS curves degrades transport hardening only, never the
  messenger's actual guarantees.

---

## 2. How routing works (read this before picking a route)

Everything is served **same-origin** from one hostname. There is no separate API
domain, no CDN. The edge (nginx or Caddy) is the only thing exposed to the
internet; it fans requests out by URL path:

```
   Browser  ──►  https://chat.example.com
                        │   TLS 1.3 (X25519MLKEM768 hybrid)
                        ▼
                ┌───────────────────────────┐
                │   Edge  :80  :443          │   nginx (Route A) or Caddy (B/C)
                │   • :80  → 301 redirect to :443 (+ ACME challenge)
                │   • :443 → TLS termination + routing:
                └───────────────────────────┘
                        │
        ┌───────────────┼─────────────────────────────┐
        │               │                             │
        ▼               ▼                             ▼
   GET /            /v1/*  (REST)                 /v1/ws  (WebSocket)
   static bundle    register / login /            live message push,
   from disk        bundles / messages            token-authenticated
   (index.html,     ──────────► reverse_proxy ──────────►  FastAPI  :8000
    JS, CSS)                                                    │
                                                                ▼
                                                          Postgres  :5432
```

**The three URL classes the edge routes:**

| Path | Goes to | Notes |
|---|---|---|
| `/` and any non-`/v1` path | static client bundle on disk | SPA fallback to `index.html`; the page-level CSP is set here |
| `/v1/*` | FastAPI `:8000` (plain reverse proxy) | register, login, key bundles, message enqueue/ack |
| `/v1/ws` | FastAPI `:8000` (HTTP Upgrade → WebSocket) | needs `Upgrade`/`Connection` headers **and** the `Origin` header forwarded |

### 2.1 DNS

Point the hostname at the machine's public IP:

```
chat.example.com.   A     203.0.113.10        # IPv4
chat.example.com.   AAAA  2001:db8::10         # IPv6 (if you have it)
```

If the box is behind a cloud load balancer / NAT, forward ports 80 and 443 to
it there too. DNS must resolve **before** you request a Let's Encrypt cert
(Route A certbot, and Routes B/C) — the ACME challenge validates the name.

### 2.2 Ports & firewall

| Port | Exposure | Purpose |
|---|---|---|
| 80/tcp | **public** | HTTP→HTTPS redirect + ACME HTTP-01 challenge |
| 443/tcp | **public** | HTTPS (and HTTP/2) |
| 443/udp | public (optional) | HTTP/3 — Caddy routes only |
| 8000/tcp | **internal only** | FastAPI server — never expose publicly |
| 5432/tcp | **internal only** | Postgres — never expose publicly |

In Docker (A/B) the server and Postgres sit on the private compose network and
are unreachable from outside by default — good. On the single box (C), bind
uvicorn to `127.0.0.1:8000` and Postgres to `localhost` so only the local edge
reaches them. A minimal host firewall:

```bash
sudo ufw allow 80,443/tcp
sudo ufw allow 443/udp        # only if you use Caddy/HTTP-3
sudo ufw enable
```

### 2.3 The one routing gotcha: WebSocket `Origin`

The server checks the WS upgrade's `Origin` header against
`MERIDIAN_EDGE_WS_ORIGINS` and **rejects a mismatch**. So two things must line
up exactly (scheme + host):

- `MERIDIAN_EDGE_WS_ORIGINS=https://chat.example.com` (the value the browser
  actually sends), and
- the edge must **forward** the `Origin` header. nginx does this explicitly
  (`proxy_set_header Origin $http_origin` in `deploy/nginx.conf`); Caddy
  preserves it by default.

If WebSocket connects but immediately drops, this is almost always the cause —
check the value matches your real origin, including `https://` and no trailing
slash.

---

## 3. Prerequisites (all routes)

1. A domain with DNS pointing at the host (§2.1).
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
> reviewed by eye but **not build-tested end-to-end** with a live Docker daemon
> (noted in CLAUDE.md W5). Run `docker compose build` and the §7 smoke checks
> before trusting any of this in front of real users.

---

## 4. Getting your TLS certificate (`privkey.pem` + `fullchain.pem`)

> **Skip this whole section if you use Route B or C** — Caddy obtains and renews
> the certificate automatically. This section is for **Route A (nginx)**, which
> mounts two files you provide.

### 4.1 What the two files are

| File | What it contains | Secrecy |
|---|---|---|
| `privkey.pem` | your certificate's **private key** | **secret** — never commit, never share, `chmod 600` |
| `fullchain.pem` | your **leaf certificate _followed by_ the intermediate CA cert(s)** — the full chain a browser needs to build trust to a known root | public |

The names matter: `deploy/nginx.conf` references exactly
`/etc/nginx/tls/fullchain.pem` and `/etc/nginx/tls/privkey.pem`, and
`docker-compose.yml` mounts your `TLS_CERT_DIR` there read-only. Whatever you do
below, you must end up with those two filenames in that directory.

Choose **one** of the three methods:

### 4.2 Method 1 — Let's Encrypt via certbot (free, auto-renewable) — recommended

Free, trusted by all browsers, 90-day certs with automated renewal.

**HTTP-01 (standalone) — simplest when port 80 is free.** Stop anything on port
80 first (the edge container, if already running), because certbot binds it to
prove domain control:

```bash
sudo certbot certonly --standalone -d chat.example.com
```

Certbot writes the cert into `/etc/letsencrypt/live/chat.example.com/`. Note
those are **symlinks** into `../../archive/…`, so copy with `-L` to dereference
them into your mount directory:

```bash
mkdir -p ./tls
sudo cp -L /etc/letsencrypt/live/chat.example.com/fullchain.pem ./tls/
sudo cp -L /etc/letsencrypt/live/chat.example.com/privkey.pem   ./tls/
```

**DNS-01 — cleanest for containers / wildcards (no port-80 juggling).** Proves
control by a TXT record instead of a listening server:

```bash
sudo certbot certonly --manual --preferred-challenges dns -d chat.example.com
# certbot prints a value; add a DNS record:
#   _acme-challenge.chat.example.com.  TXT  "the-value-it-prints"
# wait for it to propagate, then press Enter.
```

Then copy the two files exactly as in the standalone case above.

**Auto-renewal.** certbot installs a systemd timer that runs `certbot renew`
~twice daily; it only acts when a cert is within 30 days of expiry. Make renewal
re-copy the files and reload the edge with a deploy hook:

```bash
sudo certbot renew --deploy-hook '
  cp -L /etc/letsencrypt/live/chat.example.com/fullchain.pem /opt/meridian-edge/tls/ &&
  cp -L /etc/letsencrypt/live/chat.example.com/privkey.pem   /opt/meridian-edge/tls/ &&
  cd /opt/meridian-edge && docker compose restart proxy'
```

(DNS-01 with `--manual` does **not** auto-renew — use a DNS plugin such as
`certbot-dns-cloudflare` if you want hands-off DNS renewal.)

### 4.3 Method 2 — a commercial / paid CA certificate

A standard commercial DV cert is domain-validated, not server-bound, so you can
finalize it before the server exists. Generate the key + CSR yourself (keep
`privkey.pem` — it never leaves your box):

```bash
openssl req -new -newkey rsa:2048 -nodes \
  -keyout privkey.pem -out meridianedge.csr \
  -subj "/CN=chat.example.com"
```

In the CA/reseller dashboard, submit `meridianedge.csr` and complete **Domain
Control Validation** by **DNS (TXT)** or **email** — not the HTTP-file method,
which needs a running web server you don't have yet. The CA returns your leaf
cert plus one or more intermediate certs. Assemble `fullchain.pem` with the
**leaf first, then the intermediate(s)** (order is required — root is omitted,
clients already trust it):

```bash
cat your_domain.crt intermediate.crt > fullchain.pem
mkdir -p ./tls && cp fullchain.pem privkey.pem ./tls/
```

**Renewal is manual**: commercial certs typically last ~1 year. When you
re-issue, drop the new `fullchain.pem` / `privkey.pem` into `TLS_CERT_DIR` and
`docker compose restart proxy`.

### 4.4 Method 3 — self-signed (local testing only)

For poking at the stack on `localhost`. Browsers will show a trust warning —
**never use this for real users**:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout privkey.pem -out fullchain.pem -subj "/CN=localhost"
mkdir -p ./tls && mv privkey.pem fullchain.pem ./tls/
```

### 4.5 File placement & permissions

The nginx proxy container runs as a **non-root user** and mounts `TLS_CERT_DIR`
read-only, so the two files must be **readable by that user** but the private
key must not be world-exposed on a shared host. On a single-tenant box the
common, safe-enough pattern is a locked-down parent directory with the key
readable inside it:

```bash
chmod 700 ./tls                 # only you can traverse into it
chmod 644 ./tls/fullchain.pem   # public cert
chmod 644 ./tls/privkey.pem     # readable by the container user; dir perms gate access
```

If the host is shared with other users, tighten further by `chown`-ing the key
to the proxy container's service UID and using `chmod 600`. Never commit
`./tls/` — add it to `.gitignore`.

### 4.6 Verify the certificate before you deploy

```bash
# Does privkey.pem actually match fullchain.pem's leaf? (identical output = yes)
diff <(openssl x509 -in ./tls/fullchain.pem -noout -pubkey) \
     <(openssl pkey  -in ./tls/privkey.pem  -pubout) && echo "key matches cert"

# Who/what/when
openssl x509 -in ./tls/fullchain.pem -noout -subject -issuer -dates

# Is the chain order right? The FIRST cert must be your leaf (CN=your domain),
# followed by the issuing intermediate:
openssl crl2pkcs7 -nocrl -certfile ./tls/fullchain.pem | \
  openssl pkcs7 -print_certs -noout | grep -E 'subject|issuer'
```

After deploying you can confirm the live chain end-to-end:

```bash
echo | openssl s_client -connect chat.example.com:443 -servername chat.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

---

## 5. Route A — Traditional (nginx reverse proxy)

The reference topology already in the repo: `docker-compose.yml` +
`deploy/nginx.conf` + `deploy/proxy.Dockerfile`. nginx terminates TLS, serves
the built client bundle same-origin, and reverse-proxies `/v1/*` (including the
`/v1/ws` WebSocket) to the FastAPI server. Postgres runs alongside.

```bash
# 1. Secrets + config
cp .env.example .env
# edit .env:
#   POSTGRES_PASSWORD=<long random>
#   MERIDIAN_EDGE_WS_ORIGINS=https://chat.example.com
#   TLS_CERT_DIR=./tls

# 2. Obtain fullchain.pem + privkey.pem into ./tls  (see §4 — pick a method)

# 3. Build + run
docker compose up -d --build
```

**PQ TLS caveat (route-specific):** `deploy/nginx.conf` asks for
`ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1`. nginx **won't start** if its
linked OpenSSL doesn't know that group. The `nginx:1.27-alpine` base must be
OpenSSL ≥ 3.5 (ML-KEM support). If it isn't, either use a newer base image or
edit the line to `ssl_ecdh_curve X25519:secp384r1` — you lose PQ *transport*
only (§1), nothing else.

Certificate renewal is on you (§4.2's deploy hook, or a manual re-copy +
`docker compose restart proxy`). If that sounds tedious, that's exactly what
Route B removes.

---

## 6. Route B — Caddy (automatic HTTPS)

Same containerized topology, but the edge is **Caddy** instead of nginx. Caddy
provisions and renews TLS automatically (Let's Encrypt / ZeroSSL) — **no §4 at
all** — and Caddy 2.9+ negotiates the `X25519MLKEM768` hybrid group out of the
box, no OpenSSL wrangling. For most deployments this is the easiest path.

Files: `docker-compose.caddy.yml`, `deploy/caddy.Dockerfile`, `deploy/Caddyfile`
(its header set mirrors nginx.conf exactly).

```bash
# 1. Secrets + config
cp .env.example .env
# edit .env:
#   POSTGRES_PASSWORD=<long random>
#   MERIDIAN_EDGE_WS_ORIGINS=https://chat.example.com
#   MERIDIAN_EDGE_DOMAIN=chat.example.com
#   ACME_EMAIL=you@example.com
# (TLS_CERT_DIR is unused here — Caddy manages certs itself.)

# 2. DNS points at this host and ports 80 + 443 are reachable
#    (Caddy needs 80 for the ACME challenge).

# 3. Build + run
docker compose -f docker-compose.caddy.yml up -d --build
```

Caddy stores its ACME account + issued certificates in the persistent
`caddy-data` volume — don't delete it, or you'll re-issue certs (and can hit
Let's Encrypt rate limits) on the next start.

---

## 7. Route C — Single box, no orchestration (10–20 people)

The lightest operationally sane deployment: one small VPS, no Docker, Caddy on
the host for auto-TLS (again, **no §4**), one `uvicorn` process under systemd,
one local Postgres. Because the server barely works (it's a relay), this handles
a small circle of users on the cheapest tier comfortably.

> Postgres is still required — the production boot guard rejects SQLite by
> design (§7.5 of CLAUDE.md). It just runs on the same box here.

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
# Bind to localhost only — Caddy is the only thing that should reach it (§2.2)
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

**Caddy** — reuse the repo's `deploy/Caddyfile`; it already reads
`MERIDIAN_EDGE_DOMAIN` / `ACME_EMAIL` and defaults the backend to `server:8000`,
which you override to localhost for the host setup:

```bash
sudo tee /etc/caddy/env >/dev/null <<'ENV'
MERIDIAN_EDGE_DOMAIN=chat.example.com
ACME_EMAIL=you@example.com
MERIDIAN_EDGE_BACKEND=127.0.0.1:8000
ENV
sudo cp /opt/meridian-edge/deploy/Caddyfile /etc/caddy/Caddyfile
# Make the caddy service load /etc/caddy/env:
sudo mkdir -p /etc/systemd/system/caddy.service.d
sudo tee /etc/systemd/system/caddy.service.d/override.conf >/dev/null <<'OVR'
[Service]
EnvironmentFile=/etc/caddy/env
OVR

sudo systemctl daemon-reload
sudo systemctl enable --now meridian-edge
sudo systemctl restart caddy
```

That's the whole stack: Caddy (auto-TLS, PQ TLS group) → uvicorn → Postgres, all
on one host. To update: `git pull`, rebuild the client into `/srv/www`,
`pip install -r requirements.txt`, `systemctl restart meridian-edge`.

---

## 8. After deploying — smoke checks (all routes)

```bash
# 1. Static bundle loads and carries the exact security headers
curl -sI https://chat.example.com | grep -iE 'content-security-policy|strict-transport|x-content-type|referrer-policy|cross-origin'

# 2. API is reachable and returns uniform errors (no stack traces, no /docs)
curl -s  https://chat.example.com/docs -o /dev/null -w '%{http_code}\n'   # expect 404 in production

# 3. WebSocket upgrade is proxied (a full pass needs a real browser Origin)
curl -sI -H 'Connection: Upgrade' -H 'Upgrade: websocket' https://chat.example.com/v1/ws
```

Then load the site in a browser, `/register`, note the UID, and from a second
browser `/add` + `/chat` to confirm an end-to-end message round-trips. Run a
header scan (e.g. Mozilla Observatory) — CLAUDE.md §5 targets grade **A**.

---

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| nginx container exits immediately | OpenSSL in the image doesn't know `X25519MLKEM768` | newer base image, or set `ssl_ecdh_curve X25519:secp384r1` (§5) |
| nginx: `cannot load certificate … Permission denied` | proxy's non-root user can't read `privkey.pem` | fix perms per §4.5 |
| Browser: `ERR_CERT_AUTHORITY_INVALID` | self-signed cert, or `fullchain.pem` missing the intermediate | use §4.2/§4.3; ensure leaf **then** intermediate order |
| Server won't boot, logs "refusing to boot in production mode" | a §3 env var is dev-shaped | set `MERIDIAN_EDGE_WS_ORIGINS`, use a Postgres URL, unset `MERIDIAN_EDGE_DEV` |
| WebSocket connects then drops | `Origin` mismatch or not forwarded | make `MERIDIAN_EDGE_WS_ORIGINS` exactly match the browser origin; forward the header (§2.3) |
| Caddy: repeated cert issuance / rate-limited | `caddy-data` volume deleted between restarts | keep the volume; don't prune it |

---

## 10. Operational notes

- **Schema:** first boot auto-creates tables (`Base.metadata.create_all`, the W1
  migration stand-in). There's no Alembic yet, so plan schema changes manually
  when they come.
- **Backups:** back up the Postgres data volume, but the **message queue is
  intentionally ephemeral** (delete-on-ack + 14-day TTL, §5) — do not add it to
  any archival/backup that would retain delivered ciphertext. Public-key bundles
  and account rows are the durable state worth backing up.
- **Secrets:** `.env`, `./tls/`, and TLS private keys never get committed or
  baked into images. `.env.example` documents the shape; keep the real `.env`
  and your key material out of git.
- **Rate limits** (register/login/bundle/message) and WS frame caps are enforced
  in-app and need no proxy config; the edge only adds `client_max_body_size 64k`
  as belt-and-suspenders against the 64 KiB payload cap.
