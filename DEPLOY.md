# Deploying Meridian Edge

The single operator guide for running a Meridian Edge instance: how requests
route, the three deployment routes, how to obtain TLS certificates, how to
ship a new version, and how to make the site pass PQC/TLS screenings. Security
rationale for each choice lives in [CLAUDE.md](CLAUDE.md) section 5.

> **Honest status.** The Docker / Compose / nginx / Caddy artifacts were
> authored and cross-checked by eye but **not build-tested against a live
> Docker daemon** in the session that produced them. Treat this as a reviewed
> reference: run `docker compose build` and the [smoke checks](#8-verify-after-deploying)
> before trusting it with real users.

---

## Contents

1. [What you are deploying](#1-what-you-are-deploying)
2. [How routing works](#2-how-routing-works)
3. [Prerequisites and configuration](#3-prerequisites-and-configuration)
4. [Getting your TLS certificate (Route A)](#4-getting-your-tls-certificate-route-a)
5. [Route A - nginx](#5-route-a---nginx) - [B - Caddy](#6-route-b---caddy-automatic-https) - [C - single box](#7-route-c---single-box)
6. [Verify after deploying](#8-verify-after-deploying)
7. [Updating an existing deployment](#9-updating-an-existing-deployment)
8. [Passing PQC/TLS screenings](#10-passing-pqctls-screenings)
9. [Operations, scaling, troubleshooting](#11-operations)

Pick a route:

| Route | Edge | TLS certificates | Best for |
|---|---|---|---|
| **A. Traditional** | nginx (container) | **you provide them** (certbot or a CA) | you already run nginx/certbot and want explicit control |
| **B. Caddy** | Caddy (container) | **automatic** (Let's Encrypt) | most people - the simplest hardened HTTPS deploy |
| **C. Single box** | Caddy (host) | **automatic** | 10-20 users on one small VPS, no container orchestration |

All three keep the section 5 hardening posture (non-root, read-only filesystems,
TLS 1.3, the exact CSP/HSTS header set, WS origin allowlist). **If you do not
want to think about certificates, use Route B or C** - Caddy fetches and renews
TLS for you, and negotiates the post-quantum TLS group with no OpenSSL wrangling.

---

## 1. What you are deploying

The server is a **zero-knowledge relay**. Every post-quantum operation -
ML-KEM-768 key exchange, ML-DSA-65 signatures, the message ratchet - runs in the
browser. The server only stores and forwards opaque encrypted blobs and
public-key bundles; it never sees plaintext, private keys, or symmetric keys.
The database holds users' public keys, prekey bundles, the per-recipient
ciphertext queue (delete-on-ack, 14-day TTL), session-token hashes, and
Argon2id recovery-code hashes - no plaintext, ever.

Two consequences shape deployment:

- **Load is trivial.** 10-20 users generate almost no server work; the crypto
  cost lives on the clients. A 1 vCPU / 1 GB VPS is comfortable. Do not
  over-provision.
- **PQ transport is defense-in-depth, not the security boundary.** The
  `X25519MLKEM768` hybrid group on the TLS handshake is an extra layer. The
  messenger's end-to-end guarantees (ML-KEM-768 / ML-DSA-65) live in the client
  and are **unaffected** if the edge falls back to classical TLS curves. This
  distinction matters for screenings - see [section 10](#10-passing-pqctls-screenings).

The trust model does **not** depend on the server or database being trustworthy;
end-to-end encryption and the safety-number check (section 4) are what protect
users. This guide is about running the service reliably, not about making the
server a trusted party (it is not one).

---

## 2. How routing works

Everything is served **same-origin** from one hostname - no separate API domain,
no CDN. The edge (nginx or Caddy) is the only thing exposed to the internet; it
fans requests out by URL path.

```
   Browser  --->  https://chat.example.com
                        |   TLS 1.3 (X25519MLKEM768 hybrid)
                        v
                +---------------------------+
                |   Edge  :80  :443         |   nginx (A) or Caddy (B/C)
                |   :80 -> 301 to :443 (+ ACME challenge)
                |   :443 -> TLS termination + path routing
                +---------------------------+
                        |
        +---------------+-----------------------------+
        v               v                             v
   GET /            /v1/*  (REST)                 /v1/ws  (WebSocket)
   static bundle    register / login /            live message push,
   from disk        bundles / messages            token-authenticated
   (index.html,     ----------> reverse proxy ---------->  FastAPI  :8000
    JS, CSS)                                                    |
                                                                v
                                                          Postgres  :5432
```

| Path | Goes to | Notes |
|---|---|---|
| `/` and any non-`/v1` path | static client bundle on disk | SPA fallback to `index.html`; the page-level CSP is set here |
| `/v1/*` | FastAPI `:8000` (plain reverse proxy) | register, login, key bundles, message enqueue/ack |
| `/v1/ws` | FastAPI `:8000` (HTTP Upgrade to WebSocket) | needs `Upgrade`/`Connection` headers **and** the `Origin` header forwarded |

### 2.1 DNS

Point the hostname at the machine's public IP:

```
chat.example.com.   A     203.0.113.10        # IPv4
chat.example.com.   AAAA  2001:db8::10         # IPv6 (if you have it)
```

Behind a cloud LB / NAT, forward ports 80 and 443 to the box there too. DNS must
resolve **before** you request a Let's Encrypt cert (Route A certbot, and Routes
B/C) - the ACME challenge validates the name.

### 2.2 Ports and firewall

| Port | Exposure | Purpose |
|---|---|---|
| 80/tcp | **public** | HTTP->HTTPS redirect + ACME HTTP-01 challenge |
| 443/tcp | **public** | HTTPS (and HTTP/2) |
| 443/udp | public (optional) | HTTP/3 - Caddy routes only |
| 8000/tcp | **internal only** | FastAPI server - never expose publicly |
| 5432/tcp | **internal only** | Postgres - never expose publicly |

In Docker (A/B) the server and Postgres sit on the private Compose network and
are unreachable from outside; Compose publishes only `80:8080` and `443:8443`.
On the single box (C), bind uvicorn to `127.0.0.1:8000` and Postgres to
`localhost` so only the local edge reaches them. A minimal host firewall:

```bash
sudo ufw allow 80,443/tcp
sudo ufw allow 443/udp        # only if you use Caddy/HTTP-3
sudo ufw enable
```

### 2.3 The one routing gotcha: WebSocket `Origin`

The server checks the WS upgrade's `Origin` header against
`MERIDIAN_EDGE_WS_ORIGINS` and **rejects a mismatch**. Two things must line up
exactly (scheme + host, no trailing slash):

- `MERIDIAN_EDGE_WS_ORIGINS=https://chat.example.com` (the value the browser
  actually sends), and
- the edge must **forward** the `Origin` header. nginx does this explicitly
  (`proxy_set_header Origin $http_origin`); Caddy preserves it by default.

If WebSocket connects but immediately drops, this is almost always the cause.
Messages still deliver on reconnect (the recipient drains the queue on next
connect); only the live push is affected.

---

## 3. Prerequisites and configuration

1. A domain with DNS pointing at the host (section 2.1).
2. Docker Engine + the Compose v2 plugin (routes A/B) **or** a plain Linux VPS
   (route C).
3. The production configuration below.

### 3.1 Server environment (the boot guard)

The server **refuses to boot** in production if any of these is wrong
(`_assert_production_safe`, `server/app/main.py`):

| Var | Required in prod | Purpose |
|---|---|---|
| `MERIDIAN_EDGE_ENV=production` | yes | turns on the boot guard, disables `/docs` |
| `MERIDIAN_EDGE_WS_ORIGINS` | yes | exact WS `Origin` allowlist, comma-separated (e.g. `https://chat.example.com`) - **must not be empty** |
| `MERIDIAN_EDGE_DATABASE_URL` | yes | Postgres DSN - a `sqlite://` URL is **rejected** |
| `MERIDIAN_EDGE_DEV` | must be unset / not `1` | `=1` enables `/docs`; refused alongside production |

The gate also refuses to boot if the live Argon2id parameters have drifted from
the section 0 constants (m = 64 MiB, t = 3, p = 1). If the server container exits
immediately on `up`, read `docker compose logs server` - the gate names exactly
what is wrong.

### 3.2 Compose / host `.env`

Routes A and B read these from `.env` (copy `.env.example`); Compose derives the
server vars above from them and **refuses to start** if one is missing.

| Var | Used by | Notes |
|---|---|---|
| `POSTGRES_PASSWORD` | db + server DSN | any long random secret |
| `MERIDIAN_EDGE_WS_ORIGINS` | server | your exact public origin(s) |
| `TLS_CERT_DIR` | proxy (Route A) | host dir holding `fullchain.pem` + `privkey.pem`; unused for Caddy |
| `MERIDIAN_EDGE_DOMAIN`, `ACME_EMAIL` | Caddy (Route B) | public hostname + ACME contact |

Never commit `.env`, `./tls/`, or any private key - all are git-ignored.

### 3.3 Container port map (routes A/B)

| Host | Container | Service |
|---|---|---|
| 80 | 8080 | proxy (301 to https) |
| 443 | 8443 | proxy (TLS, client + `/v1`) |
| - | 8000 | server (internal only) |
| - | 5432 | db (internal only) |

The proxy listens on non-privileged 8080/8443 so it can run as a non-root user
with no added capabilities; Compose maps the host's 80/443 onto them.

---

## 4. Getting your TLS certificate (Route A)

> **Skip this section for Route B or C** - Caddy obtains and renews the
> certificate automatically. This is only for **Route A (nginx)**, which mounts
> two files you provide.

### 4.1 The two files

| File | Contents | Secrecy |
|---|---|---|
| `privkey.pem` | your certificate's **private key** | **secret** - never commit, `chmod 600` |
| `fullchain.pem` | your **leaf certificate followed by the intermediate CA cert(s)** | public |

`deploy/nginx.conf` references exactly `/etc/nginx/tls/fullchain.pem` and
`/etc/nginx/tls/privkey.pem`, and `docker-compose.yml` mounts your
`TLS_CERT_DIR` there read-only. You must end up with those two filenames in that
directory. Pick one method:

### 4.2 Method 1 - Let's Encrypt via certbot (recommended)

Free, trusted by all browsers, 90-day certs with automated renewal.

**HTTP-01 (standalone)** - simplest when port 80 is free. Stop anything on port
80 first (the edge container, if running):

```bash
sudo certbot certonly --standalone -d chat.example.com
```

Certbot writes symlinks into `/etc/letsencrypt/live/<domain>/`; copy with `-L`
to dereference into your mount directory:

```bash
mkdir -p ./tls
sudo cp -L /etc/letsencrypt/live/chat.example.com/fullchain.pem ./tls/
sudo cp -L /etc/letsencrypt/live/chat.example.com/privkey.pem   ./tls/
```

**DNS-01** - cleanest for containers / wildcards (no port-80 juggling):

```bash
sudo certbot certonly --manual --preferred-challenges dns -d chat.example.com
#   add the printed value as  _acme-challenge.chat.example.com  TXT  "<value>"
#   wait for propagation, press Enter, then copy the two files as above.
```

**Auto-renewal.** certbot installs a systemd timer that renews within 30 days of
expiry. Make renewal re-copy the files and reload the edge with a deploy hook:

```bash
sudo certbot renew --deploy-hook '
  cp -L /etc/letsencrypt/live/chat.example.com/fullchain.pem /opt/meridian-edge/tls/ &&
  cp -L /etc/letsencrypt/live/chat.example.com/privkey.pem   /opt/meridian-edge/tls/ &&
  cd /opt/meridian-edge && docker compose restart proxy'
```

(`--manual` DNS-01 does not auto-renew; use a DNS plugin like
`certbot-dns-cloudflare` for hands-off renewal.)

### 4.3 Method 2 - a commercial / paid CA certificate

Generate the key + CSR yourself (keep `privkey.pem` local):

```bash
openssl req -new -newkey rsa:2048 -nodes \
  -keyout privkey.pem -out meridianedge.csr -subj "/CN=chat.example.com"
```

Submit the CSR, complete **Domain Control Validation by DNS (TXT) or email**
(not the HTTP-file method - you have no running web server yet), then assemble
`fullchain.pem` **leaf first, then intermediate(s)** (root omitted):

```bash
cat your_domain.crt intermediate.crt > fullchain.pem
mkdir -p ./tls && cp fullchain.pem privkey.pem ./tls/
```

Renewal is manual (commercial certs last ~1 year): drop the new files into
`TLS_CERT_DIR` and `docker compose restart proxy`.

### 4.4 Method 3 - self-signed (local testing only)

Browsers show a trust warning - **never for real users**:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout privkey.pem -out fullchain.pem -subj "/CN=localhost"
mkdir -p ./tls && mv privkey.pem fullchain.pem ./tls/
```

### 4.5 Permissions and verification

The nginx container runs non-root and mounts `TLS_CERT_DIR` read-only. On a
single-tenant box, gate access with a locked-down parent directory:

```bash
chmod 700 ./tls                 # only you can traverse in
chmod 644 ./tls/fullchain.pem   # public cert
chmod 644 ./tls/privkey.pem     # readable by the container user; dir perms gate access
```

On a shared host, `chown` the key to the proxy's service UID and `chmod 600`.
Then verify before deploying:

```bash
# privkey matches the cert's leaf? (identical output = yes)
diff <(openssl x509 -in ./tls/fullchain.pem -noout -pubkey) \
     <(openssl pkey  -in ./tls/privkey.pem  -pubout) && echo "key matches cert"

# who / what / when
openssl x509 -in ./tls/fullchain.pem -noout -subject -issuer -dates

# chain order: FIRST cert must be your leaf, then the issuing intermediate
openssl crl2pkcs7 -nocrl -certfile ./tls/fullchain.pem \
  | openssl pkcs7 -print_certs -noout | grep -E 'subject|issuer'
```

---

## 5. Route A - nginx

Reference topology: `docker-compose.yml` + `deploy/nginx.conf` +
`deploy/proxy.Dockerfile`. nginx terminates TLS, serves the built client bundle
same-origin, and reverse-proxies `/v1/*` (including `/v1/ws`) to FastAPI.
Postgres runs alongside.

```bash
# 1. Secrets + config
cp .env.example .env
#    POSTGRES_PASSWORD=<long random>
#    MERIDIAN_EDGE_WS_ORIGINS=https://chat.example.com
#    TLS_CERT_DIR=./tls

# 2. Obtain fullchain.pem + privkey.pem into ./tls  (section 4)

# 3. Build + run
docker compose up -d --build
```

`server` waits for `db` to pass its health check. nginx requests
`ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1` and **will not start** if its
linked OpenSSL does not know the hybrid group (needs OpenSSL >= 3.5) - see
[section 10.4](#104-if-the-edge-cannot-negotiate-the-group). Certificate renewal
is on you (section 4.2's deploy hook); if that is tedious, Route B removes it.

---

## 6. Route B - Caddy (automatic HTTPS)

Same containerized topology, edge is **Caddy** instead of nginx. Caddy
provisions and renews TLS automatically (Let's Encrypt / ZeroSSL) and Caddy 2.9+
negotiates `X25519MLKEM768` out of the box - no section 4, no OpenSSL wrangling.
Files: `docker-compose.caddy.yml`, `deploy/caddy.Dockerfile`, `deploy/Caddyfile`
(its header set mirrors nginx.conf exactly).

```bash
# 1. Secrets + config
cp .env.example .env
#    POSTGRES_PASSWORD=<long random>
#    MERIDIAN_EDGE_WS_ORIGINS=https://chat.example.com
#    MERIDIAN_EDGE_DOMAIN=chat.example.com
#    ACME_EMAIL=you@example.com     (TLS_CERT_DIR is unused here)

# 2. DNS points at this host; ports 80 + 443 reachable (80 for the ACME challenge)

# 3. Build + run
docker compose -f docker-compose.caddy.yml up -d --build
```

Caddy stores its ACME account + certs in the persistent `caddy-data` volume - do
not delete it, or you re-issue certs (and can hit Let's Encrypt rate limits) on
the next start.

---

## 7. Route C - single box

The lightest sane deployment: one small VPS, no Docker, Caddy on the host for
auto-TLS, one `uvicorn` under systemd, one local Postgres.

> Postgres is still required - the boot guard rejects SQLite by design
> (section 7.5). It just runs on the same box here.

```bash
# 0. Base packages (Debian/Ubuntu)
sudo apt update && sudo apt install -y python3.12 python3.12-venv postgresql caddy git

# 1. Postgres: db + user
sudo -u postgres psql <<'SQL'
CREATE USER meridian_edge WITH PASSWORD 'CHANGE_ME_LONG_RANDOM';
CREATE DATABASE meridian_edge OWNER meridian_edge;
SQL

# 2. App + Python deps
sudo git clone <your-repo-url> /opt/meridian-edge
cd /opt/meridian-edge/server
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt   # psycopg[binary] is pinned; Postgres works as-is

# 3. Build the client bundle and hand it to Caddy
cd /opt/meridian-edge/client && npm ci && npm run build
sudo mkdir -p /srv/www && sudo cp -r dist/* /srv/www/
```

**systemd unit** - `/etc/systemd/system/meridian-edge.service`:

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
# Bind to localhost only - Caddy is the only thing that should reach it (section 2.2)
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

**Caddy** - reuse `deploy/Caddyfile`; override the backend to localhost:

```bash
sudo tee /etc/caddy/env >/dev/null <<'ENV'
MERIDIAN_EDGE_DOMAIN=chat.example.com
ACME_EMAIL=you@example.com
MERIDIAN_EDGE_BACKEND=127.0.0.1:8000
ENV
sudo cp /opt/meridian-edge/deploy/Caddyfile /etc/caddy/Caddyfile
sudo mkdir -p /etc/systemd/system/caddy.service.d
sudo tee /etc/systemd/system/caddy.service.d/override.conf >/dev/null <<'OVR'
[Service]
EnvironmentFile=/etc/caddy/env
OVR
sudo systemctl daemon-reload
sudo systemctl enable --now meridian-edge
sudo systemctl restart caddy
```

That is the whole stack: Caddy (auto-TLS, PQ group) -> uvicorn -> Postgres, one
host. Updating it is covered in [section 9](#9-updating-an-existing-deployment).

---

## 8. Verify after deploying

```bash
# 1. All services up (routes A/B)
docker compose ps

# 2. The API answers uniformly through the edge over TLS
curl -sS https://chat.example.com/v1/keys/status \
  -H 'Authorization: Bearer not-a-real-token' -i | head -n1
#   -> HTTP/2 401     (a 401, not 502/connection error, means browser->edge->server->db is healthy)

# 3. The static bundle carries the exact security headers
curl -sI https://chat.example.com | grep -iE 'content-security-policy|strict-transport|x-content-type|referrer-policy|cross-origin'

# 4. /docs is off in production
curl -s https://chat.example.com/docs -o /dev/null -w '%{http_code}\n'   # expect 404

# 5. http redirects to https
curl -sI http://chat.example.com/ | grep -i location
```

Then load the site, `/register`, note the UID, and from a second browser `/add`
+ `/chat` to confirm an end-to-end message round-trips. Finish with the
[PQC/TLS screenings](#10-passing-pqctls-screenings) below.

---

## 9. Updating an existing deployment

The server is **stateless** - all durable state is in Postgres (server side) and
each browser's encrypted IndexedDB (client side). Recreating the server or edge
container loses nothing but in-flight WebSocket connections, which clients
re-establish automatically. So a routine update is safe and quick.

### 9.1 Routes A / B (Docker)

```bash
cd /opt/meridian-edge
git pull
docker compose up -d --build            # Route B: docker compose -f docker-compose.caddy.yml up -d --build
```

`up -d --build` rebuilds the images and **recreates only the services whose
image or config changed**. The client bundle is rebuilt inside the proxy image,
so a new front-end ships with the proxy. Expect a brief blip while the proxy and
server restart; Postgres is untouched unless its image changed.

To rebuild just one service (e.g. after a server-only change):

```bash
docker compose up -d --build server
```

### 9.2 Route C (host)

```bash
cd /opt/meridian-edge && git pull
cd server && .venv/bin/pip install -r requirements.txt      # if deps changed
cd ../client && npm ci && npm run build && sudo cp -r dist/* /srv/www/
sudo systemctl restart meridian-edge
```

Caddy keeps serving `/srv/www` throughout; only the API blips on the uvicorn
restart. Session tokens are in-memory with a 15-minute idle expiry, so a restart
just forces clients to reconnect (and re-`/login` if their token had lapsed) -
no data loss, since each client keeps its own encrypted store.

### 9.3 Client caching - why users get the new build

Vite content-hashes the JS/CSS filenames (e.g. `index-CTYmNQn3.js`), so a new
build produces new URLs that bypass any stale cache; `index.html` is served
uncached and points at the new hashed assets. A normal page load picks up the
new front-end. There is **no server-push auto-update** in the MVP (section 7.8) -
a user with the app already open keeps the old bundle until they reload.

### 9.4 Database schema changes - read before a schema-changing release

The server uses SQLAlchemy `create_all()` as a migration stand-in: it **creates
missing tables but never alters existing ones**. Additive releases (a brand-new
table) migrate cleanly on restart. A release that **changes or drops a column**
will **not** be applied to an existing Postgres database automatically, and the
app may then error against the old shape. Before shipping such a change to a live
database:

1. Introduce a real migration tool (Alembic) and run its migration during the
   deploy, **or**
2. For a small instance you can afford to reset, back up, apply the change
   manually with `psql`, then restart.

Nothing in the current schema forces this yet; it is the one update that needs a
human in the loop when it eventually lands.

### 9.5 Rollback

Images are built from the checked-out tree, so rolling back is a git operation:

```bash
git checkout <previous-tag-or-sha>
docker compose up -d --build        # or the Route C rebuild steps
```

This is safe as long as the schema is unchanged between the two versions (see
9.4). Tag releases so `<previous-tag>` is easy to name; optionally keep the prior
built images (`docker image tag`) for an instant rollback without a rebuild.

### 9.6 Config or certificate changes on update

- **Env changes** (new `MERIDIAN_EDGE_WS_ORIGINS`, a domain move): edit `.env`
  (or the systemd unit) and recreate. The boot guard (section 3.1) catches a bad
  production config on restart rather than serving a broken one.
- **Certificate renewal** (Route A): renew into `TLS_CERT_DIR`, then
  `docker compose restart proxy`. certbot's deploy hook in section 4.2 automates
  this. Caddy (B/C) renews with no action.

### 9.7 Routine update checklist

- [ ] `git pull` on the deploy host
- [ ] review the changelog for a schema change (section 9.4) or new required env var
- [ ] `docker compose up -d --build` (A/B) or the section 9.2 steps (C)
- [ ] re-run the [smoke checks](#8-verify-after-deploying)
- [ ] spot-check the [PQC/TLS screening](#10-passing-pqctls-screenings) if the edge/image changed

---

## 10. Passing PQC/TLS screenings

Screeners (SSL Labs, testssl.sh, internet.nl, corporate scanners) grade the
**transport**. Keep the two PQC layers distinct so you know what a green result
does and does not prove:

| Layer | What it is | What proves it |
|---|---|---|
| **Application (the boundary)** | ML-KEM-768 + ML-DSA-65 + the ratchet, end-to-end in the browser | source / the `/bench` suite; **not** visible to a TLS scanner |
| **Transport (what scanners grade)** | `X25519MLKEM768` hybrid key exchange on TLS 1.3 | the checks below |

A transport screening that shows only classical curves does **not** weaken the
messenger - but it is the thing most PQC/TLS screenings actually measure, so
here is how to make it pass and prove it.

### 10.1 What the config already gives you

- **TLS 1.3 only** (`ssl_protocols TLSv1.3;` / Caddy default). No TLS 1.2 or
  lower is offered.
- **Hybrid PQ key exchange first**:
  `ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;` (nginx), native in Caddy 2.9+.
- **HSTS** `max-age=63072000; includeSubDomains; preload` on every response.
- **Full security-header set** (CSP, `nosniff`, `Referrer-Policy`, COOP, CORP,
  `Permissions-Policy`) - target Mozilla Observatory grade A (section 5).
- **Same-origin, zero CDN** - nothing downstream can strip or weaken the headers.

### 10.2 Verify the PQ handshake from the command line

Use an **OpenSSL 3.5+** client (older clients do not know the group and will
mislead you):

```bash
# Force the hybrid group; a completed 1.3 handshake reporting it = PQ transport on
openssl s_client -connect chat.example.com:443 -servername chat.example.com \
  -groups X25519MLKEM768 -tls1_3 </dev/null 2>/dev/null \
  | grep -Ei 'Negotiated TLS1.3 group|Server Temp Key|Protocol'
#   expect: Negotiated TLS1.3 group: X25519MLKEM768

# TLS 1.2 must be refused
openssl s_client -connect chat.example.com:443 -tls1_2 </dev/null 2>&1 | grep -i 'alert\|no protocols'
```

`testssl.sh` gives a fuller report and labels the group by name (3.2+):

```bash
testssl.sh --protocols --fs --headers chat.example.com
#   Protocols: TLS 1.3 offered (OK), TLS 1.2 and below not offered
#   Forward secrecy / key-share groups list: X25519MLKEM768 present
#   HSTS present with a long max-age
```

### 10.3 Online screeners and what "pass" looks like

- **Qualys SSL Labs** (`ssllabs.com/ssltest`) - target **A / A+**. A+ needs HSTS
  with a long `max-age` (we set 63072000 + `preload`) and a complete chain.
  SSL Labs may not yet name the group "post-quantum", but it must show TLS 1.3
  and strong key exchange.
- **internet.nl** (Modern TLS test) - passes on TLS 1.3 + HSTS + secure
  ciphers, and increasingly reports PQ key exchange. Good holistic check.
- **Mozilla Observatory** (`observatory.mozilla.org`) - grades the HTTP security
  headers; our set is built for grade **A/A+**. A ding here almost always means
  something downstream stripped a header (see 10.5).
- **Hardenize** - one-page TLS + DNS + headers overview; useful before go-live.
- **Browser devtools** - Chrome padlock -> Connection, or `chrome://net-internals`,
  shows the negotiated **Key Exchange**; recent Chrome/Firefox print
  `X25519MLKEM768` when it is used. This is the quickest human confirmation.

### 10.4 If the edge cannot negotiate the group

Almost always the nginx image's OpenSSL predates 3.5 (the standardized
`X25519MLKEM768` codepoint landed in **OpenSSL 3.5**, April 2025). Check inside
the image:

```bash
docker compose run --rm --entrypoint sh proxy -c \
  'openssl version && openssl list -kem-algorithms 2>/dev/null | grep -i mlkem'
```

- Lists an ML-KEM algorithm -> you are set.
- Does not -> either rebuild `deploy/proxy.Dockerfile` on an nginx image built
  against OpenSSL >= 3.5, **or** switch to **Route B/C (Caddy)**, which ships the
  group in its own Go TLS stack. As a last resort, drop the hybrid group from
  `ssl_ecdh_curve` (leaving `X25519:secp384r1`) so nginx starts at all - a
  documented downgrade of the **transport** layer only; the end-to-end
  ML-KEM/ML-DSA guarantees are untouched. Restore it once the image supports it.

> nginx **refuses to start** when the first named group is unknown, so a running
> nginx that lacks PQ means someone already dropped the group - re-add it after
> upgrading the image.

### 10.5 The terminating-proxy caveat (most common false failure)

If you put Meridian behind a TLS-terminating layer (Cloudflare's orange-cloud
proxy, an AWS/GCP L7 load balancer, a corporate reverse proxy), **that layer's**
handshake is what a scanner sees - not your nginx/Caddy. Your PQ group and header
set stop mattering at that boundary. To keep the screening (and the PQ transport)
end-to-edge, either:

- terminate TLS at the Meridian edge and use a **TCP / SNI-passthrough**
  load balancer in front, or
- enable the equivalent PQ key exchange and the full header set **at that
  terminating layer** (e.g. Cloudflare negotiates `X25519MLKEM768` to modern
  clients, but you must still reproduce the CSP/HSTS/Permissions-Policy set
  there, since it now originates your responses).

A scanner reporting classical-only TLS on a domain you configured for PQ is
almost always a terminating proxy in the path.

### 10.6 HSTS preload

Once HTTPS is stable and you are committed to it (the directive is hard to undo
quickly), submit the domain at `hstspreload.org`. It requires a base-domain
redirect to HTTPS, `includeSubDomains`, and `preload` - all of which the edge
already emits.

---

## 11. Operations

### 11.1 Logs

```bash
docker compose logs -f server     # auth failures, rate-limit trips, errors only
docker compose logs -f proxy      # access + TLS errors
docker compose logs -f db
```

Server logs are privacy-minimal by design (section 5): auth-failure counts,
rate-limit trips, and errors - no message metadata, no UIDs where avoidable.
Retain ~30 days per policy.

### 11.2 Backups

The only durable state is the Postgres volume:

```bash
docker compose exec db pg_dump -U meridian_edge meridian_edge > backup-$(date +%F).sql
```

It contains public keys, prekey bundles, session hashes, recovery-code hashes,
and the transient ciphertext queue - **no plaintext, no private keys**, so a
leaked backup does not expose message content. The **message queue is
intentionally ephemeral** (delete-on-ack + 14-day TTL, section 5) - never add it
to any archival tooling that would retain delivered ciphertext.

### 11.3 Scaling and its limits

This topology targets a **single server instance**. Two pieces of state are
in-process per server container, so naively running replicas breaks them:

- **Rate limiters** (`rate_limit.py`) are in-memory token buckets - N replicas
  behind a load balancer each enforce the limit independently (effective limit
  ~N x).
- **The WebSocket hub** (`WsHub` in `ws.py`) tracks live connections in memory -
  a message for a user connected to a different replica is not live-pushed from
  this one (it still delivers on the recipient's next connect).

To scale horizontally you would need a shared rate-limit store (Redis) and shared
pub/sub or sticky sessions for WS fan-out. Until then, scale **up** (a bigger
single container), not **out**. Postgres and the proxy scale independently in the
usual ways. Because the server is a relay, one small instance serves a small
circle comfortably.

### 11.4 What is enforced where

| Control (CLAUDE.md section 5) | Enforced by |
|---|---|
| TLS 1.3 only, `X25519MLKEM768` hybrid group | `deploy/nginx.conf` / Caddy |
| HSTS `max-age=63072000; includeSubDomains; preload` | edge headers |
| Page CSP (`default-src 'none'` -> `'self'` script/style, `wss:` connect) | `deploy/nginx.conf` / `deploy/Caddyfile` |
| API deny-all CSP + `nosniff` / `Referrer-Policy` / COOP / CORP / Permissions-Policy | `server/app/headers.py` |
| Same-origin bundle, zero CDN assets | edge serves `dist/` |
| No CORS (no wildcard, no credentials) | server installs no CORS middleware |
| WS origin allowlist, auth-before-subscribe, frame cap, idle-kill, rate cap | `server/app/ws.py` + `MERIDIAN_EDGE_WS_ORIGINS` |
| Rate limits (register / login / bundle / message / recover) | `server/app/rate_limit.py` |
| Non-root, read-only fs, no shell, secrets via env | Dockerfiles + compose `read_only` / `tmpfs` |
| Dev config refused at boot | `_assert_production_safe` |
| Docs / openapi disabled in prod | `MERIDIAN_EDGE_DEV` unset -> `docs_url=None` |
| No outbound requests (SSRF) | no HTTP client dependency (asserted by test) |

### 11.5 Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `server` exits immediately on `up` | boot-safety gate rejected a dev-shaped config | `docker compose logs server` names it: set `MERIDIAN_EDGE_WS_ORIGINS`, use a Postgres URL, unset `MERIDIAN_EDGE_DEV` |
| `proxy` (nginx) exits immediately | OpenSSL in the image does not know `X25519MLKEM768` | section 10.4: newer image, Caddy, or drop the group |
| nginx: `cannot load certificate ... Permission denied` | proxy's non-root user cannot read `privkey.pem` | fix perms per section 4.5 |
| `proxy` cannot write pid / cache under read-only fs | `/var/cache/nginx`, `/var/run`, `/tmp` not tmpfs | keep those three as writable tmpfs in compose (verify on first build) |
| Browser `ERR_CERT_AUTHORITY_INVALID` | self-signed, or `fullchain.pem` missing the intermediate | use 4.2/4.3; leaf **then** intermediate order |
| `curl .../v1/...` returns `502` | proxy cannot reach the server | `docker compose ps` (is `server` up?) + `docker compose logs server` |
| WebSocket connects then drops | `Origin` mismatch or not forwarded | make `MERIDIAN_EDGE_WS_ORIGINS` exactly match the browser origin (section 2.3) |
| Screener shows classical-only TLS | edge OpenSSL < 3.5, or a terminating proxy in front | section 10.4 / 10.5 |
| Caddy: repeated cert issuance / rate-limited | `caddy-data` volume deleted between restarts | keep the volume; do not prune it |
| `docker compose up` errors on an unset variable | a required `.env` value is missing | the message names it (`POSTGRES_PASSWORD`, `MERIDIAN_EDGE_WS_ORIGINS`, `TLS_CERT_DIR`) |

### 11.6 Known limitations

- The Docker / Compose / nginx / Caddy config is a reviewed reference,
  **not build-tested** end-to-end - `docker compose build` + section 8 first.
- No automated DB migrations (`create_all` only) - see section 9.4.
- Single-server design - see section 11.3.
- Certificate issuance/renewal is out of scope for the compose file (section 4).
- Rate limiting is the only DoS defense, by design and best-effort (section
  7.14) - not resilience against a resourced attacker.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability and for the
documented browser-platform limitations.
