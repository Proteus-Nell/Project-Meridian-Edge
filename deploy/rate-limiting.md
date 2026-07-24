# Rate limiting at the proxy

The application has its own per-endpoint rate limits (`server/app/rate_limit.py`),
and they are the first line of defence. They are **not sufficient on their own**
for a public deployment, for two concrete reasons. This document explains why,
and gives edge configuration to put a durable limiter in front.

## Why the app limits need a partner at the edge

**1. They are in-memory and per-process.** `TokenBucketLimiter` keeps its buckets
in a plain dictionary inside one process (it says so in its own docstring). Two
consequences:

- Run the API under more than one worker (e.g. `uvicorn --workers 4` or several
  containers) and each worker has its own buckets, so the effective limit is
  multiplied by the worker count.
- Every restart resets the buckets to full, so an attacker gets a fresh budget
  each time the process bounces.

**2. Behind the proxy, the app does not see the real client IP.** The per-IP
limiters (register, login-challenge, recover) and the security log key on
`request.client.host`, which is the **socket peer**. With nginx or Caddy in
front, that peer is the proxy, not the browser - so unless the app is explicitly
told to trust forwarded headers (see the last section), every request appears to
come from one address and the per-IP limits collapse into a single shared bucket.

The edge is the right place to fix both: it is one durable component that sees
the genuine client address before the request is multiplexed to any worker.

Keep the app limits **as well** - they are defence in depth (they still bound a
single authenticated UID's message/bundle rate, which the edge cannot see inside
the encrypted session), and they are the only limiter in local development where
there is no proxy.

## What the app already limits (for reference)

| Endpoint | Keyed on | Budget |
|---|---|---|
| `POST /v1/register` | client IP | 3 / hour |
| `POST /v1/login/challenge` | client IP | 10 / min |
| `POST /v1/recover` | client IP | 5 / hour |
| `GET /v1/bundles/{uid}` | UID | 30 / min |
| `POST /v1/messages` | UID | 60 / min |

`login/verify`, `logout`, `logout/all`, `sessions`, `keys/*`, and `messages/ack`
have no dedicated app limiter - they either require a valid single-use nonce or an
authenticated session first. A blanket edge limit on `/v1/` covers them.

## nginx (Route A)

nginx has `limit_req` built in. Add two zones in the `http { }` block - a general
one for all of `/v1/`, and a stricter one for the unauthenticated auth endpoints
that are the brute-force surface:

```nginx
http {
    # ~160k addresses per 10m of shared memory. rate is the steady-state cap;
    # burst absorbs short spikes. 429 matches the app's own rate-limit status.
    limit_req_zone  $binary_remote_addr  zone=meridian_api:10m   rate=30r/s;
    limit_req_zone  $binary_remote_addr  zone=meridian_auth:10m  rate=10r/m;
    limit_req_status 429;

    # Optional: cap concurrent connections per client too.
    limit_conn_zone $binary_remote_addr  zone=meridian_conn:10m;
```

Then, inside the `server { }` block, apply the general zone to the API and the
strict zone to the auth paths. The strict `location`s need their own `proxy_pass`
because a more specific prefix wins outright:

```nginx
        # Strict limit on the unauthenticated brute-force surface.
        location /v1/login/  { limit_req zone=meridian_auth burst=5 nodelay; proxy_pass http://server:8000; }
        location /v1/register { limit_req zone=meridian_auth burst=3 nodelay; proxy_pass http://server:8000; }
        location /v1/recover  { limit_req zone=meridian_auth burst=3 nodelay; proxy_pass http://server:8000; }

        # General limit on everything else under /v1/ (this is the existing
        # block from nginx.conf, with two lines added).
        location /v1/ {
            limit_req  zone=meridian_api burst=60 nodelay;
            limit_conn meridian_conn 20;
            proxy_pass http://server:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_hide_header Strict-Transport-Security;
        }
```

Two cautions:

- **Do not put `limit_req` on `location /v1/ws`.** It is a single long-lived
  upgrade, not a stream of requests; a per-request limiter would throttle or drop
  the socket. Use `limit_conn` there if you want to cap sockets per client.
- **A CDN or load balancer in front of nginx** makes `$binary_remote_addr` that
  intermediary, not the client - the same problem described above, one hop out.
  Restore the real address with the realip module, trusting only your own edge:

  ```nginx
  # in http { }
  set_real_ip_from 10.0.0.0/8;   # your LB / CDN egress range only
  real_ip_header   X-Forwarded-For;
  real_ip_recursive on;
  ```

## Caddy (Routes B and C)

**Stock Caddy has no built-in rate limiting.** Do not assume a `rate_limit`
directive exists on a default binary - it does not. You have three honest
options:

1. **Build Caddy with the community rate-limit module.** `caddy-ratelimit`
   (`github.com/mholt/caddy-ratelimit`) adds a `rate_limit` handler. Build a
   custom binary with xcaddy:

   ```
   xcaddy build --with github.com/mholt/caddy-ratelimit
   ```

   then, in the Caddyfile, inside the site block (the handler is not part of the
   standard distribution, so this only works with the custom build):

   ```caddyfile
   rate_limit {
       zone meridian_auth {
           match { path /v1/login/* /v1/register /v1/recover }
           key    {remote_host}
           events 10
           window 1m
       }
       zone meridian_api {
           match { path /v1/* }
           key    {remote_host}
           events 30
           window 1s
       }
   }
   ```

   The module is third-party and pre-1.0; pin the version you build and re-test
   on upgrades.

2. **Put nginx in front for the edge limit** and let Caddy handle only TLS, or
3. **Accept the app-level limits alone** for a small trusted deployment, and lean
   on the boot-time hardening plus monitoring of the security log for auth-failure
   and rate-limit-trip spikes.

For the single-box Route C, option 1 (a custom Caddy build) is the most
self-contained.

## Optional: let the app's own limits see the real client IP

If you want the in-app per-IP limits and the security log to reflect the genuine
client rather than the proxy - useful even with an edge limiter, for attribution
in `meridian_edge.security` log lines - run uvicorn so it trusts the proxy's
`X-Forwarded-For` (nginx already sets it; Caddy sets it by default):

```
uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 \
        --proxy-headers --forwarded-allow-ips="<proxy container IP/CIDR>"
```

Set `--forwarded-allow-ips` to the **proxy's** address only - never `*`, which
would let any client spoof its IP by sending the header directly. This is a
deploy-time change to the run command, not a code change, and it is optional: the
edge limiter above does not depend on it.

## Verifying

With the stack up, hammer an auth endpoint and confirm 429s appear once the burst
is spent:

```
for i in $(seq 1 40); do \
  curl -s -o /dev/null -w "%{http_code}\n" https://your.host/v1/login/challenge \
       -H 'content-type: application/json' -H 'origin: https://your.host' \
       --data '{"uid":"AAAAAAAAAAAAAAAAAAAAAAAAAA"}'; \
done | sort | uniq -c
```

You should see a mix of 200/400 (within budget) turning into 429 (throttled).
The exact split depends on the zone rate and burst you set.
