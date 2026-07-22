# Caddy edge + static client bundle (alternative to deploy/proxy.Dockerfile).
# Same idea as the nginx edge: build the client here and serve it same-origin,
# zero CDN assets, no separate Node process in production. TLS is provisioned
# automatically by Caddy at runtime (needs a persistent /data volume for the
# ACME account + certs - see docker-compose.caddy.yml).
#
# No OpenSSL note needed here (unlike proxy.Dockerfile): Caddy 2.9+ ships the
# X25519MLKEM768 hybrid group in its own Go TLS stack.

FROM node:22-slim AS client-build
WORKDIR /build
COPY client/package.json client/package-lock.json ./
RUN npm ci
COPY client ./
RUN npm run build

FROM caddy:2.9-alpine
COPY --from=client-build /build/dist /srv/www
COPY deploy/Caddyfile /etc/caddy/Caddyfile

EXPOSE 80 443
