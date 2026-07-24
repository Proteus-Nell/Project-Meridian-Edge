# Reverse proxy + static client bundle: the client is built here and served
# same-origin - zero CDN assets, no separate Node process in production. TLS
# termination, the page-level CSP, and HSTS live in nginx.conf.
#
# IMPORTANT: the base nginx image must be built against OpenSSL >= 3.5, where the
# standardized X25519MLKEM768 hybrid-group codepoint landed, for the group named
# in nginx.conf to be recognized. Verify with the image's `openssl version` and
# `openssl list -kem-algorithms` before relying on it in production - nginx
# refuses to start if the named group is unknown to its linked OpenSSL. If the
# pinned nginx:1.27-alpine ships an older OpenSSL, use Caddy (deploy/Caddyfile),
# which negotiates the group natively - see DEPLOY.md section 10.4.

FROM node:22-slim AS client-build
WORKDIR /build
COPY client/package.json client/package-lock.json ./
RUN npm ci
COPY client ./
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=client-build /build/dist /usr/share/nginx/html
COPY deploy/nginx.conf /etc/nginx/nginx.conf

RUN addgroup -S meridian_edge && adduser -S meridian_edge -G meridian_edge \
    && chown -R meridian_edge:meridian_edge /var/cache/nginx /var/run \
    && touch /var/run/nginx.pid && chown meridian_edge:meridian_edge /var/run/nginx.pid
USER meridian_edge

EXPOSE 443
CMD ["nginx", "-g", "daemon off;"]
