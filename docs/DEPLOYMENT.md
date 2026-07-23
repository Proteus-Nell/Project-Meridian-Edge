# Meridian Edge deployment guide

The deployment guide now lives in one place: **[DEPLOY.md](../DEPLOY.md)** at the
repo root.

It is the single source of truth for standing up an instance and covers:

- the three deployment routes (nginx, Caddy, single box) and how requests route
- prerequisites, the production env vars, and the boot-safety gate
- obtaining and renewing TLS certificates
- **[updating an existing deployment](../DEPLOY.md#9-updating-an-existing-deployment)**
  (redeploy per route, client-bundle caching, the schema-migration caveat, rollback)
- **[passing PQC/TLS screenings](../DEPLOY.md#10-passing-pqctls-screenings)**
  (verifying the `X25519MLKEM768` hybrid handshake, SSL Labs / testssl.sh /
  Observatory, and the terminating-proxy caveat)
- operations: logs, backups, scaling limits, what-is-enforced-where, troubleshooting

Local development setup is in the [README](../README.md); the security rationale
behind each hardening choice is in [CLAUDE.md](../CLAUDE.md) section 5.
