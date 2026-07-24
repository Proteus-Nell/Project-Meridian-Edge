# Security Policy

Meridian Edge is a post-quantum end-to-end-encrypted messenger. We take reports
of security issues seriously and ask that you report them privately rather than
through a public GitHub issue.

## Reporting a vulnerability

Email **security@meridian-edge.example** with:

- A description of the issue and its potential impact.
- Steps to reproduce (a minimal repro is very helpful).
- The commit hash or version you tested against.

We aim to acknowledge reports within 3 business days. Please give us a
reasonable window to investigate and ship a fix before any public disclosure.

## Scope

In scope: the client (`client/`), the server (`server/`), the handshake and
ratchet protocol design, and the deployment reference config (`deploy/`,
`docker-compose.yml`).

Out of scope: third-party dependencies themselves (report those upstream -
`@noble/post-quantum`, `@noble/ciphers`, `@noble/hashes`, FastAPI,
`cryptography`, `argon2-cffi`); denial-of-service via raw traffic volume
(rate limiting is a documented non-goal beyond the existing per-endpoint
limits - this is not resilience against a resourced attacker).

## Known limitations (documented, not bugs)

These are inherent to the browser platform, not oversights:

- XSS would still mean key theft despite the CSP - WebCrypto has no
  ML-KEM/ML-DSA, so key material must live in JS memory. CSP is a
  mitigation, not a cure.
- JS timing side channels are plausible on any web platform.
- IndexedDB deletion (`/wipe`, `/purge now`) is best-effort, not forensic
  erasure.
