# Project-Meridian-Edge

Project Meridian Edge is a passion project of mine that stemmed from a coursework assignment during my first year studying Computer Science.

The project builds **PQTerm** — a pure post-quantum end-to-end-encrypted 1:1
terminal messenger. Every asymmetric operation uses NIST-standardized PQC:
ML-KEM-768 (FIPS 203) for key establishment and ML-DSA-65 (FIPS 204) for
identity and authentication. No classical public-key crypto exists in the
application layer, and CI enforces that.

- [MVP_DOC.md](MVP_DOC.md) — the specification (what and why)
- [CLAUDE.md](CLAUDE.md) — the build guide (how), with the security invariants

## Layout

```
client/          TypeScript + Vite + xterm.js frontend
  src/terminal/  UI, command parser, renderer
  src/crypto/    constants, (later: kx, ratchet, store)
  src/net/       REST + WS clients
server/
  app/           FastAPI: routes, models, rate limiting
  tests/
shared/vectors/  JSON test vectors (liboqs → TS tests)
bench/           benchmark harness (B1–B5)
docs/adr/        architecture decision records
scripts/         CI audit gates
```

## Development

**Server** (Python ≥ 3.12):

```
cd server
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --reload          # dev server on :8000
mypy --strict app && pytest            # checks
```

**Client** (Node ≥ 22):

```
cd client
npm ci
npm run dev                            # Vite dev server, proxies /v1 → :8000
npm run typecheck && npm test          # checks
```

**Audit gates** (also run in CI, all blocking):

```
python scripts/audit.py                # classical-crypto / injection greps
```

## Status

W1 foundations: terminal shell + allowlist command parser, FastAPI skeleton,
server-authoritative UID generation + registration transaction, CI gates.
See CLAUDE.md §8 for the build order.
