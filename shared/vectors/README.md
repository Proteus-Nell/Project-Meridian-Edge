# Shared test vectors

JSON test vectors validating the client's `@noble/post-quantum` primitives
against an independent implementation (pyca `cryptography` / OpenSSL — see
docs/adr/0002 for why it stands in for liboqs).

- `ml-kem-768.json` — FIPS 203 seeds (d‖z), public keys, ciphertexts, shared
  secrets: noble must reproduce the keypair from the seed and decapsulate to
  the same secret.
- `ml-dsa-65.json` — FIPS 204 seeds (ξ), public keys, messages, signatures:
  noble must reproduce the keypair and verify the signatures.

Regenerate with `server/.venv/Scripts/python scripts/gen_vectors.py`;
consumed by `client/tests/vectors.test.ts`. Committed so client CI needs no
Python.
