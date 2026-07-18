# ADR 0002: W3 wire-format hints, non-consuming bundle fetch, pyca vectors

**Status:** accepted · **Date:** 2026-07-05

## Context

CLAUDE.md §3 prescribes the KX crypto exactly (transcript, RK₀ derivation,
signature, AEAD) and sketches the envelope as
`version ‖ type ‖ IK_A ‖ ct1 ‖ [ct2] ‖ sig_A ‖ AEAD(...)`. Three practical
decisions were needed during implementation.

## Decisions

### 1. SPK/OPK routing hints in the envelope

The responder holds several retained SPK secrets (14-day window) and up to
~200 OPK secrets; the spec layout gives no way to select the right ones. The
envelope therefore carries `SHA-512(SPK_B)` and, when present,
`SHA-512(OPK_B)` as plaintext routing hints. They are **not** covered by the
transcript: tampering them can only cause a lookup miss or an AEAD failure,
never a wrong acceptance, and they reveal nothing the server did not already
know (it served that exact bundle). The alternative — trial-decrypting the
cross product of retained secrets — is O(SPKs × OPKs) AEAD attempts.

### 2. `?opk=0` non-consuming bundle fetch

Receivers verify that a first message's claimed sender UID really owns the
envelope's `IK_A` by fetching the claimed sender's bundle and comparing
identity keys (interim TOFU pinning until W4 safety numbers). A consuming
fetch would let anyone drain a victim's OPKs simply by messaging strangers —
the opposite of the §7.4 depletion defense. The flag only skips consumption;
auth, rate limiting, and uniform 404s are identical.

### 3. Test vectors from pyca/cryptography instead of liboqs

The spec names liboqs-python for vector generation. liboqs has no Windows
wheels and requires a C toolchain build; pyca `cryptography` (already the
server-side verifier) exposes ML-KEM-768/ML-DSA-65 through OpenSSL ≥3.5 and
is an equally independent implementation from the client's `@noble` stack.
Vectors exploit FIPS seed formats: the 64-byte ML-KEM (d‖z) and 32-byte
ML-DSA (ξ) seeds regenerate keypairs in noble, proving keygen, decapsulation,
and signature verification agree across implementations. liboqs remains the
named option for the W6 benchmark baselines where native performance matters.

## Consequences

- Envelope layout (client/src/crypto/envelope.ts) is v1-final for the MVP;
  W4 adds a separate ratcheted-message envelope type alongside it.
- `scripts/gen_vectors.py` regenerates `shared/vectors/*.json`; the client
  suite fails if noble and OpenSSL ever disagree.
