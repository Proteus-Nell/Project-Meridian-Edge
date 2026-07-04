"""Shared protocol constants (CLAUDE.md section 0).

Mirrored in client/src/crypto/constants.ts - any change here must be made
there in the same commit.
"""

PROTOCOL_VERSION = 1

KDF_INFO_KX = "PQTerm-v1-KX"
KDF_INFO_RK = "PQTerm-v1-RK"
KDF_INFO_CK = "PQTerm-v1-CK"
KDF_INFO_HDR = "PQTerm-v1-HDR"

# Argon2id parameters (RFC 9106); stored beside ciphertext for future upgrades.
ARGON2ID_MEM_KIB = 65536
ARGON2ID_ITERATIONS = 3
ARGON2ID_PARALLELISM = 1

# UID: 128 bits, Crockford Base32 -> 26 chars (see docs/adr/0001).
UID_BYTES = 16
UID_CHARS = 26
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# FIPS 204 ML-DSA-65 verification key size.
ML_DSA_65_PUBKEY_BYTES = 1952

# Server payload cap (CLAUDE.md section 3).
MAX_PAYLOAD_BYTES = 65536

# Rate limits (CLAUDE.md section 5): register 3/hour/IP.
REGISTER_RATE_CAPACITY = 3
REGISTER_RATE_WINDOW_SECONDS = 3600.0
