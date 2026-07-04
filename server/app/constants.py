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

# FIPS 204 ML-DSA-65 sizes.
ML_DSA_65_PUBKEY_BYTES = 1952
ML_DSA_65_SIG_BYTES = 3309

# FIPS 203 ML-KEM-768 encapsulation key size.
ML_KEM_768_PUBKEY_BYTES = 1184

# Server payload cap (CLAUDE.md section 3).
MAX_PAYLOAD_BYTES = 65536

# Rate limits (CLAUDE.md section 5): register 3/hour/IP, login-challenge 10/min/IP.
REGISTER_RATE_CAPACITY = 3
REGISTER_RATE_WINDOW_SECONDS = 3600.0
LOGIN_CHALLENGE_RATE_CAPACITY = 10
LOGIN_CHALLENGE_RATE_WINDOW_SECONDS = 60.0

# Login nonces (CLAUDE.md section 2.3): single-use, 60 s expiry, origin-bound.
NONCE_BYTES = 32
NONCE_TTL_SECONDS = 60.0

# Session tokens: opaque 256-bit, 15-minute idle expiry, memory-only client-side.
SESSION_TOKEN_BYTES = 32
SESSION_IDLE_SECONDS = 900.0

# Recovery codes: 10 codes, 80 bits each, shown once, stored as Argon2id hashes.
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 10

# Prekeys (CLAUDE.md section 2.6).
OPK_BATCH_MAX = 50
OPK_LOW_WATERMARK = 20
OPK_UNCONSUMED_CAP = 200
