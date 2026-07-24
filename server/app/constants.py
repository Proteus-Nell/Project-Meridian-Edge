"""Shared protocol constants.

Mirrored in client/src/crypto/constants.ts - any change here must be made
there in the same commit.
"""

PROTOCOL_VERSION = 1

KDF_INFO_KX = "MeridianEdge-v1-KX"
KDF_INFO_RK = "MeridianEdge-v1-RK"
KDF_INFO_CK = "MeridianEdge-v1-CK"
KDF_INFO_HDR = "MeridianEdge-v1-HDR"

# Argon2id parameters (RFC 9106); stored beside ciphertext for future upgrades.
ARGON2ID_MEM_KIB = 65536
ARGON2ID_ITERATIONS = 3
ARGON2ID_PARALLELISM = 1

# UID: 128 bits, Crockford Base32 -> 26 chars.
UID_BYTES = 16
UID_CHARS = 26
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# FIPS 204 ML-DSA-65 sizes.
ML_DSA_65_PUBKEY_BYTES = 1952
ML_DSA_65_SIG_BYTES = 3309

# FIPS 203 ML-KEM-768 sizes.
ML_KEM_768_PUBKEY_BYTES = 1184
ML_KEM_768_CT_BYTES = 1088

# Server payload cap.
MAX_PAYLOAD_BYTES = 65536

# Message queue: delete-on-ack, 14-day TTL.
MESSAGE_TTL_SECONDS = 14 * 86400.0
ACK_MAX_IDS = 256

# WebSocket delivery (checklist).
WS_AUTH_TIMEOUT_SECONDS = 10.0
WS_MAX_FRAME_BYTES = 65536
# Idle-kill: a connection that sends nothing (not even a ping) for this long is
# closed. The client hearts-beat well inside this window (see ws.ts).
WS_IDLE_TIMEOUT_SECONDS = 90.0
# Per-connection inbound frame budget (separate from the per-UID REST rate
# limits): caps how fast one live socket can send ack/ping frames.
WS_FRAME_RATE_CAPACITY = 30
WS_FRAME_RATE_WINDOW_SECONDS = 10.0

# Rate limits: register 3/hour/IP, login-challenge
# 10/min/IP, bundle fetch 30/min/UID, message send 60/min/UID.
REGISTER_RATE_CAPACITY = 3
REGISTER_RATE_WINDOW_SECONDS = 3600.0
LOGIN_CHALLENGE_RATE_CAPACITY = 10
LOGIN_CHALLENGE_RATE_WINDOW_SECONDS = 60.0
BUNDLE_FETCH_RATE_CAPACITY = 30
BUNDLE_FETCH_RATE_WINDOW_SECONDS = 60.0
MESSAGE_SEND_RATE_CAPACITY = 60
MESSAGE_SEND_RATE_WINDOW_SECONDS = 60.0

# Prekey uploads, 10/hour/UID. These endpoints append rows, and the signed-prekey
# table has no other bound, so an authenticated client could otherwise grow it
# without limit. Legitimate traffic is far below this: one signed prekey plus one
# one-time-prekey batch at registration, a weekly signed-prekey rotation, and a
# refill only when the pool runs low.
KEYS_UPLOAD_RATE_CAPACITY = 10
KEYS_UPLOAD_RATE_WINDOW_SECONDS = 3600.0

# Login nonces: single-use, 60 s expiry, origin-bound.
NONCE_BYTES = 32
NONCE_TTL_SECONDS = 60.0

# Session tokens: opaque 256-bit, 15-minute idle expiry, memory-only client-side.
SESSION_TOKEN_BYTES = 32
SESSION_IDLE_SECONDS = 900.0

# Recovery codes: 10 codes, 80 bits each, shown once, stored as Argon2id hashes.
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 10
RECOVERY_CODE_CHARS = RECOVERY_CODE_BYTES * 8 // 5  # 16 Crockford chars

# Account recovery: redemption is rate-limited far
# below login since a legitimate user redeems at most a handful per lifetime.
RECOVER_RATE_CAPACITY = 5
RECOVER_RATE_WINDOW_SECONDS = 3600.0

# Prekeys.
OPK_BATCH_MAX = 50
OPK_LOW_WATERMARK = 20
OPK_UNCONSUMED_CAP = 200
