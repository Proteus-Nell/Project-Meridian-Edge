// Shared protocol constants (CLAUDE.md §0). Mirrored in server/app/constants.py —
// any change here must be made there in the same commit.

export const PROTOCOL_VERSION = 1;

export const KDF_INFO_KX = "MeridianEdge-v1-KX";
export const KDF_INFO_RK = "MeridianEdge-v1-RK";
export const KDF_INFO_CK = "MeridianEdge-v1-CK";
export const KDF_INFO_HDR = "MeridianEdge-v1-HDR";

// Argon2id parameters (RFC 9106); stored beside ciphertext for future upgrades.
export const ARGON2ID_MEM_KIB = 65536;
export const ARGON2ID_ITERATIONS = 3;
export const ARGON2ID_PARALLELISM = 1;

// UID: 128 bits, Crockford Base32 → 26 chars (see docs/adr/0001).
export const UID_BYTES = 16;
export const UID_CHARS = 26;
export const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// FIPS 204 ML-DSA-65 sizes.
export const ML_DSA_65_PUBKEY_BYTES = 1952;
export const ML_DSA_65_SIG_BYTES = 3309;

// FIPS 203 ML-KEM-768 sizes.
export const ML_KEM_768_PUBKEY_BYTES = 1184;
export const ML_KEM_768_CT_BYTES = 1088;

// Server payload cap (CLAUDE.md §3).
export const MAX_PAYLOAD_BYTES = 65536;

// Recovery codes (CLAUDE.md §2.2): 80 bits, Crockford Base32, 16 chars.
export const RECOVERY_CODE_CHARS = 16;

// Login nonces (CLAUDE.md §2.3).
export const NONCE_BYTES = 32;

// Prekeys (CLAUDE.md §2.6).
export const OPK_BATCH_MAX = 50;
export const OPK_LOW_WATERMARK = 20;
export const SPK_ROTATION_DAYS = 7;
export const SPK_RETENTION_DAYS = 7; // beyond rotation, for late handshakes

// Local store auto-lock (CLAUDE.md §2.4).
export const AUTO_LOCK_MS = 10 * 60 * 1000;
