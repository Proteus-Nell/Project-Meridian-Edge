"""SQLAlchemy ORM schema - the complete set of things the server persists.

Read this file as the authoritative answer to "what does the server actually
know?". Every column is one of three things: public key material (identity
keys, signed and one-time prekeys, and the signatures over them), an opaque
ciphertext blob the server routes but cannot read, or bookkeeping such as
hashes, counters and timestamps.

What is absent is as deliberate as what is present. There is no table for
plaintext, private keys or symmetric keys; no archive of delivered messages;
and no lookup that would let an unauthenticated caller learn whether a UID
exists. Secrets that must be retained at all are retained only in hashed form:
recovery codes as Argon2id hashes, session tokens as SHA-512 digests. Queue
rows are deleted on ack inside the same transaction as the delivery
confirmation, so a delivered message leaves no row behind.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .constants import UID_CHARS
from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Canonical (dash-free) UID; uniqueness enforced by the DB, collisions
    # regenerated silently inside the registration transaction.
    uid: Mapped[str] = mapped_column(String(UID_CHARS), unique=True, index=True)
    # ML-DSA-65 verification key. Public material only - the server never
    # stores private keys.
    ik_pub: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    # Argon2id encoded hash; plaintext codes are shown once and never stored.
    code_hash: Mapped[str] = mapped_column(String(256))
    used: Mapped[bool] = mapped_column(default=False)


class LoginNonce(Base):
    __tablename__ = "login_nonces"

    id: Mapped[int] = mapped_column(primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # hex
    # UID as submitted (canonical form). Deliberately not a foreign key: a
    # challenge is issued whether or not the UID exists (anti-enumeration).
    uid: Mapped[str] = mapped_column(String(UID_CHARS))
    origin: Mapped[str] = mapped_column(String(256))
    timestamp: Mapped[int] = mapped_column()  # unix seconds, signed by client
    issued_at: Mapped[float] = mapped_column()  # app clock, for TTL
    consumed: Mapped[bool] = mapped_column(default=False)


class SessionToken(Base):
    __tablename__ = "session_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    # App-clock seconds at issue; powers the age shown by GET /v1/sessions. A
    # default keeps rows created before this column was added readable.
    created_at: Mapped[float] = mapped_column(default=0.0)
    last_used: Mapped[float] = mapped_column()
    revoked: Mapped[bool] = mapped_column(default=False)


class SignedPrekey(Base):
    __tablename__ = "signed_prekeys"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    pub: Mapped[bytes] = mapped_column(LargeBinary)  # ML-KEM-768 encaps key
    sig: Mapped[bytes] = mapped_column(LargeBinary)  # ML-DSA-65 over pub
    uploaded_at: Mapped[float] = mapped_column()


class OpkBatch(Base):
    __tablename__ = "opk_batches"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    # ML-DSA-65 signature over the batch root: SHA-512 of the concatenated
    # per-OPK leaf hashes. Leaf list is retained so a single OPK stays
    # verifiable after its siblings are consumed and deleted.
    root_sig: Mapped[bytes] = mapped_column(LargeBinary)
    leaf_hashes: Mapped[bytes] = mapped_column(LargeBinary)  # 64 B x count
    created_at: Mapped[float] = mapped_column()


class OneTimePrekey(Base):
    __tablename__ = "one_time_prekeys"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("opk_batches.id"), index=True)
    batch_index: Mapped[int] = mapped_column()
    pub: Mapped[bytes] = mapped_column(LargeBinary)
    consumed: Mapped[bool] = mapped_column(default=False)


class QueuedMessage(Base):
    """Per-recipient ciphertext queue: opaque envelope
    blobs, deleted on ack in the same transaction, 14-day TTL. The server
    never parses the envelope - it routes on the recipient column only."""

    __tablename__ = "message_queue"

    id: Mapped[int] = mapped_column(primary_key=True)
    recipient_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    envelope: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[float] = mapped_column()
