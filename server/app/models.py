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
    # stores private keys (CLAUDE.md section 0).
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
    """Per-recipient ciphertext queue (CLAUDE.md section 5): opaque envelope
    blobs, deleted on ack in the same transaction, 14-day TTL. The server
    never parses the envelope - it routes on the recipient column only."""

    __tablename__ = "message_queue"

    id: Mapped[int] = mapped_column(primary_key=True)
    recipient_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    envelope: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[float] = mapped_column()
