from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, LargeBinary, String, func
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
