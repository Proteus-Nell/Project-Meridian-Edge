"""Account deletion.

One authenticated endpoint that destroys an account and everything the server
holds for it, in a single transaction:

- the identity key and the account row itself
- every recovery code, so nothing can bring the UID back
- signed prekeys, one-time prekey batches and their unconsumed keys
- the queued ciphertext addressed to this account, which nobody can read anyway
- every session token, including the one making the request
- the login nonces issued for the UID

Afterwards the UID is simply unknown. A peer fetching a bundle for it gets the
same uniform 404 an address that never existed returns, and a peer sending to it
gets the same 404 as well: deletion is not distinguishable from non-existence,
which is the same anti-enumeration rule the rest of the surface follows.

This is what the client's duress passphrase calls, so two properties matter more
than they would for an ordinary "delete my account" button. It must be a single
request (the caller may be racing someone reaching for the power cable), and it
must be all-or-nothing (a half-deleted account that still answers bundle
requests would be worse than either outcome).

What it cannot do is recall messages this account already SENT. Those sit in
their recipients' queues, addressed to them, and reaching into another user's
queue is not a capability this server grants anyone. Cooperative deletion of
already-delivered messages is the client's /delete, over the ratchet.

Known limitation, matching recover.py: a WebSocket attached before the deletion
keeps its socket until it disconnects or idles out. Its token is already gone,
so it can neither send nor receive anything new.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..auth import AuthContext, require_auth
from ..deps import get_session
from ..models import (
    LoginNonce,
    OneTimePrekey,
    OpkBatch,
    QueuedMessage,
    RecoveryCode,
    SessionToken,
    SignedPrekey,
    User,
)
from ..security_log import record_security_event

router = APIRouter(prefix="/v1")


@router.post("/account/delete", status_code=204)
def delete_account(
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> Response:
    user_id = ctx.user.id
    uid = ctx.user.uid

    # Children first: every table referencing users.id has to be empty before
    # the row it points at can go.
    batch_ids = list(
        session.execute(select(OpkBatch.id).where(OpkBatch.user_id == user_id)).scalars()
    )
    session.execute(delete(OneTimePrekey).where(OneTimePrekey.user_id == user_id))
    if batch_ids:
        # Belt and braces: one-time prekeys are also reachable through their
        # batch, and a stray row would block the batch delete below.
        session.execute(delete(OneTimePrekey).where(OneTimePrekey.batch_id.in_(batch_ids)))
    session.execute(delete(OpkBatch).where(OpkBatch.user_id == user_id))
    session.execute(delete(SignedPrekey).where(SignedPrekey.user_id == user_id))
    session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
    session.execute(delete(QueuedMessage).where(QueuedMessage.recipient_user_id == user_id))
    session.execute(delete(SessionToken).where(SessionToken.user_id == user_id))
    # Nonces key on the UID string rather than the row (a challenge is issued
    # whether or not the UID exists), so they are cleared by UID.
    session.execute(delete(LoginNonce).where(LoginNonce.uid == uid))
    session.execute(delete(User).where(User.id == user_id))
    session.commit()

    # Worth recording that an account ceased to exist - but never which one, and
    # never that a duress passphrase might have been the cause. The event says
    # only that the endpoint ran.
    record_security_event("account_deleted", endpoint="/v1/account/delete")
    return Response(status_code=204)
