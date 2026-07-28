"""Security-event logging.

The server keeps no analytics and no message metadata; this is the one place it
records anything about traffic, and it exists for a single purpose: noticing an
attack in progress. A spike in signature-verification failures, for instance, is
the visible signature of someone trying to substitute an identity key.

Privacy-minimal by construction. An event carries the event type, the endpoint,
and a coarse reason from a fixed vocabulary - never a UID, token, nonce,
signature, passphrase, or any message content. Network-sourced events also carry
the client IP, and that inclusion is a deliberate line: detecting a spike needs a
source to attribute it to, and the peer IP is inherent to serving the request,
whereas a UID is an account identifier the metadata-minimal posture keeps out of
logs where it can, and here it can, so it is omitted.

Output goes through the standard library logging system under the
"meridian_edge.security" logger. The application installs no handler of its own,
so events propagate to whatever the deployment already configured (uvicorn or
gunicorn in production); retention and rotation (target 30 days) are an
operator concern handled there, not here. Levels: WARNING for the routine
rejections, and a distinct ERROR for signature-verification failure so an alert
rule can single it out.
"""

from __future__ import annotations

import logging
from typing import Literal

SecurityEvent = Literal[
    "auth_failure",
    "rate_limit_exceeded",
    "origin_rejected",
    "signature_verification_failed",
    # An account was destroyed at its owner's request. Recorded so a burst of
    # deletions is visible; carries no UID, like everything else here, which
    # also means the log cannot say whether a duress passphrase caused it.
    "account_deleted",
]

_logger = logging.getLogger("meridian_edge.security")

# The one event that is an attack signal in its own right rather than routine
# noise, so it is logged louder for alerting.
_ERROR_EVENTS = frozenset({"signature_verification_failed"})


def record_security_event(
    event: SecurityEvent,
    *,
    endpoint: str,
    client_ip: str | None = None,
    reason: str | None = None,
) -> None:
    """Emit one privacy-minimal security event as a stable key=value line.

    `endpoint`, `reason` and `event` come only from fixed in-code vocabularies,
    and `client_ip` is the socket peer (never a client-supplied header), so no
    field can carry attacker-controlled text into the log line.
    """
    parts = [f"security_event={event}", f"endpoint={endpoint}"]
    if client_ip is not None:
        parts.append(f"client_ip={client_ip}")
    if reason is not None:
        parts.append(f"reason={reason}")
    line = " ".join(parts)
    if event in _ERROR_EVENTS:
        _logger.error(line)
    else:
        _logger.warning(line)
