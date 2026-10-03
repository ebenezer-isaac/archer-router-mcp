"""Archer AX53 error vocabulary layered on the device-agnostic core errors.

The router answers with short ``errorCode`` strings (and, less often, numeric
``error.Exxxxxxxx`` codes). This module names the ones the auth/session layer
must branch on and maps every known code to a human meaning for the envelope.
Nothing here holds state or performs I/O.
"""

from __future__ import annotations

from typing import Any

from .core.errors import AuthFailed, DeviceError, PreconditionFailed, TokenExpired

__all__ = [
    "EXCEEDED_MAX_ATTEMPTS",
    "LOGIN_FAILED",
    "MULTIPLE_LOGIN",
    "PERMISSION_DENIED",
    "TIMEOUT",
    "USER_CONFLICT",
    "AuthFailed",
    "DeviceError",
    "LockedOut",
    "PreconditionFailed",
    "ProtectedTarget",
    "ProtocolError",
    "R0Unconfirmed",
    "RateLimited",
    "RouterError",
    "SessionConflict",
    "TokenExpired",
    "WriteOutcomeUnknown",
    "error_meaning",
    "normalize_errorcode",
]

# The error strings the login/session flow branches on (from the bundle).
LOGIN_FAILED = "login failed"
USER_CONFLICT = "user conflict"
MULTIPLE_LOGIN = "multiple login"
EXCEEDED_MAX_ATTEMPTS = "exceeded max attempts"
TIMEOUT = "timeout"
PERMISSION_DENIED = "permission denied"

# The two-hour admin lockout the UI reports after the attempt budget is spent.
MAX_ATTEMPT_LOCK_SECONDS = 7200

# Known codes -> meaning. Both the string codes and the numeric ``error.Exxxxxxxx``
# forms seen in the bundle are included so the envelope can explain any of them.
ERROR_MEANINGS: dict[str, str] = {
    LOGIN_FAILED: "The password was rejected.",
    USER_CONFLICT: "Another administrator is already logged in.",
    MULTIPLE_LOGIN: "The router refused the login under its multiple-login policy.",
    EXCEEDED_MAX_ATTEMPTS: "Too many failed attempts; the admin account is locked for ~2 hours.",
    TIMEOUT: "The session expired or a response could not be decrypted.",
    PERMISSION_DENIED: "The account is not permitted to perform this operation.",
    "00000088": "Permission denied.",
    "00000089": "Too many failed attempts; the admin account is locked.",
}


def error_meaning(code: str | None) -> str | None:
    """Return a human meaning for a normalised router error code, if known."""
    if code is None:
        return None
    return ERROR_MEANINGS.get(code)


def normalize_errorcode(payload: dict[str, Any]) -> str | None:
    """Pull the error code out of any of the keys the router may use.

    The bundle accepts ``errorCode | error | errorcode | error_code``; a value of
    ``0``/``""``/``None`` means success (no error). Numeric codes become strings.
    """
    if not isinstance(payload, dict):
        return None
    for key in ("errorCode", "error", "errorcode", "error_code"):
        if key in payload and payload[key] not in (None, 0, "0", ""):
            value = payload[key]
            return value if isinstance(value, str) else str(value)
    return None


class LockedOut(DeviceError):
    """The router has locked the admin account (max attempts, or a login policy)."""

    kind = "LOCKED_OUT"

    def __init__(self, message: str, *, seconds_left: int | None = None) -> None:
        self.seconds_left = seconds_left
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"seconds_left": self.seconds_left}


class SessionConflict(DeviceError):
    """Another admin session is active and takeover was not authorised."""

    kind = "SESSION_CONFLICT"


class ProtocolError(DeviceError):
    """The router returned something the client cannot parse as a valid response.

    Typically an HTML login page or a non-JSON body where JSON was expected.
    """

    kind = "PROTOCOL_ERROR"


class RouterError(DeviceError):
    """The router answered a request with a (non-timeout) error code."""

    kind = "ROUTER_ERROR"

    def __init__(self, code: str, *, meaning: str | None = None) -> None:
        self.code = code
        self.meaning = meaning
        suffix = f": {meaning}" if meaning else ""
        super().__init__(f"The router returned an error ({code}){suffix}")

    def details(self) -> dict[str, Any]:
        return {"code": self.code, "meaning": self.meaning}


class ProtectedTarget(DeviceError):
    """A write targeted a MAC listed in ``ARCHER_ROUTER_PROTECTED_MACS``.

    Blocking, limiting, isolating or un-reserving a protected device (the server's
    or owner's own) is refused outright; no network call is made.
    """

    kind = "PROTECTED_TARGET"

    def __init__(self, mac: str, action: str) -> None:
        self.mac = mac
        self.action = action
        super().__init__(
            f"Refusing to {action} the protected device {mac}. It is listed in "
            "ARCHER_ROUTER_PROTECTED_MACS; remove it there first if this is intended."
        )

    def details(self) -> dict[str, Any]:
        return {"mac": self.mac, "action": self.action}


class RateLimited(DeviceError):
    """A rate-limited action (reboot) was attempted inside its cooldown window."""

    kind = "RATE_LIMITED"

    def __init__(self, message: str, *, retry_after_s: float, next_allowed: float) -> None:
        self.retry_after_s = retry_after_s
        self.next_allowed = next_allowed
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"retry_after_s": self.retry_after_s, "next_allowed": self.next_allowed}


class R0Unconfirmed(DeviceError):
    """A live write whose exact body is unverified until the R0 live capture lands."""

    kind = "R0_UNCONFIRMED"


class WriteOutcomeUnknown(DeviceError):
    """A non-idempotent write's reply was lost (session timeout) and was NOT resent.

    Raised by the session for a write marked ``idempotent=False`` when the router
    reports ``timeout`` for it: the write may or may not have landed, so the client
    re-authenticates and refuses to resend. The guarded-write helper then reads the
    live state back and refines ``outcome`` to ``landed`` (returned as success),
    ``not_landed`` or ``unknown`` (both surfaced as this error).
    """

    kind = "WRITE_OUTCOME_UNKNOWN"

    def __init__(
        self, message: str, *, outcome: str = "unknown", context: dict[str, Any] | None = None
    ) -> None:
        self.outcome = outcome
        self.context = dict(context or {})
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"outcome": self.outcome, **self.context}
