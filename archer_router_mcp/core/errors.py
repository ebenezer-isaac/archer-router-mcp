"""Device-agnostic exception hierarchy.

Every exception carries a stable ``kind`` (used as the envelope error code) and
``details()`` (a JSON-safe dict for the envelope). Device packages add their own
error-code tables and pass symbols/meanings in; nothing here knows any device.
"""

from __future__ import annotations

from typing import Any


class DeviceError(Exception):
    kind = "DEVICE_ERROR"

    def details(self) -> dict[str, Any]:
        return {}


class ConfigError(DeviceError):
    kind = "CONFIG_ERROR"


class InvalidInput(DeviceError, ValueError):
    """Client-supplied input was rejected before any I/O.

    Subclasses ``ValueError`` so validators that historically raised ``ValueError``
    keep their callers working, while ``run_tool`` maps it (via its ``kind``) to an
    ``INVALID_INPUT`` envelope. A plain ``ValueError`` from anywhere else is an
    internal fault, not client input, and must NOT be reported as ``INVALID_INPUT``.
    """

    kind = "INVALID_INPUT"


class TransportError(DeviceError):
    """Network, TLS, HTTP status or malformed-response failure."""

    kind = "TRANSPORT_ERROR"


class TlsPinMismatch(TransportError):
    """The peer certificate's SHA-256 did not match the configured pin."""

    kind = "TLS_PIN_MISMATCH"


class ApiError(DeviceError):
    """The device answered with a non-success code."""

    kind = "DEVICE_API_ERROR"

    def __init__(
        self,
        code: int,
        message: str | None = None,
        data: Any = None,
        *,
        symbol: str | None = None,
        meaning: str | None = None,
    ) -> None:
        self.code = code
        self.data = data
        self.symbol = symbol
        self.meaning = meaning
        label = f" ({symbol})" if symbol else ""
        super().__init__(message or f"Device returned error code {code}{label}")

    def details(self) -> dict[str, Any]:
        return {"device_error_code": self.code, "symbol": self.symbol, "meaning": self.meaning}


class AuthFailed(DeviceError):
    """The login call itself was rejected. Never retried automatically."""

    kind = "AUTH_FAILED"

    def __init__(
        self,
        message: str,
        *,
        code: int | None = None,
        symbol: str | None = None,
        attempts_left: int | None = None,
        max_attempts: int | None = None,
        lock_seconds_left: int | None = None,
        locked: bool = False,
    ) -> None:
        self.code = code
        self.symbol = symbol
        self.attempts_left = attempts_left
        self.max_attempts = max_attempts
        self.lock_seconds_left = lock_seconds_left
        self.locked = locked or attempts_left == 0 or lock_seconds_left is not None
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {
            "device_error_code": self.code,
            "symbol": self.symbol,
            "attempts_left": self.attempts_left,
            "max_attempts": self.max_attempts,
            "lock_seconds_left": self.lock_seconds_left,
            "locked": self.locked,
        }


class ProtocolError(DeviceError):
    """A reply was valid HTTP/JSON with ``error_code == 0`` but did not contain
    the section or fields a typed tool needs to normalise it. Distinct from
    ``TransportError`` (transport/HTTP/JSON failure) and ``ApiError`` (the device
    reported a non-zero code): here the device said OK but the shape was wrong."""

    kind = "PROTOCOL_ERROR"


class TokenExpired(DeviceError):
    """An authenticated call reported the session as invalid or timed out."""

    kind = "TOKEN_EXPIRED"


class NonceInvalid(DeviceError):
    """The device rejected the login nonce as stale/reused (-40410).

    Retryable: the password was never evaluated, so it does NOT count as a
    credential failure. One explicit login still sends exactly one login POST;
    the caller may retry with a fresh challenge."""

    kind = "NONCE_INVALID"


class StateUnavailable(DeviceError):
    """A persisted state store could not be used: its directory is unwritable, its
    cross-process lock could not be taken within the timeout, or the file on disk
    is unreadable, corrupt, wrongly-typed or of an unknown version. Every such
    failure is reported here (fail closed) and never coerced or ignored, so no
    caller ever mistakes an unusable store for an empty/permissive one."""

    kind = "STATE_UNAVAILABLE"


class BreakerOpen(DeviceError):
    """The persistent login breaker could not be read or written, or holds an
    open state, so logins are refused (fail closed) until a human clears it."""

    kind = "BREAKER_OPEN"


class Cooldown(DeviceError):
    """A login was refused because a device-imposed cooldown is still in effect
    (e.g. session-busy or a timed lockout). Expires on its own clock; a success
    clears it. Distinct from a credential failure: the account is not necessarily
    locked, the device is asking the client to wait."""

    kind = "COOLDOWN"

    def __init__(self, message: str, *, cooldown_remaining_s: float | None = None) -> None:
        self.cooldown_remaining_s = cooldown_remaining_s
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"cooldown_remaining_s": self.cooldown_remaining_s}


class LoginDisabled(DeviceError):
    """Authentication is frozen by configuration (``<PREFIX>_LOGIN_DISABLED``).
    Freezes login attempts only; the credential-free challenge/reachability probe
    stays allowed. No network login call is made (fail closed)."""

    kind = "LOGIN_DISABLED"


class WriteNotAllowed(DeviceError):
    """A gated write reached the guarded executor without writes enabled.

    Defense-in-depth: the two-key gate normally refuses before the executor is
    reached, so this only fires if a mutating path forgets it. Fails closed."""

    kind = "WRITE_NOT_ALLOWED"


class LockoutGuard(DeviceError):
    """A login was refused locally (circuit breaker) to protect the account.

    Carries the device-reported counters (``attempts_left``/``max_attempts``/
    ``lock_seconds_left``) when the refusal was driven by a device challenge, so
    the operator sees how long to wait, exactly like :class:`AuthFailed`."""

    kind = "LOGIN_REFUSED"

    def __init__(
        self,
        reason: str,
        *,
        attempts_left: int | None = None,
        max_attempts: int | None = None,
        lock_seconds_left: int | None = None,
    ) -> None:
        self.reason = reason
        self.attempts_left = attempts_left
        self.max_attempts = max_attempts
        self.lock_seconds_left = lock_seconds_left
        super().__init__(reason)

    def details(self) -> dict[str, Any]:
        return {
            "attempts_left": self.attempts_left,
            "max_attempts": self.max_attempts,
            "lock_seconds_left": self.lock_seconds_left,
        }


class WriteNotEnabled(DeviceError):
    """A gated write reached the guarded executor without writes enabled.

    Defense-in-depth: the two-key gate normally refuses before the executor is
    reached, so this only fires if a mutating path forgets it. Fails closed."""

    kind = "WRITE_REFUSED"


class NotFound(DeviceError):
    kind = "NOT_FOUND"


class PreconditionFailed(DeviceError):
    """A guarded write was refused because the live state did not match."""

    kind = "PRECONDITION_FAILED"

    def __init__(self, message: str, *, reason: str, context: dict[str, Any] | None = None) -> None:
        self.reason = reason
        self.context = dict(context or {})
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"reason": self.reason, **self.context}
