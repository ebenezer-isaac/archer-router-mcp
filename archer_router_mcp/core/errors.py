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


class TransportError(DeviceError):
    """Network, TLS, HTTP status or malformed-response failure."""

    kind = "TRANSPORT_ERROR"


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


class TokenExpired(DeviceError):
    """An authenticated call reported the session as invalid or timed out."""

    kind = "TOKEN_EXPIRED"


class LockoutGuard(DeviceError):
    """A login was refused locally (circuit breaker) to protect the account."""

    kind = "LOGIN_REFUSED"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


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
