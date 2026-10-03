"""Login circuit breaker (device-agnostic).

Many embedded devices lock the admin account after a handful of failed logins.
The breaker keeps an immutable per-process ledger and decides, before any
network I/O, whether a login attempt may be made at all. Once the failure
budget is spent the breaker stays open until the process restarts.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .config import DeviceSettings
from .errors import LockoutGuard

# Implicit (automatic) logins stop when the device reports this few attempts left.
IMPLICIT_LOGIN_MIN_REMAINING = 3


@dataclass(frozen=True)
class LoginLedger:
    failed: int = 0
    successful: int = 0
    last_failure: dict[str, Any] | None = None


def record_failure(ledger: LoginLedger, failure: dict[str, Any]) -> LoginLedger:
    return replace(ledger, failed=ledger.failed + 1, last_failure=dict(failure))


def record_success(ledger: LoginLedger) -> LoginLedger:
    return replace(ledger, successful=ledger.successful + 1)


def check_login_allowed(ledger: LoginLedger, settings: DeviceSettings, *, explicit: bool) -> None:
    """Raise LockoutGuard if policy forbids a login attempt right now."""
    if settings.login_disabled:
        raise LockoutGuard(
            f"Login refused: {settings.env_name('LOGIN_DISABLED')}=true. Authentication is frozen."
        )
    if ledger.failed >= settings.max_login_failures:
        raise LockoutGuard(
            f"Login refused: {ledger.failed} failed login(s) in this process "
            f"(limit {settings.max_login_failures}, {settings.env_name('MAX_LOGIN_FAILURES')}). "
            "Fix the credentials, check the device's lockout state, then restart the server."
        )
    if not explicit and ledger.failed > 0:
        raise LockoutGuard(
            "Login refused: a previous login failed. Automatic logins are disabled; "
            "use the explicit login tool after fixing the cause."
        )


def check_remaining_attempts(remaining: int | None, *, explicit: bool) -> None:
    """Guard on the device-reported remaining-attempts counter (None = unknown)."""
    if remaining is None:
        return
    if remaining <= 0:
        raise LockoutGuard(
            "Login refused: the device reports 0 login attempts remaining; the account is "
            "locked or about to be. Wait for the lock to expire."
        )
    if not explicit and remaining < IMPLICIT_LOGIN_MIN_REMAINING:
        raise LockoutGuard(
            f"Login refused: the device reports only {remaining} attempt(s) remaining. "
            "Automatic login is suspended; use the explicit login tool if you are sure "
            "the credentials are correct."
        )
