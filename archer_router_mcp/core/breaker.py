"""Login circuit breaker (device-agnostic).

Many embedded devices lock the admin account after a handful of failed logins.
The breaker keeps an immutable ledger and decides, before any network I/O,
whether a login attempt may be made at all. Once the failure budget is spent the
breaker stays open until a human clears it.

The ledger is persisted as a small JSON file (``LoginBreaker``) so the budget
survives process restarts: a device that is one failed attempt from a two-hour
lock must not be hammered again just because the server was restarted. Writes are
atomic (temp file + ``os.replace``) and the file is created ``0600``. A file that
cannot be read or parsed is treated as **open** (logins refused) — fail closed,
never fail open, because an unreadable breaker is an unknown lockout state.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .config import DeviceSettings
from .errors import LockoutGuard

log = logging.getLogger(__name__)

# Implicit (automatic) logins stop when the device reports this few attempts left.
IMPLICIT_LOGIN_MIN_REMAINING = 3

STATE_FILENAME = "login-breaker.json"


@dataclass(frozen=True)
class LoginLedger:
    failed: int = 0
    successful: int = 0
    last_failure: dict[str, Any] | None = None
    corrupt: bool = False


def record_failure(ledger: LoginLedger, failure: dict[str, Any]) -> LoginLedger:
    return replace(ledger, failed=ledger.failed + 1, last_failure=dict(failure))


def record_success(ledger: LoginLedger) -> LoginLedger:
    return replace(ledger, successful=ledger.successful + 1)


def check_login_allowed(ledger: LoginLedger, settings: DeviceSettings, *, explicit: bool) -> None:
    """Raise LockoutGuard if policy forbids a login attempt right now."""
    if ledger.corrupt:
        raise LockoutGuard(
            "Login refused: the breaker state file is unreadable, so the lockout state is "
            "unknown. Inspect it and clear the breaker before retrying."
        )
    if settings.login_disabled:
        raise LockoutGuard(
            f"Login refused: {settings.env_name('LOGIN_DISABLED')}=true. Authentication is frozen."
        )
    if ledger.failed >= settings.max_login_failures:
        raise LockoutGuard(
            f"Login refused: {ledger.failed} failed login(s) recorded "
            f"(limit {settings.max_login_failures}, {settings.env_name('MAX_LOGIN_FAILURES')}). "
            "Fix the credentials, check the device's lockout state, then clear the breaker."
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


# --------------------------------------------------------------- file persistence


def _state_file(state_dir: Path) -> Path:
    return Path(state_dir) / STATE_FILENAME


def load_ledger(path: Path) -> LoginLedger:
    """Load the ledger from ``path``. Fail closed: a missing file is an empty
    (allowing) ledger, but an unreadable or malformed file yields a ``corrupt``
    ledger that refuses every login until a human clears it."""
    path = Path(path)
    if not path.exists():
        return LoginLedger()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        log.warning("breaker state at %s is unreadable; treating the breaker as open", path)
        return LoginLedger(corrupt=True)
    if not isinstance(raw, dict):
        return LoginLedger(corrupt=True)
    failed = raw.get("failed")
    successful = raw.get("successful", 0)
    last_failure = raw.get("last_failure")
    if not isinstance(failed, int) or isinstance(failed, bool) or failed < 0:
        return LoginLedger(corrupt=True)
    if not isinstance(successful, int) or isinstance(successful, bool) or successful < 0:
        return LoginLedger(corrupt=True)
    if last_failure is not None and not isinstance(last_failure, dict):
        return LoginLedger(corrupt=True)
    return LoginLedger(failed=failed, successful=successful, last_failure=last_failure)


def save_ledger(path: Path, ledger: LoginLedger) -> None:
    """Persist ``ledger`` atomically with ``0600`` permissions (temp file + replace)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "failed": ledger.failed,
            "successful": ledger.successful,
            "last_failure": ledger.last_failure,
        },
        separators=(",", ":"),
    )
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".breaker-", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        # Best effort: platforms without POSIX modes (Windows) ignore the group/other bits.
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def clear_ledger(path: Path) -> None:
    """Remove the persisted breaker state (``breaker --clear``)."""
    Path(path).unlink(missing_ok=True)


class LoginBreaker:
    """File-backed login breaker: the failure budget survives process restarts.

    The ledger lives in ``<state_dir>/login-breaker.json``. ``check`` consults the
    persisted ledger (and ``settings``) before any network I/O; ``record_failure``
    / ``record_success`` persist the updated ledger atomically; ``clear`` removes
    it. A corrupt file makes ``check`` refuse (fail closed).
    """

    def __init__(self, state_dir: Path, settings: DeviceSettings) -> None:
        self._path = _state_file(state_dir)
        self._settings = settings

    @property
    def path(self) -> Path:
        return self._path

    def snapshot(self) -> LoginLedger:
        return load_ledger(self._path)

    def check(self, *, explicit: bool) -> None:
        check_login_allowed(self.snapshot(), self._settings, explicit=explicit)

    def record_failure(self, failure: dict[str, Any]) -> LoginLedger:
        updated = record_failure(self.snapshot(), failure)
        save_ledger(self._path, updated)
        return updated

    def record_success(self) -> LoginLedger:
        updated = record_success(self.snapshot())
        save_ledger(self._path, updated)
        return updated

    def clear(self) -> None:
        clear_ledger(self._path)

    def show(self) -> dict[str, Any]:
        """A JSON-safe, non-secret summary for the CLI (``breaker --show``)."""
        ledger = self.snapshot()
        state = "corrupt" if ledger.corrupt else ("open" if self._is_open(ledger) else "closed")
        return {
            "state": state,
            "failed": ledger.failed,
            "successful": ledger.successful,
            "last_failure": ledger.last_failure,
            "max_login_failures": self._settings.max_login_failures,
            "login_disabled": self._settings.login_disabled,
            "path": str(self._path),
        }

    def _is_open(self, ledger: LoginLedger) -> bool:
        return (
            self._settings.login_disabled
            or ledger.corrupt
            or ledger.failed >= self._settings.max_login_failures
        )
