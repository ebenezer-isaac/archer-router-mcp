"""Login circuit breaker: a thin policy over :class:`ReservationStore`.

The breaker holds one fact - *how much of the device's login budget is spent, and
may this process spend one more attempt right now* - in one authoritative place.
The admit decision and the budget increment are the **same** locked, atomic write
(:meth:`LoginBreaker.reserve_attempt`): there is no pure-read admit path, so two
processes cannot both pass. Taking the store's lock requires writing, so an
unwritable store is discovered at admit time and refused (never fail-open). The
ledger is strictly schema-validated, so a wrongly-typed field is refused, never
coerced to a permissive value. The device identity is derived once by
:func:`canonical_device_key`, so one device never holds two budgets.

Semantics (device-agnostic; no device vocabulary lives here):

* ``reserve_attempt()`` reserves one attempt before any network I/O and returns a
  :class:`Reservation`. ``release(SUCCESS)`` records a success and clears any
  cooldown; ``release(FAILURE)`` records a failure and, at/over budget, trips the
  breaker; ``release(BUSY, cooldown_s=...)`` sets a cooldown without spending
  budget; ``release(ABORT)`` cancels a reservation whose attempt never reached the
  device (a pre-send guard refused). An unresolved reservation records a failure.
* ``tripped`` is sticky: once failures reach the budget it stays set until
  :meth:`clear`, so raising the budget later never silently reopens it.
* A success never clears failures (they are sticky until a human clears them); it
  does clear the cooldown.
* A crash between reserve and release leaves the reservation counted against the
  budget until ``breaker --clear`` (fail closed).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .errors import BreakerOpen, Cooldown, LoginDisabled, StateUnavailable
from .state import Outcome, Reservation, ReservationStore

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
# Upper bound on any cooldown, so a bogus/absurd future value can never make the
# breaker unrecoverable by time alone (and ``clear`` always recovers it anyway).
MAX_COOLDOWN_S = 7200.0

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe(name: str) -> str:
    """The one filename sanitiser: collapse unsafe runs to ``_``, cap length."""
    cleaned = _UNSAFE.sub("_", name)[:64]
    return cleaned or "_"


def canonical_device_key(host: str) -> str:
    """The single source of device identity used for the ledger filename.

    Lower-cases the host; an IP address is reduced to its compressed canonical form
    so ``fe80::1`` and ``fe80:0:0:0:0:0:0:1`` (and ``Host.local`` vs ``host.local``)
    map to one key, one ledger, one budget.
    """
    h = host.strip().lower()
    try:
        return ipaddress.ip_address(h).compressed
    except ValueError:
        return h


def default_state_dir(app_name: str) -> Path:
    """Default per-user state directory for ``app_name`` (``~/.local/state/<app>``)."""
    return Path.home() / ".local" / "state" / app_name


class BreakerLedger(BaseModel):
    """The one authoritative, strictly-typed shape of the breaker's fact."""

    model_config = ConfigDict(strict=True, extra="forbid")

    version: Literal[1] = SCHEMA_VERSION
    key: str
    reserved: int = Field(ge=0)
    failures: int = Field(ge=0)
    successes: int = Field(ge=0)
    tripped: bool
    cooldown_until: float | None
    last_failure: dict[str, Any] | None
    last_update: float


class LoginBreaker:
    """Persistent per-device login breaker. One locked ledger, fail-closed."""

    def __init__(
        self,
        state_dir: Path,
        device_key: str,
        *,
        max_failures: int = 1,
        clock: Callable[[], float] = time.time,
        login_disabled: bool = False,
        disabled_hint: str = "",
        lock_timeout_s: float = 5.0,
    ) -> None:
        self._key = device_key
        self._max_failures = max(1, int(max_failures))
        self._clock = clock
        self._login_disabled = login_disabled
        self._disabled_hint = disabled_hint
        self._store: ReservationStore = ReservationStore(
            Path(state_dir),
            f"breaker-{_safe(device_key)}",
            BreakerLedger,
            make_default=self._fresh,
            lock_timeout_s=lock_timeout_s,
        )

    @property
    def path(self) -> Path:
        return self._store.path

    @property
    def login_disabled(self) -> bool:
        return self._login_disabled

    def _fresh(self) -> BreakerLedger:
        return BreakerLedger(
            key=self._key,
            reserved=0,
            failures=0,
            successes=0,
            tripped=False,
            cooldown_until=None,
            last_failure=None,
            last_update=float(self._clock()),
        )

    def _cooldown_remaining(self, ledger: BreakerLedger) -> float:
        if ledger.cooldown_until is None:
            return 0.0
        return max(0.0, min(MAX_COOLDOWN_S, ledger.cooldown_until - float(self._clock())))

    # ---- admit / resolve policy (run under the store lock) ------------------

    def _admit(self, current: BreakerLedger | None) -> BreakerLedger:
        ledger = current or self._fresh()
        if ledger.tripped:
            raise BreakerOpen(
                f"Login refused: the breaker is tripped ({ledger.failures} failure(s) recorded, "
                f"budget {self._max_failures}). It persists across restarts and does not reopen "
                "when the budget is raised; fix the credentials, check the device's lockout "
                "state, then clear it with the `breaker --clear` command."
            )
        remaining = self._cooldown_remaining(ledger)
        if remaining > 0:
            raise Cooldown(
                f"Login refused: a cooldown is in effect for about {remaining:.0f}s more. "
                "Wait for it to expire or clear the breaker.",
                cooldown_remaining_s=remaining,
            )
        if ledger.reserved + ledger.failures >= self._max_failures:
            raise BreakerOpen(
                f"Login refused: the login budget is spent ({ledger.reserved} in flight + "
                f"{ledger.failures} failed, budget {self._max_failures}). It persists across "
                "restarts; clear it with the `breaker --clear` command after fixing the cause."
            )
        return ledger.model_copy(
            update={"reserved": ledger.reserved + 1, "last_update": float(self._clock())}
        )

    def _resolve(
        self, current: BreakerLedger | None, outcome: Outcome, kwargs: dict[str, Any]
    ) -> BreakerLedger:
        ledger = current or self._fresh()
        reserved = max(0, ledger.reserved - 1)
        failures = ledger.failures
        successes = ledger.successes
        tripped = ledger.tripped
        cooldown_until = ledger.cooldown_until
        last_failure = ledger.last_failure
        cooldown_s = kwargs.get("cooldown_s")
        failure = kwargs.get("failure")

        if outcome is Outcome.SUCCESS:
            successes += 1
            cooldown_until = None  # a success proves the soft-busy condition has passed
        elif outcome is Outcome.FAILURE:
            failures += 1
            tripped = tripped or failures >= self._max_failures
            if failure is not None:
                last_failure = dict(failure)
            if cooldown_s is not None:
                cooldown_until = self._cooldown_epoch(cooldown_s)
        elif outcome is Outcome.BUSY:
            # Soft busy / device-side timeout: a cooldown, not a budget failure.
            if cooldown_s is not None:
                cooldown_until = self._cooldown_epoch(cooldown_s)
        # Outcome.ABORT: the attempt never reached the device; decrement reserved only.

        return ledger.model_copy(
            update={
                "reserved": reserved,
                "failures": failures,
                "successes": successes,
                "tripped": tripped,
                "cooldown_until": cooldown_until,
                "last_failure": last_failure,
                "last_update": float(self._clock()),
            }
        )

    def _cooldown_epoch(self, cooldown_s: float) -> float:
        return float(self._clock()) + max(0.0, min(MAX_COOLDOWN_S, float(cooldown_s)))

    # ---- public API ---------------------------------------------------------

    def reserve_attempt(self) -> Reservation:
        """Reserve one login attempt before any network I/O (the admission).

        Raises :class:`LoginDisabled` (frozen by config), :class:`BreakerOpen`
        (tripped, budget spent, or the store is unusable) or :class:`Cooldown`
        (a cooldown is in effect) - all before any reservation is committed.
        """
        if self._login_disabled:
            hint = f" ({self._disabled_hint})" if self._disabled_hint else ""
            raise LoginDisabled(f"Login refused: authentication is frozen{hint}.")
        try:
            self._store.mutate(self._admit)
        except StateUnavailable as exc:
            raise BreakerOpen(
                f"Login refused: the breaker store is unusable, so the budget cannot be "
                f"proven. {exc} Refusing logins (fail closed)."
            ) from exc
        return Reservation(self._resolver)

    def _resolver(self, outcome: Outcome, kwargs: dict[str, Any]) -> None:
        def apply(current: BreakerLedger | None) -> BreakerLedger:
            return self._resolve(current, outcome, kwargs)

        try:
            self._store.mutate(apply)
        except StateUnavailable:
            # The reserved increment is already on disk, so further logins are
            # refused (fail closed); do not turn a resolved attempt into an error.
            log.warning(
                "breaker: could not record a reservation outcome; the reserved attempt "
                "stays on disk and further logins are refused until the store is writable"
            )

    def status(self) -> dict[str, Any]:
        """A non-secret snapshot for ``--show``/healthcheck. Never raises."""
        try:
            ledger = self._store.load() or self._fresh()
        except StateUnavailable as exc:
            return {"state": "open", "reason": str(exc), "path": str(self.path)}
        remaining = self._cooldown_remaining(ledger)
        spent = ledger.reserved + ledger.failures >= self._max_failures
        if self._login_disabled:
            state = "disabled"
        elif ledger.tripped or spent:
            state = "open"
        elif remaining > 0:
            state = "cooldown"
        else:
            state = "closed"
        return {
            "state": state,
            "reserved": ledger.reserved,
            "failures": ledger.failures,
            "successes": ledger.successes,
            "tripped": ledger.tripped,
            "cooldown_remaining_s": round(remaining, 3),
            "max_failures": self._max_failures,
            "login_disabled": self._login_disabled,
            "last_failure": ledger.last_failure,
            "path": str(self.path),
        }

    def clear(self) -> None:
        """Reset the breaker (``breaker --clear``). Fail closed on store error."""
        try:
            self._store.clear()
        except StateUnavailable as exc:
            raise BreakerOpen(f"Could not clear the breaker: {exc}") from exc

    @property
    def cooldown_until(self) -> float | None:
        try:
            ledger = self._store.load()
        except StateUnavailable:
            return None
        return ledger.cooldown_until if ledger else None
