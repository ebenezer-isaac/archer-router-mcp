"""Login circuit breaker: a thin policy over the one reservation primitive.

The breaker holds one fact - *how much of the device's login budget is spent, and
may this process spend one more attempt right now* - in one authoritative place. It
adds **no** reservation mechanism of its own: admission, the slot, the lock, the
epoch and all file access belong to :class:`~.state.ReservationStore`; the breaker
only supplies the *policy* - an ``admit`` gate (login-disabled / tripped / cooldown /
budget) and a release-time ``mutate`` (failures / successes / cooldown / sticky trip).

Because the primitive inserts a uniquely-identified slot under the lock, the admit
decision and the budget increment are the same atomic write, so two processes cannot
both pass. Taking the store's lock requires writing, so an unwritable store is
discovered at admit time and refused (never fail-open). The ledger is strictly
schema-validated, so a wrongly-typed field is refused, never coerced. The device
identity is derived once by :func:`canonical_device_key`, so one device never holds
two budgets.

Semantics (device-agnostic; no device vocabulary lives here):

* ``reserve_attempt()`` reserves one attempt before any network I/O and returns a
  :class:`~.state.Reservation`. ``release(SUCCESS)`` records a success and clears any
  cooldown; ``release(FAILURE)`` records a failure and, at/over budget, trips the
  breaker; ``release(BUSY, cooldown_s=...)`` sets a cooldown without spending budget;
  ``release(ABORT)`` cancels a reservation whose attempt never reached the device. An
  unresolved reservation records a failure (fail closed).
* ``tripped`` is sticky: once failures reach the budget it stays set until
  :meth:`clear`, so raising the budget later never silently reopens it.
* A success never clears failures (sticky until a human clears them); it does clear
  the cooldown. A crash between reserve and release leaves the reservation counted
  against the budget until ``breaker --clear`` (fail closed).
"""

from __future__ import annotations

import ipaddress
import math
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .errors import BreakerOpen, Cooldown, LoginDisabled, StateUnavailable
from .state import Outcome, Reservation, ReservationStore, SlotLedger

SCHEMA_VERSION = 1
# Upper bound on any cooldown, so a bogus/absurd future value can never make the
# breaker unrecoverable by time alone (and ``clear`` always recovers it anyway).
MAX_COOLDOWN_S = 7200.0
# A legacy ``reserved`` count above this is treated as corrupt rather than migrated,
# so a hand-edited huge value cannot make the migration allocate an enormous dict.
_MAX_LEGACY_RESERVED = 10_000

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


class BreakerLedger(SlotLedger):
    """The one authoritative, strictly-typed shape of the breaker's fact.

    Inherits ``epoch`` + named ``reservations`` (and the derived ``reserved`` count)
    from :class:`~.state.SlotLedger`; adds the budget policy fields. ``epoch`` is bumped
    by :meth:`LoginBreaker.clear`, which is how a reservation taken before a clear is
    recognised as stale afterwards.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    version: Literal[1] = SCHEMA_VERSION
    key: str
    failures: int = Field(ge=0)
    successes: int = Field(ge=0)
    tripped: bool
    cooldown_until: float | None
    last_failure: dict[str, Any] | None

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_reserved(cls, data: Any) -> Any:
        """Load a v1.1.0 ledger (an anonymous ``reserved`` int, no ``reservations``).

        A valid non-negative ``reserved`` migrates to that many placeholder
        reservations so a holder that crashed before the upgrade still counts against
        the budget (fail closed). A bad-typed, negative or absurd value is left in
        place so the strict schema rejects it rather than reading as an empty budget."""
        if not isinstance(data, dict) or "reservations" in data or "reserved" not in data:
            return data
        count = data["reserved"]
        if isinstance(count, bool) or not isinstance(count, int):
            return data
        if not 0 <= count <= _MAX_LEGACY_RESERVED:
            return data
        migrated = {k: v for k, v in data.items() if k != "reserved"}
        migrated["reservations"] = {
            f"legacy-{i}": {"reserved_at": 0.0, "meta": {}} for i in range(count)
        }
        return migrated

    @field_validator("cooldown_until")
    @classmethod
    def _finite_cooldown(cls, value: float | None) -> float | None:
        """Treat a non-finite cooldown (hand-edited ``Infinity``/``NaN``) as no
        cooldown, so the breaker self-heals instead of refusing logins forever - the
        writer itself can never emit one (``_cooldown_epoch`` clamps to a finite
        number), so a non-finite value is only ever an external edit."""
        if value is None or not math.isfinite(value):
            return None
        return value


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
        self._device_key = device_key
        self._name = f"breaker-{_safe(device_key)}"
        self._max_failures = max(1, int(max_failures))
        self._clock = clock
        self._login_disabled = login_disabled
        self._disabled_hint = disabled_hint
        self._store: ReservationStore[BreakerLedger] = ReservationStore(
            Path(state_dir),
            BreakerLedger,
            make_default=self._fresh,
            clock=clock,
            lock_timeout_s=lock_timeout_s,
        )

    @property
    def path(self) -> Path:
        return self._store.path(self._name)

    @property
    def login_disabled(self) -> bool:
        return self._login_disabled

    def _fresh(self, _key: str, epoch: int) -> BreakerLedger:
        return BreakerLedger(
            key=self._device_key,
            epoch=epoch,
            reservations={},
            failures=0,
            successes=0,
            tripped=False,
            cooldown_until=None,
            last_failure=None,
            last_update=float(self._clock()),
        )

    def _cooldown_remaining(self, ledger: BreakerLedger) -> float:
        """Seconds of cooldown left, clamped to ``[0, MAX_COOLDOWN_S]``.

        Total over every input: a ``None`` or non-finite ``cooldown_until``, and a
        non-finite difference from a jumpy clock, all read as ``0`` (expired), so the
        clamp never assumes a finite operand and a bogus value cannot stick."""
        cu = ledger.cooldown_until
        if cu is None or not math.isfinite(cu):
            return 0.0
        delta = cu - float(self._clock())
        if not math.isfinite(delta):
            return 0.0
        return max(0.0, min(MAX_COOLDOWN_S, delta))

    def _cooldown_epoch(self, cooldown_s: float) -> float:
        return float(self._clock()) + max(0.0, min(MAX_COOLDOWN_S, float(cooldown_s)))

    # ---- admit / mutate policy (run under the store lock) --------------------

    def _admit(self, ledger: BreakerLedger) -> None:
        """Policy gate only; the store inserts the named slot under the lock."""
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
        if len(ledger.reservations) + ledger.failures >= self._max_failures:
            raise BreakerOpen(
                f"Login refused: the login budget is spent ({len(ledger.reservations)} in flight "
                f"+ {ledger.failures} failed, budget {self._max_failures}). It persists across "
                "restarts; clear it with the `breaker --clear` command after fixing the cause."
            )

    def _mutate(
        self, ledger: BreakerLedger, outcome: Outcome, kwargs: dict[str, Any]
    ) -> BreakerLedger:
        """Apply an outcome's policy effect. The store has already removed the slot and
        set ``last_update``; this only touches the budget/cooldown fields."""
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
        # Outcome.ABORT: the attempt never reached the device; the slot drop is enough.

        return ledger.model_copy(
            update={
                "failures": failures,
                "successes": successes,
                "tripped": tripped,
                "cooldown_until": cooldown_until,
                "last_failure": last_failure,
            }
        )

    # ---- public API ---------------------------------------------------------

    def reserve_attempt(self) -> Reservation:
        """Reserve one named login attempt before any network I/O (the admission).

        Raises :class:`LoginDisabled` (frozen by config), :class:`BreakerOpen`
        (tripped, budget spent, or the store is unusable) or :class:`Cooldown`
        (a cooldown is in effect) - all before any reservation is committed.
        """
        if self._login_disabled:
            hint = f" ({self._disabled_hint})" if self._disabled_hint else ""
            raise LoginDisabled(f"Login refused: authentication is frozen{hint}.")
        try:
            return self._store.reserve(self._name, self._admit, self._mutate)
        except StateUnavailable as exc:
            raise BreakerOpen(
                f"Login refused: the breaker store is unusable, so the budget cannot be "
                f"proven. {exc} Refusing logins (fail closed)."
            ) from exc

    def status(self) -> dict[str, Any]:
        """A non-secret snapshot for ``--show``/healthcheck. Never raises, never blocks
        (the ledger is read without the lock)."""
        try:
            ledger = self._store.load(self._name) or self._fresh(self._name, 0)
        except StateUnavailable as exc:
            return {
                "state": "open",
                "reason": str(exc),
                "cooldown_remaining_s": 0.0,
                "path": str(self.path),
            }
        remaining = self._cooldown_remaining(ledger)
        reserved = len(ledger.reservations)
        spent = reserved + ledger.failures >= self._max_failures
        if self._login_disabled:
            state = "disabled"
        elif ledger.tripped or spent:
            state = "open"
        elif remaining > 0:
            state = "cooldown"
        else:
            state = "closed"
        now = float(self._clock())
        ages = {
            rid: round(max(0.0, now - slot.reserved_at), 3)
            for rid, slot in ledger.reservations.items()
        }
        return {
            "state": state,
            "reserved": reserved,
            "reservations": ages,
            "epoch": ledger.epoch,
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
        """Reset the breaker (``breaker --clear``). Delegates to the primitive's atomic
        clear, which bumps the monotonic epoch (so a release still in flight from before
        the clear is a stale no-op and cannot decrement the new budget) and writes a
        fresh ledger - resetting tripped, failures and cooldown. Always recovers, even
        from a corrupt ledger; fails closed only if the store cannot be written."""
        try:
            self._store.clear(self._name)
        except StateUnavailable as exc:
            raise BreakerOpen(f"Could not clear the breaker: {exc}") from exc

    @property
    def cooldown_until(self) -> float | None:
        try:
            ledger = self._store.load(self._name)
        except StateUnavailable:
            return None
        return ledger.cooldown_until if ledger else None


__all__ = [
    "BreakerLedger",
    "LoginBreaker",
    "_safe",
    "canonical_device_key",
    "default_state_dir",
]
