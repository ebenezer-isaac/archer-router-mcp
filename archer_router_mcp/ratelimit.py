"""Reboot rate limit as a reserve-before-act policy over ``core.state``.

The old file-backed ``RateLimiter`` was a *decide-then-record* pair on an unlocked,
writability-unproven file (ROOT-CAUSE-breaker §4, finding RW-F2): two callers could
both read "allowed" before either recorded, and an unwritable ``STATE_DIR`` was only
discovered *after* the reboot had been sent, so the limiter failed open to unbounded
reboots. This replaces it with the same :class:`~archer_router_mcp.core.state.ReservationStore`
the login breaker uses:

* :meth:`RebootLimiter.reserve` takes the per-key cross-process lock, which requires
  writing the lock file — so an unwritable store is discovered *before* any reboot is
  sent and refused (:class:`RateLimited`, fail closed), never fail-open. Under that
  lock it checks the min-interval window and an in-flight marker and, in the same
  atomic write, reserves the attempt. Two callers cannot both pass.
* The caller releases after the request: :meth:`Reservation.release(SUCCESS)` records
  the acceptance time (starting the window); ``ABORT`` cancels it (a reboot refused
  *before* it was sent — e.g. a login failure — does not consume the window).
"""

from __future__ import annotations

import contextlib
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .core.errors import StateUnavailable
from .core.state import Outcome, Reservation, ReservationStore
from .errors import RateLimited

SCHEMA_VERSION = 1
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe(name: str) -> str:
    """The shared filename sanitiser (same rule as the breaker): cap and collapse."""
    cleaned = _UNSAFE.sub("_", name)[:64]
    return cleaned or "_"


class RebootLedger(BaseModel):
    """The one authoritative, strictly-typed shape of the reboot rate-limit fact."""

    model_config = ConfigDict(strict=True, extra="forbid")

    version: Literal[1] = SCHEMA_VERSION
    key: str
    reserved: int = Field(ge=0)
    last_accepted: float | None
    last_update: float


class RebootLimiter:
    """Persistent per-device minimum-interval gate for the reboot action."""

    def __init__(
        self,
        state_dir: Path,
        device_key: str,
        *,
        min_interval_s: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._key = device_key
        self._min_interval = max(0.0, float(min_interval_s))
        self._clock = clock
        self._store: ReservationStore = ReservationStore(
            Path(state_dir),
            f"reboot-{_safe(device_key)}",
            RebootLedger,
            make_default=self._fresh,
        )

    @property
    def path(self) -> Path:
        return self._store.path

    @property
    def min_interval_s(self) -> float:
        return self._min_interval

    def _fresh(self) -> RebootLedger:
        return RebootLedger(
            key=self._key, reserved=0, last_accepted=None, last_update=float(self._clock())
        )

    def _next_allowed(self, ledger: RebootLedger | None, now: float) -> float:
        if ledger is None or ledger.last_accepted is None:
            return now
        return ledger.last_accepted + self._min_interval

    def _admit(self, current: RebootLedger | None) -> RebootLedger:
        now = float(self._clock())
        ledger = current or self._fresh()
        if ledger.reserved > 0:
            # Another reboot is already in flight for this device.
            next_allowed = now + self._min_interval
            raise RateLimited(
                "Reboot refused: another reboot is already in progress for this device.",
                retry_after_s=self._min_interval,
                next_allowed=next_allowed,
            )
        next_allowed = self._next_allowed(ledger, now)
        if now < next_allowed:
            raise RateLimited(
                f"Reboot refused: rate-limited. Try again in {next_allowed - now:.0f}s.",
                retry_after_s=next_allowed - now,
                next_allowed=next_allowed,
            )
        return ledger.model_copy(update={"reserved": ledger.reserved + 1, "last_update": now})

    def _resolve(
        self, current: RebootLedger | None, outcome: Outcome, kwargs: dict[str, Any]
    ) -> RebootLedger:
        _ = kwargs
        now = float(self._clock())
        ledger = current or self._fresh()
        reserved = max(0, ledger.reserved - 1)
        last_accepted = ledger.last_accepted
        if outcome is Outcome.SUCCESS:
            # The reboot left the process: start the cooldown window from now.
            last_accepted = now
        # FAILURE / BUSY / ABORT: the reboot was not sent; the window is not consumed.
        return ledger.model_copy(
            update={"reserved": reserved, "last_accepted": last_accepted, "last_update": now}
        )

    def reserve(self) -> Reservation:
        """Reserve one reboot before it is sent. Raises :class:`RateLimited` (within the
        window, an in-flight reboot, or an unwritable/busy store) — always before any
        reboot leaves the process."""
        try:
            self._store.mutate(self._admit)
        except StateUnavailable as exc:
            now = float(self._clock())
            raise RateLimited(
                f"Reboot refused: the rate-limit store is unusable, so a reboot cannot be "
                f"bounded. {exc} Refusing (fail closed).",
                retry_after_s=self._min_interval,
                next_allowed=now + self._min_interval,
            ) from exc
        return Reservation(self._resolver)

    def _resolver(self, outcome: Outcome, kwargs: dict[str, Any]) -> None:
        def apply(current: RebootLedger | None) -> RebootLedger:
            return self._resolve(current, outcome, kwargs)

        # The reserved increment is already on disk, so further reboots are refused
        # (fail closed) until the store is writable; do not raise on resolution.
        with contextlib.suppress(StateUnavailable):
            self._store.mutate(apply)

    def status(self, now: float) -> dict[str, Any]:
        """A JSON-safe snapshot for ``--show``/dry-run. Never raises; fails closed."""
        try:
            ledger = self._store.load()
        except StateUnavailable as exc:
            return {
                "allowed": False,
                "reason": str(exc),
                "min_interval_s": self._min_interval,
            }
        next_allowed = self._next_allowed(ledger, now)
        in_flight = bool(ledger and ledger.reserved > 0)
        allowed = now >= next_allowed and not in_flight
        return {
            "allowed": allowed,
            "last_time": ledger.last_accepted if ledger else None,
            "next_allowed": next_allowed,
            "retry_after_s": max(0.0, next_allowed - now),
            "min_interval_s": self._min_interval,
            "in_flight": in_flight,
        }
