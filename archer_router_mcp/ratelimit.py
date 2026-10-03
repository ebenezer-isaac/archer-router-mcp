"""Reboot rate limit as a thin ``MinInterval`` policy over the shared core.

The old file-backed ``RateLimiter`` was a *decide-then-record* pair on an unlocked,
writability-unproven file (ROOT-CAUSE-breaker §4, finding RW-F2): two callers could
both read "allowed" before either recorded, and an unwritable ``STATE_DIR`` was only
discovered *after* the reboot had been sent, so the limiter failed open to unbounded
reboots. v1.3.0 of ``core/`` collapses every single-fact safety onto one reservation
primitive, so the reboot limiter is now a thin user of
:class:`~archer_router_mcp.core.slot.MinInterval` over
:class:`~archer_router_mcp.core.state.ReservationStore` — exactly as ``LoginBreaker`` is
the breaker policy and vigi's ``export_lock`` is a ``SingleSlot``, with no second
reservation mechanism of its own:

* :meth:`RebootLimiter.reserve` takes the per-key cross-process lock, which requires
  writing the lock file — so an unwritable store is discovered *before* any reboot is
  sent and refused (:class:`RateLimited`, fail closed), never fail-open. Under that
  lock ``MinInterval`` admits only when no attempt is in flight and the min-interval
  window has elapsed, and the admit-and-insert is one atomic write, so two callers
  cannot both pass.
* The caller releases after the request: :meth:`Reservation.release(SUCCESS)
  <archer_router_mcp.core.state.Reservation.release>` records the completion time
  (starting the window); ``ABORT`` (a reboot refused *before* it was sent — e.g. a
  login failure) leaves the window untouched.

The public surface is unchanged: the same constructor, ``reserve()`` → ``Reservation``
raising :class:`RateLimited`, ``status(now)`` snapshot, ``path``/``min_interval_s`` and
the persisted ``reboot-<device>.json`` under the state dir.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .core.breaker import _safe
from .core.errors import StateUnavailable
from .core.slot import IntervalLedger, MinInterval, min_interval_store
from .core.state import Reservation, ReservationStore
from .errors import RateLimited


class RebootLimiter:
    """Persistent per-device minimum-interval gate for the reboot action.

    A thin :class:`~archer_router_mcp.core.slot.MinInterval` over the canonical
    reservation store, with device-specific refusals mapped to :class:`RateLimited`.
    """

    def __init__(
        self,
        state_dir: Path,
        device_key: str,
        *,
        min_interval_s: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._key = f"reboot-{_safe(device_key)}"
        self._min_interval = max(0.0, float(min_interval_s))
        self._clock = clock
        self._store: ReservationStore[IntervalLedger] = min_interval_store(
            Path(state_dir), clock=clock
        )
        self._limiter = MinInterval(
            self._store,
            self._key,
            min_interval_s=self._min_interval,
            clock=clock,
            reason=RateLimited.kind,
            refuse=self._refuse,
        )

    @property
    def path(self) -> Path:
        return self._store.path(self._key)

    @property
    def min_interval_s(self) -> float:
        return self._min_interval

    def _refuse(self, message: str, reason: str, context: dict[str, Any]) -> Exception:
        """Map a ``MinInterval`` refusal to the router's :class:`RateLimited` envelope.

        ``MinInterval`` passes ``next_allowed`` in the context for a within-window
        refusal and omits it for an in-flight one; both carry ``retry_after_s``.
        """
        retry_after_s = float(context.get("retry_after_s", self._min_interval))
        if "next_allowed" in context:
            next_allowed = float(context["next_allowed"])
            text = f"Reboot refused: rate-limited. Try again in {retry_after_s:.0f}s."
        else:
            next_allowed = float(self._clock()) + retry_after_s
            text = "Reboot refused: another reboot is already in progress for this device."
        return RateLimited(text, retry_after_s=retry_after_s, next_allowed=next_allowed)

    def _next_allowed(self, ledger: IntervalLedger | None, now: float) -> float:
        if ledger is None or ledger.last_completed_at is None:
            return now
        return ledger.last_completed_at + self._min_interval

    def reserve(self) -> Reservation:
        """Reserve one reboot before it is sent. Raises :class:`RateLimited` (within the
        window, an in-flight reboot, or an unwritable/busy store) — always before any
        reboot leaves the process."""
        try:
            return self._limiter.reserve(meta={"pid": os.getpid()})
        except StateUnavailable as exc:
            now = float(self._clock())
            raise RateLimited(
                f"Reboot refused: the rate-limit store is unusable, so a reboot cannot be "
                f"bounded. {exc} Refusing (fail closed).",
                retry_after_s=self._min_interval,
                next_allowed=now + self._min_interval,
            ) from exc

    def status(self, now: float) -> dict[str, Any]:
        """A JSON-safe snapshot for ``--show``/dry-run at ``now``. Never raises; fails
        closed. Keeps the historical key shape (``last_time``)."""
        try:
            ledger = self._store.load(self._key)
        except StateUnavailable as exc:
            return {
                "allowed": False,
                "reason": str(exc),
                "min_interval_s": self._min_interval,
            }
        next_allowed = self._next_allowed(ledger, now)
        in_flight = bool(ledger and ledger.reservations)
        allowed = now >= next_allowed and not in_flight
        return {
            "allowed": allowed,
            "last_time": ledger.last_completed_at if ledger else None,
            "next_allowed": next_allowed,
            "retry_after_s": max(0.0, next_allowed - now),
            "min_interval_s": self._min_interval,
            "in_flight": in_flight,
        }
