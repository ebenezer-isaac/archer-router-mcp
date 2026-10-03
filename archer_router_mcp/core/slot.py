"""Generic single-fact policies over the one reservation primitive.

Two shapes recur in every device safety that is not the login budget, and both are
*the same* lock-free decide-then-record flaw the breaker had, on a sibling surface:

* **one thing in flight at a time** - one export per device, one PoE cycle per port,
  one reboot per device. :class:`SingleSlot` admits a reservation only when no live one
  exists, makes a crashed holder visible (its slot stays on disk and keeps refusing),
  and reclaims a holder older than ``stale_after_s`` by atomically replacing its slot -
  so the dead holder's later release is the primitive's stale no-op, never a decrement
  of the live holder's slot (the round-1 / x1c-F1 over-admit).
* **a minimum interval between completed actions** - a reboot rate-limit.
  :class:`MinInterval` admits only when ``now - last_completed_at >= interval`` (and no
  attempt is already in flight), recording the completion time on ``release(SUCCESS)``.

Both are *pure policy* over :class:`~.state.ReservationStore`: the lock, the named
slot, the epoch and the writability proof are the primitive's, inherited for free and
identical to the breaker. Neither keeps a second reservation mechanism. ``export_lock``
in this package, and the switch's cycle guard and the router's reboot limiter in the
sibling repos, are thin users of these two classes.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Literal

from pydantic import ConfigDict

from .errors import PreconditionFailed, StateUnavailable
from .state import Outcome, Reservation, ReservationStore, SlotLedger


class SingleSlotLedger(SlotLedger):
    """A ``SingleSlot`` ledger: just the shared epoch + named slots, plus identity."""

    model_config = ConfigDict(strict=True, extra="forbid")

    version: Literal[1] = 1
    key: str


class IntervalLedger(SlotLedger):
    """A ``MinInterval`` ledger: adds the last-completed timestamp (the window start)."""

    model_config = ConfigDict(strict=True, extra="forbid")

    version: Literal[1] = 1
    key: str
    last_completed_at: float | None


class SingleSlot:
    """One reservation in flight per key; crash-visible; stale reclaim.

    ``store`` is a :class:`~.state.ReservationStore` over :class:`SingleSlotLedger`;
    ``key`` names the ledger (``<key>.json``). ``reserve`` refuses with ``refuse`` (by
    default :class:`~.errors.PreconditionFailed`) while a live reservation exists.
    """

    def __init__(
        self,
        store: ReservationStore[SingleSlotLedger],
        key: str,
        *,
        stale_after_s: float,
        clock: Callable[[], float] = time.time,
        reason: str = "SLOT_IN_USE",
        message: str = "another operation is already in progress; only one runs at a time.",
        refuse: Callable[[str, str, dict[str, Any]], Exception] | None = None,
    ) -> None:
        self._store = store
        self._key = key
        self._stale = float(stale_after_s)
        self._clock = clock
        self._reason = reason
        self._message = message
        self._refuse = refuse or _precondition

    @property
    def path(self) -> Any:
        return self._store.path(self._key)

    def reserve(self, *, meta: dict[str, Any] | None = None) -> Reservation:
        """Reserve the single slot, or raise while a live one is held. The primitive has
        already dropped any slot older than ``stale_after_s`` before ``admit`` runs, so a
        crashed holder is reclaimed and its later release is a stale no-op. An unusable
        store surfaces as :class:`~.errors.StateUnavailable` (fail closed)."""

        def admit(ledger: SingleSlotLedger) -> None:
            if ledger.reservations:
                slot = next(iter(ledger.reservations.values()))
                raise self._refuse(
                    self._message, self._reason, {"since_epoch": int(slot.reserved_at)}
                )

        return self._store.reserve(self._key, admit, meta=meta, stale_after_s=self._stale)

    def clear(self) -> None:
        self._store.clear(self._key)

    def status(self) -> dict[str, Any]:
        """A non-secret snapshot. Never raises, never blocks (lock-free read)."""
        try:
            ledger = self._store.load(self._key)
        except StateUnavailable as exc:
            return {"in_flight": None, "reason": str(exc), "path": str(self.path)}
        now = float(self._clock())
        live = [
            slot
            for slot in (ledger.reservations.values() if ledger else [])
            if 0.0 <= now - slot.reserved_at < self._stale
        ]
        held = live[0] if live else None
        return {
            "in_flight": bool(live),
            "since_epoch": int(held.reserved_at) if held else None,
            "path": str(self.path),
        }


class MinInterval:
    """Reserve-before-act minimum-interval rate limiter.

    ``reserve`` is refused (by default :class:`~.errors.PreconditionFailed`) while an
    attempt is already in flight OR less than ``min_interval_s`` has elapsed since the
    last *completed* action; ``release(SUCCESS)`` records the completion (starting the
    window), while any other outcome leaves the window untouched (the action was not
    carried out).
    """

    def __init__(
        self,
        store: ReservationStore[IntervalLedger],
        key: str,
        *,
        min_interval_s: float,
        clock: Callable[[], float] = time.time,
        reason: str = "RATE_LIMITED",
        refuse: Callable[[str, str, dict[str, Any]], Exception] | None = None,
    ) -> None:
        self._store = store
        self._key = key
        self._interval = max(0.0, float(min_interval_s))
        self._clock = clock
        self._reason = reason
        self._refuse = refuse or _precondition

    @property
    def path(self) -> Any:
        return self._store.path(self._key)

    @property
    def min_interval_s(self) -> float:
        return self._interval

    def _next_allowed(self, ledger: IntervalLedger | None, now: float) -> float:
        if ledger is None or ledger.last_completed_at is None:
            return now
        return ledger.last_completed_at + self._interval

    def reserve(self, *, meta: dict[str, Any] | None = None) -> Reservation:
        """Reserve one action before it is sent, or raise (in-flight, or within the
        window); an unusable store surfaces as :class:`~.errors.StateUnavailable` (fail
        closed) - always before the action leaves the process."""

        def admit(ledger: IntervalLedger) -> None:
            now = float(self._clock())
            if ledger.reservations:
                raise self._refuse(
                    "refused: another action is already in progress for this key.",
                    self._reason,
                    {"retry_after_s": self._interval},
                )
            next_allowed = self._next_allowed(ledger, now)
            if now < next_allowed:
                raise self._refuse(
                    f"refused: rate-limited. Try again in {next_allowed - now:.0f}s.",
                    self._reason,
                    {"retry_after_s": next_allowed - now, "next_allowed": next_allowed},
                )

        def mutate(
            ledger: IntervalLedger, outcome: Outcome, kwargs: dict[str, Any]
        ) -> IntervalLedger:
            if outcome is Outcome.SUCCESS:
                return ledger.model_copy(update={"last_completed_at": float(self._clock())})
            # FAILURE / BUSY / ABORT: the action was not carried out; window untouched.
            return ledger

        return self._store.reserve(self._key, admit, mutate, meta=meta)

    def clear(self) -> None:
        self._store.clear(self._key)

    def status(self) -> dict[str, Any]:
        """A non-secret snapshot. Never raises, never blocks (lock-free read)."""
        try:
            ledger = self._store.load(self._key)
        except StateUnavailable as exc:
            return {"allowed": False, "reason": str(exc), "min_interval_s": self._interval}
        now = float(self._clock())
        next_allowed = self._next_allowed(ledger, now)
        in_flight = bool(ledger and ledger.reservations)
        return {
            "allowed": now >= next_allowed and not in_flight,
            "last_completed_at": ledger.last_completed_at if ledger else None,
            "next_allowed": next_allowed,
            "retry_after_s": max(0.0, next_allowed - now),
            "min_interval_s": self._interval,
            "in_flight": in_flight,
        }


def _precondition(message: str, reason: str, context: dict[str, Any]) -> Exception:
    """Default refusal: a :class:`~.errors.PreconditionFailed` carrying the reason."""
    return PreconditionFailed(message, reason=reason, context=context)


def single_slot_store(
    state_dir: Any,
    *,
    clock: Callable[[], float] = time.time,
    lock_timeout_s: float = 5.0,
) -> ReservationStore[SingleSlotLedger]:
    """A store for :class:`SingleSlot` ledgers under ``state_dir``."""

    def make_default(key: str, epoch: int) -> SingleSlotLedger:
        return SingleSlotLedger(key=key, epoch=epoch, reservations={}, last_update=float(clock()))

    return ReservationStore(
        state_dir,
        SingleSlotLedger,
        make_default=make_default,
        clock=clock,
        lock_timeout_s=lock_timeout_s,
    )


def min_interval_store(
    state_dir: Any,
    *,
    clock: Callable[[], float] = time.time,
    lock_timeout_s: float = 5.0,
) -> ReservationStore[IntervalLedger]:
    """A store for :class:`MinInterval` ledgers under ``state_dir``."""

    def make_default(key: str, epoch: int) -> IntervalLedger:
        return IntervalLedger(
            key=key,
            epoch=epoch,
            reservations={},
            last_completed_at=None,
            last_update=float(clock()),
        )

    return ReservationStore(
        state_dir,
        IntervalLedger,
        make_default=make_default,
        clock=clock,
        lock_timeout_s=lock_timeout_s,
    )
