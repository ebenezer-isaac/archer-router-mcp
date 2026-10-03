"""Device-agnostic persisted state: one fact, one owner, one atomic step.

Every single-fact device safety (the login budget, one export at a time, a reboot
rate-limit, a PoE cycle) is "read a shared fact, decide, write it", and split into two
unserialised steps on a trusted file it grows the same faults: a cross-process lost
update, a wrongly-typed field coerced to something permissive, a store found unwritable
only *after* the decision said yes (fail open), and an anonymous count any release can
zero from under a live holder. This module removes all of them with **one** primitive -
:class:`ReservationStore` named slots over strict, atomically-written JSON
(:func:`read_state`/:func:`write_state`): admit-and-insert-a-slot is one locked write (opening the
``<key>.lock`` to write is the writability proof); a release frees only its own id and
is a stale no-op once the ``epoch`` moves on; ``clear`` is one locked section and the
``epoch`` is a monotonic high-water mark in ``<key>.epoch``; ``load`` takes no lock.
``LoginBreaker`` and ``core.slot`` are thin policies over it.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Generic, TypeVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .errors import StateUnavailable

log = logging.getLogger(__name__)

# --- platform advisory file lock (one implementation chosen once at import) -----
if os.name == "nt":  # pragma: no cover - selected per platform; POSIX path on CI
    import msvcrt

    def _try_lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:  # pragma: no cover - selected per platform; Windows path on the dev host
    import fcntl

    def _try_lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


M = TypeVar("M", bound="SlotLedger")

DEFAULT_LOCK_TIMEOUT_S = 5.0
_LOCK_POLL_S = 0.01
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)


class Outcome(StrEnum):
    """How a reservation ended. Only an explicit ``SUCCESS`` counts as success."""

    SUCCESS = "success"
    FAILURE = "failure"
    BUSY = "busy"
    ABORT = "abort"


def ensure_dir(path: Path) -> None:
    """Create ``path`` and every missing parent ``0o700`` (explicit walk); raise on a file."""
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        if cursor.parent == cursor:  # pragma: no cover - filesystem root always exists
            break
        cursor = cursor.parent
    try:
        for directory in reversed(missing):
            directory.mkdir(mode=0o700, exist_ok=True)
        if not path.is_dir():
            raise StateUnavailable(f"state path {path} exists but is not a directory")
    except OSError as exc:
        raise StateUnavailable(
            f"cannot create state directory {path}: {type(exc).__name__}"
        ) from exc


def _atomic_write(path: Path, write_body: Callable[[Any], None]) -> None:
    """Atomic write: sibling tmp (``0o600``) + ``os.replace``; unlink tmp on error; raise on
    failure. The parent dir must exist (callers ``ensure_dir`` first)."""
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, _WRITE_FLAGS, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            write_body(handle)
        os.replace(tmp, path)
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise StateUnavailable(
            f"{path} could not be written ({type(exc).__name__}); refusing (fail closed)"
        ) from exc


class Slot(BaseModel):
    """One live reservation (``reserved_at`` + non-secret ``meta``); the reserved count is the
    slot count, so a release frees only its own slot."""

    model_config = ConfigDict(strict=True, extra="forbid")

    reserved_at: Annotated[float, Field(allow_inf_nan=False)]
    meta: dict[str, Any] = Field(default_factory=dict)


class SlotLedger(BaseModel):
    """Base of every ledger: epoch + named slots. Subclasses add ``version``, ``key`` and policy
    fields; the primitive touches only ``epoch``/``reservations``/``last_update``."""

    model_config = ConfigDict(strict=True, extra="forbid")

    epoch: int = Field(default=0, ge=0)
    reservations: dict[str, Slot] = Field(default_factory=dict)
    last_update: Annotated[float, Field(allow_inf_nan=False)]

    @property
    def reserved(self) -> int:
        return len(self.reservations)


def slot_is_live(reserved_at: float, stale_after_s: float | None, now: float) -> bool:
    """True while a slot blocks: no policy, or age in ``[0, window)``; a negative age is dead."""
    if stale_after_s is None:
        return True
    age = now - reserved_at
    return 0.0 <= age < stale_after_s


def read_state(path: Path, model_cls: type[M]) -> M | None:
    """The strictly-validated model at ``path``, or ``None`` if absent. Any other failure
    (unreadable, bad JSON, wrong types, unknown version, non-object) raises
    :class:`StateUnavailable` (fail closed) - never a raw exception or a coerced value."""
    try:
        raw = path.read_text("utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StateUnavailable(f"{path} is unreadable ({type(exc).__name__})") from exc
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise StateUnavailable(f"{path} is not valid JSON; refusing") from exc
    if not isinstance(data, dict):
        raise StateUnavailable(f"{path} is not a JSON object; refusing")
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        raise StateUnavailable(
            f"{path} does not match its schema ({exc.error_count()} error(s)); refusing"
        ) from exc


def write_state(path: Path, model: BaseModel) -> None:
    """Write ``model`` atomically, creating the ``0o700`` tree first; raise if unwritable."""
    ensure_dir(path.parent)
    payload = model.model_dump(mode="json")
    _atomic_write(path, lambda handle: json.dump(payload, handle, sort_keys=True))


class Reservation:
    """A committed, on-disk reservation awaiting its outcome. ``release`` applies the outcome
    under the lock once (repeats are no-ops); an unresolved context-manager exit records a
    **failure** (fail closed), so only an explicit ``release(SUCCESS)`` counts as success and
    a crash leaves the slot counting until cleared. ``release`` returns whether it was
    **stale** - its id is gone or the epoch moved on (a logged no-op; see :attr:`stale`)."""

    def __init__(self, resolver: Callable[[Outcome, dict[str, Any]], bool]) -> None:
        self._resolver = resolver
        self._resolved = False
        self._stale = False

    @property
    def resolved(self) -> bool:
        return self._resolved

    @property
    def stale(self) -> bool:
        return self._stale

    def release(self, outcome: Outcome, **kwargs: Any) -> bool:
        """Apply ``outcome`` once; return True if it was a stale no-op."""
        if self._resolved:
            return self._stale
        self._resolved = True
        self._stale = bool(self._resolver(outcome, kwargs))
        return self._stale

    def __enter__(self) -> Reservation:
        return self

    def __exit__(self, *exc: object) -> bool:
        if not self._resolved:
            self.release(Outcome.FAILURE)
        return False


# ``make_default(key, epoch)`` builds a fresh ledger; ``mutate`` applies a release-time
# update to the slot-removed ledger; ``admit`` raises (or returns False) to deny.
MakeDefault = Callable[[str, int], M]
Mutate = Callable[[M, Outcome, dict[str, Any]], M]
Admit = Callable[[M], Any]


class ReservationStore(Generic[M]):
    """Cross-process named-slot reservations over per-key strict JSON files.

    One store serves many keys (``<key>.json`` + ``<key>.lock`` + ``<key>.epoch`` each).
    ``make_default(key, epoch)`` builds the empty ledger; the policy's ``admit``/``mutate``
    decide admission and outcome; the store owns the slots, lock, epoch mark and file I/O."""

    def __init__(
        self,
        state_dir: Path,
        model_cls: type[M],
        *,
        make_default: MakeDefault[M],
        clock: Callable[[], float] = time.time,
        lock_timeout_s: float = DEFAULT_LOCK_TIMEOUT_S,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._model_cls = model_cls
        self._make_default = make_default
        self._clock = clock
        self._timeout = max(0.0, float(lock_timeout_s))

    def path(self, key: str) -> Path:
        return self._state_dir / f"{key}.json"

    def _read(self, key: str) -> M | None:
        return read_state(self.path(key), self._model_cls)

    def _lock_path(self, key: str) -> Path:
        return self._state_dir / f"{key}.lock"

    def _epoch_path(self, key: str) -> Path:
        return self._state_dir / f"{key}.epoch"

    @contextlib.contextmanager
    def _locked(self, key: str) -> Any:
        ensure_dir(self._state_dir)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(self._lock_path(key), flags, 0o600)
        except OSError as exc:
            raise StateUnavailable(
                f"cannot open lock file {self._lock_path(key)} ({type(exc).__name__}); the "
                "store is unwritable, refusing (fail closed)"
            ) from exc
        try:
            self._acquire(fd, key)
            try:
                yield
            finally:
                with contextlib.suppress(OSError):
                    _unlock(fd)
        finally:
            os.close(fd)

    def _acquire(self, fd: int, key: str) -> None:
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                _try_lock(fd)
                return
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise StateUnavailable(
                        f"lock {self._lock_path(key)} is held by another process and did not "
                        f"free within {self._timeout:g}s; refusing a concurrent attempt"
                    ) from exc
                time.sleep(_LOCK_POLL_S)

    def _read_high_water(self, key: str) -> int:
        try:
            return int(self._epoch_path(key).read_text(encoding="utf-8").strip())
        except FileNotFoundError:
            return 0
        except (ValueError, OSError):  # pragma: no cover - external corruption of the mark
            log.warning("epoch high-water %s unreadable; treating as 0", self._epoch_path(key))
            return 0

    def _write_high_water(self, key: str, value: int) -> None:
        _atomic_write(self._epoch_path(key), lambda handle: handle.write(str(int(value))))

    def _read_or_fresh(self, key: str) -> M:
        """The current ledger, or a fresh one at the persisted high-water epoch."""
        current = self._read(key)
        if current is not None:
            return current
        return self._make_default(key, self._read_high_water(key))

    def load(self, key: str) -> M | None:
        """Read the ledger WITHOUT the lock (``None`` if absent), so a status read never blocks."""
        return self._read(key)

    def reserve(
        self,
        key: str,
        admit: Admit[M],
        mutate: Mutate[M] | None = None,
        *,
        meta: dict[str, Any] | None = None,
        stale_after_s: float | None = None,
    ) -> Reservation:
        """Admit-and-reserve atomically under the lock: load-or-fresh, drop slots older than
        ``stale_after_s`` (reclaim a crashed holder), ``admit`` (raises/returns ``False`` to
        deny), insert a uniquely-identified slot and persist - the insert **is** the
        admission, so two holders cannot both pass. The handle's ``release`` removes only its
        own id (stale no-op otherwise) and applies ``mutate`` to the policy fields."""
        with self._locked(key):
            now = float(self._clock())
            ledger = self._read_or_fresh(key)
            if stale_after_s is not None:
                live = {
                    rid: slot
                    for rid, slot in ledger.reservations.items()
                    if slot_is_live(slot.reserved_at, stale_after_s, now)
                }
                ledger = ledger.model_copy(update={"reservations": live})
            if admit(ledger) is False:
                raise StateUnavailable(f"reservation for {key} was refused by policy")
            res_id = uuid4().hex
            slots = {**ledger.reservations, res_id: Slot(reserved_at=now, meta=dict(meta or {}))}
            committed = ledger.model_copy(update={"reservations": slots, "last_update": now})
            write_state(self.path(key), committed)
            epoch = committed.epoch

        def resolver(outcome: Outcome, kw: dict[str, Any]) -> bool:
            return self._release(key, res_id, epoch, outcome, kw, mutate)

        return Reservation(resolver)

    def _release(
        self,
        key: str,
        res_id: str,
        epoch: int,
        outcome: Outcome,
        kwargs: dict[str, Any],
        mutate: Mutate[M] | None,
    ) -> bool:
        """Remove the slot ``res_id`` owns and apply ``mutate``; a stale id/epoch is a no-op."""
        try:
            with self._locked(key):
                ledger = self._read(key)
                if ledger is None or ledger.epoch != epoch or res_id not in ledger.reservations:
                    log.warning(
                        "reservation %s/%s release ignored as stale (cleared or reclaimed "
                        "while in flight); budget untouched",
                        key,
                        res_id,
                    )
                    return True
                now = float(self._clock())
                remaining = {r: s for r, s in ledger.reservations.items() if r != res_id}
                base = ledger.model_copy(update={"reservations": remaining, "last_update": now})
                write_state(self.path(key), mutate(base, outcome, kwargs) if mutate else base)
            return False
        except StateUnavailable:
            # The reserved slot is already on disk, so further reservations are refused
            # (fail closed) until the store is writable; do not raise on resolution.
            log.warning(
                "could not record a reservation outcome for %s; the reserved slot stays on "
                "disk and further reservations are refused until the store is writable",
                key,
            )
            return False

    def clear(self, key: str) -> None:
        """Reset ``key`` in ONE locked section: ``max`` of the high-water mark and the
        current ledger's epoch (0 if unreadable), ``+ 1`` to both the mark and a fresh
        ledger. Atomic (no reserve races its load/write apart), monotonic (the epoch never
        repeats), and always recovers (the fresh ledger is written without the old file)."""
        with self._locked(key):
            high_water = self._read_high_water(key)
            try:
                current = self._read(key)
                ledger_epoch = current.epoch if current else 0
            except StateUnavailable:
                ledger_epoch = 0
            new_epoch = max(high_water, ledger_epoch) + 1
            self._write_high_water(key, new_epoch)
            write_state(self.path(key), self._make_default(key, new_epoch))
