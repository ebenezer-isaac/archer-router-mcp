"""Device-agnostic persisted state: one fact, one owner, one atomic step.

Several device safeties are "read a shared fact, decide, then write it": the login
budget, an export that must run one-at-a-time, a reboot rate-limit, a PoE cycle in
progress. Kept as two unserialised steps on a file whose type and writability are
trusted, each grows the same three faults: a lost update between two processes, a
wrongly-typed field that coerces to a permissive value, and a store that is only
discovered unwritable *after* the decision already said yes (fail open).

This module removes all three by construction:

* :class:`AtomicStateFile` is the only writer/reader of a state file. It validates
  against a strict pydantic schema (``strict=True, extra="forbid"`` plus a
  ``version``) on every load, so ``false`` never becomes ``0`` and an unknown shape
  is refused, never coerced. It writes tmp-file + ``os.replace`` (atomic) with the
  file ``0o600`` and the directory tree ``0o700`` (an explicit parent walk, not
  only the leaf). Any load failure raises :class:`StateUnavailable` (fail closed).
* :class:`ReservationStore` serialises the whole load -> decide -> increment ->
  write sequence for one key under a cross-process advisory lock on a dedicated
  ``<key>.lock`` file (``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows).
  **Taking the lock requires opening that file for writing, which is the
  writability proof**: an unwritable store fails at admit time, before any
  reservation, and admit-time failure is refusal. ``reserve`` increments the
  reserved count under the lock *before* returning, so the increment **is** the
  admission and two holders cannot both pass. A :class:`Reservation` that is never
  resolved (crash, dropped handle, or an unresolved ``with`` block) leaves its
  increment on disk and counts against the budget until cleared (fail closed).

``LoginBreaker`` is a thin policy over :class:`ReservationStore`; the export serial
lock and the other single-fact safeties are the same store with a different schema.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ValidationError

from .errors import StateUnavailable

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


M = TypeVar("M", bound=BaseModel)

DEFAULT_LOCK_TIMEOUT_S = 5.0
_LOCK_POLL_S = 0.01


class Outcome(StrEnum):
    """How a reservation ended. Only an explicit ``SUCCESS`` counts as success."""

    SUCCESS = "success"
    FAILURE = "failure"
    BUSY = "busy"
    ABORT = "abort"


def ensure_dir(path: Path) -> None:
    """Create ``path`` and every missing parent with mode ``0o700`` (explicit walk).

    ``Path.mkdir(parents=True)`` applies the mode only to the leaf; here each
    intermediate directory that this call creates is created ``0o700`` too, so no
    state directory is ever left group/other-accessible. Raises ``StateUnavailable``
    if the tree cannot be created or a parent is not a directory.
    """
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


class AtomicStateFile(Generic[M]):
    """One strictly-validated JSON file, read and written atomically.

    ``model_cls`` must be a pydantic model with ``strict=True, extra="forbid"`` and
    a ``version`` field; the model enforces the type of every field, so a load never
    coerces (``false`` stays a ``bool`` and is rejected where an ``int`` is wanted).
    """

    def __init__(self, path: Path, model_cls: type[M]) -> None:
        self._path = Path(path)
        self._model_cls = model_cls

    @property
    def path(self) -> Path:
        return self._path

    def read(self) -> M | None:
        """Return the validated model, or ``None`` if the file does not exist.

        Any other failure - unreadable, invalid JSON, wrong types, unknown version,
        not an object - raises :class:`StateUnavailable` (fail closed), never a raw
        exception and never a coerced value.
        """
        try:
            raw = self._path.read_text("utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StateUnavailable(
                f"state file {self._path} is unreadable ({type(exc).__name__}); refusing"
            ) from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise StateUnavailable(
                f"state file {self._path} is not valid JSON; refusing (fail closed)"
            ) from exc
        if not isinstance(data, dict):
            raise StateUnavailable(f"state file {self._path} is not a JSON object; refusing")
        try:
            return self._model_cls.model_validate(data)
        except ValidationError as exc:
            raise StateUnavailable(
                f"state file {self._path} does not match its schema "
                f"({exc.error_count()} error(s)); refusing (fail closed)"
            ) from exc

    def write(self, model: M) -> None:
        """Write ``model`` atomically: tmp file (``0o600``) + ``os.replace``.

        The directory tree is created ``0o700`` first; the tmp file is unlinked on
        any error and the live file is left untouched. Raises ``StateUnavailable``
        if the store cannot be written (fail closed).
        """
        ensure_dir(self._path.parent)
        tmp = self._path.with_name(f"{self._path.name}.{os.getpid()}.tmp")
        payload = model.model_dump(mode="json")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(tmp, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
            os.replace(tmp, self._path)
        except OSError as exc:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
            raise StateUnavailable(
                f"state file {self._path} could not be written ({type(exc).__name__}); "
                "refusing (fail closed)"
            ) from exc

    def unlink(self) -> None:
        """Remove the state file if present. Raises ``StateUnavailable`` on error."""
        try:
            self._path.unlink(missing_ok=True)
        except OSError as exc:
            raise StateUnavailable(
                f"state file {self._path} could not be removed ({type(exc).__name__})"
            ) from exc


class Reservation:
    """A committed, on-disk reservation awaiting its outcome.

    ``release`` applies the outcome under the lock exactly once (repeat calls are
    no-ops). As a context manager an unresolved exit records a **failure** (fail
    closed), so only an explicit ``release(SUCCESS)`` ever counts as a success and a
    crash between reserve and release leaves the reservation counting against the
    budget until it is cleared.

    The resolver returns whether the release was **stale** - a reservation whose slot
    no longer exists (e.g. the store was cleared after it was taken). A stale release
    is a logged no-op that never touches a current holder; ``release`` surfaces it as
    its return value and on :attr:`stale`.
    """

    def __init__(self, resolver: Callable[[Outcome, dict[str, Any]], bool]) -> None:
        self._resolver = resolver
        self._resolved = False
        self._stale = False

    @property
    def resolved(self) -> bool:
        return self._resolved

    @property
    def stale(self) -> bool:
        """True once a stale (slot-no-longer-present) release has been applied."""
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


class ReservationStore:
    """Cross-process reservations over one :class:`AtomicStateFile`.

    ``make_default`` builds the empty ledger used when no file exists yet. The
    ledger model must expose an integer ``reserved`` field; the ``admit`` and
    ``resolve`` callbacks (supplied by the policy layer, e.g. ``LoginBreaker``)
    decide what else a reservation means. All file access happens under the
    per-key lock.
    """

    def __init__(
        self,
        state_dir: Path,
        name: str,
        model_cls: type[M],
        *,
        make_default: Callable[[], M],
        lock_timeout_s: float = DEFAULT_LOCK_TIMEOUT_S,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._file: AtomicStateFile[M] = AtomicStateFile(
            self._state_dir / f"{name}.json", model_cls
        )
        self._lock_path = self._state_dir / f"{name}.lock"
        self._make_default = make_default
        self._timeout = max(0.0, float(lock_timeout_s))

    @property
    def path(self) -> Path:
        return self._file.path

    @contextlib.contextmanager
    def _locked(self) -> Any:
        """Hold the cross-process lock; opening the lock file proves writability.

        Raises ``StateUnavailable`` if the lock file cannot be opened (unwritable
        store) or the lock cannot be acquired within the timeout (busy). Never
        proceeds unlocked.
        """
        ensure_dir(self._state_dir)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(self._lock_path, flags, 0o600)
        except OSError as exc:
            raise StateUnavailable(
                f"cannot open lock file {self._lock_path} for writing "
                f"({type(exc).__name__}); the store is unwritable, refusing (fail closed)"
            ) from exc
        try:
            self._acquire(fd)
            try:
                yield
            finally:
                with contextlib.suppress(OSError):
                    _unlock(fd)
        finally:
            os.close(fd)

    def _acquire(self, fd: int) -> None:
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                _try_lock(fd)
                return
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise StateUnavailable(
                        f"lock {self._lock_path} is held by another process and did not free "
                        f"within {self._timeout:g}s; refusing to risk a concurrent attempt"
                    ) from exc
                time.sleep(_LOCK_POLL_S)

    def load(self) -> M | None:
        """Read the ledger under the lock (``None`` if none written yet)."""
        with self._locked():
            return self._file.read()

    def reserve(
        self,
        admit: Callable[[M], M],
        resolve: Callable[[M, Outcome, dict[str, Any]], M],
    ) -> Reservation:
        """Admit-and-reserve atomically, then hand back a :class:`Reservation`.

        Under the lock: load (or default), apply ``admit`` (which raises to refuse,
        or returns the ledger with ``reserved`` incremented), and persist it. The
        returned reservation's ``release`` re-takes the lock and applies ``resolve``.
        """
        with self._locked():
            ledger = self._file.read() or self._make_default()
            committed = admit(ledger)
            self._file.write(committed)

        def _resolver(outcome: Outcome, kwargs: dict[str, Any]) -> bool:
            with self._locked():
                current = self._file.read() or self._make_default()
                self._file.write(resolve(current, outcome, kwargs))
            return False

        return Reservation(_resolver)

    def mutate(self, fn: Callable[[M | None], M]) -> M:
        """Atomic read-modify-write under the lock (for non-reservation facts)."""
        with self._locked():
            updated = fn(self._file.read())
            self._file.write(updated)
            return updated

    def set(self, model: M) -> None:
        """Overwrite the ledger under the lock WITHOUT reading it first.

        Recovery paths (e.g. ``breaker --clear``) use this so they succeed even when
        the current file is corrupt or of an unknown shape - a read-modify-write would
        refuse on such a file (fail closed), but a reset must always be able to
        replace it with a clean, current-schema ledger."""
        with self._locked():
            self._file.write(model)

    def clear(self) -> None:
        """Remove the ledger under the lock. The lock file itself is kept."""
        with self._locked():
            self._file.unlink()
