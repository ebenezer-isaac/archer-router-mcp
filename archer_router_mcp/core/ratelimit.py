"""A persisted, single-event rate limiter (device-agnostic).

Some operations must not be repeated too often — a device reboot above all. The
limiter keeps the timestamp of the last accepted event in a small JSON file under
the state directory, so the cooldown survives process restarts (a reboot a minute
ago must still block one just after the server is bounced). Writes are atomic
(temp file + ``os.replace``) and created ``0600``, mirroring the login breaker.

The caller supplies ``now`` (an injected clock), so the limiter holds no clock of
its own and is fully testable with a fake time source. A missing or unreadable
file means "no previous event" — the event is allowed — because the worst case of
reading it wrong is one extra reboot, never a stuck-forever state.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class RateLimiter:
    """File-backed minimum-interval gate for one named event.

    ``status(now)`` reports whether the event is allowed and when it next will be;
    ``record(now)`` persists the acceptance. Nothing here sleeps or blocks.
    """

    def __init__(self, state_dir: str | Path, filename: str, min_interval_s: float) -> None:
        self._path = Path(state_dir).expanduser() / filename
        self._min_interval = max(0.0, float(min_interval_s))

    @property
    def path(self) -> Path:
        return self._path

    @property
    def min_interval_s(self) -> float:
        return self._min_interval

    def last_time(self) -> float | None:
        """Timestamp of the last accepted event, or ``None`` if there is none."""
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return None
        if not isinstance(raw, dict):
            return None
        value = raw.get("last")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    def status(self, now: float) -> dict[str, Any]:
        """A JSON-safe summary: whether the event is allowed now and the next time."""
        last = self.last_time()
        next_allowed = now if last is None else last + self._min_interval
        allowed = now >= next_allowed
        return {
            "allowed": allowed,
            "last_time": last,
            "next_allowed": next_allowed,
            "retry_after_s": max(0.0, next_allowed - now),
            "min_interval_s": self._min_interval,
        }

    def record(self, now: float) -> None:
        """Persist ``now`` as the last accepted event (atomic, ``0600``)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"last": float(now)}, separators=(",", ":"))
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=".ratelimit-", suffix=".tmp"
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            with contextlib.suppress(OSError):
                os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
