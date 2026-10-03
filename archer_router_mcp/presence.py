"""File-backed presence history for the Archer AX53.

The router keeps no per-client history, so this module builds one honestly: a
sampler reads the live client list, diffs it against the previous sample, and
appends the resulting join/leave/rename events to a size-capped JSON-lines log
under ``ARCHER_ROUTER_STATE_DIR``. ``first_seen``/``last_seen`` are only ever set
from real samples — nothing is back-filled or invented.

Nothing here contacts the device directly: the sampler is handed a ``poll``
coroutine. The diff logic (:func:`diff_presence`) and the store are pure/local and
fully testable without a network.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .core.errors import InvalidInput
from .core.tooling import run_tool
from .normalize import normalize_mac

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .server import Components

log = logging.getLogger(__name__)

EVENT_JOIN = "join"
EVENT_LEAVE = "leave"
EVENT_RENAME = "rename"
DEFAULT_MAX_MB = 20.0
HISTORY_DEFAULT_LIMIT = 500
HISTORY_MAX_LIMIT = 10000

Sample = dict[str, Any]  # {"ts": float, "clients": {mac: {"name","ip",...}}}
Event = dict[str, Any]


# --------------------------------------------------------------- pure diff logic


def diff_presence(prev: Sample, now: Sample) -> list[Event]:
    """Return the join/leave/rename events between two samples (pure).

    ``prev`` and ``now`` are samples ``{"ts": float, "clients": {mac: {...}}}``.
    A client present in ``now`` but not ``prev`` is a ``join``; present in ``prev``
    but not ``now`` is a ``leave``; present in both with a changed ``name`` is a
    ``rename``. Every event is stamped with ``now["ts"]``. Raises ``ValueError``
    if ``now`` precedes ``prev`` (the clock must be monotonic). Identical samples
    yield ``[]``.
    """
    prev_ts = float(prev.get("ts", 0.0))
    now_ts = float(now.get("ts", 0.0))
    if now_ts < prev_ts:
        raise ValueError("presence sample clock went backwards (now precedes prev)")
    prev_clients: dict[str, Any] = dict(prev.get("clients") or {})
    now_clients: dict[str, Any] = dict(now.get("clients") or {})
    events: list[Event] = []
    for mac in sorted(now_clients.keys() - prev_clients.keys()):
        info = now_clients[mac]
        events.append(_event(EVENT_JOIN, mac, now_ts, name=info.get("name"), ip=info.get("ip")))
    for mac in sorted(prev_clients.keys() - now_clients.keys()):
        info = prev_clients[mac]
        events.append(_event(EVENT_LEAVE, mac, now_ts, name=info.get("name"), ip=info.get("ip")))
    for mac in sorted(now_clients.keys() & prev_clients.keys()):
        old = prev_clients[mac].get("name")
        new = now_clients[mac].get("name")
        if old != new:
            events.append(
                _event(
                    EVENT_RENAME,
                    mac,
                    now_ts,
                    old_name=old,
                    new_name=new,
                    ip=now_clients[mac].get("ip"),
                )
            )
    return events


def _event(kind: str, mac: str, ts: float, **extra: Any) -> Event:
    event: Event = {"type": kind, "mac": mac, "ts": ts}
    event.update({k: v for k, v in extra.items() if v is not None})
    return event


def build_sample(prev: Sample, now_clients: dict[str, Any], ts: float) -> Sample:
    """Fold a fresh client set into a sample, carrying ``first_seen`` from ``prev``."""
    prev_clients: dict[str, Any] = dict(prev.get("clients") or {})
    clients: dict[str, Any] = {}
    for mac, info in now_clients.items():
        existing = prev_clients.get(mac) or {}
        first_seen = existing.get("first_seen", ts)
        clients[mac] = {
            "name": info.get("name"),
            "ip": info.get("ip"),
            "first_seen": first_seen,
            "last_seen": ts,
        }
    return {"ts": ts, "clients": clients}


# ------------------------------------------------------------------- the store


class PresenceStore:
    """A size-capped JSON-lines event log plus a single last-sample snapshot.

    Appends are atomic per line; when the log would exceed ``max_bytes`` it is
    rotated to ``*.1`` (one generation kept) so history stays bounded. Corrupt
    lines are skipped and counted on read, never raised.
    """

    def __init__(self, state_dir: str | Path, *, max_mb: float = DEFAULT_MAX_MB) -> None:
        self._dir = Path(state_dir).expanduser()
        self._log = self._dir / "presence.jsonl"
        self._rotated = self._dir / "presence.jsonl.1"
        self._sample = self._dir / "presence_sample.json"
        self._max_bytes = max(1, int(max_mb * 1024 * 1024))

    @property
    def log_path(self) -> Path:
        return self._log

    def append_events(self, events: list[Event]) -> None:
        if not events:
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        for event in events:
            line = json.dumps(event, sort_keys=True) + "\n"
            encoded = line.encode("utf-8")
            if self._log.exists() and self._log.stat().st_size + len(encoded) > self._max_bytes:
                os.replace(self._log, self._rotated)
            with open(self._log, "a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())

    def read_events(
        self,
        *,
        since: float = 0.0,
        mac: str | None = None,
        limit: int = HISTORY_DEFAULT_LIMIT,
    ) -> tuple[list[Event], int]:
        """Return ``(events, malformed_skipped)`` oldest-first, newest ``limit`` kept."""
        want_mac = normalize_mac(mac) if mac else None
        events: list[Event] = []
        skipped = 0
        for path in (self._rotated, self._log):
            if not path.exists():
                continue
            for raw in path.read_text(encoding="utf-8").splitlines():
                if not raw.strip():
                    continue
                try:
                    event = json.loads(raw)
                except ValueError:
                    skipped += 1
                    continue
                if not isinstance(event, dict) or "ts" not in event or "mac" not in event:
                    skipped += 1
                    continue
                if float(event.get("ts", 0.0)) < since:
                    continue
                if want_mac is not None and event.get("mac") != want_mac:
                    continue
                events.append(event)
        if limit >= 0:
            events = events[-limit:]
        return events, skipped

    def load_sample(self) -> Sample | None:
        if not self._sample.exists():
            return None
        try:
            data = json.loads(self._sample.read_text(encoding="utf-8"))
        except ValueError:
            log.warning("presence sample file was corrupt; ignoring it")
            return None
        return data if isinstance(data, dict) else None

    def save_sample(self, sample: Sample) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._dir, prefix=".sample-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(sample, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._sample)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)


# ----------------------------------------------------------------- the sampler


class PresenceSampler:
    """Runs ``poll`` every ``interval_s`` seconds, never overlapping, never crashing.

    Designed for :func:`archer_router_mcp.server.serve`: the loop sleeps, then
    ticks; a tick already in flight is skipped (no overlap); any error from
    ``poll`` is logged and swallowed so the server stays up. ``sleep`` is injected
    so tests can drive it with a fake clock.
    """

    def __init__(
        self,
        poll: Callable[[], Awaitable[Any]],
        interval_s: float,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._poll = poll
        self._interval = interval_s
        self._sleep = sleep
        self._in_flight = False
        self._stopped = False
        self._task: asyncio.Task[None] | None = None
        self.ticks = 0
        self.skipped = 0
        self.errors = 0

    async def tick(self) -> None:
        if self._in_flight:
            self.skipped += 1
            log.debug("presence sampler skipped a tick: previous sample still in flight")
            return
        self._in_flight = True
        try:
            await self._poll()
            self.ticks += 1
        except Exception:
            self.errors += 1
            log.exception("presence sample failed; will retry next interval")
        finally:
            self._in_flight = False

    async def _loop(self) -> None:
        while not self._stopped:
            await self._sleep(self._interval)
            if self._stopped:
                break
            await self.tick()

    def start(self) -> asyncio.Task[None]:
        if self._task is None:
            self._stopped = False
            self._task = asyncio.create_task(self._loop())
        return self._task

    async def stop(self) -> None:
        self._stopped = True
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass  # expected: we just cancelled it
        except Exception:
            log.exception("presence sampler raised during shutdown")


# --------------------------------------------------------------------- tools


async def poll_presence(components: Components) -> list[Event]:
    """One sample: read the live clients, diff against the last sample, persist.

    Returns the events produced. Raises on a read/parse failure so the caller's
    envelope (or the sampler's error handling) can report it.
    """
    from .tools.reads import read_online_clients

    ts = components.clock()
    online = await read_online_clients(components)
    now_clients = {c["mac"]: {"name": c.get("name"), "ip": c.get("ip")} for c in online}
    store = components.presence_store
    prev = store.load_sample() or {"ts": ts, "clients": {}}
    events = diff_presence(prev, {"ts": ts, "clients": now_clients})
    store.append_events(events)
    store.save_sample(build_sample(prev, now_clients, ts))
    return events


async def router_poll_presence(components: Components) -> dict[str, Any]:
    """Take one presence sample and append any join/leave/rename events to the log.

    Read-only against the router (one client-list read); writes only to the local
    presence store. Returns the events produced and the online count. Intended to
    be called on a schedule (see ``ARCHER_ROUTER_PRESENCE_INTERVAL_S``).
    """

    async def _run() -> dict[str, Any]:
        events = await poll_presence(components)
        return {"events": events, "event_count": len(events)}

    return await run_tool("router_poll_presence", _run)


async def router_client_history(
    components: Components,
    *,
    since: float = 0.0,
    mac: str | None = None,
    limit: int = HISTORY_DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Return recorded presence events (join/leave/rename) from the local log.

    ``since`` is a Unix timestamp lower bound; ``mac`` filters to one device;
    ``limit`` caps the number returned (newest kept). History comes only from past
    samples — this performs no router I/O and invents nothing.
    """

    async def _run() -> dict[str, Any]:
        if not isinstance(since, (int, float)) or isinstance(since, bool):
            raise InvalidInput("since must be a Unix timestamp (number)")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise InvalidInput("limit must be a non-negative integer")
        want = normalize_mac(mac) if mac else None
        if mac and want is None:
            raise InvalidInput("mac is not a valid MAC address")
        capped = min(limit, HISTORY_MAX_LIMIT)
        events, skipped = components.presence_store.read_events(
            since=float(since), mac=want, limit=capped
        )
        return {
            "events": events,
            "count": len(events),
            "malformed_skipped": skipped,
            "since": float(since),
            "mac": want,
        }

    return await run_tool("router_client_history", _run)


def make_sampler(components: Components, interval_s: float) -> PresenceSampler:
    """Build a sampler that polls and then logs out after each sample."""

    async def _poll() -> None:
        try:
            await poll_presence(components)
        finally:
            await components.session.logout()

    return PresenceSampler(_poll, interval_s)


def now_clock() -> float:
    return time.time()
