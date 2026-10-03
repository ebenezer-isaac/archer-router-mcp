"""Presence store, pure diff logic (incl. property checks), sampler and tools.

All data is anonymised (RFC 7042 documentation MACs ``00:00:5E:00:53:xx``). The
diff logic and store are exercised directly (no network); the poll/history tools
run through the fake router.
"""

from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path

import pytest

from archer_router_mcp import server
from archer_router_mcp.presence import (
    PresenceSampler,
    PresenceStore,
    build_sample,
    diff_presence,
    router_client_history,
    router_poll_presence,
)
from tests.fakes import FakeRouter, build_components


def _mac(n: int) -> str:
    return f"00:00:5E:00:53:{n:02X}"


def _sample(ts: float, clients: dict[str, str | None]) -> dict:
    return {"ts": ts, "clients": {m: {"name": name, "ip": None} for m, name in clients.items()}}


# ------------------------------------------------------------- pure diff logic


def test_diff_join_leave_rename_and_nochange() -> None:
    prev = _sample(1.0, {_mac(1): "A", _mac(2): "B"})
    now = _sample(2.0, {_mac(2): "B2", _mac(3): "C"})
    events = diff_presence(prev, now)
    kinds = {(e["type"], e["mac"]) for e in events}
    assert ("join", _mac(3)) in kinds
    assert ("leave", _mac(1)) in kinds
    assert ("rename", _mac(2)) in kinds
    rename = next(e for e in events if e["type"] == "rename")
    assert rename["old_name"] == "B" and rename["new_name"] == "B2"
    assert all(e["ts"] == 2.0 for e in events)
    # No change yields no events.
    assert diff_presence(now, _sample(3.0, {_mac(2): "B2", _mac(3): "C"})) == []


def test_diff_rejects_clock_going_backwards() -> None:
    prev = _sample(5.0, {_mac(1): "A"})
    with pytest.raises(ValueError, match="backwards"):
        diff_presence(prev, _sample(4.0, {_mac(1): "A"}))


def test_diff_equal_timestamp_is_allowed() -> None:
    prev = _sample(5.0, {_mac(1): "A"})
    assert diff_presence(prev, _sample(5.0, {_mac(1): "A", _mac(2): "B"}))[0]["type"] == "join"


@pytest.mark.parametrize("seed", range(25))
def test_diff_properties_random(seed: int) -> None:
    rng = random.Random(seed)
    universe = [_mac(i) for i in range(12)]

    def rand_clients() -> dict[str, str | None]:
        return {m: rng.choice(["x", "y", "z", None]) for m in universe if rng.random() < 0.5}

    prev_c, now_c = rand_clients(), rand_clients()
    prev, now = _sample(1.0, prev_c), _sample(2.0, now_c)
    events = diff_presence(prev, now)
    joins = {e["mac"] for e in events if e["type"] == "join"}
    leaves = {e["mac"] for e in events if e["type"] == "leave"}
    renames = {e["mac"] for e in events if e["type"] == "rename"}
    # Partition invariants.
    assert joins == now_c.keys() - prev_c.keys()
    assert leaves == prev_c.keys() - now_c.keys()
    assert renames == {m for m in now_c.keys() & prev_c.keys() if prev_c[m] != now_c[m]}
    assert joins.isdisjoint(leaves)
    # Every event mac belongs to prev or now.
    assert all(e["mac"] in prev_c.keys() | now_c.keys() for e in events)
    # Applying membership deltas to prev reproduces now's membership.
    reconstructed = (prev_c.keys() | joins) - leaves
    assert reconstructed == now_c.keys()


def test_build_sample_carries_first_seen() -> None:
    prev = {"ts": 1.0, "clients": {_mac(1): {"name": "A", "first_seen": 1.0, "last_seen": 1.0}}}
    now = {_mac(1): {"name": "A", "ip": None}, _mac(2): {"name": "B", "ip": None}}
    sample = build_sample(prev, now, 9.0)
    assert sample["clients"][_mac(1)]["first_seen"] == 1.0  # carried from prev
    assert sample["clients"][_mac(1)]["last_seen"] == 9.0
    assert sample["clients"][_mac(2)]["first_seen"] == 9.0  # new device: first=now


# ------------------------------------------------------------------- the store


def test_store_append_and_read_filters(tmp_path: Path) -> None:
    store = PresenceStore(tmp_path)
    store.append_events(
        [
            {"type": "join", "mac": _mac(1), "ts": 10.0},
            {"type": "leave", "mac": _mac(2), "ts": 20.0},
            {"type": "join", "mac": _mac(1), "ts": 30.0},
        ]
    )
    events, skipped = store.read_events()
    assert skipped == 0 and len(events) == 3
    since, _ = store.read_events(since=15.0)
    assert {e["ts"] for e in since} == {20.0, 30.0}
    one_mac, _ = store.read_events(mac="00-00-5e-00-53-01")
    assert all(e["mac"] == _mac(1) for e in one_mac) and len(one_mac) == 2
    limited, _ = store.read_events(limit=1)
    assert len(limited) == 1 and limited[0]["ts"] == 30.0


def test_store_rotation_bounds_history(tmp_path: Path) -> None:
    store = PresenceStore(tmp_path, max_mb=0.00005)  # ~52 bytes: forces rotation
    for i in range(4):
        store.append_events([{"type": "join", "mac": _mac(i), "ts": float(i)}])
    events, _ = store.read_events()
    # One rotated generation + current file: oldest events are dropped, newest kept.
    assert len(events) <= 2
    assert events[-1]["ts"] == 3.0
    assert (tmp_path / "presence.jsonl.1").exists()


def test_store_skips_and_counts_corrupt_lines(tmp_path: Path) -> None:
    store = PresenceStore(tmp_path)
    store.append_events([{"type": "join", "mac": _mac(1), "ts": 1.0}])
    with open(store.log_path, "a", encoding="utf-8") as handle:
        handle.write("this is not json\n")
        handle.write(json.dumps({"no_ts": True}) + "\n")  # missing required keys
        handle.write(json.dumps({"type": "leave", "mac": _mac(1), "ts": 2.0}) + "\n")
    events, skipped = store.read_events()
    assert skipped == 2
    assert [e["ts"] for e in events] == [1.0, 2.0]


def test_store_sample_roundtrip_and_corruption(tmp_path: Path) -> None:
    store = PresenceStore(tmp_path)
    assert store.load_sample() is None
    sample = {"ts": 1.0, "clients": {_mac(1): {"name": "A"}}}
    store.save_sample(sample)
    assert store.load_sample() == sample
    (tmp_path / "presence_sample.json").write_text("{corrupt", encoding="utf-8")
    assert store.load_sample() is None  # corrupt snapshot ignored, never raised


# --------------------------------------------------------------- poll / history

CLIENT_READS: dict[str, object] = {
    "game_accelerator": {
        "data": [
            {"mac": _mac(0x11), "deviceName": "Phone", "deviceTag": "5G", "ip": "192.0.2.11"},
            {"mac": _mac(0x12), "deviceName": "PC", "deviceTag": "wired", "ip": "192.0.2.12"},
        ]
    },
    "mesh_sclient_list_all": {"data": []},
    "network_map": {"data": []},
    "client": {"data": []},
    "client_list": {"data": []},
}


def _poll_components(tmp_path: Path, clock):
    fake = FakeRouter(envelope="https-plain", reads={k: v for k, v in CLIENT_READS.items()})
    c = build_components(fake, envelope="https-plain", state_dir=tmp_path, clock=clock)
    return fake, c


async def test_poll_presence_first_run_emits_joins(tmp_path: Path) -> None:
    ticks = iter([100.0, 101.0, 102.0])
    _fake, c = _poll_components(tmp_path, lambda: next(ticks))
    try:
        env = await router_poll_presence(c)
        assert env["success"] is True
        assert env["data"]["event_count"] == 2
        assert {e["type"] for e in env["data"]["events"]} == {"join"}
    finally:
        await c.aclose()


async def test_poll_detects_leave_and_rename(tmp_path: Path) -> None:
    times = iter([100.0, 200.0, 300.0])
    fake, c = _poll_components(tmp_path, lambda: next(times))
    try:
        await router_poll_presence(c)  # joins for Phone + PC
        # Phone renamed, PC leaves.
        fake._reads["game_accelerator"] = {
            "data": [{"mac": _mac(0x11), "deviceName": "Phone2", "deviceTag": "5G"}]
        }
        env = await router_poll_presence(c)
        kinds = {(e["type"], e["mac"]) for e in env["data"]["events"]}
        assert ("rename", _mac(0x11)) in kinds
        assert ("leave", _mac(0x12)) in kinds
    finally:
        await c.aclose()


async def test_poll_logs_out_after_sample(tmp_path: Path) -> None:
    from archer_router_mcp.presence import make_sampler

    times = iter([1.0, 2.0, 3.0, 4.0])
    _fake, c = _poll_components(tmp_path, lambda: next(times))
    try:
        sampler = make_sampler(c, 60.0)
        await sampler.tick()
        assert c.session.authenticated is False  # logged out after the sample
        assert sampler.ticks == 1
    finally:
        await c.aclose()


async def test_client_history_tool_filters(tmp_path: Path) -> None:
    _fake, c = _poll_components(tmp_path, lambda: 50.0)
    try:
        c.presence_store.append_events(
            [
                {"type": "join", "mac": _mac(1), "ts": 10.0},
                {"type": "join", "mac": _mac(2), "ts": 20.0},
            ]
        )
        env = await router_client_history(c, since=15.0)
        assert env["success"] is True
        assert env["data"]["count"] == 1
        assert env["data"]["events"][0]["mac"] == _mac(2)
        # Bad MAC -> INVALID_INPUT envelope, never an exception.
        bad = await router_client_history(c, mac="not-a-mac")
        assert bad["success"] is False and bad["error"]["code"] == "INVALID_INPUT"
        neg = await router_client_history(c, limit=-1)
        assert neg["success"] is False and neg["error"]["code"] == "INVALID_INPUT"
    finally:
        await c.aclose()


async def test_poll_presence_tool_via_server(tmp_path: Path) -> None:
    times = iter([1.0, 2.0])
    _fake, c = _poll_components(tmp_path, lambda: next(times))
    try:
        env = await server.router_poll_presence(c)
        assert env["success"] is True
        hist = await server.router_client_history(c)
        assert hist["data"]["count"] == 2
    finally:
        await c.aclose()


# ----------------------------------------------------------------- the sampler


async def test_sampler_tick_runs_poll() -> None:
    calls = []
    sampler = PresenceSampler(lambda: _noop(calls), 0.0)
    await sampler.tick()
    assert calls == [1] and sampler.ticks == 1


async def _noop(calls: list[int]) -> None:
    calls.append(1)


async def test_sampler_swallows_errors() -> None:
    async def boom() -> None:
        raise RuntimeError("sample failed")

    sampler = PresenceSampler(boom, 0.0)
    await sampler.tick()  # must not raise
    assert sampler.errors == 1 and sampler.ticks == 0


async def test_sampler_no_overlap() -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def poll() -> None:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()

    sampler = PresenceSampler(poll, 0.0)
    first = asyncio.create_task(sampler.tick())
    await started.wait()
    await sampler.tick()  # second tick while first still in flight -> skipped
    assert sampler.skipped == 1
    release.set()
    await first
    assert calls == 1


async def test_sampler_start_is_idempotent_and_stops_cleanly() -> None:
    forever = asyncio.Event()

    async def sleep(_seconds: float) -> None:
        await forever.wait()

    async def poll() -> None:  # pragma: no cover - never reached (parked in sleep)
        return None

    sampler = PresenceSampler(poll, 0.01, sleep=sleep)
    task = sampler.start()
    assert sampler.start() is task  # idempotent
    await asyncio.sleep(0)  # let the loop reach the (blocking) sleep
    await sampler.stop()
    assert task.done()
