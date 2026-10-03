"""BREAKER r3 / writes — F1: INFERRED writes are NOT gated behind R0_UNCONFIRMED.

Claim under attack (verbatim): "writes marked INFERRED (``write_spf``, speed-limit
fields, schedule shape, isolate, wol) are gated behind ``R0_UNCONFIRMED`` so they
cannot be sent before the live capture confirms them."

Reality: only ``router_set_wifi`` (``write_spf``) consults ``wifi_write_confirmed()``
and refuses a live write with ``R0_UNCONFIRMED`` while the verified doc is missing.
``router_set_client_speed_limit``, ``router_set_wifi_schedule``,
``router_isolate_device`` and ``router_wol`` carry **no** R0 gate: with
``ALLOW_WRITES=true`` and ``confirm_write=True`` they send their guessed-field
bodies straight to the device even though the verified doc does not exist.

These tests assert the behaviour the claim promises (a live write of an INFERRED
tool is refused ``R0_UNCONFIRMED`` and nothing is sent). They FAIL against the
code, which issues the live write — proving the claim false.

Adversary reading: the tool arguments come from the LLM client; the operator has
turned writes on (required for the feature at all). So this is the ordinary live
path for these four tools, not a crafted edge.
"""

from __future__ import annotations

from pathlib import Path

from archer_router_mcp import server
from archer_router_mcp.tools._write_common import wifi_write_confirmed
from tests.fakes import FakeRouter, build_components

DEV2 = "00:00:5E:00:53:02"


def _components(tmp_path: Path):
    fake = FakeRouter(envelope="https-plain", stateful=True)
    extra = {
        "ARCHER_ROUTER_PROTECTED_MACS": "00:00:5E:00:53:AA",
        "ARCHER_ROUTER_ALLOW_WRITES": "true",
    }
    comps = build_components(fake, envelope="https-plain", state_dir=tmp_path, extra_env=extra)
    return fake, comps


def test_verified_doc_is_actually_missing() -> None:
    """Sanity: the whole premise is that R0 has not landed. If this ever fails,
    the other assertions here are moot (the doc exists, so writes are confirmed)."""
    root = Path(server.__file__).resolve().parents[1]
    doc = root / "docs" / "protocol" / "archer-ax53-verified.md"
    assert not doc.exists(), "verified doc exists; R0 has landed and the premise is void"
    assert wifi_write_confirmed() is False


async def test_speed_limit_live_refused_until_r0(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_set_client_speed_limit(c, DEV2, 1000, 500, confirm_write=True)
        # Claim: an INFERRED write must be refused R0_UNCONFIRMED and send nothing.
        assert env["success"] is False, "speed-limit live write was NOT refused"
        assert env["error"]["code"] == "R0_UNCONFIRMED"
        assert fake.write_posts == 0, "an INFERRED speed-limit body reached the device pre-R0"
    finally:
        await c.aclose()


async def test_isolate_live_refused_until_r0(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_isolate_device(c, DEV2, True, confirm_write=True)
        assert env["success"] is False, "isolate live write was NOT refused"
        assert env["error"]["code"] == "R0_UNCONFIRMED"
        assert fake.write_posts == 0, "an INFERRED isolate body reached the device pre-R0"
    finally:
        await c.aclose()


async def test_schedule_live_refused_until_r0(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_set_wifi_schedule(
            c, [{"day": "mon", "start": "22:00", "end": "06:00"}], confirm_write=True
        )
        assert env["success"] is False, "schedule live write was NOT refused"
        assert env["error"]["code"] == "R0_UNCONFIRMED"
        assert fake.write_posts == 0, "an INFERRED schedule body reached the device pre-R0"
    finally:
        await c.aclose()


async def test_wol_live_refused_until_r0(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_wol(c, DEV2, confirm_write=True)
        assert env["success"] is False, "WoL live write was NOT refused"
        assert env["error"]["code"] == "R0_UNCONFIRMED"
        assert fake.wakeups == [], "an INFERRED WoL packet left the process pre-R0"
    finally:
        await c.aclose()
