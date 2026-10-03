"""BREAKER r3 / writes — F3: the PROTECTED_TARGET guard does not cover WoL/unblock.

Claim under attack (verbatim): "any block/unblock/limit/isolate/reservation-remove/
WoL targeting a protected MAC is refused (``PROTECTED_TARGET``) regardless of MAC
spelling".

The claim explicitly lists **unblock** and **WoL** among the operations refused for
a protected MAC. The code refuses only ``block`` / ``limit`` / ``isolate(True)`` /
``reservation-remove``:

* ``router_wol`` never calls ``reject_protected`` — a magic packet is sent to a
  protected MAC.
* ``router_unblock_device`` never calls ``reject_protected`` ("Always allowed").
* ``router_isolate_device(isolate=False)`` likewise un-isolates a protected MAC.

These are low-harm operations (waking / restoring access), so the *impact* is small,
but each is a direct, deterministic falsification of the claim's enumeration: a write
that targets a protected MAC leaves the process with both gates satisfied.

Adversary reading: the MAC is an LLM-supplied argument, so the state is reached by
anyone who wants it on the ordinary path.
"""

from __future__ import annotations

from pathlib import Path

from archer_router_mcp import server
from tests.fakes import FakeRouter, build_components

PROTECTED = "00:00:5E:00:53:AA"


def _components(tmp_path: Path):
    fake = FakeRouter(envelope="https-plain", stateful=True)
    extra = {
        "ARCHER_ROUTER_PROTECTED_MACS": PROTECTED,
        "ARCHER_ROUTER_ALLOW_WRITES": "true",
    }
    comps = build_components(fake, envelope="https-plain", state_dir=tmp_path, extra_env=extra)
    return fake, comps


async def test_wol_to_protected_mac_is_refused(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_wol(c, PROTECTED, confirm_write=True)
        # Claim: WoL targeting a protected MAC is refused PROTECTED_TARGET.
        assert env["success"] is False, "WoL to a protected MAC was accepted"
        assert env["error"]["code"] == "PROTECTED_TARGET"
        assert fake.wakeups == [], "a WoL packet left the process targeting a protected MAC"
    finally:
        await c.aclose()


async def test_unblock_of_protected_mac_is_refused(tmp_path) -> None:
    # Seed the black list with the protected MAC so unblock has something to remove.
    state = {
        "access_control:black_list": {
            "rows": [{"mac": "00:00:5e:00:53:aa", "key": "b1"}],
            "seq": 1,
        }
    }
    fake = FakeRouter(envelope="https-plain", stateful=True, state=state)
    c = build_components(
        fake,
        envelope="https-plain",
        state_dir=tmp_path,
        extra_env={
            "ARCHER_ROUTER_PROTECTED_MACS": PROTECTED,
            "ARCHER_ROUTER_ALLOW_WRITES": "true",
        },
    )
    try:
        env = await server.router_unblock_device(c, PROTECTED, confirm_write=True)
        # Claim: unblock targeting a protected MAC is refused PROTECTED_TARGET.
        assert env["success"] is False, "unblock of a protected MAC was accepted"
        assert env["error"]["code"] == "PROTECTED_TARGET"
        assert fake.write_posts == 0, "an unblock write targeting a protected MAC was sent"
    finally:
        await c.aclose()
