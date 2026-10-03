"""BREAKER r3 / writes — F7: the LAN-subnet check is skipped when the mask is absent.

Claim under attack (verbatim): ``router_add_dhcp_reservation`` "refuses ... an IP
outside the LAN subnet".

``_check_in_lan_subnet`` returns early (allowing the write) whenever the LAN read
does not yield both a string ``ipaddr`` and a string ``mask`` ("subnet unknown ->
cannot check; allow"). A router whose ``network?form=lan_ipv4`` read returns the IP
without a ``mask`` key (a firmware variant, or a response shape the port guessed
wrong) therefore lets an out-of-subnet reservation through — the exact write the
claim says is refused.

Low severity: the mask comes from the router, not the caller, so an adversary cannot
force it; scored for likelihood accordingly. Included because it is a concrete gap
between the claim ("refuses an IP outside the LAN subnet", unconditional) and the
code ("refuses ... when known").
"""

from __future__ import annotations

from archer_router_mcp import server
from tests.fakes import FakeRouter, build_components

DEV = "00:00:5E:00:53:01"


async def test_out_of_subnet_ip_refused_even_without_mask(tmp_path) -> None:
    # LAN read returns an address but no mask field.
    state = {"network:lan_ipv4": {"obj": {"ipaddr": "192.0.2.1"}}}
    fake = FakeRouter(envelope="https-plain", stateful=True, state=state)
    c = build_components(
        fake,
        envelope="https-plain",
        state_dir=tmp_path,
        extra_env={
            "ARCHER_ROUTER_PROTECTED_MACS": "00:00:5E:00:53:AA",
            "ARCHER_ROUTER_ALLOW_WRITES": "true",
        },
    )
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "198.51.100.5", "Dev", confirm_write=True
        )
        # Claim: an IP outside the LAN subnet is refused.
        assert env["success"] is False, "out-of-subnet reservation accepted (mask absent)"
        assert env["error"]["details"]["reason"] == "outside_lan_subnet"
        assert fake.write_posts == 0, "an out-of-subnet reservation body was sent"
    finally:
        await c.aclose()
