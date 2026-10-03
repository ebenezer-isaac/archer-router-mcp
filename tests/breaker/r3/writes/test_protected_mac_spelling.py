"""BREAKER r3 / writes — F5: a trailing-NUL protected MAC is refused with the wrong code.

Claim under attack (verbatim): a protected target is "refused (``PROTECTED_TARGET``)
regardless of MAC spelling (colons/dashes/case/no separators ... a MAC with a
trailing NUL)".

``normalize_mac`` does ``value.strip()`` then strips ``[\\s:.\\-]``; Python's
``str.strip()`` does NOT remove ``\\x00`` (NUL is not whitespace) and the NUL is not
in the separator class, so ``"00:00:5E:00:53:AA\\x00"`` fails the twelve-hex-digit
check → ``valid_mac`` raises ``ValueError`` → the tool returns ``INVALID_INPUT``,
never reaching ``reject_protected``.

Safety-wise the write is still refused (no body leaves the process), so the *harm*
is nil — but the claim's exact promise ("PROTECTED_TARGET regardless of spelling,
including a trailing NUL") is false: the refusal code is ``INVALID_INPUT``.

The robust spellings (spaces/case/dashes/no-separators) were also attacked and
produced nothing — see ``test_robust_spellings_are_PROTECTED_TARGET`` which passes
(both sides canonicalise), so that half of the claim holds and is not a finding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

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


async def test_trailing_nul_protected_mac_gives_protected_target(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_block_device(c, PROTECTED + "\x00", confirm_write=True)
        assert env["success"] is False
        # Claim: refused with PROTECTED_TARGET regardless of spelling incl. trailing NUL.
        assert env["error"]["code"] == "PROTECTED_TARGET", (
            f"trailing-NUL protected MAC refused as {env['error']['code']}, not PROTECTED_TARGET"
        )
        assert fake.write_posts == 0
    finally:
        await c.aclose()


@pytest.mark.parametrize(
    "spelling",
    [
        "  00:00:5e:00:53:aa  ",
        "00-00-5E-00-53-AA",
        "00005e005301".upper().replace("01", "AA"),  # 00005E0053AA, no separators
        "00:00:5E:00:53:AA",
    ],
)
async def test_robust_spellings_are_PROTECTED_TARGET(tmp_path, spelling) -> None:
    """Delimiter (passes): valid spellings DO canonicalise and hit the guard."""
    fake, c = _components(tmp_path)
    try:
        env = await server.router_block_device(c, spelling, confirm_write=True)
        assert env["error"]["code"] == "PROTECTED_TARGET"
        assert fake.write_posts == 0
    finally:
        await c.aclose()
