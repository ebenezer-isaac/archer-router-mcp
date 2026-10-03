"""Shared test helpers for archer-router-mcp.

Nothing here touches a real network. All addresses are RFC 5737 examples and all
identifiers are synthetic.
"""

from __future__ import annotations

DOC_HOST = "192.0.2.1"  # RFC 5737 TEST-NET-1
TEST_PASSWORD = "TestPass123"
ROUTER_PREFIX = "ARCHER_ROUTER_"
MCP_PREFIX = "ARCHER_MCP_"


def router_env(**overrides: str) -> dict[str, str]:
    base = {f"{ROUTER_PREFIX}HOST": DOC_HOST, f"{ROUTER_PREFIX}PASSWORD": TEST_PASSWORD}
    return {**base, **{f"{ROUTER_PREFIX}{k}": v for k, v in overrides.items()}}
