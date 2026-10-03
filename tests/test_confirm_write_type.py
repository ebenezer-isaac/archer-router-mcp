"""X1b: ``core.types.ConfirmWrite`` and its wiring into every router write tool.

Two levels:

* a unit check of the annotated type itself (only the JSON boolean ``true`` survives
  as ``True``; everything else collapses to ``False``; the advertised schema stays a
  plain boolean);
* end-to-end checks through the real ``mcp.call_tool`` boundary for every mutating
  tool, proving a truthy string/number no longer coerces past the write gate:
  ``"true"``/``"1"``/``1``/``"yes"`` (and falsey values / ``null``) are refused with a
  single ``WRITE_REFUSED`` envelope and zero device I/O, while the genuine boolean
  ``true`` proceeds (to the dry-run echo here).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, TypeAdapter

from archer_router_mcp import server
from archer_router_mcp.core.types import ConfirmWrite
from tests.fakes import FakeRouter, build_components

DEV = "00:00:5E:00:53:01"
PROTECTED = "00:00:5E:00:53:AA"


# --- unit: the annotated type -------------------------------------------------


class _Model(BaseModel):
    confirm_write: ConfirmWrite = False


@pytest.mark.parametrize("value", ["true", "1", "yes", "on", "false", "0", "no", "", "sure", "2"])
def test_only_boolean_true_confirms_strings(value: str) -> None:
    assert _Model(confirm_write=value).confirm_write is False


@pytest.mark.parametrize("value", [1, 0, 2, -1, 1.0])
def test_numbers_do_not_confirm(value: Any) -> None:
    assert _Model(confirm_write=value).confirm_write is False


def test_none_defaults_and_does_not_confirm() -> None:
    assert _Model().confirm_write is False
    assert _Model(confirm_write=None).confirm_write is False


def test_genuine_boolean_true_confirms() -> None:
    assert _Model(confirm_write=True).confirm_write is True
    assert _Model(confirm_write=False).confirm_write is False


def test_published_schema_is_a_plain_boolean() -> None:
    # A well-behaved client must still see {"type": "boolean"}, not an enum/const.
    schema = TypeAdapter(ConfirmWrite).json_schema()
    assert schema["type"] == "boolean"


# --- boundary: every write tool through mcp.call_tool -------------------------

# (tool_name, args without confirm_write). The write gate is the first check in each
# of these, so a refused confirm_write performs zero device I/O.
WRITE_TOOLS: list[tuple[str, dict[str, Any]]] = [
    ("router_add_dhcp_reservation", {"mac": DEV, "ip": "192.0.2.50", "name": "Dev"}),
    ("router_remove_dhcp_reservation", {"mac": DEV}),
    ("router_set_wifi", {"band": "2g", "enabled": False}),
    ("router_reboot", {}),
    ("router_block_device", {"mac": DEV}),
    ("router_unblock_device", {"mac": DEV}),
    ("router_set_access_mode", {"mode": "blacklist"}),
    ("router_set_client_speed_limit", {"mac": DEV, "down_kbps": 1000, "up_kbps": 500}),
    ("router_set_wifi_schedule", {"rules": []}),
    ("router_isolate_device", {"mac": DEV, "isolate": True}),
    ("router_wol", {"mac": DEV}),
]

# Values a caller might send instead of the JSON boolean true: none may confirm.
NON_CONFIRMING = ["true", "1", 1, "yes", "false", "0", 0, "sure", "2", None]


def _envelope(result: Any) -> dict[str, Any]:
    structured = result[1] if isinstance(result, tuple) else result
    if isinstance(structured, dict) and "result" in structured and "success" not in structured:
        structured = structured["result"]
    if isinstance(structured, dict) and "success" in structured:
        return structured
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


def _app(fake: FakeRouter, tmp_path: Path, **env: str):
    extra = {"ARCHER_ROUTER_ALLOW_WRITES": "true", "ARCHER_ROUTER_PROTECTED_MACS": PROTECTED, **env}
    comps = build_components(fake, envelope="https-plain", state_dir=tmp_path, extra_env=extra)
    return server.create_app(comps), comps


@pytest.mark.parametrize("tool,args", WRITE_TOOLS)
@pytest.mark.parametrize("confirm", NON_CONFIRMING)
async def test_non_true_confirm_is_refused_with_zero_io(tmp_path, tool, args, confirm) -> None:
    # ALLOW_WRITES is on, so the ONLY thing between the caller and the device is
    # confirm_write. A non-boolean-true value must still refuse with zero I/O.
    fake = FakeRouter(envelope="https-plain", stateful=True)
    mcp, comps = _app(fake, tmp_path)
    try:
        result = await mcp.call_tool(tool, {**args, "confirm_write": confirm})
        env = _envelope(result)
        assert env["success"] is False, f"{tool} confirm_write={confirm!r} must be refused"
        assert env["error"]["code"] == "WRITE_REFUSED", f"{tool}/{confirm!r} must be WRITE_REFUSED"
        assert fake.write_posts == 0, f"{tool} confirm_write={confirm!r} must perform zero writes"
        assert fake.login_posts == 0, f"{tool} confirm_write={confirm!r} must perform zero I/O"
    finally:
        await comps.aclose()


@pytest.mark.parametrize("tool,args", WRITE_TOOLS)
async def test_boolean_true_proceeds_to_dry_run(tmp_path, tool, args) -> None:
    # confirm_write=true (the genuine boolean) survives the ConfirmWrite coercion;
    # DRY_RUN then makes the guarded writer echo the request and perform zero I/O.
    fake = FakeRouter(envelope="https-plain", stateful=True)
    mcp, comps = _app(fake, tmp_path, ARCHER_ROUTER_DRY_RUN="true")
    try:
        result = await mcp.call_tool(tool, {**args, "confirm_write": True})
        env = _envelope(result)
        assert env["success"] is True, f"{tool} confirm_write=true must proceed"
        assert "dry_run" in env["data"], f"{tool} must reach the dry-run echo"
        assert fake.write_posts == 0, f"{tool} dry-run must perform zero write I/O"
    finally:
        await comps.aclose()
