"""Shared plumbing for the Phase R4 write tools (``writes.py``, ``writes_access.py``).

Holds the two-gate wrapper, input validation, the request-plan builder and the
small read-view helpers that both write modules use. Pure/local except for
``_guarded``, which owns the login/logout-per-batch flow.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.tooling import run_tool
from ..core.write_gate import check_write_gate
from ..crypto import build_request_body
from ..errors import ProtectedTarget
from ..normalize import first_present, normalize_mac

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Awaitable, Callable

    from ..server import Components
    from ..session import RouterSession

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
NAME_MAX = 32
WIFI_BANDS: tuple[str, ...] = ("2g", "5g")
ACCESS_MODES: tuple[str, ...] = ("off", "blacklist", "whitelist")
MAX_SCHEDULE_RULES = 64
MAC_KEYS = ("mac", "macaddr")
IP_KEYS = ("ip", "ipaddr")


# --------------------------------------------------------------- input validation


def valid_mac(value: Any) -> str:
    mac = normalize_mac(value)
    if mac is None:
        raise ValueError("mac is not a valid MAC address")
    return mac


def valid_ipv4(value: Any) -> str:
    import ipaddress

    if not isinstance(value, str):
        raise ValueError("ip must be a string")
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("ip is not a valid IPv4 address") from None
    if parsed.version != 4:
        raise ValueError("ip must be an IPv4 address")
    return str(parsed)


def valid_name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("name must be a string")
    name = value.strip()
    if not name:
        raise ValueError("name must not be empty")
    if _CONTROL.search(name):
        raise ValueError("name must not contain control characters")
    if len(name) > NAME_MAX:
        raise ValueError(f"name must be at most {NAME_MAX} characters")
    return name


def valid_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def valid_kbps(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be a non-negative integer (0 = unlimited)")
    if value < 0:
        raise ValueError(f"{label} must be >= 0")
    return value


def valid_rules(rules: Any) -> list[dict[str, Any]]:
    if rules is None:
        return []
    if not isinstance(rules, list):
        raise ValueError("rules must be a list of rule objects")
    if len(rules) > MAX_SCHEDULE_RULES:
        raise ValueError(f"rules may contain at most {MAX_SCHEDULE_RULES} entries")
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("each rule must be an object")
    return list(rules)


def reject_protected(settings: Any, mac: str, action: str) -> None:
    if mac in settings.protected_macs:
        raise ProtectedTarget(mac, action)


# ------------------------------------------------------------------ plan + rows


def plan(path: str, form: str, operation: str, params: dict[str, Any]) -> dict[str, Any]:
    """The exact request descriptor, including the plaintext wire ``body``."""
    body = build_request_body({"operation": operation, **params})
    return {"path": path, "form": form, "operation": operation, "params": params, "body": body}


def rows_of(raw: Any) -> list[dict[str, Any]]:
    data = raw.get("data") if isinstance(raw, dict) else raw
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def obj_of(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        data = raw.get("data")
        if isinstance(data, dict):
            return {**raw, **data}
        return raw
    return {}


def find_by_mac(rows: list[dict[str, Any]], cmac: str) -> tuple[int | None, dict[str, Any] | None]:
    for index, row in enumerate(rows):
        if normalize_mac(first_present(row, MAC_KEYS)) == cmac:
            return index, row
    return None, None


def mac_view(rows: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for row in rows:
        mac = normalize_mac(first_present(row, MAC_KEYS))
        if mac and mac not in out:
            out.append(mac)
    return out


# ---------------------------------------------------------------- the gate wrapper


async def guarded(
    components: Components,
    name: str,
    confirm_write: object,
    dry_fn: Callable[[], Awaitable[dict[str, Any]]],
    live_fn: Callable[[RouterSession], Awaitable[dict[str, Any]]],
) -> dict[str, Any]:
    settings = components.settings
    if settings.dry_run:
        # DRY_RUN sends nothing of any kind; it bypasses the gate so the body can be
        # reviewed before writes are enabled (see Phase R5 step 4).
        return await run_tool(name, dry_fn)
    refusal = check_write_gate(settings, name, confirm_write)
    if refusal is not None:
        return refusal

    async def _run() -> dict[str, Any]:
        async with components.session as session:
            return await live_fn(session)

    return await run_tool(name, _run)


# ------------------------------------------------------------------ R0 wifi gate


def _default_verified_doc() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "protocol" / "archer-ax53-verified.md"


def wifi_write_confirmed(doc_path: Path | None = None) -> bool:
    """True once the R0 capture records the ``write_spf`` body in the verified doc."""
    path = doc_path or _default_verified_doc()
    try:
        return path.is_file() and "write_spf" in path.read_text(encoding="utf-8")
    except OSError:
        return False
