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
from ..errors import DeviceError, ProtectedTarget, R0Unconfirmed, WriteOutcomeUnknown
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

# The single source of truth for which write bodies are field-for-field VERIFIED vs
# still INFERRED. Every INFERRED write is gated through ``guarded`` by
# ``require_r0_confirmed`` until the R0 live capture records its body in
# ``docs/protocol/archer-ax53-verified.md``; the VERIFIED set is listed with its
# evidence and needs no R0 gate. Keep both in sync with the tool registry.
INFERRED_WRITES: frozenset[str] = frozenset(
    {
        "router_set_wifi",
        "router_set_client_speed_limit",
        "router_set_wifi_schedule",
        "router_isolate_device",
        "router_wol",
    }
)
VERIFIED_WRITES: dict[str, str] = {
    "router_add_dhcp_reservation": "dhcps reservation insert — tplinkrouterc6u PR #170 + router JS",
    "router_remove_dhcp_reservation": "dhcps reservation remove/update — PR #170 + router JS",
    "router_block_device": "access_control black_list insert — router JS",
    "router_unblock_device": "access_control black_list remove — router JS",
    "router_set_access_mode": "access_control black/white list mode + enable write — router JS",
    "router_reboot": "system reboot — router JS",
}


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
    *,
    protect: tuple[Any, str] | None = None,
) -> dict[str, Any]:
    """Run a write through the two gates, the protected-MAC guard and the R0 gate.

    ``protect=(raw_mac, action)`` makes EVERY MAC-targeting write (block, unblock,
    limit, isolate, un-isolate, reservation-remove, WoL) refuse a protected MAC from
    one place, so no tool can forget it (RW-F3). INFERRED writes are refused
    ``R0_UNCONFIRMED`` on the live path until the verified doc lists them (RW-F1); their
    dry-run still returns the planned body but marked ``r0_confirmed: false``.
    """
    settings = components.settings

    def _enforce_guards() -> None:
        if protect is not None:
            raw_mac, action = protect
            reject_protected(settings, valid_mac(raw_mac), action)

    if settings.dry_run:
        # DRY_RUN sends nothing of any kind; it bypasses the write gate so the body can
        # be reviewed before writes are enabled (see Phase R5 step 4). The protected
        # guard still applies so a protected target is never even planned.
        async def _dry() -> dict[str, Any]:
            _enforce_guards()
            result = await dry_fn()
            if name in INFERRED_WRITES and isinstance(result, dict):
                return {**result, "r0_confirmed": False}
            return result

        return await run_tool(name, _dry)

    refusal = check_write_gate(settings, name, confirm_write)
    if refusal is not None:
        return refusal

    async def _run() -> dict[str, Any]:
        _enforce_guards()
        if name in INFERRED_WRITES:
            require_r0_confirmed(name)
        async with components.session as session:
            return await live_fn(session)

    return await run_tool(name, _run)


async def commit_write(
    session: RouterSession,
    request: dict[str, Any],
    *,
    read_back: Callable[[RouterSession], Awaitable[Any]] | None = None,
    verify: Callable[[Any], bool] | None = None,
    context: dict[str, Any] | None = None,
) -> tuple[Any, str]:
    """Send one non-idempotent write and determine whether it landed (RW-F6).

    The write is sent with ``idempotent=False`` so the session never resends it after a
    ``timeout``. On that lost-reply case we do NOT retry the write: we read the live
    state back (``read_back``) and apply the tool's predicate (``verify``) to decide
    ``landed`` (returned as success) vs ``not_landed``; if no read-back is possible or it
    fails, the outcome is ``unknown``. Returns ``(after_state, "landed")`` on success.
    """
    try:
        await session.request(
            request["path"],
            request["form"],
            request["operation"],
            request["params"],
            idempotent=False,
        )
    except WriteOutcomeUnknown as exc:
        if read_back is None or verify is None:
            raise WriteOutcomeUnknown(str(exc), outcome="unknown", context=context) from exc
        try:
            after = await read_back(session)
        except DeviceError as read_exc:
            raise WriteOutcomeUnknown(
                "The write's reply was lost and the read-back also failed; outcome unknown.",
                outcome="unknown",
                context=context,
            ) from read_exc
        if verify(after):
            return after, "landed"
        raise WriteOutcomeUnknown(
            "The write's reply was lost and a read-back shows it did not take effect.",
            outcome="not_landed",
            context=context,
        ) from exc
    after = await read_back(session) if read_back is not None else None
    return after, "landed"


# ------------------------------------------------------------------ R0 gate


def _default_verified_doc() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "protocol" / "archer-ax53-verified.md"


# A verified-doc row: ``| <tool> | <confirmed_on> | <note> |``. The first column names
# the write tool whose exact body the R0 live capture confirmed.
_DOC_ROW = re.compile(r"^\|([^|]+)\|([^|]+)\|(.*)\|$")


def _confirmed_tools(doc_path: Path | None = None) -> frozenset[str]:
    """The set of write tools the verified doc records as confirmed.

    Parses the documented table in ``docs/protocol/archer-ax53-verified.md``; the header
    and separator rows name no real tool and are ignored, as is any unknown name. A
    missing or unreadable doc yields an empty set (nothing is confirmed, fail closed).
    """
    path = doc_path or _default_verified_doc()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return frozenset()
    known = INFERRED_WRITES | frozenset(VERIFIED_WRITES)
    found = {
        tool
        for line in text.splitlines()
        if (match := _DOC_ROW.match(line.strip()))
        for tool in (match.group(1).strip(),)
        if tool in known
    }
    return frozenset(found)


def require_r0_confirmed(tool_name: str, doc_path: Path | None = None) -> None:
    """Raise ``R0Unconfirmed`` unless the verified doc lists ``tool_name`` (RW-F1)."""
    if tool_name in _confirmed_tools(doc_path):
        return
    raise R0Unconfirmed(
        f"Refusing a live write: {tool_name}'s body is INFERRED and unverified until the R0 "
        "live capture records it in docs/protocol/archer-ax53-verified.md "
        f"(a row '| {tool_name} | <date> | <note> |'). Use ARCHER_ROUTER_DRY_RUN=true to "
        "review the planned body."
    )


def wifi_write_confirmed(doc_path: Path | None = None) -> bool:
    """True once the R0 capture records the ``write_spf`` body in the verified doc.

    Retained as the wifi-body sanity check the breaker premise relies on;
    :func:`require_r0_confirmed` is the structural gate the write wrapper enforces.
    """
    path = doc_path or _default_verified_doc()
    try:
        return path.is_file() and "write_spf" in path.read_text(encoding="utf-8")
    except OSError:
        return False
