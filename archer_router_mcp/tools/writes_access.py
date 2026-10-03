"""Double-gated write tools (R4): access control, speed limits, schedule, isolation, WoL.

Shares the gating/validation plumbing in ``_write_common.py`` with ``writes.py``.
Field names for the speed-limit, schedule, isolation and WoL bodies are INFERRED
from the read shapes in ``router-endpoints.json`` and marked as such; the R5 live
run is where they are confirmed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..core.errors import InvalidInput
from ..errors import PreconditionFailed, WriteOutcomeUnknown
from ..normalize import as_bool, as_int, first_present, mac_dashed, normalize_mac
from ._write_common import (
    ACCESS_MODES,
    MAC_KEYS,
    commit_write,
    find_by_mac,
    guarded,
    mac_view,
    obj_of,
    plan,
    rows_of,
    valid_bool,
    valid_kbps,
    valid_mac,
    valid_rules,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..server import Components
    from ..session import RouterSession


def _access_view(enable_raw: Any, mode_raw: Any) -> dict[str, Any]:
    enable = obj_of(enable_raw)
    mode = obj_of(mode_raw)
    return {
        "enabled": as_bool(first_present(enable, ("enable", "enabled"))),
        "mode": first_present(mode, ("access_mode", "mode", "value")),
    }


def _speed_view(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    view: list[dict[str, Any]] = []
    for row in rows:
        mac = normalize_mac(first_present(row, MAC_KEYS))
        if mac is None:
            continue
        view.append(
            {
                "mac": mac,
                "down_kbps": as_int(first_present(row, ("down_kbps", "download", "down_limit"))),
                "up_kbps": as_int(first_present(row, ("up_kbps", "upload", "up_limit"))),
                "enabled": as_bool(first_present(row, ("enable", "enabled", "enableLimit"))),
            }
        )
    return view


def _schedule_view(raw: Any) -> dict[str, Any]:
    fields = obj_of(raw)
    rule_list = fields.get("rule_list")
    if not isinstance(rule_list, list):
        rule_list = rows_of(raw)
    return {
        "enabled": as_bool(first_present(fields, ("enable", "enabled"))),
        "rule_count": len(rule_list),
    }


# =============================================================== access control


async def router_block_device(
    components: Components, mac: str, *, confirm_write: bool = False
) -> dict[str, Any]:
    """Block a client by MAC (``access_control?form=black_list`` insert). MUTATES.

    This is the path the UI uses to block a client (``black_list`` insert of the MAC;
    ``black_devices?form=... block`` targets an already-listed device by key — the MCP
    works by MAC, so it inserts directly). Refused with ``PROTECTED_TARGET`` for a
    protected MAC. Idempotent: an already-blocked MAC is left as-is. Returns
    before/after blocked-MAC lists. Double-gated.
    """

    def prep() -> tuple[str, dict[str, Any]]:
        cmac = valid_mac(mac)
        params = {"new": {"mac": mac_dashed(cmac)}, "index": 0}
        return cmac, plan("admin/access_control", "black_list", "insert", params)

    async def dry() -> dict[str, Any]:
        _cmac, request = prep()
        return {"dry_run": request}

    async def _load(session: RouterSession) -> list[dict[str, Any]]:
        return rows_of(await session.request("admin/access_control", "black_list", "load"))

    async def live(session: RouterSession) -> dict[str, Any]:
        cmac, request = prep()
        before = await _load(session)
        if find_by_mac(before, cmac)[1] is not None:
            return {
                "applied": None,
                "note": "already blocked",
                "before": mac_view(before),
                "after": mac_view(before),
                "outcome": "landed",
            }
        after_rows, outcome = await commit_write(
            session,
            request,
            read_back=_load,
            verify=lambda rows: find_by_mac(rows, cmac)[1] is not None,
            context={"mac": cmac},
        )
        return {
            "applied": request,
            "before": mac_view(before),
            "after": mac_view(after_rows),
            "outcome": outcome,
        }

    return await guarded(
        components, "router_block_device", confirm_write, dry, live, protect=(mac, "block")
    )


async def router_unblock_device(
    components: Components, mac: str, *, confirm_write: bool = False
) -> dict[str, Any]:
    """Unblock a client by MAC (``access_control?form=black_list`` remove). MUTATES.

    Loads the black list, finds the row for ``mac`` and removes it by key+index.
    Refused with ``PROTECTED_TARGET`` for a protected MAC (protected devices are
    managed by hand; RW-F3). Idempotent: a MAC that is not blocked is reported as such.
    Double-gated; before/after lists.
    """

    def prep() -> str:
        return valid_mac(mac)

    async def dry() -> dict[str, Any]:
        cmac = prep()
        return {
            "dry_run": {
                "path": "admin/access_control",
                "form": "black_list",
                "operation": "remove",
                "params": {"mac": cmac},
                "note": "key and index are resolved from a live black_list load at write time",
            }
        }

    async def _load(session: RouterSession) -> list[dict[str, Any]]:
        return rows_of(await session.request("admin/access_control", "black_list", "load"))

    async def live(session: RouterSession) -> dict[str, Any]:
        cmac = prep()
        before = await _load(session)
        index, row = find_by_mac(before, cmac)
        if row is None:
            return {
                "applied": None,
                "note": "not blocked",
                "before": mac_view(before),
                "after": mac_view(before),
                "outcome": "landed",
            }
        request = plan(
            "admin/access_control", "black_list", "remove", {"key": row.get("key"), "index": index}
        )
        after_rows, outcome = await commit_write(
            session,
            request,
            read_back=_load,
            verify=lambda rows: find_by_mac(rows, cmac)[1] is None,
            context={"mac": cmac},
        )
        return {
            "applied": request,
            "before": mac_view(before),
            "after": mac_view(after_rows),
            "outcome": outcome,
        }

    return await guarded(
        components, "router_unblock_device", confirm_write, dry, live, protect=(mac, "unblock")
    )


async def router_set_access_mode(
    components: Components, mode: str, *, confirm_write: bool = False
) -> dict[str, Any]:
    """Set the access-control mode: off | blacklist | whitelist. MUTATES.

    Writes ``access_control?form=mode`` (``access_mode``) and ``form=enable``.
    Whitelist mode is refused unless **every** ``ARCHER_ROUTER_PROTECTED_MACS`` entry
    is already on the white list (checked from a live read first), so switching to
    whitelist can never lock out the owner's own devices. Double-gated; before/after
    {enabled, mode}.
    """

    def prep() -> str:
        m = str(mode).strip().lower()
        if m not in ACCESS_MODES:
            raise InvalidInput("mode must be one of: off, blacklist, whitelist")
        return m

    def plans(m: str) -> list[dict[str, Any]]:
        if m == "off":
            return [plan("admin/access_control", "enable", "write", {"enable": "off"})]
        return [
            plan("admin/access_control", "mode", "write", {"access_mode": m}),
            plan("admin/access_control", "enable", "write", {"enable": "on"}),
        ]

    async def dry() -> dict[str, Any]:
        m = prep()
        out: dict[str, Any] = {"dry_run": plans(m)}
        if m == "whitelist":
            out["precondition"] = (
                "every ARCHER_ROUTER_PROTECTED_MACS entry must already be on the white "
                "list (checked against a live read at write time)"
            )
        return out

    async def read_state(session: RouterSession) -> dict[str, Any]:
        return _access_view(
            await session.request("admin/access_control", "enable", "read"),
            await session.request("admin/access_control", "mode", "read"),
        )

    async def live(session: RouterSession) -> dict[str, Any]:
        m = prep()

        def landed(after: dict[str, Any]) -> bool:
            if m == "off":
                return after["enabled"] is False
            return after["mode"] == m and after["enabled"] is True

        before = await read_state(session)
        if m == "whitelist":
            white = rows_of(await session.request("admin/access_control", "white_list", "load"))
            present = {normalize_mac(first_present(r, MAC_KEYS)) for r in white}
            missing = [p for p in components.settings.protected_macs if p not in present]
            if missing:
                raise PreconditionFailed(
                    "Whitelist mode refused: protected devices are not on the white list: "
                    + ", ".join(missing),
                    reason="protected_not_whitelisted",
                    context={"missing": missing},
                )
        applied = plans(m)
        try:
            for request in applied:
                await session.request(
                    request["path"],
                    request["form"],
                    request["operation"],
                    request["params"],
                    idempotent=False,
                )
        except WriteOutcomeUnknown as exc:
            # A reply was lost mid-sequence: never resend; read the mode back instead.
            after = await read_state(session)
            if not landed(after):
                raise WriteOutcomeUnknown(
                    "An access-mode write's reply was lost and the mode did not fully apply.",
                    outcome="not_landed",
                    context={"mode": m},
                ) from exc
            return {"applied": applied, "before": before, "after": after, "outcome": "landed"}
        after = await read_state(session)
        return {"applied": applied, "before": before, "after": after, "outcome": "landed"}

    return await guarded(components, "router_set_access_mode", confirm_write, dry, live)


# ================================================================= speed limits


async def router_set_client_speed_limit(
    components: Components,
    mac: str,
    down_kbps: int,
    up_kbps: int,
    *,
    confirm_write: bool = False,
) -> dict[str, Any]:
    """Set a per-client bandwidth limit (``smart_network?form=client_speed_limit``). MUTATES.

    ``0`` means unlimited for that direction. Refused with ``PROTECTED_TARGET`` for a
    protected MAC. On a live write the requested rates are checked against the router's
    maxima (``read_max``) first. Field names are INFERRED. Double-gated.
    """

    def prep() -> tuple[str, int, int, dict[str, Any]]:
        cmac = valid_mac(mac)
        down = valid_kbps(down_kbps, "down_kbps")
        up = valid_kbps(up_kbps, "up_kbps")
        params = {
            "mac": mac_dashed(cmac),
            "down_kbps": down,
            "up_kbps": up,
            "enable": "on" if (down > 0 or up > 0) else "off",
        }
        return cmac, down, up, plan("admin/smart_network", "client_speed_limit", "write", params)

    async def dry() -> dict[str, Any]:
        *_rest, request = prep()
        return {"dry_run": request}

    async def _load(session: RouterSession) -> list[dict[str, Any]]:
        return rows_of(
            await session.request("admin/smart_network", "client_speed_limit", "read_max")
        )

    async def live(session: RouterSession) -> dict[str, Any]:
        cmac, down, up, request = prep()
        bounds_raw = await session.request("admin/smart_network", "client_speed_limit", "read_max")
        _check_speed_bounds(bounds_raw, down, up)
        before = _speed_view(rows_of(bounds_raw))
        after_rows, outcome = await commit_write(
            session,
            request,
            read_back=_load,
            verify=lambda rows: find_by_mac(rows, cmac)[1] is not None,
            context={"mac": cmac},
        )
        return {
            "applied": request,
            "before": before,
            "after": _speed_view(after_rows),
            "outcome": outcome,
        }

    return await guarded(
        components,
        "router_set_client_speed_limit",
        confirm_write,
        dry,
        live,
        protect=(mac, "limit"),
    )


def _check_speed_bounds(raw: Any, down: int, up: int) -> None:
    fields = obj_of(raw)
    dmax = as_int(first_present(fields, ("down_max", "max_down_kbps", "download_max", "max_down")))
    umax = as_int(first_present(fields, ("up_max", "max_up_kbps", "upload_max", "max_up")))
    if dmax is not None and down > dmax:
        raise PreconditionFailed(
            f"down_kbps {down} exceeds the router maximum {dmax}.",
            reason="down_over_max",
            context={"max": dmax},
        )
    if umax is not None and up > umax:
        raise PreconditionFailed(
            f"up_kbps {up} exceeds the router maximum {umax}.",
            reason="up_over_max",
            context={"max": umax},
        )


# ============================================================== Wi-Fi schedule


async def router_set_wifi_schedule(
    components: Components, rules: list[dict[str, Any]], *, confirm_write: bool = False
) -> dict[str, Any]:
    """Replace the Wi-Fi on/off schedule (``wireless_schedule_v2?form=settings``). MUTATES.

    Minimal: enables the schedule when ``rules`` is non-empty (disables it when empty)
    and replaces the rule list wholesale. The rule shape is INFERRED from the read;
    validation only checks that it is a list of objects (<=64). Double-gated;
    before/after {enabled, rule_count}.
    """

    def prep() -> tuple[bool, dict[str, Any]]:
        norm = valid_rules(rules)
        params = {"enable": "on" if norm else "off", "rule_list": norm}
        return bool(norm), plan("admin/wireless_schedule_v2", "settings", "write", params)

    async def dry() -> dict[str, Any]:
        _enabled, request = prep()
        return {"dry_run": request}

    async def _read(session: RouterSession) -> dict[str, Any]:
        return _schedule_view(
            await session.request("admin/wireless_schedule_v2", "settings", "read")
        )

    async def live(session: RouterSession) -> dict[str, Any]:
        want_enabled, request = prep()
        before = await _read(session)
        after, outcome = await commit_write(
            session,
            request,
            read_back=_read,
            verify=lambda view: view["enabled"] is want_enabled,
        )
        return {"applied": request, "before": before, "after": after, "outcome": outcome}

    return await guarded(components, "router_set_wifi_schedule", confirm_write, dry, live)


# ================================================================ IoT isolation


async def router_isolate_device(
    components: Components, mac: str, isolate: bool, *, confirm_write: bool = False
) -> dict[str, Any]:
    """Isolate or un-isolate a device (``iot_security?form=isolated_list``). MUTATES.

    ``isolate=True`` writes the MAC into the isolated list; ``isolate=False`` removes
    it. Both directions are refused with ``PROTECTED_TARGET`` for a protected MAC
    (protected devices are managed by hand; RW-F3). Field names are INFERRED.
    Double-gated; before/after isolated-MAC lists.
    """

    def prep() -> tuple[str, dict[str, Any]]:
        cmac = valid_mac(mac)
        valid_bool(isolate, "isolate")
        op = "write" if isolate else "remove"
        return cmac, plan("admin/iot_security", "isolated_list", op, {"mac": mac_dashed(cmac)})

    async def dry() -> dict[str, Any]:
        _cmac, request = prep()
        return {"dry_run": request}

    async def _load(session: RouterSession) -> list[dict[str, Any]]:
        return rows_of(await session.request("admin/iot_security", "isolated_list", "load"))

    async def live(session: RouterSession) -> dict[str, Any]:
        cmac, request = prep()
        before = mac_view(await _load(session))
        after_rows, outcome = await commit_write(
            session,
            request,
            read_back=_load,
            verify=lambda rows: (find_by_mac(rows, cmac)[1] is not None) is isolate,
            context={"mac": cmac},
        )
        return {
            "applied": request,
            "before": before,
            "after": mac_view(after_rows),
            "outcome": outcome,
        }

    return await guarded(
        components,
        "router_isolate_device",
        confirm_write,
        dry,
        live,
        protect=(mac, "isolate" if isolate else "un-isolate"),
    )


# ======================================================================== WoL


async def router_wol(
    components: Components, mac: str, *, confirm_write: bool = False
) -> dict[str, Any]:
    """Send a Wake-on-LAN magic packet to a device (``wol?form=device`` wakeup). MUTATES.

    A one-shot action (not a persistent change), so there is no before/after read.
    Refused with ``PROTECTED_TARGET`` for a protected MAC (protected devices are managed
    by hand; RW-F3). Field names are INFERRED. Double-gated.
    """

    def prep() -> dict[str, Any]:
        cmac = valid_mac(mac)
        return plan("admin/wol", "device", "wakeup", {"mac": mac_dashed(cmac)})

    async def dry() -> dict[str, Any]:
        return {"dry_run": prep()}

    async def live(session: RouterSession) -> dict[str, Any]:
        request = prep()
        # One-shot, non-idempotent: a lost reply surfaces as WRITE_OUTCOME_UNKNOWN rather
        # than resending the packet (there is no state to read back).
        ack = await session.request(
            request["path"],
            request["form"],
            request["operation"],
            request["params"],
            idempotent=False,
        )
        return {
            "applied": request,
            "ack": ack,
            "note": "Wake-on-LAN is a one-shot action; there is no state to re-read",
            "outcome": "landed",
        }

    return await guarded(components, "router_wol", confirm_write, dry, live, protect=(mac, "wake"))
