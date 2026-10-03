"""Hand-written, LLM-friendly read tools for the Archer AX53.

Each tool logs in lazily, performs its read(s) through the shared
``RouterSession`` (which serialises I/O and re-logs-in once on an expired token),
then logs out at the end of the batch via ``async with``. Every tool returns a
normalised pydantic model under ``data`` and, when ``include_raw=True``, the raw
router payload(s) under ``raw``. Device-response shapes that cannot be validated
become a ``PROTOCOL_ERROR`` envelope — never an exception — because every tool is
wrapped by ``core.tooling.run_tool``. All reads are read-only: no mutating verb
is ever sent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from ..core.tooling import run_tool
from ..errors import ProtocolError
from ..normalize import (
    as_bool,
    as_int,
    decode_name,
    first_present,
    normalize_mac,
    payload_obj,
    payload_rows,
)
from .clients import SOURCE_READS, merge_clients
from .models import (
    DhcpLease,
    MeshNode,
    PortForward,
    Reservation,
    SpeedLimitRow,
    StatusInfo,
    WanInfo,
    WifiBand,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..server import Components
    from ..session import RouterSession

WIFI_BANDS: tuple[str, ...] = ("2g", "5g")
ACCESS_FORMS: tuple[str, ...] = (
    "enable",
    "mode",
    "black_list",
    "white_list",
    "black_devices",
    "white_devices",
)
_UP_WORDS = {"connected", "up", "online"}


def _build(model_cls: type, **fields: Any) -> Any:
    """Construct a model, mapping a validation failure to ``ProtocolError``."""
    try:
        return model_cls(**fields)
    except ValidationError as exc:
        raise ProtocolError(
            f"The router response did not match the expected {model_cls.__name__} shape."
        ) from exc


def _require_mac(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    mac = normalize_mac(first_present(row, keys))
    if mac is None:
        raise ProtocolError("A router row was missing a usable MAC address.")
    return mac


async def _read(session: RouterSession, path: str, form: str, operation: str) -> dict[str, Any]:
    return await session.request(path, form, operation)


async def read_online_clients(
    components: Components, *, include_offline: bool = False
) -> list[dict[str, Any]]:
    """Merge the five client lists into dicts (used by the presence sampler).

    Logs in lazily and logs out after the batch. Raises on a read/parse failure so
    the caller can surface it; returns merged client dicts keyed by MAC order.
    """
    sources: dict[str, list[dict[str, Any]]] = {}
    async with components.session as s:
        for name, path, form, operation, _is_live in SOURCE_READS:
            sources[name] = payload_rows(await _read(s, path, form, operation))
    return [c.model_dump() for c in merge_clients(sources, include_offline=include_offline)]


def _wan_up(value: Any) -> bool | None:
    if isinstance(value, str) and value.strip().lower() in _UP_WORDS:
        return True
    if isinstance(value, str) and value.strip():
        return as_bool(value) if as_bool(value) is not None else False
    return as_bool(value)


# --------------------------------------------------------------------- status


async def router_get_status(components: Components, *, include_raw: bool = False) -> dict[str, Any]:
    """Summarise the router: model, firmware, uptime, WAN/LAN addresses, radios.

    Read-only. Merges ``status?form=all``/``internet`` with ``network`` WAN and LAN
    reads. Field mapping is INFERRED from the UI bundle; pass ``include_raw`` for
    the untouched payloads.
    """

    async def _run() -> dict[str, Any]:
        async with components.session as s:
            all_ = payload_obj(await _read(s, "admin/status", "all", "read"))
            internet = payload_obj(await _read(s, "admin/status", "internet", "read"))
            wan = payload_obj(await _read(s, "admin/network", "wan_ipv4_status", "read"))
            lan = payload_obj(await _read(s, "admin/network", "lan_ipv4", "read"))
        merged = {**internet, **wan, **lan, **all_}
        model = _build(
            StatusInfo,
            model=first_present(merged, ("model", "device_model", "product")),
            firmware=first_present(merged, ("fw_ver", "firmware_version", "sw_ver")),
            hardware_version=first_present(merged, ("hw_ver", "hardware_version")),
            uptime_seconds=as_int(
                first_present(merged, ("wan_ipv4_uptime", "uptime", "sys_uptime"))
            ),
            wan_up=_wan_up(first_present(merged, ("wan_ipv4_status", "status", "conn_status"))),
            wan_ip=first_present(merged, ("wan_ipv4_ipaddr", "wan_ip", "ipaddr")),
            lan_ip=first_present(merged, ("lan_ipv4_ipaddr", "lan_ip")),
            lan_mac=normalize_mac(first_present(merged, ("lan_macaddr", "lan_mac"))),
            wan_mac=normalize_mac(first_present(merged, ("wan_macaddr", "wan_mac"))),
            cpu_usage=as_int(merged.get("cpu_usage")),
            mem_usage=as_int(merged.get("mem_usage")),
            radio_2g_on=as_bool(first_present(merged, ("wireless_2g_enable", "wireless_2g"))),
            radio_5g_on=as_bool(first_present(merged, ("wireless_5g_enable", "wireless_5g"))),
            client_count=as_int(first_present(merged, ("client_num", "client_count"))),
        )
        out = model.model_dump()
        if include_raw:
            out["raw"] = {"all": all_, "internet": internet, "wan": wan, "lan": lan}
        return out

    return await run_tool("router_get_status", _run)


async def router_get_wan(components: Components, *, include_raw: bool = False) -> dict[str, Any]:
    """Report WAN IPv4 status: connection type, IP/mask/gateway, DNS, uptime.

    Read-only, single read of ``network?form=wan_ipv4_status``. Fields INFERRED.
    """

    async def _run() -> dict[str, Any]:
        async with components.session as s:
            raw = await _read(s, "admin/network", "wan_ipv4_status", "read")
        fields = payload_obj(raw)
        dns = [
            v
            for v in (
                first_present(fields, ("pridns", "dns1", "dns")),
                first_present(fields, ("snddns", "dns2")),
            )
            if isinstance(v, str) and v
        ]
        model = _build(
            WanInfo,
            conn_type=first_present(fields, ("conntype", "proto", "conn_type")),
            ip=first_present(fields, ("ipaddr", "wan_ipv4_ipaddr", "ip")),
            netmask=first_present(fields, ("netmask", "mask")),
            gateway=first_present(fields, ("gateway", "gw")),
            dns=dns,
            uptime_seconds=as_int(first_present(fields, ("uptime", "wan_ipv4_uptime"))),
            up=_wan_up(first_present(fields, ("status", "conn_status"))),
        )
        out = model.model_dump()
        if include_raw:
            out["raw"] = fields
        return out

    return await run_tool("router_get_wan", _run)


# -------------------------------------------------------------------- clients


async def router_list_clients(
    components: Components,
    *,
    include_offline: bool = False,
    include_raw: bool = False,
) -> dict[str, Any]:
    """List connected clients, merged across all five of the router's device lists.

    Read-only. Returns one entry per MAC with ``{mac, ip, name, type, band, wired,
    signal, rx_mbps, tx_mbps, online, source[]}``. Offline/known-but-absent devices
    are excluded unless ``include_offline=True``. Field mapping is INFERRED.
    """

    async def _run() -> dict[str, Any]:
        raws: dict[str, Any] = {}
        sources: dict[str, list[dict[str, Any]]] = {}
        async with components.session as s:
            for name, path, form, operation, _is_live in SOURCE_READS:
                raw = await _read(s, path, form, operation)
                raws[name] = raw
                sources[name] = payload_rows(raw)
        clients = merge_clients(sources, include_offline=include_offline)
        out: dict[str, Any] = {"clients": [c.model_dump() for c in clients], "count": len(clients)}
        if include_raw:
            out["raw"] = raws
        return out

    return await run_tool("router_list_clients", _run)


# ----------------------------------------------------------------- dhcp / nat


async def router_list_dhcp_leases(
    components: Components, *, include_raw: bool = False
) -> dict[str, Any]:
    """List active DHCP leases (``dhcps?form=client``): mac, ip, name, lease time.

    Read-only. Field names are VERIFIED (``macaddr``/``ipaddr``/``name``/``leasetime``).
    """

    async def _run() -> dict[str, Any]:
        async with components.session as s:
            raw = await _read(s, "admin/dhcps", "client", "load")
        leases = [
            _build(
                DhcpLease,
                mac=_require_mac(row, ("macaddr", "mac")),
                ip=first_present(row, ("ipaddr", "ip")),
                name=decode_name(first_present(row, ("name", "hostname"))),
                lease_time=_coerce_str(first_present(row, ("leasetime", "lease_time"))),
            ).model_dump()
            for row in payload_rows(raw)
        ]
        out: dict[str, Any] = {"leases": leases, "count": len(leases)}
        if include_raw:
            out["raw"] = raw
        return out

    return await run_tool("router_list_dhcp_leases", _run)


async def router_list_dhcp_reservations(
    components: Components, *, include_raw: bool = False
) -> dict[str, Any]:
    """List DHCP address reservations (``dhcps?form=reservation``).

    Read-only. Rows are ``{mac, ip, hostname, enable, key}`` plus ``max_rules``.
    Field names VERIFIED from the bundle.
    """

    async def _run() -> dict[str, Any]:
        async with components.session as s:
            raw = await _read(s, "admin/dhcps", "reservation", "load")
        rows = [
            _build(
                Reservation,
                mac=_require_mac(row, ("mac", "macaddr")),
                ip=first_present(row, ("ip", "ipaddr")),
                hostname=decode_name(first_present(row, ("hostname", "name"))),
                enable=as_bool(row.get("enable")),
                row_id=_coerce_str(row.get("key")),
            ).model_dump()
            for row in payload_rows(raw)
        ]
        max_rules = as_int(raw.get("max_rules")) if isinstance(raw, dict) else None
        out: dict[str, Any] = {"reservations": rows, "count": len(rows), "max_rules": max_rules}
        if include_raw:
            out["raw"] = raw
        return out

    return await run_tool("router_list_dhcp_reservations", _run)


async def router_list_port_forwards(
    components: Components, *, include_raw: bool = False
) -> dict[str, Any]:
    """List virtual-server port-forward rules (``nat?form=vs``). Fields INFERRED."""

    async def _run() -> dict[str, Any]:
        async with components.session as s:
            raw = await _read(s, "admin/nat", "vs", "load")
        rows = [
            _build(
                PortForward,
                row_id=_coerce_str(row.get("key")),
                name=decode_name(first_present(row, ("name", "desc"))),
                enable=as_bool(row.get("enable")),
                protocol=first_present(row, ("protocol", "proto")),
                external_port=_coerce_str(first_present(row, ("external_port", "ext_port"))),
                internal_port=_coerce_str(first_present(row, ("internal_port", "int_port"))),
                internal_ip=first_present(row, ("ipaddr", "internal_ip", "ip")),
            ).model_dump()
            for row in payload_rows(raw)
        ]
        out: dict[str, Any] = {"port_forwards": rows, "count": len(rows)}
        if include_raw:
            out["raw"] = raw
        return out

    return await run_tool("router_list_port_forwards", _run)


# --------------------------------------------------------------------- wifi


async def router_get_wifi(components: Components, *, include_raw: bool = False) -> dict[str, Any]:
    """Report Wi-Fi per band (``wireless?form=wireless_<band>``) and guest SSIDs.

    Read-only. Returns ``{enable, ssid, encryption, hidden, channel}`` per band.
    The pre-shared key (``psk_key``) is never returned. Fields INFERRED.
    """

    async def _run() -> dict[str, Any]:
        raws: dict[str, Any] = {}
        bands: list[dict[str, Any]] = []
        async with components.session as s:
            for band in WIFI_BANDS:
                raw = await _read(s, "admin/wireless", f"wireless_{band}", "read_spf")
                raws[band] = raw
                fields = payload_obj(raw)
                bands.append(
                    _build(
                        WifiBand,
                        band=band,
                        enable=as_bool(fields.get("enable")),
                        ssid=decode_name(fields.get("ssid")),
                        encryption=first_present(fields, ("encryption", "psk_version", "security")),
                        hidden=as_bool(fields.get("hidden")),
                        channel=as_int(first_present(fields, ("channel", "current_channel"))),
                    ).model_dump()
                )
            multi = payload_obj(
                await _read(s, "admin/status", "status_wireless_multi_ssid", "read")
            )
        out: dict[str, Any] = {
            "bands": bands,
            "guest_enabled": as_bool(first_present(multi, ("enable", "guest_enable"))),
        }
        if include_raw:
            out["raw"] = {**raws, "multi_ssid": multi}
        return out

    return await run_tool("router_get_wifi", _run)


# --------------------------------------------------------------------- mesh


async def router_list_mesh_nodes(
    components: Components, *, include_raw: bool = False
) -> dict[str, Any]:
    """List EasyMesh nodes (``easymesh_network?form=get_mesh_device_list_all``). INFERRED."""

    async def _run() -> dict[str, Any]:
        async with components.session as s:
            raw = await _read(s, "admin/easymesh_network", "get_mesh_device_list_all", "read")
        nodes = [
            _build(
                MeshNode,
                name=decode_name(first_present(row, ("name", "device_name", "nickname"))),
                model=first_present(row, ("model", "device_model", "product")),
                ip=first_present(row, ("ip", "ipaddr")),
                mac=normalize_mac(first_present(row, ("mac", "macaddr"))),
                version=first_present(row, ("version", "sw_ver", "fw_ver")),
            ).model_dump()
            for row in payload_rows(raw)
        ]
        out: dict[str, Any] = {"nodes": nodes, "count": len(nodes)}
        if include_raw:
            out["raw"] = raw
        return out

    return await run_tool("router_list_mesh_nodes", _run)


# ----------------------------------------------------- access control / limits


async def router_get_access_control(
    components: Components, *, include_raw: bool = False
) -> dict[str, Any]:
    """Report access control: enabled, mode, black/white lists and devices. INFERRED."""

    async def _run() -> dict[str, Any]:
        raws: dict[str, Any] = {}
        async with components.session as s:
            for form in ACCESS_FORMS:
                raws[form] = await _read(s, "admin/access_control", form, "load")
        enable = payload_obj(raws["enable"])
        mode = payload_obj(raws["mode"])
        out: dict[str, Any] = {
            "enabled": as_bool(first_present(enable, ("enable", "enabled"))),
            "mode": first_present(mode, ("mode", "value")),
            "black_list": _mac_list(raws["black_list"]),
            "white_list": _mac_list(raws["white_list"]),
            "black_devices": _device_list(raws["black_devices"]),
            "white_devices": _device_list(raws["white_devices"]),
        }
        if include_raw:
            out["raw"] = raws
        return out

    return await run_tool("router_get_access_control", _run)


async def router_get_speed_limits(
    components: Components, *, include_raw: bool = False
) -> dict[str, Any]:
    """Report per-client speed limits (``smart_network?form=client_speed_limit`` read_max)."""

    async def _run() -> dict[str, Any]:
        async with components.session as s:
            raw = await _read(s, "admin/smart_network", "client_speed_limit", "read_max")
        rows = []
        for row in _loose_rows(raw):
            mac = normalize_mac(first_present(row, ("mac", "macaddr")))
            if mac is None:
                continue
            rows.append(
                _build(
                    SpeedLimitRow,
                    mac=mac,
                    name=decode_name(first_present(row, ("name", "deviceName"))),
                    down_kbps=as_int(first_present(row, ("down_kbps", "download", "down_limit"))),
                    up_kbps=as_int(first_present(row, ("up_kbps", "upload", "up_limit"))),
                    enabled=as_bool(first_present(row, ("enable", "enabled", "enableLimit"))),
                ).model_dump()
            )
        out: dict[str, Any] = {"limits": rows, "count": len(rows)}
        if include_raw:
            out["raw"] = raw
        return out

    return await run_tool("router_get_speed_limits", _run)


async def router_get_wifi_schedule(
    components: Components, *, include_raw: bool = False
) -> dict[str, Any]:
    """Report the Wi-Fi on/off schedule (``wireless_schedule_v2?form=settings`` read)."""

    async def _run() -> dict[str, Any]:
        async with components.session as s:
            raw = await _read(s, "admin/wireless_schedule_v2", "settings", "read")
        fields = payload_obj(raw)
        out: dict[str, Any] = {
            "enabled": as_bool(first_present(fields, ("enable", "enabled"))),
            "rules": _loose_rows(raw) if include_raw else len(_loose_rows(raw)),
        }
        if include_raw:
            out["raw"] = raw
        return out

    return await run_tool("router_get_wifi_schedule", _run)


async def router_get_iot_isolation(
    components: Components, *, include_raw: bool = False
) -> dict[str, Any]:
    """Report IoT isolation (``iot_security?form=enable`` + ``isolated_list``)."""

    async def _run() -> dict[str, Any]:
        async with components.session as s:
            enable_raw = await _read(s, "admin/iot_security", "enable", "read")
            list_raw = await _read(s, "admin/iot_security", "isolated_list", "load")
        enable = payload_obj(enable_raw)
        out: dict[str, Any] = {
            "enabled": as_bool(first_present(enable, ("enable", "enabled"))),
            "isolated": _mac_list(list_raw),
        }
        if include_raw:
            out["raw"] = {"enable": enable_raw, "isolated_list": list_raw}
        return out

    return await run_tool("router_get_iot_isolation", _run)


# ------------------------------------------------------------------- helpers


def _coerce_str(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def _loose_rows(raw: Any) -> list[dict[str, Any]]:
    """Best-effort row extraction that tolerates an absent list (returns ``[]``)."""
    if isinstance(raw, dict):
        data = raw.get("data")
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    return []


def _mac_list(raw: Any) -> list[str]:
    macs: list[str] = []
    rows = _loose_rows(raw)
    if rows:
        for row in rows:
            mac = normalize_mac(first_present(row, ("mac", "macaddr")))
            if mac and mac not in macs:
                macs.append(mac)
        return macs
    # Also accept a bare list of MAC strings under data.
    data = raw.get("data") if isinstance(raw, dict) else raw
    if isinstance(data, list):
        for item in data:
            mac = normalize_mac(item)
            if mac and mac not in macs:
                macs.append(mac)
    return macs


def _device_list(raw: Any) -> list[dict[str, Any]]:
    devices = []
    for row in _loose_rows(raw):
        mac = normalize_mac(first_present(row, ("mac", "macaddr")))
        if mac is None:
            continue
        devices.append({"mac": mac, "name": decode_name(first_present(row, ("name", "hostname")))})
    return devices
