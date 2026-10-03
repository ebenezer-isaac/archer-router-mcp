"""Merging the router's five overlapping client lists into one per-MAC view.

The Archer exposes the same devices through several forms, each with a different
subset of fields and its own field names. ``merge_clients`` is a pure function
that folds all of them into one :class:`ClientInfo` per normalised MAC, recording
which sources contributed. Scalar fields are first-wins by source precedence
(richest first); ``online`` is OR-ed across the *live* sources only; ``source``
lists every contributor. Field mappings are INFERRED from the bundle.
"""

from __future__ import annotations

from typing import Any

from ..normalize import as_float, as_int, decode_name, first_present, normalize_mac
from .models import ClientInfo

# Source name -> (path, form, operation, is_live). Precedence = list order.
SOURCE_READS: tuple[tuple[str, str, str, str, bool], ...] = (
    ("game_accelerator", "admin/smart_network", "game_accelerator", "loadDevice", True),
    ("mesh", "admin/easymesh_network", "mesh_sclient_list_all", "read", True),
    ("network_map", "admin/status", "network_map", "read", True),
    ("dhcp", "admin/dhcps", "client", "load", False),
    ("nat", "admin/nat", "client_list", "read", False),
)

_MAC_KEYS = ("mac", "macaddr", "mac_addr", "MACAddress", "deviceMac", "mac_address")
_IP_KEYS = ("ip", "ipaddr", "ip_addr", "deviceIp", "ip_address")
_NAME_KEYS = ("deviceName", "name", "hostname", "dev_name", "nickname")
_TYPE_KEYS = ("deviceType", "type", "dev_type")
_TAG_KEYS = ("deviceTag", "tag", "conn_type", "connType")
_SIGNAL_KEYS = ("signal", "rssi", "signal_strength", "signalStrength")
_RX_KEYS = ("downloadSpeed", "rxrate", "rx_rate", "download")
_TX_KEYS = ("uploadSpeed", "txrate", "tx_rate", "upload")

_BAND_TAGS = {"2.4g": "2.4G", "5g": "5G", "5g_2": "5G", "6g": "6G"}


def _extract(row: dict[str, Any], source: str, is_live: bool) -> dict[str, Any] | None:
    mac = normalize_mac(first_present(row, _MAC_KEYS))
    if mac is None:
        return None  # a row without a usable MAC cannot be merged; skip it.
    tag_raw = first_present(row, _TAG_KEYS)
    tag = str(tag_raw).strip().lower() if isinstance(tag_raw, str) else None
    offline = tag == "offline"
    band = _BAND_TAGS.get(tag) if tag else None
    wired = (tag == "wired") if tag is not None else None
    # Live sources assert presence unless the row is explicitly tagged offline.
    online = is_live and not offline
    return {
        "mac": mac,
        "ip": first_present(row, _IP_KEYS),
        "name": decode_name(first_present(row, _NAME_KEYS)),
        "type": first_present(row, _TYPE_KEYS),
        "band": band,
        "wired": wired,
        "signal": as_int(first_present(row, _SIGNAL_KEYS)),
        "rx_mbps": as_float(first_present(row, _RX_KEYS)),
        "tx_mbps": as_float(first_present(row, _TX_KEYS)),
        "online": online,
        "source": source,
    }


def _fold(acc: dict[str, Any], part: dict[str, Any]) -> None:
    # First-wins for scalars (sources are visited richest-first); OR for online.
    for field in ("ip", "name", "type", "band", "wired", "signal", "rx_mbps", "tx_mbps"):
        if acc.get(field) in (None, "") and part.get(field) not in (None, ""):
            acc[field] = part[field]
    acc["online"] = bool(acc.get("online")) or bool(part.get("online"))
    if part["source"] not in acc["source"]:
        acc["source"].append(part["source"])


def merge_clients(
    sources: dict[str, list[dict[str, Any]]],
    *,
    include_offline: bool = False,
) -> list[ClientInfo]:
    """Fold raw rows from each source into one :class:`ClientInfo` per MAC.

    ``sources`` maps a source name (see :data:`SOURCE_READS`) to its raw rows.
    Rows with no usable MAC are dropped. Output is sorted by MAC for determinism;
    offline clients are excluded unless ``include_offline`` is set.
    """
    merged: dict[str, dict[str, Any]] = {}
    for name, _path, _form, _op, is_live in SOURCE_READS:
        for row in sources.get(name, []):
            part = _extract(row, name, is_live)
            if part is None:
                continue
            mac = part["mac"]
            if mac not in merged:
                merged[mac] = {**part, "source": [part["source"]]}
            else:
                _fold(merged[mac], part)
    clients = [ClientInfo(**entry) for entry in merged.values()]
    if not include_offline:
        clients = [c for c in clients if c.online]
    return sorted(clients, key=lambda c: c.mac)
