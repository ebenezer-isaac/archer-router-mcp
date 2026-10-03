"""R3 read tools: normalisation, redaction, error mapping and the read-only invariant.

All data here is anonymised (RFC 5737 ``192.0.2.x`` and RFC 7042 documentation
MACs). Tests drive the tools through the fake router; the ``https-plain`` envelope
is used so the fake records each request's plain ``operation`` verb, which the
read-only invariant test asserts on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from archer_router_mcp import server
from archer_router_mcp.normalize import normalize_mac
from archer_router_mcp.tools import clients as clients_mod
from archer_router_mcp.tools.clients import merge_clients
from tests.fakes import FakeRouter, build_components

READ_VERBS = {"read", "load", "loadDevice", "read_spf", "read_max", "logout"}


def _wrap(data: object) -> dict:
    return {"data": data}


# Canned, anonymised router responses for every read form.
FIXTURES: dict[str, object] = {
    "all": {
        "model": "Archer AX53",
        "fw_ver": "1.11.0",
        "hw_ver": "AX53 v1",
        "lan_ipv4_ipaddr": "192.0.2.1",
        "lan_macaddr": "00:00:5e:00:53:01",
        "wan_macaddr": "00:00:5e:00:53:02",
        "wan_ipv4_ipaddr": "192.0.2.100",
        "wan_ipv4_status": "connected",
        "wan_ipv4_uptime": "3600",
        "cpu_usage": "7",
        "mem_usage": "41",
        "wireless_2g_enable": "on",
        "wireless_5g_enable": "off",
        "client_num": "3",
    },
    "internet": _wrap({"conn_status": "connected"}),
    "wan_ipv4_status": _wrap(
        {
            "conntype": "dhcp",
            "ipaddr": "192.0.2.100",
            "netmask": "255.255.255.0",
            "gateway": "192.0.2.1",
            "pridns": "192.0.2.53",
            "snddns": "192.0.2.54",
            "uptime": "7200",
            "status": "connected",
        }
    ),
    "lan_ipv4": _wrap({"ipaddr": "192.0.2.1"}),
    "game_accelerator": _wrap(
        [
            {
                "mac": "00-00-5E-00-53-11",
                "deviceName": "My%20Phone",
                "deviceType": "phone",
                "deviceTag": "5G",
                "ip": "192.0.2.11",
                "downloadSpeed": "100",
                "uploadSpeed": "50",
            },
            {
                "mac": "00:00:5e:00:53:12",
                "deviceName": "Desk-PC",
                "deviceTag": "wired",
                "ip": "192.0.2.12",
            },
            {"mac": "00005E005313", "deviceName": "Away", "deviceTag": "offline"},
        ]
    ),
    "mesh_sclient_list_all": _wrap([{"mac": "00:00:5e:00:53:11", "signal": "-55", "band": "5G"}]),
    "network_map": _wrap([{"mac": "00:00:5E:00:53:14", "name": "MapOnly", "ip": "192.0.2.14"}]),
    "client": _wrap(
        [
            {
                "macaddr": "00-00-5E-00-53-11",
                "name": "PhoneDHCP",
                "ipaddr": "192.0.2.11",
                "leasetime": "7200",
            },
            {"macaddr": "00:00:5E:00:53:99", "name": "OfflineKnown", "ipaddr": "192.0.2.99"},
        ]
    ),
    "client_list": _wrap([{"mac": "00:00:5e:00:53:12", "name": "PC-NAT"}]),
    "reservation": {
        "data": [
            {
                "key": "r1",
                "mac": "00:00:5e:00:53:21",
                "ip": "192.0.2.21",
                "hostname": "Printer%20A",
                "enable": "on",
            }
        ],
        "max_rules": 32,
    },
    "wireless_2g": _wrap(
        {
            "enable": "on",
            "ssid": "Home%20WiFi",
            "encryption": "psk2",
            "hidden": "off",
            "channel": "6",
            "psk_key": "topsecretpassphrase",
        }
    ),
    "wireless_5g": _wrap(
        {"enable": "off", "ssid": "Home-5G", "encryption": "psk2", "hidden": "on", "channel": "36"}
    ),
    "status_wireless_multi_ssid": _wrap({"enable": "off"}),
    "vs": _wrap(
        [
            {
                "key": "v1",
                "name": "Web%20Server",
                "enable": "on",
                "protocol": "TCP",
                "external_port": "8080",
                "internal_port": "80",
                "ipaddr": "192.0.2.50",
            }
        ]
    ),
    "get_mesh_device_list_all": _wrap(
        [
            {
                "name": "Living%20Room",
                "model": "Archer AX53",
                "ip": "192.0.2.2",
                "mac": "00:00:5e:00:53:31",
                "version": "1.11.0",
            }
        ]
    ),
    "access_control:enable": _wrap({"enable": "on"}),
    "access_control:mode": _wrap({"mode": "blacklist"}),
    "access_control:black_list": _wrap([{"mac": "00:00:5e:00:53:41"}]),
    "access_control:white_list": _wrap([{"mac": "00:00:5e:00:53:42"}]),
    "access_control:black_devices": _wrap([{"mac": "00:00:5e:00:53:41", "name": "Blocked"}]),
    "access_control:white_devices": _wrap([{"mac": "00:00:5e:00:53:42", "name": "Allowed"}]),
    "client_speed_limit": _wrap(
        [
            {
                "mac": "00:00:5e:00:53:51",
                "name": "Capped",
                "down_kbps": "2000",
                "up_kbps": "1000",
                "enable": "on",
            }
        ]
    ),
    "settings": _wrap({"enable": "on"}),
    "iot_security:enable": _wrap({"enable": "on"}),
    "isolated_list": _wrap([{"mac": "00:00:5e:00:53:61"}]),
}


def _components(tmp_path: Path, **kw):
    fake = FakeRouter(envelope="https-plain", reads=dict(FIXTURES), **kw)
    return fake, build_components(fake, envelope="https-plain", state_dir=tmp_path)


# ------------------------------------------------------------------- status/wan


async def test_get_status_normalises(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        env = await server.router_get_status(c)
        data = env["data"]
        assert env["success"] is True
        assert data["model"] == "Archer AX53"
        assert data["wan_up"] is True
        assert data["wan_ip"] == "192.0.2.100"
        assert data["lan_ip"] == "192.0.2.1"
        assert data["lan_mac"] == "00:00:5E:00:53:01"
        assert data["uptime_seconds"] == 3600
        assert data["radio_2g_on"] is True
        assert data["radio_5g_on"] is False
        assert data["client_count"] == 3
    finally:
        await c.aclose()


async def test_get_wan_normalises_dns_list(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_get_wan(c))["data"]
        assert data["conn_type"] == "dhcp"
        assert data["gateway"] == "192.0.2.1"
        assert data["dns"] == ["192.0.2.53", "192.0.2.54"]
        assert data["up"] is True
        assert data["uptime_seconds"] == 7200
    finally:
        await c.aclose()


# ---------------------------------------------------------------------- clients


async def test_list_clients_merges_and_normalises_macs(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_list_clients(c))["data"]
        by_mac = {row["mac"]: row for row in data["clients"]}
        # offline (game "offline" tag) and DHCP-only known device are excluded.
        assert set(by_mac) == {
            "00:00:5E:00:53:11",
            "00:00:5E:00:53:12",
            "00:00:5E:00:53:14",
        }
        phone = by_mac["00:00:5E:00:53:11"]
        assert phone["name"] == "My Phone"  # game precedence over DHCP "PhoneDHCP"
        assert phone["band"] == "5G"
        assert phone["signal"] == -55  # contributed by mesh
        assert phone["rx_mbps"] == 100.0
        assert phone["online"] is True
        assert set(phone["source"]) == {"game_accelerator", "mesh", "dhcp"}
        assert by_mac["00:00:5E:00:53:12"]["wired"] is True
    finally:
        await c.aclose()


async def test_list_clients_include_offline(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_list_clients(c, include_offline=True))["data"]
        macs = {row["mac"] for row in data["clients"]}
        assert "00:00:5E:00:53:99" in macs  # DHCP-only known device
        assert "00:00:5E:00:53:13" in macs  # game "offline" tag
    finally:
        await c.aclose()


def test_merge_clients_pure_empty() -> None:
    assert merge_clients({}, include_offline=True) == []


def test_merge_clients_skips_rows_without_mac() -> None:
    rows = {"game_accelerator": [{"deviceName": "no mac"}, {"mac": "zzzz"}]}
    assert merge_clients(rows, include_offline=True) == []


def test_source_reads_cover_all_five() -> None:
    assert {s[0] for s in clients_mod.SOURCE_READS} == {
        "game_accelerator",
        "mesh",
        "network_map",
        "dhcp",
        "nat",
    }


# ------------------------------------------------------------------ dhcp / nat


async def test_list_dhcp_leases(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_list_dhcp_leases(c))["data"]
        assert data["count"] == 2
        assert data["leases"][0]["mac"] == "00:00:5E:00:53:11"
        assert data["leases"][0]["lease_time"] == "7200"
    finally:
        await c.aclose()


async def test_list_dhcp_reservations_decodes_name_and_max_rules(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_list_dhcp_reservations(c))["data"]
        assert data["max_rules"] == 32
        row = data["reservations"][0]
        assert row["mac"] == "00:00:5E:00:53:21"
        assert row["hostname"] == "Printer A"
        assert row["enable"] is True
        assert row["row_id"] == "r1"
    finally:
        await c.aclose()


async def test_list_port_forwards(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_list_port_forwards(c))["data"]
        row = data["port_forwards"][0]
        assert row["name"] == "Web Server"
        assert row["external_port"] == "8080"
        assert row["internal_ip"] == "192.0.2.50"
    finally:
        await c.aclose()


# --------------------------------------------------------------------- wifi


async def test_get_wifi_never_returns_psk_key(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        env = await server.router_get_wifi(c, include_raw=True)
        blob = json.dumps(env)
        assert "topsecretpassphrase" not in blob  # redacted even inside raw
        assert "psk_key" not in {k for band in env["data"]["bands"] for k in band}
        band2g = next(b for b in env["data"]["bands"] if b["band"] == "2g")
        assert band2g["ssid"] == "Home WiFi"
        assert band2g["enable"] is True
        assert band2g["channel"] == 6
    finally:
        await c.aclose()


# --------------------------------------------------------------------- mesh


async def test_list_mesh_nodes(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_list_mesh_nodes(c))["data"]
        node = data["nodes"][0]
        assert node["name"] == "Living Room"
        assert node["mac"] == "00:00:5E:00:53:31"
        assert node["version"] == "1.11.0"
    finally:
        await c.aclose()


# ------------------------------------------------- access control / limits / iot


async def test_get_access_control(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_get_access_control(c))["data"]
        assert data["enabled"] is True
        assert data["mode"] == "blacklist"
        assert data["black_list"] == ["00:00:5E:00:53:41"]
        assert data["white_devices"][0]["name"] == "Allowed"
    finally:
        await c.aclose()


async def test_get_speed_limits(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_get_speed_limits(c))["data"]
        row = data["limits"][0]
        assert row["mac"] == "00:00:5E:00:53:51"
        assert row["down_kbps"] == 2000
        assert row["enabled"] is True
    finally:
        await c.aclose()


async def test_get_wifi_schedule(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_get_wifi_schedule(c))["data"]
        assert data["enabled"] is True
    finally:
        await c.aclose()


async def test_get_iot_isolation(tmp_path: Path) -> None:
    _fake, c = _components(tmp_path)
    try:
        data = (await server.router_get_iot_isolation(c))["data"]
        assert data["enabled"] is True
        assert data["isolated"] == ["00:00:5E:00:53:61"]
    finally:
        await c.aclose()


# -------------------------------------------------------- adversarial / errors


async def test_malformed_list_becomes_protocol_error(tmp_path: Path) -> None:
    fake, c = _components(
        tmp_path,
    )
    fake._reads["reservation"] = {"data": "not-a-list"}
    try:
        env = await server.router_list_dhcp_reservations(c)
        assert env["success"] is False
        assert env["error"]["code"] == "PROTOCOL_ERROR"
    finally:
        await c.aclose()


async def test_errorcode_mapped_to_meaning(tmp_path: Path) -> None:
    fake, c = _components(tmp_path)
    fake._reads["client"] = {"errorcode": "permission denied"}
    try:
        env = await server.router_list_dhcp_leases(c)
        assert env["success"] is False
        assert env["error"]["code"] == "ROUTER_ERROR"
        assert env["error"]["details"]["code"] == "permission denied"
        assert "not permitted" in env["error"]["details"]["meaning"]
    finally:
        await c.aclose()


async def test_empty_list_handled(tmp_path: Path) -> None:
    fake, c = _components(tmp_path)
    fake._reads["client"] = {"data": []}
    try:
        env = await server.router_list_dhcp_leases(c)
        assert env["success"] is True
        assert env["data"] == {"leases": [], "count": 0}
    finally:
        await c.aclose()


async def test_missing_mac_in_row_is_protocol_error(tmp_path: Path) -> None:
    fake, c = _components(tmp_path)
    fake._reads["reservation"] = {"data": [{"ip": "192.0.2.21"}], "max_rules": 32}
    try:
        env = await server.router_list_dhcp_reservations(c)
        assert env["success"] is False
        assert env["error"]["code"] == "PROTOCOL_ERROR"
    finally:
        await c.aclose()


async def test_garbage_scalar_response_is_protocol_error(tmp_path: Path) -> None:
    fake, c = _components(tmp_path)
    # A bare JSON string where an object was expected.
    fake._reads["wan_ipv4_status"] = "nonsense"
    try:
        env = await server.router_get_wan(c)
        assert env["success"] is False
        assert env["error"]["code"] == "PROTOCOL_ERROR"
    finally:
        await c.aclose()


# -------------------------------------------------------- read-only invariant


async def test_reads_never_send_a_write_verb(tmp_path: Path) -> None:
    fake, c = _components(tmp_path)
    try:
        await server.router_get_status(c)
        await server.router_get_wan(c)
        await server.router_list_clients(c, include_offline=True)
        await server.router_list_dhcp_leases(c)
        await server.router_list_dhcp_reservations(c)
        await server.router_get_wifi(c)
        await server.router_list_port_forwards(c)
        await server.router_list_mesh_nodes(c)
        await server.router_get_access_control(c)
        await server.router_get_speed_limits(c)
        await server.router_get_wifi_schedule(c)
        await server.router_get_iot_isolation(c)
        assert fake.authed_ops, "expected the tools to have issued requests"
        offenders = [op for (_m, _f, op) in fake.authed_ops if op not in READ_VERBS]
        assert offenders == [], f"a read tool sent a mutating verb: {offenders}"
    finally:
        await c.aclose()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("00-00-5E-00-53-11", "00:00:5E:00:53:11"),
        ("00:00:5e:00:53:11", "00:00:5E:00:53:11"),
        ("00005E005311", "00:00:5E:00:53:11"),
        ("garbage", None),
        (None, None),
    ],
)
def test_normalize_mac_forms(raw, expected) -> None:
    assert normalize_mac(raw) == expected
