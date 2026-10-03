"""Normalised, LLM-friendly pydantic output models for the read tools.

Every model is frozen and ignores unexpected keys. Fields the router does not
always provide are optional and default to ``None`` so a firmware that drops a
field yields a partial-but-valid model rather than a crash. Confidence of the
underlying field mapping (``VERIFIED`` vs ``INFERRED``) is noted per model; the
tools surface the raw payload under ``raw`` when asked, for anything not modelled.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")


class StatusInfo(_Model):
    """Router summary from ``status?form=all`` (+ ``internet``/``lan_ipv4``). Fields INFERRED."""

    model: str | None = None
    firmware: str | None = None
    hardware_version: str | None = None
    uptime_seconds: int | None = None
    wan_up: bool | None = None
    wan_ip: str | None = None
    lan_ip: str | None = None
    lan_mac: str | None = None
    wan_mac: str | None = None
    cpu_usage: int | None = None
    mem_usage: int | None = None
    radio_2g_on: bool | None = None
    radio_5g_on: bool | None = None
    client_count: int | None = None


class WanInfo(_Model):
    """WAN IPv4 status from ``network?form=wan_ipv4_status``. Fields INFERRED."""

    conn_type: str | None = None
    ip: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    dns: list[str] = []
    uptime_seconds: int | None = None
    up: bool | None = None


class ClientInfo(_Model):
    """One connected/known client, merged across up to five sources (fields INFERRED)."""

    mac: str
    ip: str | None = None
    name: str | None = None
    type: str | None = None
    band: str | None = None
    wired: bool | None = None
    signal: int | None = None
    rx_mbps: float | None = None
    tx_mbps: float | None = None
    online: bool = False
    source: list[str] = []


class DhcpLease(_Model):
    """A DHCP lease row from ``dhcps?form=client`` (VERIFIED field names)."""

    mac: str
    ip: str | None = None
    name: str | None = None
    lease_time: str | None = None


class Reservation(_Model):
    """A DHCP address-reservation row from ``dhcps?form=reservation`` (VERIFIED)."""

    mac: str
    ip: str | None = None
    hostname: str | None = None
    enable: bool | None = None
    row_id: str | None = None  # the router's row ``key`` (renamed to survive redaction)


class WifiBand(_Model):
    """One wireless band from ``wireless?form=wireless_<band>`` (``psk_key`` never included)."""

    band: str
    enable: bool | None = None
    ssid: str | None = None
    encryption: str | None = None
    hidden: bool | None = None
    channel: int | None = None


class PortForward(_Model):
    """A virtual-server (port-forward) row from ``nat?form=vs``. Fields INFERRED."""

    row_id: str | None = None  # the router's row ``key`` (renamed to survive redaction)
    name: str | None = None
    enable: bool | None = None
    protocol: str | None = None
    external_port: str | None = None
    internal_port: str | None = None
    internal_ip: str | None = None


class MeshNode(_Model):
    """An EasyMesh node from ``easymesh_network?form=get_mesh_device_list_all`` (INFERRED)."""

    name: str | None = None
    model: str | None = None
    ip: str | None = None
    mac: str | None = None
    version: str | None = None


class SpeedLimitRow(_Model):
    """A per-client speed limit from ``smart_network?form=client_speed_limit`` (INFERRED)."""

    mac: str
    name: str | None = None
    down_kbps: int | None = None
    up_kbps: int | None = None
    enabled: bool | None = None


class PresenceEvent(_Model):
    """A presence change derived from two samples; timestamps come only from samples."""

    type: str  # "join" | "leave" | "rename"
    mac: str
    ts: float
    name: str | None = None
    old_name: str | None = None
    new_name: str | None = None
    ip: str | None = None
