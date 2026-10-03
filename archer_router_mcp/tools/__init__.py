"""The ``router_*`` read tools (R3), kept out of ``server.py`` to bound its size."""

from __future__ import annotations

from .reads import (
    router_get_access_control,
    router_get_iot_isolation,
    router_get_speed_limits,
    router_get_status,
    router_get_wan,
    router_get_wifi,
    router_get_wifi_schedule,
    router_list_clients,
    router_list_dhcp_leases,
    router_list_dhcp_reservations,
    router_list_mesh_nodes,
    router_list_port_forwards,
)

__all__ = [
    "router_get_access_control",
    "router_get_iot_isolation",
    "router_get_speed_limits",
    "router_get_status",
    "router_get_wan",
    "router_get_wifi",
    "router_get_wifi_schedule",
    "router_list_clients",
    "router_list_dhcp_leases",
    "router_list_dhcp_reservations",
    "router_list_mesh_nodes",
    "router_list_port_forwards",
]
