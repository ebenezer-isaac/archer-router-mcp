"""The ``router_*`` tools (R3 reads, R4 writes), kept out of ``server.py``."""

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
from .writes import (
    router_add_dhcp_reservation,
    router_reboot,
    router_remove_dhcp_reservation,
    router_set_wifi,
)
from .writes_access import (
    router_block_device,
    router_isolate_device,
    router_set_access_mode,
    router_set_client_speed_limit,
    router_set_wifi_schedule,
    router_unblock_device,
    router_wol,
)

__all__ = [
    "router_add_dhcp_reservation",
    "router_block_device",
    "router_get_access_control",
    "router_get_iot_isolation",
    "router_get_speed_limits",
    "router_get_status",
    "router_get_wan",
    "router_get_wifi",
    "router_get_wifi_schedule",
    "router_isolate_device",
    "router_list_clients",
    "router_list_dhcp_leases",
    "router_list_dhcp_reservations",
    "router_list_mesh_nodes",
    "router_list_port_forwards",
    "router_reboot",
    "router_remove_dhcp_reservation",
    "router_set_access_mode",
    "router_set_client_speed_limit",
    "router_set_wifi",
    "router_set_wifi_schedule",
    "router_unblock_device",
    "router_wol",
]
