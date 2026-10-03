"""Component wiring, the ``router_*`` tools, and the FastMCP application factory.

Everything the server does is built from one :class:`Components` bundle so the CLI
and the tests can inject a fake transport. Tools never raise: each runs through
``core.tooling.run_tool``, which redacts the result and maps errors to the
``{success, data, error}`` envelope. No tool ever returns a token or cookie.
"""

from __future__ import annotations

import os
import random
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .auth import RouterAuthenticator
from .core.breaker import LoginBreaker
from .core.cli import configure_logging
from .core.config import (
    DeviceSettings,
    GlobalSettings,
    load_device_settings,
    load_global_settings,
)
from .core.tooling import run_tool
from .presence import (
    PresenceSampler,
    PresenceStore,
    make_sampler,
    now_clock,
    router_client_history,
    router_poll_presence,
)
from .session import RouterSession
from .tools import (
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
from .transport import ArcherTransport, FingerprintProbe

DEVICE_PREFIX = "ARCHER_ROUTER_"
MCP_PREFIX = "ARCHER_MCP_"
LOG_LEVEL_VAR = f"{MCP_PREFIX}LOG_LEVEL"
SERVER_NAME = "archer-router-mcp"

TOOL_NAMES: tuple[str, ...] = (
    "router_status",
    "router_check_auth",
    "router_login",
    "router_logout",
    "router_get_status",
    "router_get_wan",
    "router_list_clients",
    "router_list_dhcp_leases",
    "router_list_dhcp_reservations",
    "router_get_wifi",
    "router_list_port_forwards",
    "router_list_mesh_nodes",
    "router_get_access_control",
    "router_get_speed_limits",
    "router_get_wifi_schedule",
    "router_get_iot_isolation",
    "router_poll_presence",
    "router_client_history",
)


def resolve_state_dir(settings: DeviceSettings) -> Path:
    """Where the breaker/rate-limit state lives (``ARCHER_ROUTER_STATE_DIR`` default)."""
    if settings.state_dir:
        return Path(settings.state_dir).expanduser()
    return Path.home() / ".local" / "state" / "archer-router-mcp"


@dataclass
class Components:
    settings: DeviceSettings
    global_settings: GlobalSettings
    transport: ArcherTransport
    breaker: LoginBreaker
    authenticator: RouterAuthenticator
    session: RouterSession
    presence_store: PresenceStore
    clock: Callable[[], float] = now_clock

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
        fingerprint_probe: FingerprintProbe | None = None,
        rng: random.Random | None = None,
        clock: Callable[[], float] | None = None,
    ) -> Components:
        source = os.environ if env is None else env
        settings = load_device_settings(DEVICE_PREFIX, source)
        global_settings = load_global_settings(MCP_PREFIX, source)
        transport = ArcherTransport(
            host=settings.host,
            port=settings.port,
            base_url=settings.base_url,
            verify_tls=settings.verify_tls,
            timeout_seconds=settings.timeout_seconds,
            tls_fingerprint_sha256=settings.tls_fingerprint_sha256,
            http_transport=http_transport,
            fingerprint_probe=fingerprint_probe,
        )
        breaker = LoginBreaker(resolve_state_dir(settings), settings)
        authenticator = RouterAuthenticator(settings, transport, breaker, rng=rng)
        session = RouterSession(settings, transport, authenticator)
        presence_store = PresenceStore(resolve_state_dir(settings), max_mb=settings.presence_max_mb)
        return cls(
            settings,
            global_settings,
            transport,
            breaker,
            authenticator,
            session,
            presence_store,
            clock or now_clock,
        )

    async def aclose(self) -> None:
        await self.transport.aclose()


# --------------------------------------------------------------------- tools


async def router_status(components: Components) -> dict[str, Any]:
    """Healthcheck: device capabilities and breaker state, with no login."""

    async def _run() -> dict[str, Any]:
        caps = await components.authenticator.read_device_config()
        fingerprint = await components.transport.observed_fingerprint()
        return {
            "model": caps.model,
            "ui_version": caps.ui_version,
            "certification": caps.certification,
            "feature_flags": caps.flags,
            "mode": caps.mode,
            "tls_fingerprint_sha256": fingerprint,
            "breaker": components.breaker.show(),
        }

    return await run_tool("router_status", _run)


async def router_check_auth(components: Components, *, do_login: bool = False) -> dict[str, Any]:
    """Report capabilities and breaker counters; optionally perform one login."""

    async def _run() -> dict[str, Any]:
        caps = await components.authenticator.read_device_config()
        result: dict[str, Any] = {
            "model": caps.model,
            "ui_version": caps.ui_version,
            "feature_flags": caps.flags,
            "certification": caps.certification,
            "breaker": components.breaker.show(),
            "login_attempted": do_login,
            "authenticated": False,
        }
        if do_login:
            await components.session.login(explicit=True, force_takeover=True)
            result["authenticated"] = True
            result["mode"] = components.session.mode or caps.mode or "router"
        return result

    return await run_tool("router_check_auth", _run)


async def router_login(components: Components) -> dict[str, Any]:
    """Explicitly log in (one attempt). Returns mode and flags, never the token."""

    async def _run() -> dict[str, Any]:
        caps = await components.authenticator.read_device_config()
        session = await components.session.login(explicit=True, force_takeover=True)
        return {
            "authenticated": True,
            "mode": session.mode or caps.mode or "router",
            "feature_flags": caps.flags,
        }

    return await run_tool("router_login", _run)


async def router_logout(components: Components) -> dict[str, Any]:
    """Log out of the router session if one is active."""

    async def _run() -> dict[str, Any]:
        was_authenticated = components.session.authenticated
        await components.session.logout()
        return {"logged_out": True, "was_authenticated": was_authenticated}

    return await run_tool("router_logout", _run)


def create_app(components: Components, *, sampler: PresenceSampler | None = None) -> Any:
    """Build a FastMCP app exposing the ``router_*`` tools over ``components``.

    When ``sampler`` is given, it is started on server startup and stopped on
    shutdown via the app lifespan, so the optional presence sampler runs inside the
    server's own event loop.
    """
    from contextlib import asynccontextmanager

    from mcp.server.fastmcp import FastMCP

    lifespan = None
    if sampler is not None:

        @asynccontextmanager
        async def lifespan(_server: Any):
            sampler.start()
            try:
                yield {}
            finally:
                await sampler.stop()

    app = FastMCP(SERVER_NAME, lifespan=lifespan)

    @app.tool(name="router_status")
    async def _status() -> dict[str, Any]:
        """Device model, UI version, SG feature flags, observed TLS fingerprint and
        breaker state. Read-only; performs no login."""
        return await router_status(components)

    @app.tool(name="router_check_auth")
    async def _check_auth() -> dict[str, Any]:
        """Report capabilities and login-breaker counters without logging in."""
        return await router_check_auth(components, do_login=False)

    @app.tool(name="router_login")
    async def _login() -> dict[str, Any]:
        """Perform exactly one explicit login. Returns mode and flags only — never a
        token or cookie. Refused if the breaker is open or logins are disabled."""
        return await router_login(components)

    @app.tool(name="router_logout")
    async def _logout() -> dict[str, Any]:
        """End the current router session."""
        return await router_logout(components)

    @app.tool(name="router_get_status")
    async def _get_status(include_raw: bool = False) -> dict[str, Any]:
        """Router summary: model, firmware, uptime, WAN/LAN addresses and radios.
        Read-only; no writes are ever sent."""
        return await router_get_status(components, include_raw=include_raw)

    @app.tool(name="router_get_wan")
    async def _get_wan(include_raw: bool = False) -> dict[str, Any]:
        """WAN IPv4 status: connection type, IP/mask/gateway, DNS and uptime. Read-only."""
        return await router_get_wan(components, include_raw=include_raw)

    @app.tool(name="router_list_clients")
    async def _list_clients(
        include_offline: bool = False, include_raw: bool = False
    ) -> dict[str, Any]:
        """The connected-clients list, merged across all five of the router's device
        lists, one entry per MAC. Set include_offline to include known-but-absent
        devices. Read-only."""
        return await router_list_clients(
            components, include_offline=include_offline, include_raw=include_raw
        )

    @app.tool(name="router_list_dhcp_leases")
    async def _list_leases(include_raw: bool = False) -> dict[str, Any]:
        """Active DHCP leases: mac, ip, name and lease time. Read-only."""
        return await router_list_dhcp_leases(components, include_raw=include_raw)

    @app.tool(name="router_list_dhcp_reservations")
    async def _list_reservations(include_raw: bool = False) -> dict[str, Any]:
        """DHCP address reservations (static leases) plus the max-rules limit. Read-only."""
        return await router_list_dhcp_reservations(components, include_raw=include_raw)

    @app.tool(name="router_get_wifi")
    async def _get_wifi(include_raw: bool = False) -> dict[str, Any]:
        """Wi-Fi per band: enable, SSID, encryption and hidden flag. The pre-shared
        key is never returned. Read-only."""
        return await router_get_wifi(components, include_raw=include_raw)

    @app.tool(name="router_list_port_forwards")
    async def _list_port_forwards(include_raw: bool = False) -> dict[str, Any]:
        """Virtual-server port-forward rules. Read-only."""
        return await router_list_port_forwards(components, include_raw=include_raw)

    @app.tool(name="router_list_mesh_nodes")
    async def _list_mesh(include_raw: bool = False) -> dict[str, Any]:
        """EasyMesh nodes: name, model, ip, mac and firmware version. Read-only."""
        return await router_list_mesh_nodes(components, include_raw=include_raw)

    @app.tool(name="router_get_access_control")
    async def _get_access_control(include_raw: bool = False) -> dict[str, Any]:
        """Access control: enabled, mode (black/white list) and the device lists. Read-only."""
        return await router_get_access_control(components, include_raw=include_raw)

    @app.tool(name="router_get_speed_limits")
    async def _get_speed_limits(include_raw: bool = False) -> dict[str, Any]:
        """Per-client bandwidth speed limits. Read-only."""
        return await router_get_speed_limits(components, include_raw=include_raw)

    @app.tool(name="router_get_wifi_schedule")
    async def _get_wifi_schedule(include_raw: bool = False) -> dict[str, Any]:
        """The scheduled Wi-Fi on/off rules. Read-only."""
        return await router_get_wifi_schedule(components, include_raw=include_raw)

    @app.tool(name="router_get_iot_isolation")
    async def _get_iot_isolation(include_raw: bool = False) -> dict[str, Any]:
        """IoT isolation: whether it is enabled and which devices are isolated. Read-only."""
        return await router_get_iot_isolation(components, include_raw=include_raw)

    @app.tool(name="router_poll_presence")
    async def _poll_presence() -> dict[str, Any]:
        """Take one presence sample: read the live clients, diff against the last
        sample, and append join/leave/rename events to the local history log.
        Read-only against the router."""
        return await router_poll_presence(components)

    @app.tool(name="router_client_history")
    async def _client_history(
        since: float = 0.0, mac: str | None = None, limit: int = 500
    ) -> dict[str, Any]:
        """Recorded presence events (join/leave/rename) from the local history log,
        optionally filtered by since (Unix time) and mac. No router I/O; history
        comes only from past samples."""
        return await router_client_history(components, since=since, mac=mac, limit=limit)

    return app


def serve(env: Mapping[str, str] | None = None) -> None:  # pragma: no cover - runs the server loop
    source = os.environ if env is None else env
    configure_logging(LOG_LEVEL_VAR, source)
    components = Components.from_env(source)
    interval = components.settings.presence_interval_s
    sampler = make_sampler(components, interval) if interval > 0 else None
    app = create_app(components, sampler=sampler)
    app.run(transport=components.global_settings.mcp_transport)
