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
from .config import (
    DeviceSettings,
    GlobalSettings,
    load_device_settings,
    load_global_settings,
)
from .core.breaker import LoginBreaker, canonical_device_key
from .core.cli import configure_logging
from .core.tooling import run_tool
from .core.types import ConfirmWrite
from .presence import (
    PresenceSampler,
    PresenceStore,
    make_sampler,
    now_clock,
    router_client_history,
    router_poll_presence,
)
from .ratelimit import RebootLimiter
from .session import RouterSession
from .tools import (
    router_add_dhcp_reservation,
    router_block_device,
    router_get_access_control,
    router_get_iot_isolation,
    router_get_speed_limits,
    router_get_status,
    router_get_wan,
    router_get_wifi,
    router_get_wifi_schedule,
    router_isolate_device,
    router_list_clients,
    router_list_dhcp_leases,
    router_list_dhcp_reservations,
    router_list_mesh_nodes,
    router_list_port_forwards,
    router_reboot,
    router_remove_dhcp_reservation,
    router_set_access_mode,
    router_set_client_speed_limit,
    router_set_wifi,
    router_set_wifi_schedule,
    router_unblock_device,
    router_wol,
)
from .transport import ArcherTransport

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
    "router_add_dhcp_reservation",
    "router_remove_dhcp_reservation",
    "router_set_wifi",
    "router_reboot",
    "router_block_device",
    "router_unblock_device",
    "router_set_access_mode",
    "router_set_client_speed_limit",
    "router_set_wifi_schedule",
    "router_isolate_device",
    "router_wol",
)


def _require_protected_macs(settings: DeviceSettings) -> None:
    """Fail fast: writes may be enabled only with a non-empty PROTECTED_MACS list.

    The protected set guards the server's and owner's own devices from being
    blocked, limited, isolated or un-reserved. Enforced here (device layer) rather
    than in the shared core so the core stays device-agnostic.
    """
    from .core.errors import ConfigError

    if settings.allow_writes and not settings.protected_macs:
        raise ConfigError(
            f"{settings.env_name('PROTECTED_MACS')} must list at least one MAC address "
            f"when {settings.env_name('ALLOW_WRITES')}=true (the server's and owner's own "
            "devices). This guards block/limit/isolate/reservation-remove from hitting them."
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
    reboot_rate_limiter: RebootLimiter
    clock: Callable[[], float] = now_clock

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
        rng: random.Random | None = None,
        clock: Callable[[], float] | None = None,
    ) -> Components:
        source = os.environ if env is None else env
        settings = load_device_settings(DEVICE_PREFIX, source)
        _require_protected_macs(settings)
        global_settings = load_global_settings(MCP_PREFIX, source)
        resolved_clock = clock or now_clock
        transport = ArcherTransport(
            host=settings.host,
            port=settings.port,
            base_url=settings.base_url,
            verify_tls=settings.verify_tls,
            timeout_seconds=settings.timeout_seconds,
            tls_fingerprint_sha256=settings.tls_fingerprint_sha256,
            http_transport=http_transport,
        )
        device_key = canonical_device_key(settings.host)
        state_dir = resolve_state_dir(settings)
        breaker = LoginBreaker(
            state_dir,
            device_key,
            max_failures=settings.max_login_failures,
            login_disabled=settings.login_disabled,
            disabled_hint=f"{settings.env_name('LOGIN_DISABLED')}=true",
        )
        authenticator = RouterAuthenticator(settings, transport, breaker, rng=rng)
        session = RouterSession(settings, transport, authenticator)
        presence_store = PresenceStore(state_dir, max_mb=settings.presence_max_mb)
        reboot_rate_limiter = RebootLimiter(
            state_dir,
            device_key,
            min_interval_s=settings.reboot_min_interval_s,
            clock=resolved_clock,
        )
        return cls(
            settings,
            global_settings,
            transport,
            breaker,
            authenticator,
            session,
            presence_store,
            reboot_rate_limiter,
            resolved_clock,
        )

    async def aclose(self) -> None:
        await self.transport.aclose()


# --------------------------------------------------------------------- tools


async def router_status(components: Components) -> dict[str, Any]:
    """Healthcheck: device capabilities and breaker state, with no login."""

    async def _run() -> dict[str, Any]:
        caps = await components.authenticator.read_device_config()
        return {
            "model": caps.model,
            "ui_version": caps.ui_version,
            "certification": caps.certification,
            "feature_flags": caps.flags,
            "mode": caps.mode,
            "tls_fingerprint_observed": components.transport.observed_fingerprint,
            "breaker": components.breaker.status(),
        }

    return await run_tool("router_status", _run)


async def router_check_auth(
    components: Components, *, do_login: bool = False, force_takeover: bool = False
) -> dict[str, Any]:
    """Report capabilities and breaker counters; optionally perform one login.

    ``force_takeover`` defaults to False and only takes effect when the env var
    ``ARCHER_ROUTER_FORCE_SESSION_TAKEOVER`` is also set (double-gated in the
    authenticator); otherwise a ``user conflict`` surfaces rather than evicting the
    owner's web session.
    """

    async def _run() -> dict[str, Any]:
        caps = await components.authenticator.read_device_config()
        result: dict[str, Any] = {
            "model": caps.model,
            "ui_version": caps.ui_version,
            "feature_flags": caps.flags,
            "certification": caps.certification,
            "breaker": components.breaker.status(),
            "login_attempted": do_login,
            "authenticated": False,
        }
        if do_login:
            await components.session.login(explicit=True, force_takeover=force_takeover)
            result["authenticated"] = True
            result["mode"] = components.session.mode or caps.mode or "router"
        return result

    return await run_tool("router_check_auth", _run)


async def router_login(components: Components, *, force_takeover: bool = False) -> dict[str, Any]:
    """Explicitly log in (one attempt). Returns mode and flags, never the token.

    ``force_takeover`` defaults to False; it evicts another admin session only when
    ``ARCHER_ROUTER_FORCE_SESSION_TAKEOVER`` is also set (double-gated).
    """

    async def _run() -> dict[str, Any]:
        caps = await components.authenticator.read_device_config()
        session = await components.session.login(explicit=True, force_takeover=force_takeover)
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
    async def _login(force_takeover: bool = False) -> dict[str, Any]:
        """Perform exactly one explicit login. Returns mode and flags only — never a
        token or cookie. Refused if the breaker is open or logins are disabled.
        force_takeover (default False) evicts another admin session only when
        ARCHER_ROUTER_FORCE_SESSION_TAKEOVER is also set."""
        return await router_login(components, force_takeover=force_takeover)

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

    # ---- write tools (R4): double-gated (ALLOW_WRITES env + confirm_write) ----

    @app.tool(name="router_add_dhcp_reservation")
    async def _add_reservation(
        mac: str, ip: str, name: str, confirm_write: ConfirmWrite = False
    ) -> dict[str, Any]:
        """MUTATES. Add a DHCP address reservation. Refuses a duplicate MAC, an IP
        already reserved for another device, or an IP outside the LAN subnet. Needs
        ALLOW_WRITES=true and confirm_write=true; DRY_RUN shows the exact body."""
        return await router_add_dhcp_reservation(
            components, mac, ip, name, confirm_write=confirm_write
        )

    @app.tool(name="router_remove_dhcp_reservation")
    async def _remove_reservation(mac: str, confirm_write: ConfirmWrite = False) -> dict[str, Any]:
        """MUTATES. Remove a DHCP reservation by MAC. Refused for a protected MAC or
        if no such reservation exists. Double-gated; DRY_RUN sends nothing."""
        return await router_remove_dhcp_reservation(components, mac, confirm_write=confirm_write)

    @app.tool(name="router_set_wifi")
    async def _set_wifi(
        band: str, enabled: bool, confirm_write: ConfirmWrite = False
    ) -> dict[str, Any]:
        """MUTATES. Turn a Wi-Fi band (2g|5g) radio on/off. The write body is
        UNVERIFIED until the R0 capture, so a live write is refused with
        R0_UNCONFIRMED; DRY_RUN still shows the planned body. Double-gated."""
        return await router_set_wifi(components, band, enabled, confirm_write=confirm_write)

    @app.tool(name="router_reboot")
    async def _reboot(confirm_write: ConfirmWrite = False) -> dict[str, Any]:
        """MUTATES; disruptive. Reboot the router, rate-limited to one per
        ARCHER_ROUTER_REBOOT_MIN_INTERVAL_S. Double-gated; DRY_RUN shows the next
        allowed time and sends nothing."""
        return await router_reboot(components, confirm_write=confirm_write)

    @app.tool(name="router_block_device")
    async def _block(mac: str, confirm_write: ConfirmWrite = False) -> dict[str, Any]:
        """MUTATES. Block a client by MAC (access-control black list). Refused for a
        protected MAC. Double-gated; DRY_RUN sends nothing."""
        return await router_block_device(components, mac, confirm_write=confirm_write)

    @app.tool(name="router_unblock_device")
    async def _unblock(mac: str, confirm_write: ConfirmWrite = False) -> dict[str, Any]:
        """MUTATES. Unblock a client by MAC. Double-gated; DRY_RUN sends nothing."""
        return await router_unblock_device(components, mac, confirm_write=confirm_write)

    @app.tool(name="router_set_access_mode")
    async def _set_access_mode(mode: str, confirm_write: ConfirmWrite = False) -> dict[str, Any]:
        """MUTATES. Set access-control mode (off|blacklist|whitelist). Whitelist is
        refused unless every protected MAC is already whitelisted. Double-gated."""
        return await router_set_access_mode(components, mode, confirm_write=confirm_write)

    @app.tool(name="router_set_client_speed_limit")
    async def _set_speed(
        mac: str, down_kbps: int, up_kbps: int, confirm_write: ConfirmWrite = False
    ) -> dict[str, Any]:
        """MUTATES. Set a per-client bandwidth limit in kbps (0 = unlimited). Refused
        for a protected MAC. Double-gated; DRY_RUN sends nothing."""
        return await router_set_client_speed_limit(
            components, mac, down_kbps, up_kbps, confirm_write=confirm_write
        )

    @app.tool(name="router_set_wifi_schedule")
    async def _set_schedule(
        rules: list[dict[str, Any]] | None = None, confirm_write: ConfirmWrite = False
    ) -> dict[str, Any]:
        """MUTATES. Replace the Wi-Fi on/off schedule (enable + rule list). Rule shape
        is INFERRED. Double-gated; DRY_RUN sends nothing."""
        return await router_set_wifi_schedule(components, rules or [], confirm_write=confirm_write)

    @app.tool(name="router_isolate_device")
    async def _isolate(
        mac: str, isolate: bool, confirm_write: ConfirmWrite = False
    ) -> dict[str, Any]:
        """MUTATES. Isolate (True) or un-isolate (False) a device. Isolating a
        protected MAC is refused. Double-gated; DRY_RUN sends nothing."""
        return await router_isolate_device(components, mac, isolate, confirm_write=confirm_write)

    @app.tool(name="router_wol")
    async def _wol(mac: str, confirm_write: ConfirmWrite = False) -> dict[str, Any]:
        """MUTATES. Send a Wake-on-LAN magic packet to a device by MAC. Double-gated;
        DRY_RUN sends nothing."""
        return await router_wol(components, mac, confirm_write=confirm_write)

    return app


def serve(env: Mapping[str, str] | None = None) -> None:  # pragma: no cover - runs the server loop
    source = os.environ if env is None else env
    configure_logging(LOG_LEVEL_VAR, source)
    components = Components.from_env(source)
    interval = components.settings.presence_interval_s
    sampler = make_sampler(components, interval) if interval > 0 else None
    app = create_app(components, sampler=sampler)
    app.run(transport=components.global_settings.mcp_transport)
