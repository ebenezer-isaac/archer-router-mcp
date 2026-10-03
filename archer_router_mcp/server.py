"""Component wiring, the ``router_*`` tools, and the FastMCP application factory.

Everything the server does is built from one :class:`Components` bundle so the CLI
and the tests can inject a fake transport. Tools never raise: each runs through
``core.tooling.run_tool``, which redacts the result and maps errors to the
``{success, data, error}`` envelope. No tool ever returns a token or cookie.
"""

from __future__ import annotations

import os
import random
from collections.abc import Mapping
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
from .session import RouterSession
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

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
        fingerprint_probe: FingerprintProbe | None = None,
        rng: random.Random | None = None,
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
        return cls(settings, global_settings, transport, breaker, authenticator, session)

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


def create_app(components: Components) -> Any:
    """Build a FastMCP app exposing the ``router_*`` tools over ``components``."""
    from mcp.server.fastmcp import FastMCP

    app = FastMCP(SERVER_NAME)

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

    return app


def serve(env: Mapping[str, str] | None = None) -> None:  # pragma: no cover - runs the server loop
    source = os.environ if env is None else env
    configure_logging(LOG_LEVEL_VAR, source)
    components = Components.from_env(source)
    app = create_app(components)
    app.run(transport=components.global_settings.mcp_transport)
