"""Console entry point for ``archer-router-mcp``.

Surfaces: ``--list-tools`` (the release gate depends on it), ``--check-auth
[--login]`` (capabilities, optionally one login), ``breaker --show|--clear``
(inspect or reset the persistent login breaker), and ``serve`` (run the MCP
server). Every path returns an honest result; there are no stubs.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence

from . import server
from .core.cli import configure_logging, emit_envelope, emit_lines
from .core.envelope import fail, ok
from .core.errors import ConfigError

TOOLS: tuple[str, ...] = server.TOOL_NAMES


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="archer-router-mcp",
        description="MCP server for the TP-Link Archer AX53 v1 (auth + session build).",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["serve", "breaker"],
        default=None,
        help="serve: run the MCP server. breaker: inspect/reset the login breaker.",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print the registered MCP tool names, one per line, then exit.",
    )
    parser.add_argument(
        "--check-auth",
        action="store_true",
        help="Read router capabilities (no login unless --login is given).",
    )
    parser.add_argument(
        "--login",
        action="store_true",
        help="With --check-auth: perform exactly one login attempt.",
    )
    parser.add_argument(
        "--force-takeover",
        action="store_true",
        help="With --check-auth --login: evict another admin session (only when "
        "ARCHER_ROUTER_FORCE_SESSION_TAKEOVER=true is also set). Off by default.",
    )
    parser.add_argument("--show", action="store_true", help="breaker: show the current state.")
    parser.add_argument("--clear", action="store_true", help="breaker: clear the breaker state.")
    return parser


def list_tools() -> list[str]:
    """Return the registered tool names."""
    return list(TOOLS)


def _run_check_auth(
    do_login: bool, components: server.Components | None, *, force_takeover: bool = False
) -> int:
    configure_logging(server.LOG_LEVEL_VAR)

    async def _go() -> dict:
        comps = components or server.Components.from_env()
        try:
            return await server.router_check_auth(
                comps, do_login=do_login, force_takeover=force_takeover
            )
        finally:
            if components is None:
                await comps.aclose()

    try:
        result = asyncio.run(_go())
    except ConfigError as exc:
        result = fail("CONFIG_ERROR", str(exc))
    return emit_envelope(result)


def _run_breaker(show: bool, clear: bool, components: server.Components | None) -> int:
    configure_logging(server.LOG_LEVEL_VAR)

    async def _go() -> dict:
        comps = components or server.Components.from_env()
        try:
            if clear:
                comps.breaker.clear()
                return ok({"cleared": True, "path": str(comps.breaker.path)})
            return ok(comps.breaker.show())
        finally:
            if components is None:
                await comps.aclose()

    try:
        result = asyncio.run(_go())
    except ConfigError as exc:
        result = fail("CONFIG_ERROR", str(exc))
    return emit_envelope(result)


def main(argv: Sequence[str] | None = None, *, components: server.Components | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.list_tools:
        return emit_lines(list_tools())
    if args.check_auth:
        return _run_check_auth(args.login, components, force_takeover=args.force_takeover)
    if args.command == "breaker":
        return _run_breaker(args.show, args.clear, components)
    if args.command == "serve":
        server.serve()
        return 0
    parser.print_help(sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
