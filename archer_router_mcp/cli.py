"""Console entry point for ``archer-router-mcp``.

Phase R1 ships only the pure crypto layer, so the sole stable CLI surface is
``--list-tools`` (the release gate depends on it). The tool registry is empty
until Phase R2 adds the authenticated session and the ``router_*`` tools; this
module lists whatever is registered and otherwise prints usage. There are no
stubs here: every path returns an honest result for what R1 actually provides.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .core.cli import emit_lines

# Populated by later phases as tools are registered. Empty in R1 by design.
TOOLS: tuple[str, ...] = ()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="archer-router-mcp",
        description="MCP server for the TP-Link Archer AX53 v1 (crypto layer only in this build).",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print the names of the registered MCP tools, one per line, then exit.",
    )
    return parser


def list_tools() -> list[str]:
    """Return the registered tool names (empty until Phase R2)."""
    return list(TOOLS)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.list_tools:
        return emit_lines(list_tools())
    parser.print_help(sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
