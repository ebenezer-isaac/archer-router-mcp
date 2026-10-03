"""Small helpers shared by device CLIs."""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Mapping
from typing import Any, TextIO


def configure_logging(level_var: str, environ: Mapping[str, str] | None = None) -> None:
    """Log to stderr (stdout is the MCP stdio channel) at ``$level_var`` (default INFO)."""
    source = os.environ if environ is None else environ
    level = str(source.get(level_var, "INFO")).upper()
    logging.basicConfig(
        level=level if level in logging.getLevelNamesMapping() else "INFO",
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def emit_envelope(result: dict[str, Any], stream: TextIO | None = None) -> int:
    """Print an envelope as sorted JSON; return exit code 0 on success, 1 otherwise."""
    print(json.dumps(result, indent=2, sort_keys=True), file=stream or sys.stdout)
    return 0 if result.get("success") is True else 1


def emit_lines(lines: list[str], stream: TextIO | None = None) -> int:
    for line in lines:
        print(line, file=stream or sys.stdout)
    return 0
