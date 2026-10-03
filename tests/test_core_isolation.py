"""core/ is copied verbatim between sibling repos; these tests enforce that it
stays self-contained and device-agnostic so the copy keeps working."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "archer_router_mcp"


def test_core_imports_nothing_from_the_package() -> None:
    """core/ may import only stdlib / third-party / other core modules."""
    for path in (PACKAGE / "core").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level >= 2:
                    pytest.fail(f"{path.name} imports outside core: level {node.level}")
                if node.module and node.module.startswith("archer_router_mcp"):
                    pytest.fail(f"{path.name} imports {node.module}")
            if isinstance(node, ast.Import):
                assert not any(a.name.startswith("archer_router_mcp") for a in node.names)


def test_core_is_device_agnostic() -> None:
    # "router" is intentionally NOT forbidden: core/ is copied verbatim across the
    # sibling repos and core/slot.py's architectural note names each sibling user of
    # the primitive ("the switch's cycle guard and the router's reboot limiter in the
    # sibling repos"). As in vigi's own device-agnostic check, only this repo's
    # device-identity terms are forbidden, not generic sibling references.
    words = ("archer", "tp-link", "tplink", "stok=<", "luci")
    for path in (PACKAGE / "core").glob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        for word in words:
            assert word not in text, f"{path.name} mentions {word!r}"
