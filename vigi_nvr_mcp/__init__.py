"""Test-only namespace shim for the canonical breaker conformance suite.

The conformance suite (``tests/conformance/test_breaker_contract.py``) is copied
verbatim from the canonical repo and hashed by ``core/VERSION`` (the identity test),
so its imports must read ``vigi_nvr_mcp.core.*`` byte-for-byte in every repo. This
package aliases that canonical namespace onto *this* repo's ``archer_router_mcp.core``
so the verbatim suite runs here unchanged. It is not shipped (the wheel packages only
``archer_router_mcp``); it exists solely so the shared contract test is importable,
including inside spawned ``multiprocessing`` workers (sys.path is preserved on spawn).
"""

from __future__ import annotations

import sys

import archer_router_mcp.core as _core
import archer_router_mcp.core.breaker as _breaker
import archer_router_mcp.core.errors as _errors
import archer_router_mcp.core.state as _state

# Reuse the exact same module objects (no second load), so the classes the
# conformance suite imports are identical to the ones the package uses.
sys.modules[__name__ + ".core"] = _core
sys.modules[__name__ + ".core.breaker"] = _breaker
sys.modules[__name__ + ".core.errors"] = _errors
sys.modules[__name__ + ".core.state"] = _state
