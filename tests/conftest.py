"""Shared test fixtures.

The breaker conformance suite (``tests/conformance/test_breaker_contract.py``) is
copied verbatim from the canonical repo and hashed by ``core/VERSION``, so it must
not name any one package. It resolves ``breaker``/``errors``/``state`` from the
``core_pkg`` fixture below (and its spawned multiprocess workers import the same
package by the path passed through their arguments, ``core_pkg.__name__``)."""

from __future__ import annotations

import pytest


@pytest.fixture
def core_pkg():
    import archer_router_mcp.core as core  # this repo's core package

    return core
