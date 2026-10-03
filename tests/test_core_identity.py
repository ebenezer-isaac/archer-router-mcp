"""The core-identity gate: ``core/`` and the conformance test are byte-identical to
``core/VERSION``'s manifest, so the three repos' copies cannot drift silently.

This is the test that would have caught the three-way split the root-cause pass
found. The only documented exception is the package-name line in ``core/README.md``
(normalised by ``scripts/core_manifest.py`` before hashing).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import core_manifest  # noqa: E402 - needs the scripts path appended above


def test_core_manifest_matches_version_file() -> None:
    recorded = core_manifest.read_version()
    computed = core_manifest.compute_manifest()
    assert recorded.get("manifest") == computed, (
        "core/ or the conformance test changed without regenerating core/VERSION; "
        "run `python scripts/core_manifest.py`."
    )


def test_version_lists_every_core_file_and_the_conformance_test() -> None:
    recorded = set(core_manifest.read_version()["manifest"])
    assert "tests/conformance/test_breaker_contract.py" in recorded
    assert "core/breaker.py" in recorded
    assert "core/state.py" in recorded
    assert "core/transport.py" in recorded
