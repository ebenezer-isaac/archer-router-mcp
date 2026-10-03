"""BREAKER r1 / crypto — F3: no feature-flag / isSupport / shouldSkipEncrypt code.

Claim under attack: "`shouldSkipEncrypt`/feature-flag derivation reproduces the
bundle's `isSupport()` for the SG certification."

crypto.py contains none of this: no FEATURE_MAP, no is_support(), no
shouldSkipEncrypt(), no needEncrypt(). The only occurrence of the word
"certification" in the whole package is a docstring line. The fixture carries
the authoritative ``isSupport`` output produced by executing the real bundle
across several certification strings; nothing in crypto.py can reproduce it.
"""

from __future__ import annotations

import json
from pathlib import Path

from archer_router_mcp import crypto

_FIX = json.loads(
    (Path(__file__).parent / "fixtures" / "breaker_vectors.json").read_text(encoding="utf-8")
)
_ALL_FLAGS = _FIX["feature_map_all_flags"]
_SG = _FIX["isSupport_by_cert"]["SG"]


def _any_support_callable() -> object | None:
    for name in ("is_support", "isSupport", "supports", "feature_enabled"):
        fn = getattr(crypto, name, None)
        if callable(fn):
            return fn
    return None


def test_crypto_exposes_a_feature_map() -> None:
    """FAILS: the bundle's FEATURE_MAP has no counterpart in crypto.py."""
    has_map = any(
        isinstance(getattr(crypto, n, None), dict)
        for n in ("FEATURE_MAP", "FEATURES", "feature_map")
    )
    assert has_map, "crypto.py has no FEATURE_MAP equivalent for the SG profile"


def test_crypto_can_reproduce_isSupport_for_sg_profile() -> None:
    """FAILS: there is no isSupport()/shouldSkipEncrypt() to call at all."""
    fn = _any_support_callable()
    assert fn is not None, "crypto.py exposes no is_support()/shouldSkipEncrypt()"
    produced = {flag: bool(fn(flag, ["US FCC", "SG CLS L1 STAGE2"])) for flag in _ALL_FLAGS}
    assert produced == _SG, f"isSupport output diverges: {produced} != {_SG}"


def test_crypto_exposes_should_skip_encrypt() -> None:
    """FAILS: shouldSkipEncrypt is claimed for crypto.py but absent."""
    assert hasattr(crypto, "should_skip_encrypt") or hasattr(crypto, "shouldSkipEncrypt"), (
        "crypto.py has no shouldSkipEncrypt derivation despite the claim"
    )
