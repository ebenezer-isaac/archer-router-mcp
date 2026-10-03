"""BREAKER r1 / crypto — F2: AesKey repr/str leaks the key and IV.

Claim under attack: "all functions ... never put a password, key, IV or hash
into an exception message or repr."

``AesKey`` is a ``@dataclass(frozen=True)`` with no ``repr=False`` on its
fields, so Python synthesises a ``__repr__`` (and therefore ``__str__``) that
prints the secret key and IV verbatim. Any ``repr(aes)``, ``str(aes)``,
``f"{aes}"``, ``logging.debug("%r", aes)``, error ``details=aes`` or a
locals-printing traceback hook (pytest -l, cgitb, Sentry) discloses the AES
session key and IV — exactly what the claim says never happens.
"""

from __future__ import annotations

import pytest

from archer_router_mcp.crypto import AesKey

_KEY = "1234567890123456"
_IV = "6543210987654321"


def test_repr_does_not_contain_key_or_iv() -> None:
    """FAILS: the default dataclass repr embeds the key and IV."""
    aes = AesKey(_KEY, _IV)
    text = repr(aes)
    assert _KEY not in text, f"AES key leaked in repr: {text!r}"
    assert _IV not in text, f"AES iv leaked in repr: {text!r}"


def test_str_does_not_contain_key_or_iv() -> None:
    """FAILS: str() falls back to the same leaking repr."""
    aes = AesKey(_KEY, _IV)
    text = str(aes)
    assert _KEY not in text and _IV not in text, f"AES secret leaked in str: {text!r}"


def test_exception_carrying_aeskey_does_not_leak() -> None:
    """FAILS: putting an AesKey in an exception message leaks it via its repr."""
    aes = AesKey(_KEY, _IV)
    with pytest.raises(RuntimeError) as info:
        raise RuntimeError(f"transport failed for session {aes!r}")
    assert _KEY not in str(info.value), f"AES key leaked through exception: {info.value}"
