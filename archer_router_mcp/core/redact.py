"""Recursive redaction of credential-bearing fields. Pure: always returns new objects."""

from __future__ import annotations

from typing import Any

REDACTED = "<redacted>"
TRUNCATED = "<truncated: max depth>"
MAX_DEPTH = 64

# Rule-based so a new credential spelling is caught without editing a hand-list.
# A key is sensitive if its lower-cased name is an exact match, OR contains one of
# the substrings, OR ends with one of the suffixes.
_EXACT_KEYS = frozenset(
    {
        "ciphertext",
        "stok",
        "token",
        "nonce",
        "cookie",
        "secret",
        "authorization",
        "pubkey",
        "key",
        "sysauth",
    }
)
_CONTAINS = ("pass", "pwd", "secret", "token", "cipher")
_ENDSWITH = ("_key",)


def is_sensitive_key(key: object) -> bool:
    name = str(key).lower()
    if name in _EXACT_KEYS:
        return True
    if any(fragment in name for fragment in _CONTAINS):
        return True
    return name.endswith(_ENDSWITH)


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Return a copy of ``value`` with sensitive fields replaced by ``REDACTED``.

    Dicts and lists/tuples are rebuilt (tuples become lists, matching JSON).
    Nesting deeper than ``MAX_DEPTH`` is replaced by ``TRUNCATED``, which also
    terminates self-referencing structures.
    """
    if _depth >= MAX_DEPTH:
        return TRUNCATED
    if isinstance(value, dict):
        return {
            k: (REDACTED if is_sensitive_key(k) else redact(v, _depth=_depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(item, _depth=_depth + 1) for item in value]
    return value
