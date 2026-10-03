"""Recursive redaction of credential-bearing fields. Pure: always returns new objects.

Single source of truth for which keys are secret-bearing (mirrored in
``docs/specs/00-MASTER-PLAN.md`` §1.6). The rule set is the UNION of every
device's credential vocabulary served by this shared core, so one canonical
``core/redact.py`` is copied verbatim into all three repos. A key (lower-cased) is
redacted when it:

* equals one of the EXACT names: ``ciphertext, stok, token, nonce, cookie,
  h_p_ssid, sysauth, secret, authorization, pubkey, key, password, cpassword``;
* CONTAINS one of: ``pass, pwd, secret, token, cipher, cookie`` (so ``password``,
  ``old_password``, ``new_pwd``, ``passwd``, ``api_token`` … are all caught); or
* ENDS WITH ``_key`` (so ``public_key``, ``rsa_key`` … are caught).

Rule-based rather than a hand-maintained exact list, so spellings the devices may
emit (``nonce``, ``cookie``, ``pubkey``, ``Authorization``, ``h_p_ssid``,
``sysauth``, ``cpassword``, password-change fields) cannot silently slip through.
Harmless over-matching (e.g. ``passwd_strength``) is accepted; names like
``auth_result``, ``online``, ``conn_status``, ``uuid``, ``row_id``, ``key_present``
and PoE/port field names deliberately survive.
"""

from __future__ import annotations

from typing import Any

REDACTED = "<redacted>"
TRUNCATED = "<truncated: max depth>"
MAX_DEPTH = 64

_EXACT_KEYS = frozenset(
    {
        "ciphertext",
        "stok",
        "token",
        "nonce",
        "cookie",
        "h_p_ssid",
        "sysauth",
        "secret",
        "authorization",
        "pubkey",
        "key",
        "password",
        "cpassword",
    }
)
_CONTAINS = ("pass", "pwd", "secret", "token", "cipher", "cookie")
_ENDSWITH = ("_key",)


def is_sensitive_key(key: object) -> bool:
    name = str(key).lower()
    return (
        name in _EXACT_KEYS
        or any(fragment in name for fragment in _CONTAINS)
        or name.endswith(_ENDSWITH)
    )


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
