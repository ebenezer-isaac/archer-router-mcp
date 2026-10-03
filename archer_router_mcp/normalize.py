"""Pure normalisation helpers for the Archer AX53 read tools.

Nothing here performs I/O or holds state. Every function returns new values and
never mutates its inputs. The router is inconsistent about field names, casing,
MAC separators and percent-encoding of device names, so these helpers give the
read tools one honest place to canonicalise before pydantic validation.
"""

from __future__ import annotations

import math
import re
from typing import Any
from urllib.parse import unquote

from .errors import ProtocolError

_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_MAC_SEP = re.compile(r"[\s:.\-]")
_TRUTHY = {"1", "on", "true", "yes", "enable", "enabled"}
_FALSEY = {"0", "off", "false", "no", "disable", "disabled", ""}


def normalize_mac(value: Any) -> str | None:
    """Return a MAC as canonical upper-case colon form (``HH:HH:HH:HH:HH:HH``).

    Accepts ``aa:bb:..``, ``AA-BB-..``, ``aabbccddeeff`` and dotted forms; any
    whitespace is stripped. Returns ``None`` for empty/non-string input or a
    value that is not exactly twelve hex digits once separators are removed, so
    callers can skip junk rows instead of crashing on them.
    """
    if not isinstance(value, str):
        return None
    compact = _MAC_SEP.sub("", value.strip()).lower()
    if not _HEX12.fullmatch(compact):
        return None
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2)).upper()


def decode_name(value: Any) -> str | None:
    """Percent-decode a device/host name and drop control characters.

    Router names arrive URL-encoded (``My%20Phone``) and occasionally carry stray
    control bytes; we decode once and strip C0/C1 controls. Empty becomes ``None``.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        decoded = unquote(value)
    except (ValueError, UnicodeDecodeError):
        decoded = value
    cleaned = "".join(ch for ch in decoded if ch == "\t" or ord(ch) >= 0x20).strip()
    return cleaned or None


def as_bool(value: Any) -> bool | None:
    """Coerce the router's many boolean spellings; ``None`` when undecidable."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _TRUTHY:
            return True
        if token in _FALSEY:
            return False
    return None


def as_int(value: Any) -> int | None:
    """Parse an int from int/str; reject bools, NaN, Infinity and junk."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else None
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text)
        except (TypeError, ValueError):
            try:
                parsed = float(text)
            except (TypeError, ValueError):
                return None
            return int(parsed) if math.isfinite(parsed) else None
    return None


def as_float(value: Any) -> float | None:
    """Parse a finite float from int/str; reject bools, NaN and Infinity."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(float(value)) else None
    if isinstance(value, str):
        try:
            parsed = float(value.strip())
        except (TypeError, ValueError):
            return None
        return parsed if math.isfinite(parsed) else None
    return None


def first_present(source: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """Return the first value for any of ``keys`` present and not ``None``."""
    for key in keys:
        if key in source and source[key] is not None:
            return source[key]
    return None


def payload_obj(result: Any) -> dict[str, Any]:
    """Flatten a single-object response to one dict of fields.

    ``RouterSession.request`` hands back either the inner ``data`` dict or the
    whole envelope; either way the useful scalar fields live at the top once the
    nested ``data`` object (if any) is merged over the outer keys.
    """
    if not isinstance(result, dict):
        raise ProtocolError("The router returned a response that is not a JSON object.")
    data = result.get("data")
    if isinstance(data, dict):
        return {**result, **data}
    return result


def payload_rows(result: Any) -> list[dict[str, Any]]:
    """Extract a list of row dicts from a list-style response.

    Raises :class:`ProtocolError` when a ``data`` field is present but is neither
    a list nor ``None`` (a malformed response), or when its rows are not objects.
    A missing/empty list yields ``[]`` so empty tables are not an error.
    """
    if not isinstance(result, dict):
        raise ProtocolError("The router returned a response that is not a JSON object.")
    data = result.get("data")
    if data is None:
        # Some forms return the rows under a different single list-valued key.
        lists = [v for v in result.values() if isinstance(v, list)]
        data = lists[0] if len(lists) == 1 else []
    if not isinstance(data, list):
        raise ProtocolError("The router returned a non-list body where a list was expected.")
    rows: list[dict[str, Any]] = []
    for row in data:
        if not isinstance(row, dict):
            raise ProtocolError("The router returned a row that is not a JSON object.")
        rows.append(row)
    return rows
