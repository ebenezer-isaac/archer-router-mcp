"""Shared, strict tool-input types (device-agnostic; copied verbatim per repo).

``ConfirmWrite`` is the type every mutating tool uses for its ``confirm_write``
parameter. The vulnerability it closes: a FastMCP tool parameter typed plain
``bool`` lets pydantic *coerce* a JSON string ``"true"`` / ``"1"`` / ``"yes"`` (and
the integer ``1``) to ``True`` **before** the write gate runs, so the gate's
``confirm_write is not True`` check — which exists precisely to reject truthy
non-booleans — is defeated at the MCP boundary.

Fail closed: only the JSON boolean ``true`` confirms a write. Every other value
(a truthy or falsey string, a number, ``null``) resolves to ``False`` and is
refused by the write gate with the ordinary ``WRITE_REFUSED`` envelope and **no
network I/O** — never silently coerced through. The advertised JSON schema stays
``{"type": "boolean"}`` so a well-behaved client sends a real boolean.

Why a ``BeforeValidator`` and not ``pydantic.StrictBool``: ``StrictBool`` would
reject a non-boolean at *validation* time, which FastMCP surfaces as a raised
``ToolError`` (a schema error) **before the tool body runs** — not our uniform
``{success, data, error}`` envelope, and with a different shape for a string than
for a number. We want exactly one behaviour for every non-``true`` input: the
tool body runs, the write gate sees ``False``, and the caller gets a single
fail-closed ``WRITE_REFUSED`` envelope with zero I/O and no schema error. The
``BeforeValidator`` collapses every non-``True`` value to ``False`` to guarantee
that, while leaving the published schema a plain boolean.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BeforeValidator, Field

__all__ = ["ConfirmWrite"]


def _only_true_confirms(value: object) -> bool:
    """Only the boolean ``True`` authorises a write; everything else is ``False``."""
    return value is True


ConfirmWrite = Annotated[
    bool,
    BeforeValidator(_only_true_confirms),
    Field(
        default=False,
        description=(
            "Must be the JSON boolean true to authorise this mutating write. A string "
            'such as "true"/"1"/"yes" does NOT count and the write is refused with no '
            "network call; re-send with the boolean confirm_write=true after confirming "
            "the change with the operator."
        ),
    ),
]
