"""BREAKER r1 / crypto — F4/F5: seq==0 and empty-plaintext chunking diverge.

Claim under attack: "chunked at 53 chars ... `s` uses the base64 ciphertext
length" and the byte-for-byte reproduction of the bundle.

F4 (seq==0): the bundle's ``encrypt()`` opens with ``if(!this.sequence) return
{}`` — a zero (or falsy) sequence makes it emit NOTHING (no ``sign``, no
``data``), so the request is never sent. ``crypto._s_value`` / ``sign_request``
accept seq==0 and happily produce a full 128-hex signature. The two layers
disagree about what a zero sequence means. (Low likelihood: the router is not
known to hand out seq 0; the guard also lives in the R2 transport layer, not in
these primitives. Recorded for completeness.)

F5 (empty chunking): the bundle's ``_getEncryptedSignature`` loops
``for(n=0;n<len;n+=53)`` — an empty plaintext yields ZERO chunks and an empty
signature. ``crypto.chunk53("")`` returns ``[""]`` (one empty chunk), so a
signer built on it would transform one empty chunk instead of none. Not
reachable through the real ``h=..&s=..`` plaintext (never empty), so this is a
latent primitive-level divergence only.
"""

from __future__ import annotations

import json
from pathlib import Path

from archer_router_mcp import crypto
from archer_router_mcp.crypto import AesKey

_FIX = json.loads(
    (Path(__file__).parent / "fixtures" / "breaker_vectors.json").read_text(encoding="utf-8")
)
_AES = AesKey(_FIX["inputs"]["KEY"], _FIX["inputs"]["IV"])
_SEQ0 = next(c for c in _FIX["cases"] if c.get("name") == "seq0")


def test_seq_zero_matches_bundle_which_sends_nothing() -> None:
    """FAILS: bundle emits {} for seq==0; crypto still produces a signature."""
    assert _SEQ0["encrypt_returned_empty"] is True  # vendor ground truth
    sign = crypto.sign_request(_AES, _SEQ0["rolling_hash"], 0, _SEQ0["aes_b64"])
    # The bundle would have sent no request at all; a byte-for-byte port must not
    # silently produce a signable request for a zero sequence.
    assert sign == "", (
        "crypto.sign_request produced a signature for seq==0 "
        f"({len(sign)} hex chars) where the bundle sends nothing"
    )


def test_empty_plaintext_chunking_matches_bundle_zero_chunks() -> None:
    """FAILS: bundle makes 0 chunks for ''; chunk53('') returns one empty chunk."""
    # The bundle's for-loop produces no chunks for an empty string.
    assert crypto.chunk53("") == [], (
        f"chunk53('') returned {crypto.chunk53('')!r}; the bundle yields no chunks "
        f"(empty signature) for an empty plaintext"
    )
