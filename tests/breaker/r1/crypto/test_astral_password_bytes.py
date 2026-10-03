"""BREAKER r1 / crypto — F1: supplementary-plane password RSA bytes diverge.

Claim under attack: "crypto.py reproduces the Archer AX53 web bundle
byte-for-byte ... RSA PKCS#1 v1.5 password encryption from hex n".

The vendor bundle encrypts the RAW password with jsbn's ``pkcs1pad2``, which
walks the JS string by ``charCodeAt`` and UTF-8-encodes each UTF-16 code unit
INDIVIDUALLY. For a character outside the Basic Multilingual Plane (an emoji,
or any U+10000+ codepoint) the JS string holds a surrogate PAIR, and jsbn emits
CESU-8 (two 3-byte sequences) instead of the 4-byte UTF-8 sequence.

``crypto.rsa_pkcs1v15_hex`` does ``plaintext.encode("utf-8")`` — correct UTF-8.
So for an astral-plane password the Python client encrypts DIFFERENT bytes than
the router's own web UI used when the password was set. The router therefore
decrypts a different password and the login fails (and burns a lockout attempt).

The vectors in ``fixtures/breaker_vectors.json`` were produced by executing the
real bundle (``RSA.encrypt`` = the 3-arg jsbn path) in Node; ``pw_rsa_hex`` is
the vendor ciphertext and ``test_rsa_private_pem_pkcs8`` the matching key.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from archer_router_mcp import crypto

_FIX = json.loads(
    (Path(__file__).parent / "fixtures" / "breaker_vectors.json").read_text(encoding="utf-8")
)
_PRIV = serialization.load_pem_private_key(
    _FIX["inputs"]["test_rsa_private_pem_pkcs8"].encode("ascii"), None
)
_N = _FIX["inputs"]["rsa_public_n_hex"]
_E = _FIX["inputs"]["rsa_public_e_hex"]
_PW_CASES = {c["name"]: c for c in _FIX["cases"] if c["kind"] == "password"}


def _vendor_plaintext_bytes(name: str) -> bytes:
    """Decrypt the bundle's recorded PKCS#1 v1.5 ciphertext -> the bytes jsbn fed in."""
    return _PRIV.decrypt(bytes.fromhex(_PW_CASES[name]["pw_rsa_hex"]), padding.PKCS1v15())


def _python_plaintext_bytes(password: str) -> bytes:
    """Decrypt crypto.py's PKCS#1 v1.5 output -> the bytes crypto.py fed in."""
    hexed = crypto.rsa_pkcs1v15_hex(_N, _E, password)
    return _PRIV.decrypt(bytes.fromhex(hexed), padding.PKCS1v15())


def test_ascii_password_bytes_agree_with_vendor() -> None:
    # Control: pure-ASCII must agree (and does).
    assert _python_plaintext_bytes(_PW_CASES["ascii"]["pw"]) == _vendor_plaintext_bytes("ascii")


def test_bmp_password_bytes_agree_with_vendor() -> None:
    # Control: BMP accents agree too (both 1-3 byte UTF-8).
    assert _python_plaintext_bytes(_PW_CASES["bmp"]["pw"]) == _vendor_plaintext_bytes("bmp")


def test_astral_password_bytes_match_vendor_bundle() -> None:
    """FAILS: emoji password -> crypto.py sends UTF-8, the bundle sent CESU-8."""
    pw = _PW_CASES["astral"]["pw"]  # 'pw\U0001f511\U0001f389'
    python_bytes = _python_plaintext_bytes(pw)
    vendor_bytes = _vendor_plaintext_bytes("astral")
    # The router stored the password via the bundle (vendor_bytes); the native
    # client must reproduce those exact bytes or the login is rejected.
    assert python_bytes == vendor_bytes, (
        f"password RSA bytes diverge for an astral-plane password: "
        f"python(utf-8)={python_bytes.hex()} vendor(jsbn/cesu-8)={vendor_bytes.hex()}"
    )


def test_mixed_bmp_and_astral_password_matches_vendor_bundle() -> None:
    """FAILS: one emoji among ASCII+BMP is enough to diverge."""
    assert _python_plaintext_bytes(_PW_CASES["mixed"]["pw"]) == _vendor_plaintext_bytes("mixed")
