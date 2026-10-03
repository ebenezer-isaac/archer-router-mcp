"""Pure cryptography for the Archer AX53 v1 (UI 1.11.0) SG-hardened web protocol.

Clean-room reimplementation written from ``docs/specs/archer-ax53-auth-flow.md``
and verified byte-for-byte against ``tests/fixtures/router_auth_vectors.json``
(the vectors were produced by executing the router's own JavaScript bundle
offline). Nothing here performs I/O, keeps global state, or mutates its inputs;
every function is a pure transform so it can be vector-tested in isolation.

The SG profile (certification ``SG CLS L1 STAGE2``) turns on six feature flags;
the two that shape this module are ``12_replace_hash`` (the rolling request hash)
and ``13_rsa_pad_with_pkcs1_oaep`` (login signature uses RSA-OAEP, not HMAC).

Primitive summary (all confirmed against the vectors):

* password hash  = ``SHA256("admin" + password)`` lower-case hex.
* AES envelope   = AES-128-CBC / PKCS7, key and IV each 16 ASCII decimal digits
  used as UTF-8 bytes; ciphertext is CryptoJS-style base64.
* password field = RSA PKCS#1 v1.5 over the RAW password, hex, zero-left-padded
  to the modulus width.
* login signature= RSA-OAEP(SHA-1 / MGF1-SHA1) over 53-char chunks of
  ``k=..&i=..&h=<pwHash>&s=<seq+len(b64)>``, hex outputs concatenated.
* request signature = HMAC-SHA256 keyed by ``k=..&i=..`` over 53-char chunks of
  ``h=<hash>&s=<seq+len(b64)>``, hex outputs concatenated (73-char plaintext ->
  two chunks -> 128 hex chars, never 64).
* rolling hash   = ``SHA256(<this request's own base64 ciphertext>)``; login does
  not update it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import random
import re
from dataclasses import dataclass
from urllib.parse import quote

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

PASSWORD_HASH_PREFIX = "admin"  # noqa: S105 - public protocol constant, not a secret
SIGNATURE_OFFSET = 53  # the bundle's chunk size for both RSA and HMAC signatures
AES_KEY_DIGITS = 16  # key and IV are each 16 ASCII decimal digits
_AES_BLOCK_BITS = 128
_SHA1_LEN = 20  # OAEP label hash length, for the max-message-size guard
_DIGITS = "0123456789"
_AES_KEY_RE = re.compile(r"\A[0-9]{16}\Z")
_HEX_RE = re.compile(r"\A[0-9A-Fa-f]+\Z")


# --------------------------------------------------------------------------- hashes


def sha256_hex(text: str) -> str:
    """Lower-case hex SHA-256 of ``text`` (UTF-8). Matches ``CryptoJS.SHA256``."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def password_hash(password: str) -> str:
    """``SHA256("admin" + password)`` lower-case hex (the login ``h`` value)."""
    if not isinstance(password, str):
        raise TypeError("password must be str")
    return sha256_hex(PASSWORD_HASH_PREFIX + password)


def rolling_hash(data_b64: str) -> str:
    """Per-request rolling hash: ``SHA256`` of this request's own base64 ciphertext.

    Self-contained by design: it depends only on ``data_b64``, so a lost or
    duplicated request never desynchronises the signatures of later requests.
    """
    return sha256_hex(data_b64)


# ------------------------------------------------------------------------------ AES


@dataclass(frozen=True)
class AesKey:
    """A session AES key: ``key`` and ``iv`` are each 16 ASCII decimal digits.

    The digits are used directly as UTF-8 bytes (16 bytes -> AES-128), exactly as
    the router's ``CryptoJS.enc.Utf8.parse`` does. Wrong sizes are rejected so a
    malformed key can never silently become a different cipher.
    """

    key: str
    iv: str

    def __post_init__(self) -> None:
        for name, value in (("key", self.key), ("iv", self.iv)):
            if not isinstance(value, str) or not _AES_KEY_RE.match(value):
                raise ValueError(f"AES {name} must be {AES_KEY_DIGITS} decimal digits")

    @property
    def formatted(self) -> str:
        """The ``k=<key>&i=<iv>`` form used as the HMAC key and signature prefix."""
        return f"k={self.key}&i={self.iv}"


def gen_aes_key(rng: random.Random) -> AesKey:
    """Generate a fresh ``AesKey`` of 16 decimal digits each from ``rng``.

    ``rng`` is injected (e.g. ``random.SystemRandom()`` in production,
    ``random.Random(seed)`` in tests) to keep this function pure and testable.
    """
    key = "".join(rng.choices(_DIGITS, k=AES_KEY_DIGITS))
    iv = "".join(rng.choices(_DIGITS, k=AES_KEY_DIGITS))
    return AesKey(key=key, iv=iv)


def _aes_bytes(key: AesKey) -> tuple[bytes, bytes]:
    return key.key.encode("ascii"), key.iv.encode("ascii")


def aes_encrypt(key: AesKey, plaintext: str) -> str:
    """AES-128-CBC / PKCS7 encrypt ``plaintext`` (UTF-8); return CryptoJS base64."""
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be str")
    key_bytes, iv_bytes = _aes_bytes(key)
    padder = PKCS7(_AES_BLOCK_BITS).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")


def aes_decrypt(key: AesKey, data_b64: str) -> str:
    """Inverse of :func:`aes_encrypt`. Raises ``ValueError`` on malformed input."""
    if not isinstance(data_b64, str):
        raise TypeError("data_b64 must be str")
    key_bytes, iv_bytes = _aes_bytes(key)
    try:
        ciphertext = base64.b64decode(data_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("ciphertext is not valid base64") from exc
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext length is not a multiple of the AES block size")
    decryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(_AES_BLOCK_BITS).unpadder()
    try:
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise ValueError("ciphertext has invalid PKCS7 padding") from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("decrypted plaintext is not valid UTF-8") from exc


# ------------------------------------------------------------------------------ RSA


def _load_public_key(n_hex: str, e_hex: str) -> rsa.RSAPublicKey:
    for name, value in (("modulus", n_hex), ("exponent", e_hex)):
        if not isinstance(value, str) or not _HEX_RE.match(value.strip() or "x"):
            raise ValueError(f"RSA {name} must be a non-empty hex string")
    try:
        n = int(n_hex, 16)
        e = int(e_hex, 16)
    except ValueError as exc:
        raise ValueError("RSA modulus/exponent is not valid hex") from exc
    if n <= 0 or e <= 0:
        raise ValueError("RSA modulus/exponent must be positive")
    try:
        return rsa.RSAPublicNumbers(e, n).public_key()
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("RSA parameters do not form a valid public key") from exc


def _modulus_byte_len(n_hex: str) -> int:
    return (int(n_hex, 16).bit_length() + 7) // 8


def rsa_pkcs1v15_hex(n_hex: str, e_hex: str, plaintext: str) -> str:
    """RSA PKCS#1 v1.5 encrypt ``plaintext`` (UTF-8); hex, zero-padded to ``len(n_hex)``.

    Used for the password field: the RAW password is encrypted, never the hash.
    The output is randomised by the padding, so tests assert the scheme by
    decrypting with the matching private key, not by matching bytes.
    """
    key = _load_public_key(n_hex, e_hex)
    data = plaintext.encode("utf-8")
    max_len = key.key_size // 8 - 11
    if len(data) > max_len:
        raise ValueError(f"plaintext too long for PKCS#1 v1.5 ({len(data)} > {max_len} bytes)")
    ciphertext = key.encrypt(data, padding.PKCS1v15())
    return ciphertext.hex().zfill(len(n_hex))


def rsa_oaep_sha1_hex(n_hex: str, e_hex: str, plaintext: str) -> str:
    """RSA-OAEP(SHA-1 / MGF1-SHA1) encrypt one block; hex, zero-padded to ``len(n_hex)``.

    SHA-1 is the node-forge default the bundle relies on; it is asserted against
    the vectors, not merely round-tripped. The length guard mirrors forge's
    ``min(53, k-42)`` so a modulus too small for the chunk is rejected cleanly.
    """
    key = _load_public_key(n_hex, e_hex)
    data = plaintext.encode("utf-8")
    max_len = key.key_size // 8 - 2 * _SHA1_LEN - 2
    if max_len < 1:
        raise ValueError("RSA modulus too small for OAEP(SHA-1)")
    if len(data) > max_len:
        raise ValueError(f"plaintext too long for OAEP(SHA-1) ({len(data)} > {max_len} bytes)")
    ciphertext = key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),  # noqa: S303
    )
    return ciphertext.hex().zfill(len(n_hex))


# ----------------------------------------------------------------------- signatures


def chunk53(text: str) -> list[str]:
    """Split ``text`` into consecutive substrings of at most ``SIGNATURE_OFFSET`` chars."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if text == "":
        return [""]
    return [text[i : i + SIGNATURE_OFFSET] for i in range(0, len(text), SIGNATURE_OFFSET)]


def _s_value(seq: int, data_b64: str) -> int:
    """``s = seq + len(base64 ciphertext STRING)`` (the length of the b64 text)."""
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise TypeError("seq must be an int")
    return seq + len(data_b64)


def sign_login(
    aes: AesKey, password_hash_hex: str, seq: int, data_b64: str, n_sig: str, e_sig: str
) -> str:
    """Login signature: RSA-OAEP(SHA-1) per 53-char chunk of
    ``k=..&i=..&h=<pwHash>&s=<seq+len(data)>``, hex outputs concatenated.

    The ``h`` value is the password hash (login is ``withAesKey=true`` and does
    not roll the request hash).
    """
    s = _s_value(seq, data_b64)
    plaintext = f"{aes.formatted}&h={password_hash_hex}&s={s}"
    return "".join(rsa_oaep_sha1_hex(n_sig, e_sig, chunk) for chunk in chunk53(plaintext))


def sign_request(aes: AesKey, request_hash: str, seq: int, data_b64: str) -> str:
    """Post-login signature: HMAC-SHA256 keyed by ``k=..&i=..`` per 53-char chunk of
    ``h=<hash>&s=<seq+len(data)>``, hex outputs concatenated.

    ``request_hash`` is this request's :func:`rolling_hash`. The 73-char sample
    plaintext yields two chunks and therefore 128 hex characters, not 64.
    """
    s = _s_value(seq, data_b64)
    plaintext = f"h={request_hash}&s={s}"
    mac_key = aes.formatted.encode("utf-8")
    return "".join(
        hmac.new(mac_key, chunk.encode("utf-8"), hashlib.sha256).hexdigest()
        for chunk in chunk53(plaintext)
    )


# --------------------------------------------------------------------- body builders


def build_login_body(password_rsa_hex: str, confirm: bool) -> str:
    """The login plaintext body (before AES): ``password=<rsa>&operation=login&confirm=<bool>``."""
    if not isinstance(password_rsa_hex, str):
        raise TypeError("password_rsa_hex must be str")
    if not isinstance(confirm, bool):
        raise TypeError("confirm must be a bool")
    return f"password={password_rsa_hex}&operation=login&confirm={'true' if confirm else 'false'}"


def _encode_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict | list):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return str(value)


def build_request_body(params: dict[str, object]) -> str:
    """URL-encode ``params`` into a request body, preserving insertion order.

    Object values (dict/list) are JSON-stringified compactly (as the router's
    ``qr`` helper does); ``None`` values are dropped; booleans become
    ``true``/``false``. Values are percent-encoded (``encodeURIComponent``-style).
    """
    if not isinstance(params, dict):
        raise TypeError("params must be a dict")
    parts: list[str] = []
    for key, value in params.items():
        if value is None:
            continue
        encoded = quote(_encode_value(value), safe="")
        parts.append(f"{quote(str(key), safe='')}={encoded}")
    return "&".join(parts)
