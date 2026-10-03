"""Byte-exact vector tests for the Archer AX53 crypto layer.

Deterministic fields of ``router_auth_vectors.json`` are asserted equal; the
RSA outputs (randomised by padding) are verified by decrypting with the fixture's
matching private key, which also pins the login signature to OAEP **SHA-1**.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from archer_router_mcp import crypto
from archer_router_mcp.crypto import AesKey

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "router_auth_vectors.json").read_text(encoding="utf-8")
)
INP = VECTORS["inputs"]
N_HEX: str = INP["rsa_public_n_hex"]
E_HEX: str = INP["rsa_public_e_hex"]
SEQ: int = INP["seq"]
AES = AesKey(INP["aes_key_16_decimal_digits"], INP["aes_iv_16_decimal_digits"])
PRIV = serialization.load_pem_private_key(INP["test_rsa_private_pem_pkcs8"].encode("ascii"), None)
_OAEP_SHA1 = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)  # noqa: S303


def _oaep_blocks(sign_hex: str) -> list[bytes]:
    block = (len(N_HEX) // 2) * 2  # hex chars per 256-byte block
    return [bytes.fromhex(sign_hex[i : i + block]) for i in range(0, len(sign_hex), block)]


# --------------------------------------------------------------------------- happy


def test_password_hash_matches_vector() -> None:
    assert crypto.password_hash(INP["password"]) == VECTORS["b_password_hash"]["value"]


def test_sha256_hex_is_lowercase_hex() -> None:
    out = crypto.sha256_hex("admin" + INP["password"])
    assert out == VECTORS["b_password_hash"]["value"]
    assert out == out.lower() and len(out) == 64


def test_aes_encrypt_matches_vector() -> None:
    assert (
        crypto.aes_encrypt(AES, VECTORS["c_aes"]["sample_plaintext"])
        == (VECTORS["c_aes"]["ciphertext_base64"])
    )


def test_aes_round_trip() -> None:
    assert (
        crypto.aes_decrypt(AES, VECTORS["c_aes"]["ciphertext_base64"])
        == (VECTORS["c_aes"]["sample_plaintext"])
    )
    for text in ["", "a", "operation=read", "x" * 47, "üñîçödé=✓", "a=b&c=d"]:
        assert crypto.aes_decrypt(AES, crypto.aes_encrypt(AES, text)) == text


def test_rolling_hash_matches_vector() -> None:
    d = VECTORS["d_normal_request"]
    assert crypto.rolling_hash(d["data_sent"]) == d["rolling_hash_value"]


def test_chunk53_of_request_plaintext_is_53_plus_20() -> None:
    d = VECTORS["d_normal_request"]
    chunks = crypto.chunk53(d["sign_plaintext"])
    assert chunks == d["sign_plaintext_chunks_53"]
    assert [len(c) for c in chunks] == [53, 20]


def test_sign_request_matches_vector_and_is_128_hex() -> None:
    d = VECTORS["d_normal_request"]
    sign = crypto.sign_request(AES, d["rolling_hash_value"], SEQ, d["data_sent"])
    assert sign == d["sign_output_hex"]
    assert len(sign) == 128  # two chunks -> 2 * 64, never a single 64-char HMAC


def test_s_value_uses_base64_string_length() -> None:
    d = VECTORS["d_normal_request"]
    # s = seq + len(b64 string); the sample plaintext encodes exactly that.
    assert d["sign_plaintext"] == f"h={d['rolling_hash_value']}&s={SEQ + len(d['data_sent'])}"
    assert SEQ + len(d["data_sent"]) == d["s_value"]


# ------------------------------------------------------------------- RSA / signatures


def test_pkcs1v15_password_decrypts_to_raw_password() -> None:
    hexed = crypto.rsa_pkcs1v15_hex(N_HEX, E_HEX, INP["password"])
    assert len(hexed) == len(N_HEX)
    recovered = PRIV.decrypt(bytes.fromhex(hexed), padding.PKCS1v15())
    assert recovered.decode("utf-8") == INP["password"]


def test_recorded_pkcs1v15_vector_decrypts_to_raw_password() -> None:
    ct = bytes.fromhex(VECTORS["d_login_request"]["password_rsa_hex"])
    assert PRIV.decrypt(ct, padding.PKCS1v15()).decode("utf-8") == INP["password"]


def test_sign_login_decrypts_to_expected_plaintext_with_password_hash() -> None:
    data_b64 = VECTORS["d_login_request"]["login_body_ciphertext_base64"]
    h0 = VECTORS["b_password_hash"]["value"]
    sign = crypto.sign_login(AES, h0, SEQ, data_b64, N_HEX, E_HEX)
    assert len(sign) == 1536  # three OAEP blocks for the 111-char plaintext
    recovered = b"".join(PRIV.decrypt(block, _OAEP_SHA1) for block in _oaep_blocks(sign))
    expected_s = SEQ + len(data_b64)
    assert recovered.decode("ascii") == f"{AES.formatted}&h={h0}&s={expected_s}"
    assert expected_s == VECTORS["d_login_request"]["s_value"]


def test_recorded_login_sign_uses_oaep_sha1_not_sha256() -> None:
    sign = VECTORS["d_login_request"]["sign_output_hex_example"]
    blocks = _oaep_blocks(sign)
    recovered = b"".join(PRIV.decrypt(block, _OAEP_SHA1) for block in blocks)
    assert recovered.decode("ascii") == VECTORS["d_login_request"]["sign_plaintext_before_rsa"]
    # The same ciphertext must NOT decrypt under SHA-256 OAEP: proves it is SHA-1.
    sha256_oaep = padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )
    with pytest.raises(ValueError):
        PRIV.decrypt(blocks[0], sha256_oaep)


def test_sign_login_does_not_use_the_rolling_hash() -> None:
    data_b64 = VECTORS["d_login_request"]["login_body_ciphertext_base64"]
    h0 = VECTORS["b_password_hash"]["value"]
    sign = crypto.sign_login(AES, h0, SEQ, data_b64, N_HEX, E_HEX)
    recovered = b"".join(PRIV.decrypt(block, _OAEP_SHA1) for block in _oaep_blocks(sign)).decode()
    assert f"&h={h0}&" in recovered
    assert crypto.rolling_hash(data_b64) not in recovered  # login never rolls the hash


def test_generated_2048_key_round_trips_both_schemes() -> None:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = priv.public_key().public_numbers()
    n_hex, e_hex = format(nums.n, "x"), format(nums.e, "x")
    pk = crypto.rsa_pkcs1v15_hex(n_hex, e_hex, "secret-msg")
    assert priv.decrypt(bytes.fromhex(pk), padding.PKCS1v15()).decode() == "secret-msg"
    oa = crypto.rsa_oaep_sha1_hex(n_hex, e_hex, "k=..&i=..&h=..&s=..")
    assert priv.decrypt(bytes.fromhex(oa), _OAEP_SHA1).decode() == "k=..&i=..&h=..&s=.."


# --------------------------------------------------------------------- chunk boundaries


@pytest.mark.parametrize(
    ("length", "expected_lens"),
    [
        (0, []),
        (1, [1]),
        (52, [52]),
        (53, [53]),
        (54, [53, 1]),
        (106, [53, 53]),
        (107, [53, 53, 1]),
    ],
)
def test_chunk53_boundaries(length: int, expected_lens: list[int]) -> None:
    chunks = crypto.chunk53("a" * length)
    assert [len(c) for c in chunks] == expected_lens
    assert "".join(chunks) == "a" * length


# ------------------------------------------------------------------------- AES keys


def test_gen_aes_key_is_16_decimal_digits_and_deterministic_under_seed() -> None:
    key = crypto.gen_aes_key(random.Random(1234))
    assert len(key.key) == 16 and len(key.iv) == 16
    assert key.key.isdigit() and key.iv.isdigit()
    assert crypto.gen_aes_key(random.Random(1234)) == key  # pure w.r.t. the rng
    assert crypto.gen_aes_key(random.Random(1)) != key
    assert key.formatted == f"k={key.key}&i={key.iv}"


@pytest.mark.parametrize(
    ("key", "iv"),
    [
        ("123456789012345", "1234567890123456"),  # 15 digits
        ("12345678901234567", "1234567890123456"),  # 17 digits
        ("1234567890123456", "123456789012345a"),  # non-digit
        ("", ""),
        ("abcdefghijklmnop", "1234567890123456"),
    ],
)
def test_wrong_aes_key_sizes_rejected(key: str, iv: str) -> None:
    with pytest.raises(ValueError, match="decimal digits"):
        AesKey(key, iv)


# ----------------------------------------------------------------------- body builders


def test_build_login_body_matches_vector_shape() -> None:
    pw = VECTORS["d_login_request"]["password_rsa_hex"]
    assert (
        crypto.build_login_body(pw, confirm=False)
        == (VECTORS["d_login_request"]["login_body_plaintext"])
    )
    assert crypto.build_login_body(pw, confirm=True).endswith("&confirm=true")


def test_build_request_body_drops_none_and_jsonifies_objects_in_order() -> None:
    body = crypto.build_request_body(
        {
            "operation": "insert",
            "new": {"hostname": "cam", "ip": "192.0.2.5", "mac": "AA", "enable": "on"},
            "index": 0,
            "skip": None,
        }
    )
    assert body.startswith("operation=insert&new=")
    assert "skip" not in body
    assert body.endswith("&index=0")
    # object value is compact JSON, percent-encoded, order preserved
    assert "%7B%22hostname%22%3A%22cam%22" in body


def test_build_request_body_read_verb() -> None:
    assert crypto.build_request_body({"operation": "read"}) == "operation=read"


def test_build_request_body_encodes_injection_characters() -> None:
    body = crypto.build_request_body({"operation": "write", "name": "a&b=c\nd"})
    assert "a&b=c" not in body  # the raw separators must be encoded, not literal
    assert body.count("=") == 2 and body.count("&") == 1  # only the two real pairs


def test_build_request_body_booleans() -> None:
    assert (
        crypto.build_request_body({"enable": True, "hidden": False}) == "enable=true&hidden=false"
    )


# ---------------------------------------------------------------- adversarial / edges


@pytest.mark.parametrize("password", ["", "x", "üñîçödé", "p=a&b", "A" * 32])
def test_password_hash_handles_unicode_and_edges(password: str) -> None:
    out = crypto.password_hash(password)
    assert len(out) == 64
    assert out == crypto.sha256_hex("admin" + password)


@pytest.mark.parametrize("bad", ["zz", "0x10", "", "10g1", " "])
def test_malformed_rsa_params_raise_valueerror_not_crash(bad: str) -> None:
    with pytest.raises(ValueError):
        crypto.rsa_pkcs1v15_hex(bad, E_HEX, "x")
    with pytest.raises(ValueError):
        crypto.rsa_oaep_sha1_hex(N_HEX, bad, "x")


def test_oaep_rejects_plaintext_too_large_for_modulus() -> None:
    # cryptography refuses to generate sub-1024-bit keys, so exercise the guard
    # (forge's min(53, k-42)) by exceeding a 1024-bit key's capacity: max OAEP
    # (SHA-1) message = 128 - 42 = 86 bytes, so 90 chars must be rejected cleanly.
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    nums = priv.public_key().public_numbers()
    n_hex, e_hex = format(nums.n, "x"), format(nums.e, "x")
    with pytest.raises(ValueError, match="too long for OAEP"):
        crypto.rsa_oaep_sha1_hex(n_hex, e_hex, "a" * 90)


def test_aes_decrypt_rejects_malformed_ciphertext() -> None:
    with pytest.raises(ValueError):
        crypto.aes_decrypt(AES, "not valid base64 !!!")
    with pytest.raises(ValueError):
        crypto.aes_decrypt(AES, "YWJj")  # valid b64 but not a block multiple


def test_pkcs1v15_rejects_overlong_plaintext_without_leaking_it() -> None:
    secret = "P@ssw0rd-" + "z" * 300
    with pytest.raises(ValueError) as info:
        crypto.rsa_pkcs1v15_hex(N_HEX, E_HEX, secret)
    assert secret not in str(info.value)  # never echo the plaintext


# --------------------------------------------------------------------- state machine


def test_rolling_hash_depends_only_on_current_ciphertext() -> None:
    # Two different "prior" states are irrelevant: same input -> same hash.
    assert crypto.rolling_hash("AAAA==") == crypto.rolling_hash("AAAA==")
    assert crypto.rolling_hash("AAAA==") != crypto.rolling_hash("BBBB==")


def test_no_password_leaks_into_login_body_or_signature() -> None:
    pw = INP["password"]
    pw_rsa = crypto.rsa_pkcs1v15_hex(N_HEX, E_HEX, pw)
    body = crypto.build_login_body(pw_rsa, confirm=False)
    assert pw not in body  # only the RSA-encrypted hex appears
    sign = crypto.sign_login(AES, crypto.password_hash(pw), SEQ, "AAAA==", N_HEX, E_HEX)
    assert pw not in sign
