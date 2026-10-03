"""R2 additions to the copied core: persistent breaker, rule-based redaction,
fail-loud config, and TLS fingerprint primitives. Plus the device_config
feature-flag layer reproduced across every certification set in the breaker fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from archer_router_mcp import crypto
from archer_router_mcp.config import load_device_settings, load_global_settings
from archer_router_mcp.core import transport
from archer_router_mcp.core.breaker import LoginBreaker, canonical_device_key
from archer_router_mcp.core.config import normalise_fingerprint
from archer_router_mcp.core.errors import BreakerOpen, ConfigError, TlsPinMismatch
from archer_router_mcp.core.redact import REDACTED, redact
from archer_router_mcp.core.state import Outcome
from tests.helpers import DOC_HOST, ROUTER_PREFIX, router_env

# ----------------------------------- persistent login breaker (reserve/release API)
# The full device-agnostic contract lives in tests/conformance/test_breaker_contract.py
# (hashed by core/VERSION and run by the gate). These check the router's own wiring.


def _key() -> str:
    return canonical_device_key(DOC_HOST)


def test_breaker_persists_failures_across_instances(tmp_path: Path) -> None:
    first = LoginBreaker(tmp_path, _key(), max_failures=1)
    first.reserve_attempt().release(Outcome.FAILURE, failure={"error": "login failed"})
    # A brand-new instance reads the same file and now refuses (budget of 1).
    second = LoginBreaker(tmp_path, _key(), max_failures=1)
    with pytest.raises(BreakerOpen):
        second.reserve_attempt()
    assert second.status()["failures"] == 1


def test_breaker_clear_reopens(tmp_path: Path) -> None:
    b = LoginBreaker(tmp_path, _key(), max_failures=1)
    b.reserve_attempt().release(Outcome.FAILURE)
    b.clear()
    b.reserve_attempt().release(Outcome.SUCCESS)  # no raise after clear
    assert b.status()["failures"] == 0


def test_breaker_file_is_atomic_and_restrictive(tmp_path: Path) -> None:
    b = LoginBreaker(tmp_path, _key(), max_failures=5)
    b.reserve_attempt().release(Outcome.SUCCESS)
    assert b.path.exists()
    # No leftover temp files from the atomic write.
    assert list(tmp_path.glob("*.tmp")) == []


@pytest.mark.parametrize(
    "content", ["{ not json", "[]", '{"failures": -1}', '{"failures": "x"}', ""]
)
def test_corrupt_breaker_file_fails_closed(tmp_path: Path, content: str) -> None:
    b = LoginBreaker(tmp_path, _key(), max_failures=1)
    b.path.write_text(content, encoding="utf-8")
    with pytest.raises(BreakerOpen):
        b.reserve_attempt()
    assert b.status()["state"] == "open"  # --show must never crash on a bad file


def test_missing_breaker_file_is_allowing(tmp_path: Path) -> None:
    # A fresh breaker on an empty dir admits the first attempt.
    LoginBreaker(tmp_path, _key(), max_failures=1).reserve_attempt().release(Outcome.SUCCESS)


def test_breaker_status_is_json_safe(tmp_path: Path) -> None:
    b = LoginBreaker(tmp_path, _key(), max_failures=5)
    b.reserve_attempt().release(
        Outcome.FAILURE, failure={"error": "login failed", "failure_count": 2}
    )
    json.dumps(b.status())  # must not raise
    assert b.status()["failures"] == 1


# ------------------------------------------------------------------- rule redaction


@pytest.mark.parametrize(
    "key",
    [
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
        "psk_key",  # endswith _key
        "access_token",  # contains token
        "my_password",  # contains pass
        "user_pwd",  # contains pwd
        "client_secret",  # contains secret
        "aes_cipher",  # contains cipher
    ],
)
def test_sensitive_keys_redacted(key: str) -> None:
    assert redact({key: "v"}) == {key: REDACTED}


@pytest.mark.parametrize(
    "key", ["auth_result", "online", "uuid", "device_uuid", "keyring_name", "monkey", "username"]
)
def test_safe_keys_survive(key: str) -> None:
    assert redact({key: "v"}) == {key: "v"}


# ------------------------------------------------------------------- fail-loud config


def test_unknown_device_env_key_fails_loudly() -> None:
    env = router_env()
    env["ARCHER_ROUTER_ALLOW_WRITE"] = "true"  # typo: missing trailing S
    with pytest.raises(ConfigError, match="ARCHER_ROUTER_ALLOW_WRITE"):
        load_device_settings(ROUTER_PREFIX, env)


def test_unknown_global_env_key_fails_loudly() -> None:
    with pytest.raises(ConfigError, match="ARCHER_MCP_BOGUS"):
        load_global_settings("ARCHER_MCP_", {"ARCHER_MCP_BOGUS": "1"})


def test_known_r2_keys_are_accepted() -> None:
    s = load_device_settings(
        ROUTER_PREFIX,
        router_env(
            STATE_DIR="/tmp/state",
            FORCE_SESSION_TAKEOVER="true",
            ENVELOPE="https-plain",
            TLS_FINGERPRINT_SHA256=":".join(["AB"] * 32),
        ),
    )
    assert s.force_session_takeover is True
    assert s.envelope == "https-plain"
    assert s.state_dir == "/tmp/state"
    assert s.tls_fingerprint_sha256 == "ab" * 32


def test_global_log_level_known_and_validated() -> None:
    assert load_global_settings("ARCHER_MCP_", {"ARCHER_MCP_LOG_LEVEL": "debug"}).mcp_log_level == (
        "DEBUG"
    )
    with pytest.raises(ConfigError, match="ARCHER_MCP_LOG_LEVEL"):
        load_global_settings("ARCHER_MCP_", {"ARCHER_MCP_LOG_LEVEL": "LOUD"})


@pytest.mark.parametrize("bad", ["xyz", "ab", "gg" * 32, "12:34"])
def test_bad_fingerprint_rejected(bad: str) -> None:
    with pytest.raises(ConfigError, match="ARCHER_ROUTER_TLS_FINGERPRINT_SHA256"):
        load_device_settings(ROUTER_PREFIX, router_env(TLS_FINGERPRINT_SHA256=bad))


def test_empty_fingerprint_is_none() -> None:
    assert (
        load_device_settings(
            ROUTER_PREFIX, router_env(TLS_FINGERPRINT_SHA256="")
        ).tls_fingerprint_sha256
        is None
    )


def test_prefix_isolation_still_holds_with_fail_loud() -> None:
    env = {**router_env(), "OTHER_DEV_HOST": DOC_HOST, "OTHER_DEV_PASSWORD": "x"}
    # Loading ARCHER_ROUTER_ must not trip over the unrelated OTHER_DEV_ keys.
    assert load_device_settings(ROUTER_PREFIX, env).host == DOC_HOST


# ----------------------------------------------------------- fingerprint primitives


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AB" * 32, "ab" * 32),
        (":".join(["ab"] * 32), "ab" * 32),
        ("ab " * 31 + "ab", "ab" * 32),
    ],
)
def test_normalise_fingerprint(raw: str, expected: str) -> None:
    assert normalise_fingerprint(raw) == expected


@pytest.mark.parametrize("bad", ["", "zz" * 32, "ab" * 31, "ab" * 33, 123])
def test_normalise_fingerprint_rejects(bad: object) -> None:
    with pytest.raises(ValueError, match="hex"):
        normalise_fingerprint(bad)


def test_verify_cert_fingerprint_matches_and_mismatches() -> None:
    der = b"leaf-certificate-der-bytes"
    pin = transport.fingerprint_sha256(der)
    transport.verify_cert_fingerprint(der, pin)  # match, no raise
    with pytest.raises(TlsPinMismatch, match="does not match"):
        transport.verify_cert_fingerprint(b"a-different-certificate", pin)


def test_fingerprint_sha256_known_value() -> None:
    import hashlib

    assert transport.fingerprint_sha256(b"abc") == hashlib.sha256(b"abc").hexdigest()


# -------------------------------------------- feature flags across all certification sets

_BREAKER_FIX = json.loads(
    (
        Path(__file__).parent / "breaker" / "r1" / "crypto" / "fixtures" / "breaker_vectors.json"
    ).read_text(encoding="utf-8")
)
# The actual certification arrays the fixture generator fed to each labelled set.
_CERT_SETS = {
    "SG": ["US FCC", "SG CLS L1 STAGE2"],
    "US_only": ["US FCC"],
    "empty": [],
    "RG": ["RG"],
    "CE_RED": ["CE RED"],
}


@pytest.mark.parametrize("label", list(_CERT_SETS))
def test_is_support_reproduces_bundle_for_every_cert_set(label: str) -> None:
    certs = _CERT_SETS[label]
    expected = _BREAKER_FIX["isSupport_by_cert"][label]
    produced = {
        flag: crypto.is_support(flag, certs) for flag in _BREAKER_FIX["feature_map_all_flags"]
    }
    assert produced == expected


def test_should_skip_encrypt_follows_https() -> None:
    assert crypto.should_skip_encrypt(True) is True
    assert crypto.should_skip_encrypt(False) is False
