"""A fake Archer AX53 that speaks the SG crypto end-to-end, for tests only.

It implements both wire envelopes. Over ``http-encrypted`` it recovers the
client's AES session key by RSA-OAEP-decrypting the login signature (exactly as
the router does), AES-decrypts the request body, and returns AES-encrypted
responses; over ``https-plain`` it reads and writes plain JSON. It can inject
every error string, present a configurable TLS fingerprint, and queue per-request
errors (e.g. ``timeout``) for the re-login tests. No real network is touched.
"""

from __future__ import annotations

import contextlib
import copy
import json
import random
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from archer_router_mcp import crypto
from archer_router_mcp.core import transport as core_transport
from archer_router_mcp.crypto import AesKey
from archer_router_mcp.normalize import normalize_mac
from archer_router_mcp.server import Components

READ_OPS = frozenset({"read", "load", "loadDevice", "read_spf", "read_max"})


def _default_state() -> dict[str, Any]:
    """A fresh mutable table set for the stateful write tests (anonymised)."""
    return {
        "dhcps:reservation": {"rows": [], "max_rules": 32, "seq": 0},
        "access_control:black_list": {"rows": [], "seq": 0},
        "access_control:white_list": {"rows": [], "seq": 0},
        "access_control:enable": {"obj": {"enable": "off"}},
        "access_control:mode": {"obj": {"access_mode": "blacklist"}},
        "iot_security:isolated_list": {"rows": [], "seq": 0},
        "iot_security:enable": {"obj": {"enable": "on"}},
        "smart_network:client_speed_limit": {
            "rows": [],
            "seq": 0,
            "max": {"down_max": 1000000, "up_max": 1000000},
        },
        "wireless_schedule_v2:settings": {"obj": {"enable": "off", "rule_list": []}},
        "wireless:wireless_2g": {
            "obj": {"enable": "on", "ssid": "Home", "encryption": "psk2", "channel": "6"}
        },
        "wireless:wireless_5g": {
            "obj": {"enable": "on", "ssid": "Home-5G", "encryption": "psk2", "channel": "36"}
        },
        "network:lan_ipv4": {"obj": {"ipaddr": "192.0.2.1", "mask": "255.255.255.0"}},
        "wol:device": {"rows": [], "seq": 0},
    }


_FIX = json.loads(
    (Path(__file__).parent / "fixtures" / "router_auth_vectors.json").read_text(encoding="utf-8")
)
N_HEX: str = _FIX["inputs"]["rsa_public_n_hex"]
E_HEX: str = _FIX["inputs"]["rsa_public_e_hex"]
_PRIV = serialization.load_pem_private_key(
    _FIX["inputs"]["test_rsa_private_pem_pkcs8"].encode("ascii"), None
)
_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)  # noqa: S303

DEFAULT_CERT = ["US FCC", "SG CLS L1 STAGE2"]
FAKE_STOK = "FAKESTOK000000000000"  # synthetic, not a real token
FAKE_SYSAUTH = "FAKESYSAUTH000000000"
DEFAULT_SEQ = 1000
# Synthetic leaf-certificate DER bytes and their real SHA-256 fingerprints. The
# transport now reads the fingerprint from the certificate the serving connection
# presents (no side-channel probe), so the fake attaches one to every response.
CERT_A_DER = b"archer-fake-leaf-certificate-A"
CERT_B_DER = b"archer-fake-leaf-certificate-B"
FINGERPRINT_A = core_transport.fingerprint_sha256(CERT_A_DER)
FINGERPRINT_B = core_transport.fingerprint_sha256(CERT_B_DER)


class FakeSSLObject:
    """Minimal ``ssl_object`` exposing a DER leaf certificate (binary form)."""

    def __init__(self, der: bytes) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = True) -> bytes:
        return self._der


class FakeNetworkStream:
    """Minimal httpcore network stream exposing a :class:`FakeSSLObject`."""

    def __init__(self, der: bytes) -> None:
        self._ssl_object = FakeSSLObject(der)

    def get_extra_info(self, name: str) -> object | None:
        return self._ssl_object if name == "ssl_object" else None


def _parse_pairs(body: str) -> dict[str, str]:
    return dict(part.split("=", 1) for part in body.split("&") if "=" in part)


class FakeRouter:
    def __init__(
        self,
        *,
        password: str = "TestPass123",  # noqa: S107 - dummy test credential
        envelope: str = "http-encrypted",
        certification: list[str] | None = None,
        model: str | None = "Archer AX53",
        ui_version: str | None = "AX53v1_1.11.0_2026-01-05",
        seq: int = DEFAULT_SEQ,
        login_error: str | None = None,
        login_failure_data: dict[str, Any] | None = None,
        conflict_until_confirm: bool = False,
        authed_errors: list[str | None] | None = None,
        device_config_html: bool = False,
        login_html: bool = False,
        authed_payload: dict[str, Any] | None = None,
        reads: dict[str, Any] | None = None,
        stateful: bool = False,
        state: dict[str, Any] | None = None,
    ) -> None:
        self._password = password
        self._envelope = envelope
        self._certification = DEFAULT_CERT if certification is None else certification
        self._model = model
        self._ui_version = ui_version
        self._seq = seq
        self._login_error = login_error
        self._login_failure_data = login_failure_data
        self._conflict_until_confirm = conflict_until_confirm
        self._authed_errors = list(authed_errors or [])
        self._device_config_html = device_config_html
        self._login_html = login_html
        self._authed_payload = authed_payload or {"ok": True}
        self._reads = reads or {}
        self._stateful = stateful
        self._state = _default_state()
        if state:
            for key, entry in state.items():
                self._state[key] = copy.deepcopy(entry)
        self._session_aes: dict[str, AesKey] = {}
        # The leaf certificate this fake "presents" on every TLS connection; the
        # transport derives ``observed_fingerprint`` from it (default: CERT_A_DER).
        self.cert_der = CERT_A_DER
        # observability
        self.login_posts = 0
        self.confirm_values: list[bool] = []
        self.paths: list[tuple[str, str | None]] = []
        self.authed_requests: list[tuple[str, str, str]] = []  # (form, data_b64, sign)
        self.authed_ops: list[tuple[str, str, str]] = []  # (module, form, operation)
        # write observability (stateful mode)
        self.write_posts = 0  # count of MUTATING ops actually received
        self.mutations: list[tuple[str, str, str, dict[str, Any]]] = []
        self.reboots = 0
        self.wakeups: list[Any] = []

    # -- httpx wiring --------------------------------------------------------

    def transport(self) -> httpx.MockTransport:
        def route(request: httpx.Request) -> httpx.Response:
            response = self._route(request)
            # Attach the leaf certificate to the serving connection so the transport's
            # real-connection pin check / fingerprint observation has a cert to read.
            response.extensions["network_stream"] = FakeNetworkStream(self.cert_der)
            return response

        return httpx.MockTransport(route)

    def _route(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        form = request.url.params.get("form")
        self.paths.append((path, form))
        body = request.content.decode("utf-8")
        if path.endswith("/device_config") and form == "config":
            return self._device_config()
        if path.endswith("/login") and form == "keys":
            return self._keys()
        if path.endswith("/login") and form == "auth":
            return self._auth()
        if path.endswith("/login") and form == "login":
            return self._login(body)
        return self._authed(path, form, body)

    # -- pre-login reads (always plain) -------------------------------------

    def _device_config(self) -> httpx.Response:
        if self._device_config_html:
            return httpx.Response(200, content="<html><body>login</body></html>")
        return self._plain(
            {
                "certification": self._certification,
                "model": self._model,
                "sw_ver": self._ui_version,
            }
        )

    def _keys(self) -> httpx.Response:
        return self._plain({"password": [N_HEX, E_HEX], "mode": "router", "username": ""})

    def _auth(self) -> httpx.Response:
        return self._plain({"key": [N_HEX, E_HEX], "seq": self._seq})

    # -- login ---------------------------------------------------------------

    def _login(self, body: str) -> httpx.Response:
        self.login_posts += 1
        if self._login_html:
            return httpx.Response(200, content="<html>login</html>")
        aes = None
        if self._envelope == "https-plain":
            plain = body
        else:
            pairs = _parse_pairs(body)
            aes = self._recover_aes(pairs["sign"])
            plain = crypto.aes_decrypt(aes, unquote(pairs["data"]))
        fields = _parse_pairs(plain)
        confirm = fields.get("confirm") == "true"
        self.confirm_values.append(confirm)

        if self._login_error is not None:
            return self._login_reply(aes, error=self._login_error, data=self._login_failure_data)
        if self._conflict_until_confirm and not confirm:
            return self._login_reply(aes, error="user conflict")
        recovered = _PRIV.decrypt(bytes.fromhex(fields["password"]), padding.PKCS1v15())
        if recovered != crypto.encode_js_utf8(self._password):
            return self._login_reply(
                aes, error="login failed", data={"failureCount": 1, "attemptsAllowed": 4}
            )
        if aes is not None:
            self._session_aes[FAKE_STOK] = aes
        return self._login_reply(aes, success={"stok": FAKE_STOK, "mode": "router"}, cookie=True)

    def _recover_aes(self, sign_hex: str) -> AesKey:
        block = len(N_HEX)  # hex chars per 256-byte RSA block
        plain = b"".join(
            _PRIV.decrypt(bytes.fromhex(sign_hex[i : i + block]), _OAEP)
            for i in range(0, len(sign_hex), block)
        )
        match = re.search(r"k=(\d{16})&i=(\d{16})", plain.decode("ascii"))
        assert match is not None, "login signature did not carry the AES key"
        return AesKey(match.group(1), match.group(2))

    def _login_reply(
        self,
        aes: AesKey | None,
        *,
        error: str | None = None,
        data: dict[str, Any] | None = None,
        success: dict[str, Any] | None = None,
        cookie: bool = False,
    ) -> httpx.Response:
        if error is not None:
            payload: dict[str, Any] = {"errorcode": error}
            if data is not None:
                payload["data"] = data
        else:
            payload = {"success": True, "data": success}
        return self._enveloped(aes, payload, cookie=cookie)

    # -- authed requests -----------------------------------------------------

    def _authed(self, path: str, form: str | None, body: str) -> httpx.Response:
        match = re.search(r";stok=([^/]*)", path)
        stok = match.group(1) if match else ""
        module = path.rstrip("/").split("/")[-1]
        if form != "logout" and self._authed_errors:
            injected = self._authed_errors.pop(0)
            if injected:
                return httpx.Response(200, content=json.dumps({"errorcode": injected}))
        aes = self._session_aes.get(stok)
        if self._envelope != "https-plain" and aes is None:
            return httpx.Response(200, content=json.dumps({"errorcode": "timeout"}))
        plain = body if self._envelope == "https-plain" else self._decrypt_body(aes, body)
        operation = _parse_pairs(plain).get("operation", "")
        self.authed_ops.append((module, form or "", operation))
        if self._envelope != "https-plain":
            pairs = _parse_pairs(body)
            self.authed_requests.append((form or "", unquote(pairs["data"]), pairs["sign"]))
        if self._stateful:
            params = self._decode_params(plain)
            payload = self._apply(module, form or "", operation, params)
            return self._enveloped(aes, payload)
        payload = self._read_payload(module, form)
        return self._enveloped(aes, payload)

    # -- stateful write engine (opt-in via stateful=True) --------------------

    @staticmethod
    def _decode_params(plain: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in _parse_pairs(plain).items():
            decoded: Any = unquote(value)
            # JSON-stringified object/array values (new=, old=, rule_list=, ...) are
            # decoded back to structures, as the real router parses them.
            if isinstance(decoded, str) and decoded[:1] in ("[", "{"):
                with contextlib.suppress(ValueError):
                    decoded = json.loads(decoded)
            out[key] = decoded
        if "index" in out:
            with contextlib.suppress(TypeError, ValueError):
                out["index"] = int(out["index"])
        return out

    def _apply(
        self, module: str, form: str, operation: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        if form == "logout" or operation == "logout":
            return {"success": True}
        key = f"{module}:{form}"
        entry = self._state.setdefault(key, {"rows": [], "seq": 0})
        if operation in READ_OPS:
            return self._state_read(entry)
        self.write_posts += 1
        self.mutations.append((module, form, operation, params))
        if operation == "reboot":
            self.reboots += 1
            return {"success": True}
        if operation == "wakeup":
            self.wakeups.append(params.get("mac"))
            return {"success": True}
        if "rows" in entry:
            self._mutate_rows(entry, operation, params)
        else:
            obj = entry.setdefault("obj", {})
            if operation in ("write", "write_spf"):
                for field, value in params.items():
                    if field != "operation":
                        obj[field] = value
        return {"success": True}

    @staticmethod
    def _state_read(entry: dict[str, Any]) -> dict[str, Any]:
        if "rows" in entry:
            payload: dict[str, Any] = {"success": True, "data": [dict(r) for r in entry["rows"]]}
            if "max_rules" in entry:
                payload["max_rules"] = entry["max_rules"]
            if "max" in entry:
                payload.update(entry["max"])
            return payload
        return {"success": True, "data": dict(entry.get("obj", {}))}

    def _mutate_rows(self, entry: dict[str, Any], operation: str, params: dict[str, Any]) -> None:
        rows: list[dict[str, Any]] = entry["rows"]
        if operation == "insert":
            new = params.get("new") or {}
            row = dict(new)
            entry["seq"] = entry.get("seq", 0) + 1
            row.setdefault("key", f"k{entry['seq']}")
            rows.append(row)
        elif operation == "remove":
            key = params.get("key")
            mac = params.get("mac")
            index = params.get("index")
            # AX53 reservation rows carry no server-side key, so the client sends
            # key == str(index): no row matches that key, and the real router deletes
            # the row at the given table index. A firmware that DOES expose a real
            # server key (or a mac) matches by that instead. Mirror both faithfully:
            # match by key/mac when a row actually matches, else delete by index.
            matched = any(self._row_matches(r, key, mac) for r in rows)
            if matched:
                entry["rows"] = [r for r in rows if not self._row_matches(r, key, mac)]
            elif isinstance(index, int):
                entry["rows"] = [r for i, r in enumerate(rows) if i != index]
        elif operation == "update":
            key = params.get("key")
            new = params.get("new") or {}
            for row in rows:
                if str(row.get("key")) == str(key):
                    row.update(new)
        elif operation in ("write", "block", "access"):
            if isinstance(params.get("new"), dict):
                payload_row = dict(params["new"])
            else:
                payload_row = {k: v for k, v in params.items() if k != "operation"}
            mac = payload_row.get("mac")
            if mac is not None:
                existing = next(
                    (r for r in rows if normalize_mac(r.get("mac")) == normalize_mac(mac)), None
                )
                if existing is not None:
                    existing.update(payload_row)
                    return
            entry["seq"] = entry.get("seq", 0) + 1
            payload_row.setdefault("key", f"k{entry['seq']}")
            rows.append(payload_row)

    @staticmethod
    def _row_matches(row: dict[str, Any], key: Any, mac: Any) -> bool:
        if key is not None and str(row.get("key")) == str(key):
            return True
        return mac is not None and normalize_mac(row.get("mac")) == normalize_mac(mac)

    def _decrypt_body(self, aes: AesKey | None, body: str) -> str:
        if aes is None:  # pragma: no cover - guarded by caller
            return body
        pairs = _parse_pairs(body)
        return crypto.aes_decrypt(aes, unquote(pairs["data"]))

    def _read_payload(self, module: str, form: str | None) -> dict[str, Any]:
        for key in (f"{module}:{form}", form):
            if key in self._reads:
                return self._reads[key]
        return {"success": True, "data": self._authed_payload}

    # -- envelope helpers ----------------------------------------------------

    def _plain(self, payload: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(payload))

    def _enveloped(
        self, aes: AesKey | None, payload: dict[str, Any], *, cookie: bool = False
    ) -> httpx.Response:
        if self._envelope == "https-plain" or aes is None:
            content = json.dumps(payload)
        else:
            content = json.dumps({"data": crypto.aes_encrypt(aes, json.dumps(payload))})
        headers = {"Set-Cookie": f"sysauth={FAKE_SYSAUTH}; Path=/"} if cookie else {}
        return httpx.Response(200, content=content, headers=headers)


def build_components(
    fake: FakeRouter,
    *,
    envelope: str = "http-encrypted",
    state_dir: str | Path,
    extra_env: dict[str, str] | None = None,
    tls_fingerprint: str | None = None,
    rng: random.Random | None = None,
    clock: Any = None,
) -> Components:
    env = {
        "ARCHER_ROUTER_HOST": "192.0.2.1",
        "ARCHER_ROUTER_PASSWORD": "TestPass123",
        "ARCHER_ROUTER_ENVELOPE": envelope,
        "ARCHER_ROUTER_STATE_DIR": str(state_dir),
    }
    if tls_fingerprint is not None:
        env["ARCHER_ROUTER_TLS_FINGERPRINT_SHA256"] = tls_fingerprint
    if extra_env:
        env.update(extra_env)
    return Components.from_env(
        env,
        http_transport=fake.transport(),
        rng=rng or random.Random(12345),
        clock=clock,
    )
