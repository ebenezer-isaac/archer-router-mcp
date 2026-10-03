"""A fake Archer AX53 that speaks the SG crypto end-to-end, for tests only.

It implements both wire envelopes. Over ``http-encrypted`` it recovers the
client's AES session key by RSA-OAEP-decrypting the login signature (exactly as
the router does), AES-decrypts the request body, and returns AES-encrypted
responses; over ``https-plain`` it reads and writes plain JSON. It can inject
every error string, present a configurable TLS fingerprint, and queue per-request
errors (e.g. ``timeout``) for the re-login tests. No real network is touched.
"""

from __future__ import annotations

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
from archer_router_mcp.crypto import AesKey
from archer_router_mcp.server import Components

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
FINGERPRINT_A = "aa" * 32
FINGERPRINT_B = "bb" * 32


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
        self._session_aes: dict[str, AesKey] = {}
        self.fingerprint = FINGERPRINT_A
        # observability
        self.login_posts = 0
        self.confirm_values: list[bool] = []
        self.paths: list[tuple[str, str | None]] = []
        self.authed_requests: list[tuple[str, str, str]] = []  # (form, data_b64, sign)
        self.authed_ops: list[tuple[str, str, str]] = []  # (module, form, operation)

    # -- httpx wiring --------------------------------------------------------

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._route)

    async def probe(self) -> str:
        return self.fingerprint

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
        payload = self._read_payload(module, form)
        return self._enveloped(aes, payload)

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
    fingerprint_probe: Any = None,
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
    probe = fingerprint_probe if fingerprint_probe is not None else fake.probe
    return Components.from_env(
        env,
        http_transport=fake.transport(),
        fingerprint_probe=probe,
        rng=rng or random.Random(12345),
        clock=clock,
    )
