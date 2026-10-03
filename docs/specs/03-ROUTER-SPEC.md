# 03 — Archer AX53 backend (`archer-router-mcp`, standalone repo)

Target: TP-Link Archer AX53 v1 (AX3000), UI build `AX53v1_1.11.0_2026-01-05`, certification profile `["US FCC","SG CLS L1 STAGE2"]` (the SG hardened variant). Maintainer-confirmed architecture: a **standalone repo**, not a consolidated server.

- Repo: `E:/projects-working-dir/archer-router-mcp`. Package `archer_router_mcp`. Console script `archer-router-mcp`. MIT, public. Python 3.11+, `mcp` (FastMCP), `httpx`, `cryptography`, `pydantic` v2, `python-dotenv`; dev: `pytest`, `pytest-cov`, `respx`, `ruff`.
- Env prefix `ARCHER_ROUTER_*`: `HOST`, `PORT`, `PASSWORD`, `VERIFY_TLS`, `TLS_FINGERPRINT_SHA256`, `ALLOW_WRITES`, `LOGIN_DISABLED`, `DRY_RUN`, `FORCE_SESSION_TAKEOVER` (default `false`), `STATE_DIR`.
- Tool prefix `router_`, plus the global `router_status`.
- **`archer_router_mcp/core/` is COPIED VERBATIM** from `vigi-nvr-mcp/vigi_nvr_mcp/core/` (device-agnostic template: `config.py`, `envelope.py`, `errors.py`, `redact.py`, `write_gate.py`, `breaker.py`, `serial.py`, `transport.py`, `backend.py`, `server.py`, `cli.py`). Phase R1 **starts by copying it**, not re-implementing it; then renames the env prefix constant and tool-registry hooks.

Read `00-MASTER-PLAN.md` §1–§2 first; every non-negotiable there applies (public repo = zero secrets/real network data; no browser at runtime; lockout safety; writes gated twice; `{success,data,error}` envelope; redaction; serialised per-device I/O; style; fault-finding tests). `scripts/gate.py` and the Phase Report format are identical to the master plan.

Inputs available to agents (scratchpad `router/discovery/`, orchestrator copies the needed ones into the repo under `archer_router_mcp/protocol/` and `tests/fixtures/archer_router/`):
- `router-auth-vectors.json` — byte-exact login/request vectors produced by **executing the router's own bundle** (dummy inputs). **Authoritative for crypto.**
- `router-endpoints.json` — 27 curated capabilities + 442 call sites; `_review`/`_about` keys describe format; `priority[]` has `{capability, operation, path, mutates, request, response, ui_context, source, confidence}`.
- `../archer-ax53-auth-flow.md` — full flow, `[V]/[O]/[I]` tagged, with a `## Review notes` section (Node-verified). **Do not re-derive.**
- `tplinkrouterc6u` `client/sg.py` (GPL-3.0) — **cross-check only, never copied**. This port is a clean-room MIT implementation from the two docs above.

## Protocol (do not re-derive — from `archer-ax53-auth-flow.md` + `router-auth-vectors.json`)

- Pre-auth and authed share one URL shape: `POST http(s)://<host>:<port>/cgi-bin/luci/;stok=<token>/<path>`. Before login the token is empty → `/cgi-bin/luci/;stok=/login?form=…`. Headers `Content-Type: application/x-www-form-urlencoded`, `Cache-Control: no-cache`. Body is urlencoded `operation=<verb>&…` (except `/v2/…` paths, which are JSON — none of our tools use them). Response envelope normalises to `errorCode` from any of `errorCode|error|errorcode|error_code`; `success:false` carries the code.
- **Capability gate**: `POST …/device_config?form=config` (`operation=read`, pre-login, in whitelist `Gr`) returns `certification`. This profile → flags `2_login_SHA256, 3_login_failed, 4_multiple_login, 5_gdpr, 12_replace_hash, 13_rsa_pad_with_pkcs1_oaep` all ON (verified by executing the bundle). Branch exactly on these.
- **Password hash** `h0 = SHA256("admin"+password)` lowercase hex.
- **Challenge**: `login?form=keys` → `{password:[n_pw,"010001"], mode, username}` (2048-bit n). `login?form=auth` → `{key:[n_sig,"010001"], seq}` (2048-bit n).
- **AES** session envelope: AES-128-CBC/PKCS7, key and IV each **16 ASCII decimal digits** used as UTF-8 bytes; ciphertext is base64. `k=<16d>&i=<16d>` is the "formatted key".
- **Password field**: `RSA PKCS#1 v1.5` over the RAW password, hex, zero-left-padded to `len(n_pw hex)`.
- **Login** (`withAesKey=true`): body `password=<pw_rsa>&operation=login&confirm=<true|false>`; `data=AES_b64(body)`; `sign = concat( RSA-OAEP(SHA-1/MGF1-SHA1)(chunk) )` over 53-char chunks of `k=..&i=..&h=<h0>&s=<seq+len(data)>`. POST `sign=…&data=<urlencoded b64>`. Response AES-decrypts to `{success, data:{stok,…}}`. Keep the `sysauth` cookie the router sets and send it back. Login does NOT roll the hash.
- **Post-login** (`withAesKey=false`): `data=AES_b64(body)`; set `hash := SHA256(data)` (self-contained per request — a lost request does NOT desync later ones); `sign = concat( hex(HMAC-SHA256(key="k=..&i=..", chunk)) )` over 53-char chunks of `h=<hash>&s=<seq+len(data)>`. `seq` is constant for the session. **HMAC is chunked at 53 too** (73-char plaintext → 128 hex chars, not 64).
- **Over HTTPS** the bundle's `shouldSkipEncrypt()` sends the plain urlencoded body with no `sign` and does not decrypt responses. **Whether the router accepts this is the central R0 question.**
- Client verbs → body: `read`=`operation=read`; `load`=`operation=load`; `write`=`operation=write&…`; `insert`=`operation=insert&new=<JSON>&index=0`; `remove`=`operation=remove&key&index`; `update`=`operation=update&key&new=<JSON>&old=<JSON>`.
- **Errors/lockout**: wrong password → `errorCode:"login failed"` with `data.failureCount`/`data.attemptsAllowed`; threshold ≈ 5 (init) / 7 (local); over threshold → `"exceeded max attempts"`, **locked 2 hours**. `"user conflict"` → another admin logged in; resending `confirm:true` **evicts** them. `"multiple login"` → policy refusal. `"timeout"` → decrypt failure or expired token.

## Phase R0 — LIVE envelope capture (orchestrator-run, maintainer present)

**Purpose**: confirm which wire envelope the router actually accepts, before any code depends on it. This is the one phase that touches the device; one login only; maintainer logged out of the web UI.

**Deliverables** (a dev-only utility, isolated, never imported by the package)
- `tools/capture-login/` with its own `package.json` (headless-Chrome one-shot) AND a pure-`httpx` probe script `tools/capture-login/probe.py` that does NOT use a browser.
- Capture plan, run by the orchestrator with the maintainer present and the maintainer logged out:
  1. `GET`/`POST …/device_config?form=config` over **HTTP** and over **HTTPS** → record `certification` and that both transports answer pre-login.
  2. `login?form=keys` and `login?form=auth` over each transport → record modulus bit-length, `e`, `seq` shape (values redacted).
  3. **One** full login over **HTTPS** sending the plain (skip-encrypt) body `password=<pw_rsa>&operation=login&confirm=false` with **no `sign`** → does the router return a `stok` + `sysauth` cookie? (Answers the skip-encrypt question.) If it refuses, immediately fall back to the HTTP AES+sign envelope for the same single login.
  4. With the obtained `stok`: one `admin/dhcps?form=reservation` `operation=load` over the accepted transport → confirm response envelope and the reservation row shape (`hostname,enable,ip,mac`).
  5. One `admin/wireless?form=wireless_2g` `operation=read_spf` then nothing (capture the band read shape for the write body). `admin/system?form=logout`.
- `docs/protocol/archer-ax53-verified.md` (sanitised): which transport won, whether skip-encrypt is accepted, the exact reservation and wifi-band field names, the `write_spf` minimal enable body.

**Tests**: none (live, manual). **Done when** the doc records: (a) skip-encrypt accepted yes/no, (b) reservation name field confirmed `hostname`, (c) `write_spf` enable body confirmed. **Rules**: one login only; never loop; stop on any surprise; redact all real values.

## Phase R1 — crypto (pure functions + vector tests, one agent)

**Deliverables**
- Copy `vigi-nvr-mcp/vigi_nvr_mcp/core/` → `archer_router_mcp/core/` verbatim; rename env prefix to `ARCHER_ROUTER_*` and the tool-registry/back­end hooks for `router_`. Keep ≥ 90% coverage on `core/` (its tests come with it; re-run them).
- `archer_router_mcp/crypto.py` (pure, no I/O, no globals), each a clean-room implementation from the protocol section:
  - `sha256_hex(s)`; `password_hash(pw) -> str` = `sha256_hex("admin"+pw)`.
  - `AesKey` (dataclass: `key: str`, `iv: str`); `gen_aes_key(rng) -> AesKey` = 16 decimal digits each; `aes_encrypt(key, plaintext) -> b64`; `aes_decrypt(key, b64) -> str` (AES-128-CBC/PKCS7, utf-8 digit bytes).
  - `rsa_pkcs1v15_hex(n_hex, e_hex, plaintext) -> str` (raw password; hex zero-padded to len(n_hex)).
  - `rsa_oaep_sha1_hex(n_hex, e_hex, plaintext) -> str` (single block).
  - `chunk53(s) -> list[str]`; `sign_login(aes, h0, seq, data_b64, n_sig, e_sig) -> str` (RSA-OAEP per chunk of `k=..&i=..&h=<h0>&s=<seq+len(data)>`); `sign_request(aes, rolling_hash, seq, data_b64) -> str` (HMAC-SHA256 per chunk of `h=<hash>&s=<seq+len(data)>`).
  - `rolling_hash(data_b64) -> str` = `sha256_hex(data_b64)`.
  - `build_login_body(pw_rsa, confirm) -> str`; `build_request_body(params: dict) -> str` (urlencode with object values JSON-stringified, `null/undefined` dropped, key order preserved).
- `tests/fixtures/archer_router/auth_vectors.json` (copy of `router-auth-vectors.json`) + `tests/test_crypto.py`.

**Tests**
- Happy: `password_hash("TestPass123") == <vector b_password_hash.value>`; `aes_encrypt({1234567890123456,6543210987654321},"operation=read")` equals the vector ciphertext; `aes_decrypt` round-trips; `chunk53` of the 73-char request plaintext yields 2 chunks (53+20); `sign_request` for the vector equals `d_normal_request.sign_output_hex` (asserts HMAC chunking → 128 hex chars).
- Edge: body builder drops `None` values and JSON-stringifies dicts/lists; preserves insertion order; `s` uses len of the **b64 string**; zero-pad of RSA hex to modulus width; unicode password; empty/overlong (32-char) password.
- Adversarial: RSA with a generated 2048-bit key round-trips (OAEP decrypt with the matching private key recovers the plaintext); PKCS1v15 likewise; reject a key whose modulus is too small for the chunk (guard like forge's `min(53, k-42)`); malformed `n_hex`/`e_hex` raise, not crash.
- State machine: `rolling_hash` depends only on the current `data_b64` (two different prior hashes → same result); login sign does not consume/alter the rolling hash.

**Done when** gate passes and every deterministic field of `auth_vectors.json` is asserted equal.

## Phase R2 — auth + session (one agent)

**Deliverables**
- `archer_router_mcp/transport.py` (`ArcherTransport(core.HttpTransport)`): builds `/cgi-bin/luci/;stok=<token><path>`; persists the `sysauth` cookie; `verify_tls` or SHA-256 fingerprint pin; `post_pre_login(path, params)`, `post_authed(path, params, *, mutating)`. Chooses envelope: if `use_https_plain` (set after R0) send plain `operation=…` body; else AES-encrypt + `sign` and attach `sign=…&data=…`, updating the rolling hash before signing. Decrypts responses on the HTTP path. Maps normalised `errorCode` to errors.
- `archer_router_mcp/auth.py` (`ArcherAuthenticator(settings, transport, breaker)`): `read_capabilities()` (= `device_config?form=config`, pre-login, returns the six flags), `get_keys()` (`login?form=keys`), `get_auth()` (`login?form=auth`), `login() -> Token` — exactly ONE HTTP login; honours `login_disabled` and the breaker **before any network call**; builds the login body/sign via `crypto`; parses `stok`; on `"login failed"` raises `AuthFailed(failure_count, attempts_allowed)` and `breaker.record_failure`; on `"user conflict"` raises `SessionConflict` **unless** `FORCE_SESSION_TAKEOVER` (then re-login once with `confirm=true`); on `"exceeded max attempts"`/`"multiple login"` raises `LockedOut`. `confirm` defaults to **False**.
- `archer_router_mcp/client.py` (`ArcherClient`): `call(verb, path, params) -> dict` with serialised execution (`core.SerialExecutor`), lazy single login, **single** re-login on `"timeout"`/expired-token (counts against breaker), never on `AuthFailed`/`LockedOut`; `logout()` (`admin/system?form=logout`); `close()`.
- `archer_router_mcp/backend.py` (`ArcherRouterBackend(core.DeviceBackend)`): `name="archer_router"`, `prefix="router_"`, `healthcheck()` = `read_capabilities()` only (no login), returning the flags + any attempt counters.
- Tools: `router_check_auth` (capabilities only; shows counters if present), `router_login` (explicit; one attempt; returns `mode`/flags only — never the token/cookie), and the global `router_status`.
- `errors.py` additions (subclass core): `SessionConflict`, and an error-string table mapping `"login failed"/"user conflict"/"multiple login"/"exceeded max attempts"/"timeout"/"permission denied"` + the `error.Exxxxxxxx` codes from the bundle to meanings (vendored `protocol/errcodes.json`).

**Tests**
- Happy: capability read parses six flags from a fixture; a full login against a **fake router** (a test double that implements the SG crypto incl. HMAC chunking and rolling hash) yields a token; `logout` sends the right body.
- Edge: `confirm` default False; HTTPS-plain vs HTTP-AES envelope both produce an accepted login against the fake; cookie round-trips; `seq` constant across a batch.
- Adversarial: wrong password → `AuthFailed(failure_count, attempts_allowed)` surfaced, **no retry**, breaker written; `login_disabled` and breaker-open → **no HTTP call at all** (assert transport mock not called); `"user conflict"` without force → `SessionConflict` and no takeover; with `FORCE_SESSION_TAKEOVER` → exactly one `confirm=true` re-login; `"exceeded max attempts"` → `LockedOut`, breaker written; a login page / HTML returned instead of JSON → `ProtocolError` envelope, not an exception; tampered rolling hash from the fake → `"timeout"` → exactly one re-login then success; `"timeout"` twice → raised, no third login.
- State machine: expired token mid-batch → one re-login; serialised executor prevents concurrent logins.

**Done when** gate passes; `--list-tools` shows `router_status`, `router_check_auth`, `router_login`.

## Phase R3 — read tools (one agent)

Hand-written, LLM-friendly reads; each returns a normalised pydantic model under `data`, `raw` when `include_raw=True`; all go through `client.call`; none bypass validation. Paths/ops from `router-endpoints.json` `priority[]`.

| Tool | Path / verb | Notes |
|---|---|---|
| `router_get_status` | `admin/status?form=all`, `read` | model, fw, uptime, wan up/ip, lan ip, radio on/off, client count |
| `router_list_clients` | `admin/smart_network?form=game_accelerator`, `load` (+ `admin/nat?form=client_list`) | MAC, IP, name, wired/band, up/down; **the connected-clients list** |
| `router_list_dhcp_leases` | `admin/dhcps?form=client`, `load` | mac, ip, name, lease time |
| `router_list_dhcp_reservations` | `admin/dhcps?form=reservation`, `load` | rows `{hostname, enable, ip, mac}` + `max_rules` |
| `router_get_wifi` | `admin/wireless?form=wireless_<band>`, `read_spf` per supported band | per band: enable, ssid, encryption, hidden (never return `psk_key`) |
| `router_list_port_forwards` | `admin/nat?form=vs`, `load` | rows (fields INFERRED; mark so) |
| `router_list_mesh_nodes` | `admin/easymesh_network?form=get_mesh_device_list_all`, `read` | name, model, ip, mac, version |
| `router_get_wan` | `admin/network?form=wan_ipv4_status`, `read` | type, ip, mask, gw, DNS, uptime |

**Tests** per tool: fixture → normalised model; malformed/missing fields → `ProtocolError` envelope not exception; `errorCode` mapped to meaning; `psk_key`/`password` stripped by `redact` (assert absent in output); URL-encoded names decoded; empty lists handled.

## Phase R4 — write tools (one agent)

All double-gated (`ARCHER_ROUTER_ALLOW_WRITES=true` env **and** `confirm_write=True`) and support `ARCHER_ROUTER_DRY_RUN` (returns the exact body under `data.dry_run`, sends nothing).

**Deliverables**
- `router_add_dhcp_reservation(mac, ip, name, confirm_write=False)`: `insert` to `admin/dhcps?form=reservation` with `new={"hostname":name,"ip":ip,"mac":mac,"enable":"on"}`, `index:0`. Validates mac (canonical `AA:BB:..:EE:FF`), ip (IPv4, in LAN subnet when known from `router_get_wan`/lan read), name (≤ 32, no control chars). Refuses if a reservation for that mac already exists (re-reads first) unless `replace=True`.
- `router_remove_dhcp_reservation(mac, confirm_write=False)`: re-read `load`, find the row's `key`, `remove` with `{key, index}`. Refuses if no such mac. Returns before/after lists.
- `router_set_wifi(band, enabled, confirm_write=False)`: read the band (`read_spf`), flip `enable`, `write_spf` the whole band object to `/admin/wireless?form=wireless_<band>`. `band` enum from supported bands. (Exact minimal body confirmed in R0; until then DRY_RUN only — the tool refuses a live write with `R0_UNCONFIRMED` if `docs/protocol/archer-ax53-verified.md` does not record the write body.)
- `router_reboot(confirm_write=False)`: `admin/system?form=reboot`, `operation=reboot`. **Rate-limited to 1 per 15 min** via a persisted timestamp under `STATE_DIR`; a second call inside the window returns `{success:false, error:{code:"RATE_LIMITED"}}` and sends nothing.

**Tests**
- Happy: each write's dry-run body equals the exact expected string (incl. `new=<JSON>` with `hostname`); add→list shows the row (fake router); remove→list removes it.
- Edge: writes-disabled env → no network call; `confirm_write=False` → no network call; mac normalisation (lowercase, `-` separators, no separators) → canonical; ip outside LAN subnet rejected; name with control chars / 33 chars rejected; reboot second call rate-limited.
- Adversarial: injection in `name` (`&`, `=`, newline, NUL, `"`/JSON-breaking) is encoded/rejected, never breaks the body; duplicate-mac insert refused without `replace`; `router_set_wifi` live write refused while R0 unconfirmed.
- State machine: token expiry between re-read and write → one re-login then proceed; failure mid-sequence leaves no partial reservation; breaker-open blocks all writes.

**Done when** gate passes; every write refuses correctly under each gate and under DRY_RUN sends nothing; `--list-tools` lists all R3+R4 tools.

## Phase R5 — LIVE test (orchestrator-run, maintainer present)

1. `archer-router-mcp check-auth --device router` → capabilities only (six flags).
2. `archer-router-mcp check-auth --device router --login` → **one** login; expect a token (never printed) and `mode:router`.
3. `router_get_status`, `router_list_clients`, `router_list_dhcp_reservations` → compare to the known LAN.
4. `router_add_dhcp_reservation(mac=<wired-camera MAC>, ip=<desired>, name=<label>)` in **DRY_RUN** first (review the exact body), then with `confirm_write=True` and `ALLOW_WRITES=true`.
5. `router_list_dhcp_reservations` → verify the new row.
6. `router_remove_dhcp_reservation(mac=<same>)` → verify removed (restore prior state), unless the maintainer wants to keep it.
7. `router_logout`. Record sanitised results in `docs/protocol/archer-ax53-verified.md`.

Use `192.0.2.1` and placeholder MACs in all committed docs; real values stay in the private env file only.

## Sequencing & licensing

```
R0 LIVE envelope capture ─► R1 crypto (copy core) ─► R2 auth+session ─► R3 read tools ─► R4 write tools ─► R5 LIVE reservation test
```
R1 may begin from the JS/vectors before R0 lands (crypto is fully specified); R2 needs R0's skip-encrypt answer to pick the default envelope (code both paths; flip a flag). Each phase = one agent, ≤ 14 files, ≤ 1500 LOC, gate green before commit, conventional commits ending `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, never push.

**Licensing**: this is a clean-room **MIT** native port written from `archer-ax53-auth-flow.md` and `router-auth-vectors.json`. `tplinkrouterc6u` (`client/sg.py`, GPL-3.0) is a **cross-check reference only** — read to confirm behaviour, **never copied** (no code, no comments, no structure lifted). Record in `NOTICE` that no GPL code was incorporated.

## Addendum (maintainer request 2026-10-03) — clients, presence history, blocking, limits

Verified from `router-endpoints.json` (local API, no cloud): client lists (`status?form=network_map`, `smart_network?form=game_accelerator` op `loadDevice`, `dhcps?form=client`, `easymesh_network?form=mesh_sclient_list_all`, `nat?form=client_list`), access control (`access_control?form=enable|mode|black_list|white_list|black_devices(block)|white_devices(access)`), per-client speed limit (`smart_network?form=client_speed_limit` ops `read_max`/`write`), IoT isolation (`iot_security?form=enable|isolated_list|isolated_devices_*`), Wi-Fi schedule (`wireless_schedule_v2?form=settings`), WoL (`wol?form=device`), LED (`ledgeneral`/`ledpm`). **Not in the local API**: website filtering / parental controls (HomeShield cloud), usage history, notifications to clients.

Add to **R3 (reads)**: `router_list_clients(include_offline=False)` → normalised `{mac, ip, name, type, band, wired, signal, rx_mbps, tx_mbps, online, last_seen}` merged across the sources above; `router_client_history(since, mac=None)` → join/leave events from the MCP's own presence log; `router_get_access_control()`; `router_get_speed_limits()`; `router_get_wifi_schedule()`; `router_get_iot_isolation()`. The **presence log** is a small file-backed store under `ARCHER_ROUTER_STATE_DIR` (JSON lines, size-capped, pure merge logic tested) fed by an optional sampler `router_poll_presence()` (one read; designed to be called by a cron/`ARCHER_ROUTER_PRESENCE_INTERVAL_S` background task in the server when > 0) — no history is fabricated: `first_seen`/`last_seen` only ever come from samples.
Add to **R4 (writes, double-gated + dry-run)**: `router_block_device(mac, confirm_write)`, `router_unblock_device(mac, confirm_write)`, `router_set_access_mode(mode: blacklist|whitelist|off, confirm_write)`, `router_set_client_speed_limit(mac, down_kbps, up_kbps, confirm_write)`, `router_set_wifi_schedule(...)`, `router_isolate_device(mac, isolate: bool, confirm_write)`, `router_wol(mac, confirm_write)`. Safety: `ARCHER_ROUTER_PROTECTED_MACS` (required when writes are on; the server's and the maintainer's own devices) — any block/limit/isolate on a protected MAC is refused; whitelist mode is refused unless the protected MACs are already on the white list (read-check first).
README recipe for the agent: "new device alert" (poll → diff → notify via the agent's own channel) and "block a device" (list → confirm MAC → block → verify). Note the HomeShield limitation and the DNS-filter alternative (AdGuard Home on the LAN host; the router's DHCP DNS setting is the only router-side change).
