# archer-router-mcp

A local, browser-free [MCP](https://modelcontextprotocol.io) server for the
**TP-Link Archer AX53** Wi-Fi router. It lets an LLM client (Claude Desktop,
Claude Code, or any MCP host) read and — carefully — change your router's
settings by speaking the router's own web protocol directly: no headless
browser at runtime, no cloud account, nothing leaves your LAN.

It is built **read-first, write-gated, and lockout-aware** so that an automated
client cannot brick the admin account, kick you out of the router UI, or
silently rewire your network.

```
you ──▶ MCP host (LLM) ──▶ archer-router-mcp ──▶ https://<router>/cgi-bin/luci/...
                              (this server)         (your Archer, on the LAN)
```

## Why this exists

The Archer web UI is a single-page app that signs and encrypts every request
with a per-session scheme. There is no documented local API. This server is a
clean-room reimplementation of that scheme, wrapped in 29 MCP tools with typed,
normalised output, so an assistant can answer "who's on my Wi-Fi?", "reserve an
IP for the hallway camera", or "block that unknown device" without you opening a
browser — and without it ever spending a login attempt you didn't ask for.

## Supported and tested hardware

| | |
|---|---|
| **Model** | TP-Link Archer AX53 v1 (AX3000) |
| **Web UI** | `AX53v1_1.11.0` |
| **Certification profile** | `["US FCC", "SG CLS L1 STAGE2"]` (the SG-hardened variant) |

The router's login and request-signing scheme is **gated on the device's
certification flags**. On the SG-hardened profile the UI bundle turns on six
flags, two of which change the crypto:

- `13_rsa_pad_with_pkcs1_oaep` — the login signature uses RSA-OAEP, not HMAC.
- `12_replace_hash` — every post-login request carries a rolling SHA-256 hash.

The pre-login tool **`router_status`** reads `device_config?form=config` (no
login, no credentials) and reports exactly which flags your unit has:

```jsonc
{ "model": "...", "ui_version": "...",
  "certification": ["US FCC", "SG CLS L1 STAGE2"],
  "feature_flags": { "2_login_SHA256": true, "13_rsa_pad_with_pkcs1_oaep": true, ... } }
```

Run `router_status` (or `archer-router-mcp --check-auth`) first. If your unit
reports a **different certification set**, the login/sign path may differ and
the server has not been verified against it — treat it as unverified and do an
R0 capture (see [Safety model](#r0-unconfirmed-writes) and
[`deploy/install.md`](deploy/install.md)) before enabling writes. Other Archer
models (AX23, AX55, …) share the family protocol but are **not tested here**;
they may need the same R0 verification step.

## Clean-room note

This project is a **clean-room MIT** reimplementation. The protocol was
recovered by reading and executing the router's **own static JavaScript bundle
offline** (documented in `docs/specs/archer-ax53-auth-flow.md` and pinned by the
byte-exact vectors in `tests/fixtures/router_auth_vectors.json`). The GPL-3.0
project [`tplinkrouterc6u`](https://github.com/AlexandrErohin/TP-Link-Archer-C6U)
(`client/sg.py`) was consulted **only** to cross-check observed behaviour; **no
code, comments, structure, or other expression was copied**. This repository
contains no GPL-licensed code and ships under MIT. See [`NOTICE`](NOTICE).

## Features

29 MCP tools (all under the `router_` prefix):

- **Reads (no changes):** router status, WAN status, connected clients (merged
  across the router's five device lists), DHCP leases, DHCP reservations, Wi-Fi
  per band, port-forward (virtual-server) rules, EasyMesh nodes, access control,
  per-client speed limits, Wi-Fi schedule, IoT isolation.
- **Presence history:** an honest, file-backed join/leave/rename log the router
  itself does not keep — a one-shot sampler (`router_poll_presence`) plus a
  query tool (`router_client_history`), optionally driven by a background
  sampler inside the server.
- **Writes (double-gated, dry-runnable):** add/remove a DHCP reservation, turn a
  Wi-Fi band on/off, reboot, block/unblock a client, set the access-control mode,
  set a per-client speed limit, replace the Wi-Fi schedule, isolate/un-isolate a
  device, and Wake-on-LAN.

See the full [tools table](#tools) below.

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/ebenezer-isaac/archer-router-mcp
cd archer-router-mcp
pip install .
# or, for development:
pip install -e '.[dev]'
```

This installs the `archer-router-mcp` console script.

## Configuration

All configuration is environment variables. Copy [`.env.example`](.env.example)
to `.env` (never commit it) and edit. `192.0.2.1` is an RFC 5737 documentation
placeholder — replace it with your router's address.

### Router connection (`ARCHER_ROUTER_*`)

| Variable | Default | Meaning |
|---|---|---|
| `ARCHER_ROUTER_HOST` | — (required) | Router IP or hostname. |
| `ARCHER_ROUTER_PORT` | `443` | Admin HTTPS port (`80` if you use HTTP). |
| `ARCHER_ROUTER_PASSWORD` | — (required) | Router admin password. |
| `ARCHER_ROUTER_VERIFY_TLS` | `false` | Verify the TLS cert chain. Archer ships a self-signed cert, so this is off by default — pin instead (below). |
| `ARCHER_ROUTER_TLS_FINGERPRINT_SHA256` | unset | Pin the router cert by SHA-256 fingerprint (hex, no colons). See [TLS pinning](#tls-pinning-tofu). |
| `ARCHER_ROUTER_TIMEOUT_SECONDS` | `10` | Per-request timeout. |
| `ARCHER_ROUTER_ENVELOPE` | `auto` | Wire envelope: `auto` (plain over HTTPS, AES+sign over HTTP), `https-plain`, or `http-encrypted`. Leave `auto` unless an R0 capture says otherwise. |

### Safety switches (`ARCHER_ROUTER_*`)

| Variable | Default | Meaning |
|---|---|---|
| `ARCHER_ROUTER_ALLOW_WRITES` | `false` | Master write switch. Writes also need `confirm_write=true` per call. |
| `ARCHER_ROUTER_PROTECTED_MACS` | empty | Comma/space-separated MAC list of devices that may never be blocked, limited, isolated, un-reserved or woken. **Required (non-empty) whenever `ALLOW_WRITES=true`** — the server refuses to start otherwise. |
| `ARCHER_ROUTER_DRY_RUN` | `false` | Return the exact request body for every write and send **nothing**. |
| `ARCHER_ROUTER_REBOOT_MIN_INTERVAL_S` | `900` | Minimum seconds between accepted reboots (persisted under the state dir). |
| `ARCHER_ROUTER_FORCE_SESSION_TAKEOVER` | `false` | Allow evicting another logged-in admin (e.g. the Tether app / your browser). Off by default so a login never kicks you out without intent. Still requires the per-call `force_takeover` argument too. |
| `ARCHER_ROUTER_LOGIN_DISABLED` | `false` | Freeze authentication: no login request is ever sent while true. |
| `ARCHER_ROUTER_MAX_LOGIN_FAILURES` | `1` | Failed logins tolerated per process before all logins are refused (1–5). |
| `ARCHER_ROUTER_STATE_DIR` | `~/.local/state/archer-router-mcp` | Where the login breaker, reboot rate-limit, and presence log live. |

### Presence history (`ARCHER_ROUTER_*`)

| Variable | Default | Meaning |
|---|---|---|
| `ARCHER_ROUTER_PRESENCE_MAX_MB` | `20` | Size cap for the JSON-lines presence log (rotates once). |
| `ARCHER_ROUTER_PRESENCE_INTERVAL_S` | `0` | In-server background sampler interval; `0` disables it (call `router_poll_presence` on your own schedule instead). |

### MCP server (`ARCHER_MCP_*`)

| Variable | Default | Meaning |
|---|---|---|
| `ARCHER_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http`. |
| `ARCHER_MCP_HOST` | `127.0.0.1` | Bind address for streamable-HTTP (keep it on loopback). |
| `ARCHER_MCP_PORT` | `8770` | Bind port for streamable-HTTP. |
| `ARCHER_MCP_LOG_LEVEL` | `INFO` | Log level (logs go to stderr). |

## Running

```bash
# Inspect capabilities — no login:
archer-router-mcp --check-auth

# Perform exactly one login attempt (counts against the breaker):
archer-router-mcp --check-auth --login

# Inspect / reset the persistent login breaker:
archer-router-mcp breaker --show
archer-router-mcp breaker --clear

# List the registered tools:
archer-router-mcp --list-tools

# Run the MCP server:
archer-router-mcp serve
```

**stdio** (for Claude Desktop / Claude Code), an MCP client config entry:

```jsonc
{
  "mcpServers": {
    "archer-router": {
      "command": "archer-router-mcp",
      "args": ["serve"],
      "env": {
        "ARCHER_ROUTER_HOST": "192.0.2.1",
        "ARCHER_ROUTER_PASSWORD": "your-router-password"
      }
    }
  }
}
```

**streamable-HTTP** (for a long-running service), bound to loopback:

```bash
ARCHER_MCP_TRANSPORT=streamable-http ARCHER_MCP_HOST=127.0.0.1 ARCHER_MCP_PORT=8770 \
  archer-router-mcp serve
```

Reach it across machines only over Tailscale/SSH — never expose the port to the
LAN or the internet. For a systemd unit, see [`deploy/`](deploy/).

## Safety model

The Archer firmware is unforgiving about logins and admin sessions. This server
is designed around that.

### Single admin session

The router allows **one** admin session at a time. Logging in **evicts** whatever
else holds it (your browser, the TP-Link Tether app) — but only if the login
sends `confirm=true`. By default this server **refuses** rather than evict: a
`user conflict` surfaces as a `SESSION_CONFLICT` error and your session is left
alone. To deliberately take over, set `ARCHER_ROUTER_FORCE_SESSION_TAKEOVER=true`
**and** pass `force_takeover=true` on the call (double-gated).

### Lockout breaker

On this firmware, a handful of failed logins (≈5–7) locks the admin account for
**~2 hours**. So the server:

- **never auto-retries** a failed login;
- consults a **persistent breaker** (a lock-protected, schema-validated ledger
  file under the state dir) **before any login request leaves the process** —
  the admission and the attempt-count increment are one atomic, cross-process
  step, so two processes can't both spend the last attempt;
- surfaces the device's own `failureCount` / `attemptsAllowed` in the error;
- makes a `exceeded max attempts` lock a first-class cooldown the breaker
  honours (it refuses until the ~2 h window elapses);
- offers `ARCHER_ROUTER_LOGIN_DISABLED=true` as a hard freeze, and
  `archer-router-mcp breaker --clear` as the human reset.

A crashed login leaves the attempt counted (fail closed); recovery is a
deliberate `breaker --clear`.

### Writes are gated twice (and dry-runnable)

A mutating tool does nothing unless **both** `ARCHER_ROUTER_ALLOW_WRITES=true`
(env) **and** `confirm_write=true` (per call) are set; otherwise it returns a
`WRITE_REFUSED` envelope and makes **no network call**. With
`ARCHER_ROUTER_DRY_RUN=true`, every write instead returns the exact
`{path, form, operation, params, body}` it *would* send and sends nothing — use
this to review a body before enabling writes.

### Protected MACs

Every MAC in `ARCHER_ROUTER_PROTECTED_MACS` (your own and the server's devices)
is refused by **every** MAC-targeting write — block/unblock, speed limit,
isolate/un-isolate, reservation-remove and Wake-on-LAN — with `PROTECTED_TARGET`,
before any network call. Switching access control to **whitelist** mode is
refused unless every protected MAC is already whitelisted, so you can't lock
yourself off your own network. The list is **required** when writes are enabled.

### R0-unconfirmed writes

Some write bodies are **field-for-field verified** from the router's own write
DTOs; others are still **inferred** from the read shapes and need one live
capture ("R0") to confirm. Inferred writes refuse a *live* write with
`R0_UNCONFIRMED` until that capture is recorded — `DRY_RUN` still shows the
planned body.

| Write tool | Body status |
|---|---|
| `router_add_dhcp_reservation` | **Verified** |
| `router_remove_dhcp_reservation` | **Verified** |
| `router_block_device` | **Verified** |
| `router_unblock_device` | **Verified** |
| `router_set_access_mode` | **Verified** |
| `router_reboot` | **Verified** |
| `router_set_wifi` | **Inferred** → R0 |
| `router_set_client_speed_limit` | **Inferred** → R0 |
| `router_set_wifi_schedule` | **Inferred** → R0 |
| `router_isolate_device` | **Inferred** → R0 |
| `router_wol` | **Inferred** → R0 |

To unlock the inferred writes, perform the R0 capture (see
[`deploy/install.md`](deploy/install.md)) and record each confirmed tool as a
row in **`docs/protocol/archer-ax53-verified.md`**:

```
| router_set_wifi | 2026-10-05 | write_spf enable-only body confirmed over HTTPS |
```

The file format (a Markdown table with the header
`| tool | confirmed_on | note |`) is documented in that file's template. A row
whose first column is a known inferred tool name unlocks that tool's live write;
a missing or unreadable file unlocks nothing (fail closed).

### No-replay + read-back for writes

Writes are sent **non-idempotent**: if the reply is lost (a session `timeout`),
the server does **not** resend. Instead it re-authenticates, reads the live state
back, and reports the outcome as `landed`, `not_landed`, or `unknown`
(`WRITE_OUTCOME_UNKNOWN`) — it never doubles a write it isn't sure about. Reboot
and Wake-on-LAN, which have no state to read back, surface the lost reply
directly. The reboot limiter **reserves the cooldown slot before sending**, so an
unwritable state dir refuses the reboot rather than firing unthrottled.

### TLS pinning (TOFU)

Archer ships a self-signed certificate, so chain verification is off by default.
Set `ARCHER_ROUTER_TLS_FINGERPRINT_SHA256` to pin the cert by its SHA-256
fingerprint; the pin is enforced on the server's own connection at TLS
handshake. The observed fingerprint is reported by `router_status`
(`tls_fingerprint_observed`) — a trust-on-first-use flow: read it once over a
trusted link, then pin it.

### Exit codes

The CLI maps failures to shell exit codes so scripts can branch on the kind:

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Auth failed (wrong password) / other error |
| `2` | Config error |
| `3` | Lockout / breaker open / cooldown / login disabled / state unavailable |
| `4` | Transport error / TLS pin mismatch |

Every tool itself returns the `{success, data, error}` envelope and **never
raises**; credential-bearing fields are redacted from all output.

## Tools

R = read-only · W = mutating (double-gated). Inferred write bodies are gated by
`R0_UNCONFIRMED` until verified (see above).

### Session & health

| Tool | R/W | What it does |
|---|---|---|
| `router_status` | R | Model, UI version, certification flags, observed TLS fingerprint, breaker state. **No login.** |
| `router_check_auth` | R | Capabilities + breaker counters; optional one login. |
| `router_login` | — | Exactly one explicit login. Returns mode/flags, never the token. |
| `router_logout` | — | End the current session. |

### Reads

| Tool | R/W | What it does |
|---|---|---|
| `router_get_status` | R | Model, firmware, uptime, WAN/LAN addresses, radios, client count. |
| `router_get_wan` | R | WAN IPv4: connection type, IP/mask/gateway, DNS, uptime. |
| `router_list_clients` | R | Connected clients, merged across the five device lists, one per MAC (`include_offline` optional). |
| `router_list_dhcp_leases` | R | Active DHCP leases: mac, ip, name, lease time. |
| `router_list_dhcp_reservations` | R | DHCP address reservations + max-rules limit. |
| `router_get_wifi` | R | Per band: enable, SSID, encryption, hidden, channel. The PSK is never returned. |
| `router_list_port_forwards` | R | Virtual-server port-forward rules. |
| `router_list_mesh_nodes` | R | EasyMesh nodes: name, model, ip, mac, firmware. |
| `router_get_access_control` | R | Enabled, mode, black/white lists and devices. |
| `router_get_speed_limits` | R | Per-client bandwidth limits. |
| `router_get_wifi_schedule` | R | Scheduled Wi-Fi on/off rules. |
| `router_get_iot_isolation` | R | IoT isolation state and isolated devices. |
| `router_poll_presence` | R | One presence sample → append join/leave/rename events to the local log. Read-only against the router. |
| `router_client_history` | R | Query the local presence log (`since`, `mac`, `limit`). No router I/O. |

### Writes (double-gated)

| Tool | R/W | Body | What it does |
|---|---|---|---|
| `router_add_dhcp_reservation` | W | Verified | Add a reservation (mac, ip, name); refuses duplicate/conflict/out-of-subnet. |
| `router_remove_dhcp_reservation` | W | Verified | Remove a reservation by MAC. |
| `router_block_device` | W | Verified | Block a client (access-control black list). |
| `router_unblock_device` | W | Verified | Unblock a client. |
| `router_set_access_mode` | W | Verified | Set access-control mode: off / blacklist / whitelist. |
| `router_reboot` | W | Verified | Reboot the router (rate-limited). |
| `router_set_wifi` | W | Inferred | Turn a Wi-Fi band (2g/5g) radio on/off. |
| `router_set_client_speed_limit` | W | Inferred | Set a per-client kbps limit (0 = unlimited). |
| `router_set_wifi_schedule` | W | Inferred | Replace the Wi-Fi on/off schedule. |
| `router_isolate_device` | W | Inferred | Isolate / un-isolate a device. |
| `router_wol` | W | Inferred | Send a Wake-on-LAN magic packet. |

## Recipes

**New-device alert.** Schedule `router_poll_presence` (or set
`ARCHER_ROUTER_PRESENCE_INTERVAL_S`), then have the assistant call
`router_client_history(since=<last check>)` and surface any `join` events for
MACs it doesn't recognise, via its own notification channel. Nothing is
fabricated — `first_seen`/`last_seen` come only from real samples.

**Block a device.** `router_list_clients` → confirm the MAC with the user →
`router_block_device(mac, confirm_write=true)` (with `ALLOW_WRITES=true`) →
`router_get_access_control` to verify it's on the black list. Protected MACs are
refused.

**Reserve an IP for a camera.** `router_list_clients` or
`router_list_dhcp_leases` to find the camera's MAC → run
`router_add_dhcp_reservation(mac, ip, name)` with `DRY_RUN=true` to review the
exact body → then with `ALLOW_WRITES=true` and `confirm_write=true` → confirm
with `router_list_dhcp_reservations`.

## Limitations

- **Parental controls / website filtering are cloud-only.** HomeShield parental
  controls and web filtering are not in the router's local API, so this server
  cannot read or change them. A local alternative is a DNS filter (e.g. AdGuard
  Home on a LAN host); the only router-side change is the DHCP DNS setting.
- **No usage history on-device.** The router keeps no per-client traffic/usage
  history, so there is none to read. The presence log here is the only history,
  and it is built from samples this server takes — not back-filled.
- **No client notifications.** The router cannot push notifications to clients;
  any alerting must come from the MCP client's own channel.

## Troubleshooting

- **`user conflict` / `SESSION_CONFLICT`** — another admin (your browser or the
  Tether app) holds the single session. Log out there, or set
  `ARCHER_ROUTER_FORCE_SESSION_TAKEOVER=true` and pass `force_takeover=true` to
  evict it deliberately.
- **`login failed` with counters** — wrong password. The error carries the
  router's `failureCount` and `attemptsAllowed` (attempts left before the lock).
  The breaker also refuses further logins after `MAX_LOGIN_FAILURES`; fix the
  password, then `archer-router-mcp breaker --clear`.
- **`exceeded max attempts` / `LOCKED_OUT`** — the account is locked for ~2
  hours. Wait it out; the breaker honours the cooldown. Do not keep trying.
- **`timeout`** — a session expired or a response could not be decrypted. Reads
  re-login once automatically; writes do not resend (they read back the state).
  Persistent timeouts usually mean a wrong `ARCHER_ROUTER_ENVELOPE` for your
  transport.
- **Envelope selection** — `auto` sends a plain body over HTTPS and an AES+signed
  body over HTTP (mirroring the UI). If logins succeed over one transport but
  not the other, pin `ARCHER_ROUTER_ENVELOPE` to `https-plain` or
  `http-encrypted` to match what an R0 capture showed your unit accepts.

## Prior art and credits

- [`tplinkrouterc6u`](https://github.com/AlexandrErohin/TP-Link-Archer-C6U)
  (GPL-3.0) — used as a **cross-check reference only** (its `client/sg.py` SG
  login flow), never copied. See [`NOTICE`](NOTICE).
- [`tplinkctl`](https://github.com/liuxingbaoyu/tplinkctl) — prior art for
  TP-Link web-UI control.
- [`taroru5358/tplink-router-mcp`](https://github.com/taroru5358/tplink-router-mcp)
  — an earlier TP-Link router MCP server.
- [`sharozdawa/tplink-archer-mcp`](https://github.com/sharozdawa/tplink-archer-mcp)
  — Archer MCP endpoint list.

## Development

```bash
pip install -e '.[dev]'
python scripts/gate.py   # ruff + pytest(+coverage) + secret-scan + stub-scan + --list-tools
```

The gate must pass (and the secret scan must be clean) before every commit. CI
runs it on Ubuntu and Windows across Python 3.11–3.13. The device-agnostic
`core/` directory is canonical in a sibling project and copied verbatim here —
see [`CONTRIBUTING.md`](CONTRIBUTING.md) before touching it.

## License

MIT. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
