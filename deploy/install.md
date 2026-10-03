# Deploying archer-router-mcp

A non-root systemd service that runs the MCP server over streamable-HTTP on
loopback, reachable only over Tailscale/SSH. Example unit:
[`archer-router-mcp.service.example`](archer-router-mcp.service.example).

## 1. Install the package

Into a dedicated venv (or pipx), as a normal user:

```bash
sudo mkdir -p /opt/archer-router-mcp
sudo chown "$USER" /opt/archer-router-mcp
python3 -m venv /opt/archer-router-mcp/.venv
/opt/archer-router-mcp/.venv/bin/pip install archer-router-mcp
# or from a checkout: /opt/archer-router-mcp/.venv/bin/pip install .
```

## 2. The environment file (secrets, mode 0600)

```bash
sudo install -m 0600 /dev/null /etc/archer-router-mcp.env
sudoedit /etc/archer-router-mcp.env
```

Minimum contents (see `.env.example` for every option). Replace `192.0.2.1` with
your router's address:

```
ARCHER_ROUTER_HOST=192.0.2.1
ARCHER_ROUTER_PASSWORD=<your-router-password>
ARCHER_ROUTER_TLS_FINGERPRINT_SHA256=<pin>
ARCHER_MCP_TRANSPORT=streamable-http
ARCHER_MCP_HOST=127.0.0.1
ARCHER_MCP_PORT=8770
ARCHER_ROUTER_STATE_DIR=/var/lib/archer-router-mcp
# Leave writes off until you have verified the device (step 3) and set protected MACs:
ARCHER_ROUTER_ALLOW_WRITES=false
```

Keep this file at mode `0600`. It is the only place real credentials live.

## 3. Verify the unit before enabling writes

Run a read-only check first (no login, no credentials needed for capabilities):

```bash
sudo -u "#$(id -u)" env $(sudo cat /etc/archer-router-mcp.env | xargs) \
  /opt/archer-router-mcp/.venv/bin/archer-router-mcp --check-auth
```

Confirm `certification` is `["US FCC", "SG CLS L1 STAGE2"]` and the six SG
`feature_flags` are on. If your unit reports a **different** certification set,
the login/sign path is unverified for it — do the R0 capture (below) before
trusting writes. Pin the TLS fingerprint reported as `tls_fingerprint_observed`.

Then one login:

```bash
... archer-router-mcp --check-auth --login     # expect authenticated:true, mode:router
```

## 4. Enable the service

```bash
sudo cp deploy/archer-router-mcp.service.example /etc/systemd/system/archer-router-mcp.service
sudoedit /etc/systemd/system/archer-router-mcp.service   # fix the venv path; add IPAddressAllow for the router
sudo systemctl daemon-reload
sudo systemctl enable --now archer-router-mcp
systemctl status archer-router-mcp
```

Add one entry to your MCP client config pointing at
`http://127.0.0.1:8770` (over the Tailscale/SSH tunnel). Never expose the port to
the LAN or internet.

## 5. (Optional) R0 capture — confirm the inferred write bodies

Five write tools (`router_set_wifi`, `router_set_client_speed_limit`,
`router_set_wifi_schedule`, `router_isolate_device`, `router_wol`) ship with
**inferred** bodies and refuse a live write with `R0_UNCONFIRMED` until one live
capture confirms them. Do this deliberately, once, with the router owner present:

1. **Log the owner out of the router web UI and the Tether app.** The router
   allows one admin session; this avoids a `user conflict` and an accidental
   eviction.
2. Read capabilities over **both HTTP and HTTPS** (`device_config?form=config`)
   and confirm both answer and report the same `certification`.
3. Perform **exactly one** login. Test the HTTPS skip-encrypt envelope first
   (plain body, no `sign`): does the router return a token? If it refuses, fall
   back once to the HTTP AES+sign envelope. Record which transport the unit
   accepts and set `ARCHER_ROUTER_ENVELOPE` accordingly (or leave `auto`).
4. With `ARCHER_ROUTER_DRY_RUN=true`, call each inferred write tool and record the
   exact `{path, form, operation, params}` body it plans. Compare against the
   router's actual accepted body for that action (read the relevant form first,
   e.g. the Wi-Fi band, to see the field names).
5. For each confirmed tool, add a row to
   [`docs/protocol/archer-ax53-verified.md`](../docs/protocol/archer-ax53-verified.md):

   ```
   | <tool_name> | <YYYY-MM-DD> | <transport, body shape, how confirmed> |
   ```

   That row unlocks that tool's live write. **Sanitise every note** — no real
   MACs, IPs, hostnames, or captured responses.
6. Log out (`admin/system?form=logout`). Never loop logins; stop on any surprise.

Only after the relevant rows exist should you set `ARCHER_ROUTER_ALLOW_WRITES=true`
and a non-empty `ARCHER_ROUTER_PROTECTED_MACS` (your own and the server's
devices). The service refuses to start with writes on and no protected MACs.

## Operating notes

- Inspect/reset the login breaker: `archer-router-mcp breaker --show|--clear`
  (run with the service's `ARCHER_ROUTER_STATE_DIR`).
- The state dir (`/var/lib/archer-router-mcp`) holds the breaker ledger, reboot
  rate-limit, and presence log. Back it up if you care about presence history.
- Logs go to the journal (`journalctl -u archer-router-mcp`).
