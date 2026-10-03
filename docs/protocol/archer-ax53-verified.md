# Archer AX53 — R0 verified write bodies

This file is the **unlock gate for inferred write tools**. It starts empty (no
rows): no inferred write has been confirmed, so every inferred write refuses a
live call with `R0_UNCONFIRMED`. An "R0" live capture (one login, owner logged
out of the web UI — see [`../../deploy/install.md`](../../deploy/install.md))
confirms a write's exact body; you then add a row here and that tool's live
write unlocks.

## How the gate reads this file

The server parses the table below. A row whose **first column** is a known
inferred write-tool name unlocks that tool's live write; the header and
separator rows, and any unknown name, are ignored. A missing or unreadable file
unlocks nothing (fail closed). Nothing in this file is executed — it is a record.

The inferred tools (locked until a row confirms them):

- `router_set_wifi` — the Wi-Fi band enable/disable body.
- `router_set_client_speed_limit` — the per-client speed-limit fields.
- `router_set_wifi_schedule` — the schedule rule shape.
- `router_isolate_device` — the IoT-isolation body.
- `router_wol` — the Wake-on-LAN body.

## How to add a row

After an R0 capture confirms a tool's body, add one line to the "Verified write
bodies" table whose first cell is the tool name, for example a row reading
`router_set_wifi` then the date `YYYY-MM-DD` then a short note (transport, body
shape, how it was confirmed). Keep notes sanitised: no real MACs, IPs,
hostnames, or captured responses.

> Note: do not write example rows with a real tool name in the first column
> anywhere in this file — the gate parses every table-shaped line, so a sample
> row would unlock that tool. Use a placeholder like `<tool_name>` in any
> illustration.

## Verified write bodies

| tool | confirmed_on | note |
|---|---|---|
