# Archer AX53 wire protocol (user-level)

This is a practical description of how `archer-router-mcp` talks to the router:
the request shape, the SG-hardened login/sign chain, the two wire envelopes, the
error vocabulary, and the feature flags that decide which path is used. It is a
summary for operators and contributors; the exhaustive, source-tagged derivation
(with `[V]`/`[O]`/`[I]` evidence tags and byte offsets into the UI bundle) lives
in [`../specs/archer-ax53-auth-flow.md`](../specs/archer-ax53-auth-flow.md), and
the byte-exact vectors in `tests/fixtures/router_auth_vectors.json`.

All addresses here are RFC 5737 placeholders (`192.0.2.1`).

## Endpoints

Every call — pre-login and authenticated — is a POST to one URL shape:

```
POST http(s)://<host>:<port>/cgi-bin/luci/;stok=<token>/<path>
Content-Type: application/x-www-form-urlencoded
Cache-Control: no-cache
```

Before login the token is empty, giving `/cgi-bin/luci/;stok=/login?form=...`.
After login the router returns a session token (`stok`) and sets a `sysauth`
cookie; both must be sent on subsequent calls.

The body is URL-encoded `operation=<verb>&<fields>`. Object-valued fields (used
by list operations) are JSON-stringified. The client "verbs":

| Verb | Body |
|---|---|
| `read` | `operation=read` |
| `load` | `operation=load` |
| `write` | `operation=write` + fields |
| `insert` | `operation=insert&new=<JSON>&index=0` |
| `remove` | `operation=remove&key=<k>&index=<i>` |
| `update` | `operation=update&key=<k>&new=<JSON>&old=<JSON>` |

The response is a JSON object normalised to
`{success, data, errorCode|error|errorcode|error_code}`; a non-null, non-zero
error code means failure. Reads this server uses live under `admin/<module>?form=<form>`
(e.g. `admin/dhcps?form=reservation`, `admin/wireless?form=wireless_2g`); the
full catalogue is in [`../specs/router-endpoints.json`](../specs/router-endpoints.json).

## Feature flags

A pre-login, credential-free read of `device_config?form=config` returns the
device `certification` list. The UI reproduces `isSupport(flag)` as "this flag is
on when `certification` contains a profile string that enables it." On the tested
unit (`certification = ["US FCC", "SG CLS L1 STAGE2"]`) six flags are on:

```
2_login_SHA256  3_login_failed  4_multiple_login  5_gdpr
12_replace_hash  13_rsa_pad_with_pkcs1_oaep
```

Two of these change the crypto chain: `13_rsa_pad_with_pkcs1_oaep` makes the
login signature RSA-OAEP, and `12_replace_hash` turns on the per-request rolling
hash. `router_status` reports the observed flags so you can confirm your unit
matches before trusting the login path.

## SG crypto chain

1. **Password hash** `h0 = SHA256("admin" + password)`, lower-case hex.
2. **Challenge** — two pre-login reads:
   - `login?form=keys` → `{password: [n_pw, "010001"], mode, username}` (2048-bit RSA modulus).
   - `login?form=auth` → `{key: [n_sig, "010001"], seq}` (2048-bit; `seq` is constant for the session).
3. **AES session key** — a fresh key and IV, each **16 ASCII decimal digits**,
   used directly as UTF-8 bytes (AES-128-CBC/PKCS7). The "formatted key" is
   `k=<16 digits>&i=<16 digits>`. Ciphertext is CryptoJS-style base64.
4. **Password field** — `RSA PKCS#1 v1.5` over the **raw** password (not the
   hash), hex, zero-left-padded to the modulus hex width. The password bytes are
   encoded per UTF-16 code unit the way the UI's `pkcs1pad2` does (CESU-8 for
   supplementary-plane characters), so an emoji password matches the router.
5. **Login body** (`withAesKey=true`) —
   `password=<pw_rsa>&operation=login&confirm=<true|false>`. Then:
   - `data = AES_base64(body)`
   - `sign = concat( RSA-OAEP(SHA-1/MGF1-SHA1)(chunk) )` over 53-character chunks
     of `k=..&i=..&h=<h0>&s=<seq + len(data)>`.
   - POST `sign=<hex>&data=<url-encoded base64>`; the reply AES-decrypts to
     `{success, data: {stok, ...}}`. Login does **not** roll the request hash.
6. **Post-login requests** (`withAesKey=false`) —
   - `data = AES_base64(body)`
   - set `hash := SHA256(data)` (self-contained per request — a lost request does
     **not** desync later ones)
   - `sign = concat( hex(HMAC-SHA256(key="k=..&i=..", chunk)) )` over 53-character
     chunks of `h=<hash>&s=<seq + len(data)>`. The HMAC is chunked at 53 too, so a
     73-character plaintext yields **128** hex characters, not 64.

`s` is `seq` plus the length of the base64 **string**.

## Wire envelopes

The UI's `shouldSkipEncrypt()` decides the envelope by transport:

- **Over HTTPS** (`https-plain`): the plain URL-encoded body is sent with **no
  `sign`**, and responses are not decrypted.
- **Over HTTP** (`http-encrypted`): every non-whitelisted request is AES-encrypted
  and signed as above; responses are AES-decrypted.

`ARCHER_ROUTER_ENVELOPE=auto` mirrors this (plain over HTTPS, encrypted over
HTTP). Whether a given unit's server actually *accepts* the HTTPS skip-encrypt
body is the central question an **R0 capture** answers; until then `auto` picks
the transport-matching default, and you can pin `https-plain` or `http-encrypted`
explicitly. The pre-login forms (`login?form=keys`, `login?form=auth`,
`device_config?form=config`, …) are always sent plain, on either transport.

## Error strings

The login/session flow branches on these `errorCode` strings:

| Code | Meaning | Handling |
|---|---|---|
| `login failed` | Wrong password | Carries `failureCount` / `attemptsAllowed`; counts one failure; never retried. |
| `user conflict` | Another admin holds the single session | Refused as `SESSION_CONFLICT` unless takeover is explicitly authorised (then one `confirm=true` resend). |
| `multiple login` | Multiple-login policy refusal | `LOCKED_OUT`; no attempt spent. |
| `exceeded max attempts` | Account locked (~2 h) | `LOCKED_OUT`; the breaker honours the cooldown. |
| `timeout` | Session expired / response undecryptable | Reads re-login once; non-idempotent writes do not resend. |
| `permission denied` | Operation not allowed for the account | Surfaced (also seen as numeric `00000088`). |

A numeric `error.Exxxxxxxx` form also appears (e.g. `00000089` = locked). The
server maps every known code to a human meaning in the error envelope.
