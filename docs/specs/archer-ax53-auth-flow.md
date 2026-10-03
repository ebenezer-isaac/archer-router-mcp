# Archer AX53 v1 (UI 1.11.0, 2026-01-05): auth and transport flow

This is reconstructed from the router's own static JavaScript, which is saved in `js/archer-ax53/js/`. Offsets are byte offsets into the named file, taken from `grep -bo`.

Tags:
- **[V]**: VERIFIED-from-JS.
- **[O]**: observed in an unauthenticated probe.
- **[I]**: INFERRED, meaning from prior art or not directly visible in the JS.

**No login was performed.** Any value written as `<…>` is a placeholder.

## 0. Files

| File | Bytes | Contains |
|---|---|---|
| `update-store-DQkZxaRI.js` | 602,109 | the axios client, interceptors, URL builder, AES, RSA (jsbn and node-forge OAEP), signature, rolling hash, feature map, token store |
| `index-Ba_XuV8T.js` | 22,704 | the login view: password hash, the login call, lockout and conflict handling |
| `index-Cd9lOeyT.js` | ~2 KB | pre-login readers (`keys`, `auth`, `check_factory_default`, `dlogin`) and logout |
| `vendor-BrE4IMR2.js` | 299,426 | Vue and CryptoJS (the `lt` alias) |

## 1. Capability gating [V][O]

`update-store@283035` (`var Jn=`) and `@283541` (`FEATURE_MAP`):
```js
["2_login_SHA256",[RG,SG_L1_S2,CE_RED,ATO_2436]], ["3_login_failed",[RG,SG_L1_S2,CE_RED,ATO_2436]],
["4_multiple_login",[SG_L1_S2,CE_RED]], ["5_gdpr",[SG_L1_S2,CE_RED,ATO_2436]],
["12_replace_hash",[SG_L1_S2]], ["13_rsa_pad_with_pkcs1_oaep",[SG_L1_S2]]
```
`isSupport(f)` is true when `deviceConfig.certification` contains a listed profile. `vt.SG_L1_S2 = "SG CLS L1 STAGE2"` (`update-store@68479`).

**[O]** `POST /cgi-bin/luci/;stok=/device_config?form=config` with `operation=read` returns `certification:["US FCC","SG CLS L1 STAGE2"]`. So **all six flags are ON** for this unit. A client must read `device_config` first and branch on these flags exactly as the JS does.

## 2. Transport [V]

**axios instance** (`update-store@249205`):
```js
const Jr=d.create({timeout:3e4,responseType:"json",baseURL:"/",
  headers:{"Content-Type":"application/x-www-form-urlencoded","Cache-Control":"no-cache"}});
Jr.interceptors.request.use(e=>{const{encrypt:t,url:r,data:n}=e, i=t??!Gr.includes(r??""), ...
  o={...e,encrypt:i,data:{username:a,...n}}; return Wr(o),Hr(o),o})
```
- `username` is undefined unless super-admin, so it is dropped when the body is serialised.
- `encrypt` defaults to true for any URL **not** in the pre-login whitelist `Gr` (`@246141`). That whitelist includes `login?form=keys`, `login?form=auth`, `device_config?form=config`, `locale?form=lang` and other pre-login forms.

**URL builder** `Wr` (`@247847`):
```js
const r=(/^\//.test(t)?t:`/${t}`).replace(/^\/v2/,""); e.url=`/cgi-bin/luci/;stok=${kt.getToken()}${r}`
```
Before login the token is empty, which gives `/cgi-bin/luci/;stok=/login?form=…`. **[O]** That works.

**Body builder** `Hr` (`@247435`):
- `/v2/…` URLs serialise the body as JSON. All other URLs are urlencoded, with object values JSON-stringified (`qr`).
- Then: `Ar.needEncrypt(e) ? e.data = $u.getEncryptor().encrypt(body, withAesKey) : Ar.shouldSkipEncrypt() && (e.data = body)`.

**`Ar`** (`@84429`):
```js
static needEncrypt(e){return!this.isHttps()&&this._isProduction()&&e.encrypt&&$n.isSupport(Jn.GDPR)}
static shouldSkipEncrypt(){return this.isHttps()&&this._isProduction()}
```
This means:
- **Over HTTP**, every non-whitelisted request is AES-encrypted and signed.
- **Over HTTPS**, the JS sends the plain urlencoded body with no `sign`, AND it does not decrypt responses. Whether the server accepts this needs a one-shot capture. **[I]**

**Response** (`Ur@244961`, `xr@245181`):
- If `needEncrypt`, the client does `JSON.parse(AES.decrypt(resp.data))`. On a decrypt failure it synthesises `errorCode:"timeout"`, which resets the session.
- `xr` normalises `errorCode | error | errorcode | error_code`.
- `success:false` with `"timeout"` triggers re-login. `"permission denied"` is surfaced as error 00000088.

**Client verbs** (`tn@250617`):

| Verb | Body |
|---|---|
| `read` | `operation=read` |
| `write` | `operation=write` plus fields |
| `load` | `operation=load` |
| `insert` | `operation=insert&new=<JSON>&index=0` |
| `remove` | `operation=remove&key&index` |
| `update` | `operation=update&key&new=<JSON>&old=<JSON>` |
| `request` | arbitrary `operation` |
| `file` | multipart |

## 3. Crypto primitives [V]

**AES**, class `ni` (`@284407`). Options are `ei={mode:CBC,padding:Pkcs7}` (`@284055`).
```js
generateKey(){const e=ri(16),t=ri(16); this.key=e; this.iv=t; this.keyUtf8=Utf8.parse(e); ...}
// ri(n): n random decimal digits 0-9 (crypto.getRandomValues)
encrypt(e){ return lt.AES.encrypt(e,this.keyUtf8,{...ei,iv:this.ivUtf8}).toString() }  // base64
getFormattedKey(){ return `k=${this.key}&i=${this.iv}` }
```
So the key and IV are each **16 ASCII digits**, used as UTF-8 bytes. AES-128-CBC with PKCS7 padding, output as base64.

**RSA**, class `Xu`/`Qu` (`@594159`):
```js
encrypt(t){return this.n&&this.e?e.encrypt(t,this.n,this.e,!0):""}       // instance: used for SIGNATURE
static encrypt(e,t,r,n=!1){ if($n.isSupport(Jn.RSA_PKCS1_OAEP)&&n) return this.padWithPKCS1OAEP(e,t,r);
  this.encryptor||(this.encryptor=new Oi); this.encryptor.setPublic(t,r); let i=this.encryptor.encrypt(e);
  ... return i.padStart(Math.max(t.length,i.length),"0") }               // static, n=false: used for PASSWORD
```
- `padWithPKCS1OAEP` → class `Yu` (`@593701`) → node-forge `encrypt(e,"RSA-OAEP")`. node-forge's default is SHA-1 with MGF1-SHA1 and an empty label. **[V]** that it is node-forge with the default options; SHA-1 is **[I]** from forge's documented defaults.
- `Oi` is jsbn RSAKey (`setPublic@306067`): **PKCS#1 v1.5 type-2 padding**, output as hex left-padded to the modulus hex length.
- **The password uses PKCS#1 v1.5. The signature uses OAEP** when flag 13 is on, which it is here.

**Signature**, class `Zu` (`@594867`; `generateSignature@595477`):
```js
generateSignature(e,t){ let r=`h=${this.hash}&s=${e}`; return t&&(r=`${this.getAESFormattedKey()}&${r}`),
                        this._getEncryptedSignature(r,t) }
_getEncryptedSignature(e,t){ ... for(n=0;n<len;n+=53){ const r=e.substring(n,n+53);
    t||!$n.isSupport(Jn.GDPR) ? i+=this.rsa.encrypt(r) : i+=ct.HmacSHA256(r,this.getAESFormattedKey()) } return i }
```
- **Login** (`t = withAesKey = true`): `sign = concat(RSA-OAEP(chunk))` over 53-character chunks of `k=<16d>&i=<16d>&h=<hash>&s=<seq+len>`.
- **Post-login** (GDPR is on): `sign = concat(hex(HMAC-SHA256(key="k=<16d>&i=<16d>", msg=chunk)))` over 53-character chunks of `h=<hash>&s=<seq+len>`.

**Rolling hash and request envelope**, `encrypt` (`@595858`):
```js
encrypt(e,t=!1){ if(!this.sequence) return {};
  const r=this.aes.encrypt(e);
  $n.isSupport(Jn.REPLACE_HASH)&&!t&&kt.isValid()&&this.setHash(ct.SHA256(r).toString());
  return { sign:this.generateSignature(this.sequence+r.length,t), data:r } }
```
- `s = seq + len(base64 ciphertext)`. `seq` comes from `form=auth` and **does not increment**.
- After login (`kt.isValid()` means a token exists), every non-login request first sets `hash := hex(SHA256(base64 ciphertext of this request))`, *then* signs. So the hash depends on the current request's own ciphertext. The chain never reuses the previous request's hash, which means a lost request does **not** desync the next one. **[V]** This corrects the "desync" worry in `feasibility.md`.
- Wire body: axios serialises `{sign, data}` as `sign=<hex>&data=<urlencoded base64>`. **[I]** The exact serialisation is axios form default; tplinkrouterc6u `sg.py` sends `'sign={}&data={}'.format(sign, quote(data))`.

## 4. Login sequence [V] (index-Ba_XuV8T.js)

`Ze` (`@3936`):
```js
async function Ze(e,a){ const n = e===K.Cloud ? a : (a=>{const x=`admin${a}`;
     return w.isSupport(y.SHA256) ? g.SHA256(x).toString() : g.MD5(x).toString()})(a);
  const o = await I();                 // I = read("/login?form=auth")  (index-Cd9lOeyT.js export g)
  m.init(n, o.seq, ...o.key) }         // $u.init(hash, seq, n, e): generateAESKey, set RSA key, seq, hash
```
`ea` (`@4126`): `function ea(e,a){return v.encrypt(e,...a)}`. Here `v = Xu.encrypt` (static, PKCS#1 v1.5), and `a` is the `[n,e]` from `login?form=keys`, injected via the `rsaPublicKey` symbol.

Login call (`@7404`, `va`):
```js
p.write("/login?form=login", {password:e, operation:"login", confirm:a},
        {preventSuccess:!0, preventError:!0, withAesKey:!0})   // returns {stok, ...}
```
`We(stok)` stores the token (`kt.setToken`, which also writes it to localStorage).

Putting it together:
1. `POST /cgi-bin/luci/;stok=/login?form=keys` with `operation=read` returns `{password:[n_pw,"010001"], mode:"router", username:""}`. **[O]** The modulus is 2048-bit.
2. `POST …/login?form=auth` with `operation=read` returns `{key:[n_sig,"010001"], seq:<int>}`. **[O]** The modulus is 2048-bit.
3. `hash = SHA256_hex("admin" + password)`.
4. Generate the 16-digit AES key and IV.
5. `pw_enc = RSA_PKCS1v15_hex(password, n_pw)`. **The raw password is encrypted, not the hash.**
6. `body = "password=<pw_enc>&operation=login&confirm=<true|false>"`. Key order follows the object literal; urlencoded.
7. Over HTTP:
   - `data = AES_b64(body)`;
   - `sign = RSA_OAEP_chunks("k=..&i=..&h=<hash>&s=<seq+len(data)>", n_sig)`;
   - POST `sign=…&data=…`;
   - the response is `{data:<b64>}`, which AES-decrypts to `{success, data:{stok, …}}`.
8. All later calls go to `/cgi-bin/luci/;stok=<stok>/admin/…`.
   - **[I]** The router also sets a `sysauth` cookie on login. The JS never touches cookies because the browser handles them; tplinkrouterc6u reads `sysauth` from `Set-Cookie` and sends it back. **A native client must keep the cookie.**

## 5. Errors, lockout, single session [V]

`index-Ba_XuV8T.js@4168` and `ia@4278`:
```js
const na="user conflict", oa="login failed", ta="exceeded max attempts", sa="multiple login";
function ia(e,a){const n=e===K.Init, o=n?5:7, ...
  const p=e.errorCode??"", v=e.data?.errorcode??"", m=e.data?.failureCount??0, f=e.data?.attemptsAllowed??0; ...
  case na: confirm("login.userConflict", onOk → re-login with confirm:true)
  case oa: isSupport(LOGIN_FAILED) ? "login.incorrectPassword" {times:m, maxTimes:m+f, hour:2} : ...
  case ta: "error.00000089" {attemptTimes:m+f}
  case sa: isSupport(MULTIPLE_LOGIN) ? "login.multipleLogin" : "login.loginFailed"
```
- Wrong password: `errorCode:"login failed"` with `data.failureCount` and `data.attemptsAllowed`.
- After the maximum (about `failureCount + attemptsAllowed`, with UI thresholds of 5 or 7), the result is `"exceeded max attempts"`. The UI text says **locked for 2 hours** (`hour:2`).
- `"user conflict"`: another admin is logged in. Sending `confirm:true` **evicts** that session.
- `"multiple login"`: the multiple-login policy refused the login.
- `"timeout"` (a decrypt failure or an expired token): the UI resets local state and goes back to login.

**Logout** [V]: `index-Cd9lOeyT.js@392` does `request("/admin/system?form=logout", undefined, …)`. It is an encrypted, signed request with no extra fields; the interceptor still adds `operation` if one is present.

## 6. How this maps to a native client

| Step | Primitive | Python equivalent |
|---|---|---|
| hash | SHA256 hex of `"admin"+pw` | `hashlib.sha256` |
| password | RSA PKCS#1 v1.5, hex, zero-padded to len(n_hex) | `Crypto.Cipher.PKCS1_v1_5` |
| login sign | RSA-OAEP(SHA-1), per 53-char chunk, hex concatenated | `PKCS1_OAEP.new(key)` |
| body | AES-128-CBC/PKCS7, key and IV = 16 ASCII digits, base64 | `Crypto.Cipher.AES` |
| request sign | HMAC-SHA256(key=`k=..&i=..`), per 53-char chunk, hex concatenated | `hmac` |
| hash rotation | `hash = sha256(b64_ciphertext)` before signing each post-login request | — |

**Cross-check:** tplinkrouterc6u `client/sg.py` (GPL-3.0, last changed 2026-08-19) implements exactly this. That includes `oaep_step = min(53, k-42)` as a guard for small keys; with this router's 2048-bit key the step is 53. A clean-room port written from this document should produce byte-identical requests. Use the JS under Node to generate test vectors: load `update-store-*.js` in a vm with stubbed `window` and `localStorage`, call the `Zu` encryptor, and compare outputs.

## Review notes (added by the vectors agent — executed the bundle in Node)

I loaded `update-store-DQkZxaRI.js` + `vendor-BrE4IMR2.js` under Node (polyfilled `window`/`localStorage`/`document`, no network), forced `deviceConfig.certification=["US FCC","SG CLS L1 STAGE2"]`, and **ran the bundle's own `Zu` encryptor, `Xu` RSA, CryptoJS SHA256/HMAC and `$n.isSupport`**. Everything in §1–§6 reproduced exactly. Byte-exact outputs are in `router-auth-vectors.json`. Confirmations and one clarification:

- **Feature flags**: executing `$n.isSupport` for this profile returns exactly `2_login_SHA256, 3_login_failed, 4_multiple_login, 5_gdpr, 12_replace_hash, 13_rsa_pad_with_pkcs1_oaep` = true; `1_login_password_strength, 6_hide_HTTPS, 14, 15` = false. Matches §1.
- **HMAC is ALSO chunked at 53.** §3 is correct but worth making explicit for an implementer: the post-login `_getEncryptedSignature` splits the plaintext `h=<hash>&s=<s>` into 53-char substrings and HMAC-SHA256s **each chunk**, concatenating the hex. For the sample `operation=read` request the plaintext is 73 chars → two chunks → **128 hex chars** (not 64). A single whole-string HMAC is wrong and the router would reject it. Verified: the bundle's `enc.encrypt(...).sign` equals my chunked HMAC and differs from a whole-string HMAC.
- **Rolling hash**: confirmed self-contained. `encrypt()` sets `hash=SHA256(b64 ciphertext of THIS request)` *before* signing, so each request's sign depends only on its own body. §3's "a lost request does not desync" is correct.
- **`s = seq + len(b64 ciphertext)`**: confirmed `len` is the length of the base64 **string**, and `seq` (from `form=auth`) is constant for the session (never incremented). For `TestPass123`/seq 1000, the 14-char body `operation=read` → 24-char b64 → `s=1024`.
- **Login sign uses the password hash as `h`.** `Ze()` calls `$u.init(hash=SHA256("admin"+pw), seq, n, e)`, so the very first login signature's `h=` is the password hash, not a ciphertext hash (login is `withAesKey=true`, which skips the rolling-hash update). Verified against the bundle.
- **Password RSA = PKCS#1 v1.5** (jsbn `Oi`, 3-arg `Xu.encrypt`, `n=false`), hex, left-padded to modulus hex width. **Login signature RSA = OAEP** (node-forge, SHA-1/MGF1-SHA1 default), 53-char chunks → 3×256-byte blocks = 1536 hex chars for a 73-char plaintext under a 2048-bit key. Both reproduced.
- **DHCP reservation name field is `hostname`** (not `comment`). Verified from the write DTO in `model-DSIxX6DP.js`: insert strips `key`, converts `enable`→`"on"/"off"`, and sends `{hostname, ip, mac, enable}` as `new=<JSON>`. This resolves one of the three R0 open items from the JS alone; R0 only needs to confirm the server's acceptance, not the field name.
- **Wi-Fi `write_spf`**: the band write posts `operation=write_spf` to a multi-form URL `/admin/wireless?form=wireless_2g&form=wireless_5g[&form=wireless_5g_2][&form=wireless_6g]` (bands from `getSupportBands()`); fields are per-band prefixed (`wireless_<band>_enable`, `_ssid`, `_encryption`, `_psk_key`, `_hidden`; the IoT variant uses `iot_<band>_*`). The exact enable-only body for a radio toggle still needs an R0 capture (read the band first, flip `enable`, write back the whole band object).
