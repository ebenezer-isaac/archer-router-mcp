# Breaker round 1 — vector crypto — archer-router-mcp @ eb83311

Model: claude-opus-4-8
Branch: breaker/r1-crypto (from eb83311)

Claim attacked: "`archer_router_mcp/crypto.py` reproduces the Archer AX53 (SG profile)
web bundle byte-for-byte … SHA256 password hash; AES-128-CBC/PKCS7 with 16-decimal-digit
key/IV; RSA PKCS#1 v1.5 password encryption; RSA-OAEP(SHA-1) login signature 53-chunked;
HMAC-SHA256 post-login signature; `s` = seq + len(base64); rolling hash = SHA256(own b64);
all functions pure, never mutate, reject wrong key sizes, **never put a password, key, IV or
hash into an exception message or repr**; **`shouldSkipEncrypt`/feature-flag derivation
reproduces the bundle's `isSupport()` for the SG certification**."

Method: generated NEW vectors by executing the real vendor bundle
(`update-store-DQkZxaRI.js` + `vendor-BrE4IMR2.js`) in Node — `fixtures/breaker_vectors.mjs`,
output `fixtures/breaker_vectors.json` — with inputs the existing suite never exercised
(unicode/astral passwords, body lengths 0/52/53/54/105/106/107, seq 0 / 1 / 2^31,
key+IV with leading zeros, a 1 MB body, and `isSupport` across five certification sets),
then compared crypto.py byte-for-byte. RSA password bytes were compared by decrypting both
the vendor ciphertext and crypto.py's output with the fixture private key.

Axes with no finding (verified identical to the vendor bundle, or not reachable):
- **AES-128-CBC/PKCS7 + CryptoJS base64**: identical for body lengths 0/52/53/54/105/106/107
  and for a 1 MB body; **no newlines** in the base64 even at 1 MB (CryptoJS and Python agree).
- **`s` = seq + len(base64 STRING)**: identical for every body length and for seq 1 and 2^31.
- **rolling hash = SHA256(this request's own b64 ciphertext)**: identical in all cases.
- **HMAC-SHA256 post-login signature**: key is exactly `k=..&i=..` (incl. the `&`); 53-chunked;
  128 hex for the 73-char plaintext — identical to the bundle in every request case.
- **key/IV with leading zeros** (`0000000000000001`): used as ASCII bytes, never parsed as int;
  AES output and HMAC identical to the bundle.
- **BMP unicode password** (`café-Ñ-ü`, i.e. U+0000–U+FFFF): password hash AND RSA password
  bytes both match the bundle (both correct UTF-8). Only supplementary-plane chars diverge (F1).
- **password hash** SHA256("admin"+pw): matches CryptoJS (UTF-8) for ASCII, BMP and astral input.
- **OAEP SHA-1 vs SHA-256** and **PKCS1v15(password) vs OAEP(signature) not swapped**: correct
  (covered by the existing suite and re-confirmed).
- **hex `n` uppercase / odd length / exponent ≠ 010001**: `int(n,16)` + `zfill(len(n))` matches
  jsbn's `padStart(max(len(n_hex),len(out)))` for every canonical router modulus; a non-canonical
  modulus hex is not a state the router can produce — no reachable divergence found.
- **mutation of inputs**: `build_request_body` builds a new list; no primitive mutates a passed
  dict/bytes.
- **exceptions leaking the plaintext/password**: the overlong-PKCS1v15 and OAEP errors carry only
  a length, not the secret (confirmed). The *only* secret-exposure path found is the AesKey repr (F2).

---

## F1  Supplementary-plane (emoji/astral) password → RSA password bytes diverge from the bundle — Impact 3 (login rejected; each rejected attempt counts toward the device's 5–7-try, 2-hour admin lockout — rubric lists "locks the admin account" at impact 4) × Likelihood 2 (astral chars in an admin password are uncommon and not observed on this unit — a strict "no on-record case" reading is Likelihood 1 → Minor; adversary-reading? no) = 6 Major
Test: tests/breaker/r1/crypto/test_astral_password_bytes.py::test_astral_password_bytes_match_vendor_bundle (and ::test_mixed_bmp_and_astral_password_matches_vendor_bundle)
What happens: for a password containing a codepoint >= U+10000 (e.g. `pw🔑🎉`), the vendor bundle's
jsbn `pkcs1pad2` walks the JS string by `charCodeAt` and UTF-8-encodes each UTF-16 **code unit**
separately, emitting CESU-8: 🔑 → `ed a0 bd ed b4 91` (two 3-byte sequences). `crypto.rsa_pkcs1v15_hex`
does `password.encode("utf-8")`, emitting real 4-byte UTF-8 `f0 9f 94 91`. Decrypting both ciphertexts
with the fixture private key: vendor bytes `7077eda0bdedb491eda0bcedbe89` vs crypto.py `7077f09f9491f09f8e89`.
The router stored the password via its own web UI (the jsbn/CESU-8 path), so the native client submits
bytes the router will not match → login fails for that owner, permanently, and marches toward the lockout.
This directly disproves the "byte-for-byte … RSA PKCS#1 v1.5 password encryption" claim. (ASCII and BMP
passwords are a byte-for-byte match — controls in the same file pass — so the break is isolated to U+10000+.)
Why (root cause hypothesis): the spec/port assumed Python UTF-8 equals jsbn's per-code-unit encoder; jsbn
is CESU-8 for surrogate pairs. Do not fix here — a fixer must reproduce jsbn's encoding to stay byte-exact.

## F2  `AesKey` repr/str embeds the AES key and IV — Impact 4 (a key written where it must not be — rubric top row) × Likelihood 1 (no code in crypto.py reprs/logs it yet; the leak needs a downstream `repr`/log/`-l` traceback, none present at R1; adversary-reading? no) = 4 Minor
Test: tests/breaker/r1/crypto/test_aeskey_repr_leak.py::test_repr_does_not_contain_key_or_iv (+ ::test_str_… , ::test_exception_carrying_aeskey_…)
What happens: `AesKey` is `@dataclass(frozen=True)` with no `repr=False`, so `repr(aes)` / `str(aes)` /
`f"{aes}"` / `logging.debug("%r", aes)` / an exception message holding the object yields
`AesKey(key='1234567890123456', iv='6543210987654321')` — the live session key and IV in clear. The claim
"never put a … key, IV … into an exception message or repr" is factually false for this type regardless of
likelihood: the default repr *is* such a repr.
Why (root cause hypothesis): the secret-bearing field was given Python's auto-repr instead of a redacting one
(e.g. `field(repr=False)` or a custom `__repr__`). Do not fix here.

## F3  No `isSupport()` / `shouldSkipEncrypt()` / FEATURE_MAP exists in crypto.py — Impact 2 (a claimed capability is simply absent; wrong encrypt-gating would later send a plaintext body over HTTP, but that wiring is R2, not R1) × Likelihood 1 (not yet called by anything in the package) = 2 Won't-fix (claim correction)
Test: tests/breaker/r1/crypto/test_feature_flags_absent.py::test_crypto_can_reproduce_isSupport_for_sg_profile (+ ::test_crypto_exposes_a_feature_map, ::test_crypto_exposes_should_skip_encrypt)
What happens: the claim says crypto.py "reproduces the bundle's `isSupport()`" and does
"`shouldSkipEncrypt`/feature-flag derivation". crypto.py contains none of it — no FEATURE_MAP, no
`is_support`, no `should_skip_encrypt`, no `need_encrypt`; the only "certification" token in the whole
package is one docstring line. The fixture carries the bundle's authoritative `isSupport` output across
five certification sets (SG, US-only, empty, RG, CE RED) and 10 flags; nothing in crypto.py can produce it.
The claim over-states crypto.py's scope; this logic must be built and vector-tested in R2 against the
fixture — not assumed present now.
Why (root cause hypothesis): the feature-gating layer was deferred to R2 (auth/session) but the claim was
written as if R1/crypto.py already owned it.

## F4  `seq == 0` — bundle sends nothing, crypto.py produces a full signature — Impact 2 (a request would be signed/sent that the vendor would never have emitted) × Likelihood 1 (the router is not known to issue seq 0; the `if(!this.sequence) return {}` guard belongs to the R2 transport `encrypt()` orchestration, not to these primitives; adversary-reading? no) = 2 Won't-fix
Test: tests/breaker/r1/crypto/test_seq_zero_and_empty_chunk.py::test_seq_zero_matches_bundle_which_sends_nothing
What happens: the bundle's `encrypt()` opens `if(!this.sequence) return {}` — a zero/falsy sequence yields
no `sign` and no `data` (vector `seq0`: `encrypt_returned_empty: true`). `crypto.sign_request(aes, hash, 0, b64)`
returns a normal 128-hex signature. The guard lives above crypto.py, so this is recorded as a scope note for
R2 rather than a crypto.py defect.
Why (root cause hypothesis): the falsy-sequence short-circuit is a transport-layer concern not mirrored by the
pure signer (correctly, but the aggregate behaviour must be reproduced in R2).

## F5  `chunk53("")` returns `[""]`; the bundle yields zero chunks (empty signature) — Impact 1 × Likelihood 1 (the real sign plaintext `h=..&s=..` / `k=..&i=..&h=..&s=..` is never empty) = 1 Won't-fix
Test: tests/breaker/r1/crypto/test_seq_zero_and_empty_chunk.py::test_empty_plaintext_chunking_matches_bundle_zero_chunks
What happens: the bundle's `for(n=0;n<len;n+=53)` produces no chunks (empty signature) for an empty plaintext;
`crypto.chunk53("")` returns `[""]`, so a signer over it would transform one empty chunk. Latent only — not
reachable through any real signature plaintext.
Why (root cause hypothesis): `chunk53` special-cases the empty string to `[""]` instead of `[]` to avoid an
empty result; harmless because the input is never empty, but it is a byte-level divergence from the loop.
