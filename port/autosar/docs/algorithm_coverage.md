# Algorithm Coverage

Status of each primitive in the Classic Crypto Driver and the Adaptive
CryptoProvider.

**Legend**: ✅ implemented and covered by the smoke tests · 🔵
implemented, not covered · ⚪ not supported · `-` not applicable.

"Classic async" means the job completes through `Crypto_MainFunction`
and `CryIf_CallbackNotification`. Primitives marked *(blocking)* have no
wolfHSM Request/Response pair; `Crypto_MainFunction` runs them as one
blocking call once no other request is in flight.

| Primitive                              | Classic sync | Classic async      | Adaptive |
|----------------------------------------|:------------:|:------------------:|:--------:|
| Hash SHA-256 / 384 / 512, single call  | ✅           | ✅                 | ✅       |
| Hash START / UPDATE / FINISH           | ✅           | ✅ *(blocking)*    | ✅       |
| AES-ECB / CBC / CTR                    | ✅           | ✅                 | ✅ CBC, CTR; 🔵 ECB |
| AES-GCM                                | ✅           | ✅                 | ✅       |
| CMAC-AES generate / verify (truncated) | ✅           | ✅                 | ✅       |
| ECDSA P-256                            | ✅           | ✅                 | ✅       |
| Ed25519 (pure, RFC 8032)               | ✅           | ✅ *(blocking)*    | ✅       |
| RSASSA-PKCS1-v1_5                      | ✅           | ✅ *(blocking)*    | ✅       |
| RSASSA-PSS                             | ✅           | ✅ *(blocking)*    | ✅       |
| ML-DSA-44 / 65 / 87                    | ✅ 44        | ✅ 44 *(blocking)* | ✅ 44    |
| ECDH P-256 (CalcPubVal / CalcSecret)   | ✅           | ✅ *(blocking)*    | ✅       |
| X25519 (CalcPubVal / CalcSecret)       | ✅           | 🔵 *(blocking)*    | ✅       |
| KeyDerive HKDF / CMAC-KDF              | ✅           | 🔵 *(blocking)*    | ✅ HKDF; 🔵 CMAC-KDF |
| KeyGenerate AES / ECC / Ed25519 / RSA / ML-DSA / X25519 | ✅ | ✅ AES *(blocking)* | - |
| KeySetValid / KeySetInvalid / KeyGetStatus | ✅       | ✅ SetValid        | -        |
| KeyElementSet / Get / Copy / CopyPartial / IdsGet, KeyCopy | ✅ | -        | -        |
| KeyStorage Save / Load / Commit / Erase | -           | -                  | ✅       |
| RandomGenerate                         | ✅           | ✅                 | ✅       |
| RandomSeed                             | ⚪           | ⚪                 | ⚪       |

RandomSeed has no wolfHSM client API. `Crypto_RandomSeed` returns
`E_NOT_OK`.

## Smoke tests

`classic/examples/csm_smoke/` runs one binary against
`wh_posix_server` over TCP. Each category lives in its own file:

| File                | Covers |
|---------------------|--------|
| `csm_smoke.c`       | RNG, SHA-256 (sync, async, 8 KiB chunked, multi-call), keystore, async queueing |
| `test_kat.c`        | NIST hash and AES-CBC vectors; ECDSA (incl. malformed DER), Ed25519, RSA and CMAC round trips |
| `test_det.c`        | DET `(serviceId, errorId)` reports for parameter checks |
| `test_accounting.c` | async slot and hash state leak checks |
| `test_cancel.c`     | cancel of queued, pending and unknown jobs |
| `test_timeout.c`    | forced cleanup after `CRYPTO_ASYNC_TIMEOUT_TICKS` |
| `test_concurrency.c`| worker threads submitting and cancelling async jobs |
| `test_cipher.c`     | SP 800-38A ECB/CBC/CTR, AES-GCM against software wolfCrypt, KeyCopy, multi-call SHA-384/512 |
| `test_sig.c`        | RSA PKCS#1 v1.5 / PSS, ECDSA and Ed25519 verified in software with the exported public key; ML-DSA-44 |
| `test_edge.c`       | truncated CMAC, derived-key use and salt, buffer/length/key-id/IV/verifyPtr checks, NVM-only key re-validation, cancel of a streamed hash, large async RNG, IV taken at submission, stream job state |
| `test_keymgmt.c`    | key state, key element APIs, `CRYPTO_E_BUSY`, key exchange and key management jobs |
| `test_policy.c`     | async key validity, cancel of an in-flight job, partial copy and key exchange policy, server-side AES keygen, rejected inputs |

`adaptive/examples/ap_smoke/` exercises each provider context against a
fresh `wh_posix_server`: RSA and Ed25519 signatures cross-checked in
software, ML-DSA by sign/verify round trip, X25519, an AES-CTR vector,
GCM tag mismatch and the key storage calls.

CI's `build-and-test-autosar.yml` builds and runs both, with and
without ASAN.
