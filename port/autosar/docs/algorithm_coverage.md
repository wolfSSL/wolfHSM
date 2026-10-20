# Algorithm Coverage

Status of each AUTOSAR R22-11 primitive in the wolfHSM Classic Crypto
Driver and the Adaptive CryptoProvider.

**Legend**: ✅ working & smoke-tested · 🔵 implemented, not yet in the
smoke suite · ⚪ stub (compiles, returns `E_NOT_OK` / `kRuntimeFault`)
· — not in scope.

The async columns describe **real** non-blocking dispatch: `Crypto_ProcessJob`
issues the wolfHSM `*Request` half and returns; `Crypto_MainFunction`
polls the matching `*Response`. There is no synchronous fallback hidden
inside the async path.

| AUTOSAR primitive             | wolfHSM client async pair            | Classic sync | Classic async | Adaptive |
|-------------------------------|---------------------------------------|:------------:|:-------------:|:--------:|
| Crypto_Init                   | wh_Client_Init / CommInit             | ✅           | n/a           | ✅       |
| Crypto_GetVersionInfo         | static                                | ✅           | n/a           | ✅       |
| RandomGenerate                | RngGenerateRequest/Response           | ✅           | ✅            | ✅       |
| Hash SHA-256 (single)         | Sha256Update/FinalRequest/Response    | ✅           | ✅            | ✅       |
| Hash SHA-256 (multi-call)     | Sha256Update/FinalRequest/Response    | ✅           | 🔵            | ✅       |
| Hash SHA-384                  | Sha384Update/FinalRequest/Response    | ✅           | 🔵            | ✅       |
| Hash SHA-512                  | Sha512Update/FinalRequest/Response    | ✅           | 🔵            | ✅       |
| Cipher AES-ECB                | AesEcbRequest/Response                | 🔵           | 🔵            | 🔵       |
| Cipher AES-CBC                | AesCbcRequest/Response                | 🔵           | 🔵            | ✅       |
| Cipher AES-CTR                | AesCtrRequest/Response                | 🔵           | 🔵            | 🔵       |
| AEAD AES-GCM                  | AesGcmRequest/Response                | 🔵           | 🔵            | ✅       |
| MAC CMAC-AES (gen/verify)     | CmacGenerateRequest/Response          | ✅           | ✅            | ✅       |
| Signature ECDSA (sign/verify) | EccSign/Verify Request/Response       | ✅           | 🔵            | ✅       |
| Signature Ed25519             | wh_Client_Ed25519Sign / Verify        | ✅           | n/a*          | 🔵       |
| Signature RSA (PKCS#1 v1.5)   | wc_RsaSSL_Sign/Verify via cryptocb    | ✅           | n/a**         | 🔵       |
| Signature RSA (PSS)           | wc_RsaPSS_Sign/Verify (pending mode)  | ⚪           | n/a*          | ⚪       |
| Signature ML-DSA              | wh_Client_MlDsaSign / Verify          | ⚪           | n/a*          | ⚪       |
| Key agreement ECDH (P-256)    | EccSharedSecretRequest/Response       | 🔵           | 🔵            | ✅       |
| Key agreement X25519          | wh_Client_Curve25519SharedSecret      | ⚪           | n/a*          | ⚪       |
| KDF HKDF                      | wh_Client_HkdfMakeCacheKey            | 🔵           | n/a*          | ✅       |
| KDF CMAC-KDF                  | wh_Client_CmacKdfMakeCacheKey         | 🔵           | n/a*          | 🔵       |
| KeyStorage Save / Load        | wh_Client_KeyCache / KeyExport        | ✅           | n/a           | ✅       |
| KeyGenerate (AES/ECC/Ed25519/X25519/RSA) | various MakeCacheKey       | 🔵           | n/a           | ⚪       |
| KeyDerive                     | wh_Client_HkdfMakeCacheKey            | 🔵           | n/a           | ⚪       |
| KeyExchangeCalcPubVal         | EccMakeCacheKey + ExportPublic        | 🔵           | n/a           | ⚪       |
| KeyExchangeCalcSecret         | EccSharedSecretRequest/Response       | 🔵           | n/a           | ⚪       |
| KeyElementSet                 | wh_Client_KeyCache                    | ✅           | n/a           | ⚪       |
| KeyElementGet                 | wh_Client_KeyExport                   | ✅           | n/a           | ⚪       |
| KeyElementCopy / KeyCopy      | Get + Set                             | 🔵           | n/a           | ⚪       |
| KeySetValid                   | wh_Client_KeyCommit                   | 🔵           | n/a           | ⚪       |
| RandomSeed                    | (no client API)                       | ⚪           | n/a           | ⚪       |
| MainFunction                  | drives the async slot machine         | ✅           | n/a           | n/a      |
| CancelJob                     | flips slot to CANCELLING; drains rsp  | ✅           | n/a           | n/a      |

\* "n/a" in the async column means **wolfHSM today exposes only the
blocking wrapper** for that primitive — there is no `*Request` /
`*Response` pair to wire. As soon as wolfHSM grows one, the slot
machinery in `Crypto_ProcessJob.c` adds a case in the same shape as the
existing primitives.

\*\* RSA-PKCS#1-v1.5 async: wolfHSM exposes
`wh_Client_RsaFunctionRequest/Response`, but it operates on **raw** RSA
(`RSA_PRIVATE_ENCRYPT` / `RSA_PUBLIC_DECRYPT`). PKCS#1 v1.5 padding has
to be applied client-side, and wolfSSL doesn't expose its padding
helpers as public API. Wiring this async path therefore requires either
duplicating the v1.5 padding block construction inside the port or
waiting for wolfSSL to expose `wc_RsaPad_PKCS1v15` / `wc_RsaUnPad`.
Sync RSA-PKCS#1-v1.5 (via `wc_RsaSSL_Sign/Verify`) keeps working
unchanged.

## Smoke harness

`classic/examples/csm_smoke/` builds a stand-alone test binary
organised into per-category test files (`test_kat.c`, `test_det.c`,
`test_accounting.c`, `test_cancel.c`, `test_timeout.c`,
`test_concurrency.c`, plus the original "basic" tests in
`csm_smoke.c`). It talks to `wh_posix_server` over TCP and runs:

```
wolfHSM AUTOSAR Crypto Driver v1.0.0 (vendor=0, module=114)
[basic]                                    # 9 regression tests
[kat]
  KAT hash: 5 vector(s) OK                 # NIST SHA-256/384/512
  KAT aes-cbc: 2 vector(s) OK              # NIST SP 800-38A F.2
  KAT ecdsa P-256: sign + good-sig verify + tampered-sig OK
  KAT ed25519: keygen + sign + verify + tampered-sig OK
  KAT rsa-pkcs1-v1.5 2048: keygen + sign + verify + tampered-sig OK
  KAT cmac-aes-128: sync gen+verify-good+verify-bad, async gen (match) + verify-good OK
[det]
  DET: 10 parameter-check paths fire correct (apiId, errorId)
[accounting]
  accounting: leak-free across UPDATE/START misuse + 20-cycle async churn
[cancel]
  cancel: queued / pending / unknown-job paths OK
[timeout]
  timeout: force-cleanup after CRYPTO_ASYNC_TIMEOUT_TICKS fires E_NOT_OK callback
[concurrency]
  concurrency: 32 async submitted, 6 cancelled, 26 callbacks delivered
csm_smoke: all tests passed
```

Six pitfall categories covered:

1. **KAT vectors** — wire-level correctness. NIST SHA / AES-CBC
   vectors plus an ECDSA P-256 sign+verify+tampered-sig round-trip.
2. **DET coverage** — 10 parameter-check paths exercise the
   `(serviceId, errorId)` tuple that fires through
   `Det_ReportError`.
3. **Resource accounting** — every test asserts
   `wh_Autosar_DebugActiveSlotCount` and `ActiveHashStateCount`
   return to zero, with a 2-second drain budget.
4. **Concurrency stress** — async-only multi-worker submit + cancel
   storm verifying `submitted - cancelled == delivered`.
5. **Timeout** — synthetic fake-pending injection + tick advance
   exercises the force-cleanup path deterministically.
6. **Cancel-during-pending** — accepts both cancel-vs-completion
   race outcomes; uses per-job callback tracking.

### Extension flags

| Flag | Effect |
|---|---|
| `-DWH_SMOKE_TEST_MALFORMED_SIG=1` | Adds a tampered-DER ECDSA verify test. See [`client_workarounds.md`](client_workarounds.md); the path requires upstream wolfHSM to fold wolfCrypt verify-rejection codes into `(rc=0, res=0)`. Pre-fold the wolfHSM client tears down the connection on the rc<0 response. |
| `-DCRYPTO_MAX_ASYNC_JOBS=N`        | Override the default 8-slot async queue. Higher values let the concurrency and accounting tests sustain deeper queues. |

The basic tests (under `[basic]`) include the original regression
set: sync + async RNG, sync + async + chunked + multi-call SHA-256,
keystore set/get + no-collision, and 3-back-to-back async queueing.
The async tests submit a job, return immediately, and wait on a
`pthread_cond_t` that is broadcast from `CryIf_CallbackNotification`
when `Crypto_MainFunction` (running on a separate thread) drains the
matching `wh_Client_*Response`. The "8 KiB chunked" hash test compares
the async digest against a sync reference to detect any mis-chunking.

## Adaptive smoke

`adaptive/examples/ap_smoke/` builds a small C++ binary that
constructs a `WolfhsmCryptoProvider` over a TCP wolfHSM client and
exercises one happy-path call per functional cluster. Run alongside
the same `wh_posix_server`:

```
wolfHSM Adaptive Crypto Provider smoke (TCP)
  Random OK (32 bytes)
  Hash SHA-256("abc") matches NIST vector
  AES-CBC-128 NIST F.2.1 OK
  AES-GCM-128 roundtrip OK
  CMAC-AES generate + verify good + verify tampered OK
  ECDSA P-256 sign + verify-good + verify-bad OK
  ECDH P-256 shared secret OK (32 bytes)
  HKDF-SHA256 -> 32 bytes OK
  KeyStorage save / load roundtrip OK
ap_smoke: all tests passed
```

CI's `build-and-test-autosar.yml` runs both `csm_smoke` and
`ap_smoke` per matrix cell.
