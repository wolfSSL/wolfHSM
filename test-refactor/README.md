# wolfHSM unit tests

## Overview
The wolfHSM unit tests are designed to run on separate cores, or separate processes to model a real HSM client-server.

Tests can be run on either a POSIX host (ie a development laptop), or on the embedded target.

The unit tests are split into 3 groups:

- Client, for tests that run on the client core/process
- Server, for tests that run on the server core/process
- Misc, for tests that can run on either core/process

The groups are organized in `wh_test_list.c`.

## Running the tests from a dev machine
To run the unit tests on a POSIX system (Linux/Mac):

```
cd test-refactor
make check
```

The top-level `make` forwards to the POSIX port; `cd test-refactor/posix && make check` still works if you want to invoke the port directly.

Results are printed via `WOLFHSM_CFG_PRINTF` from the wolfHSM build. `test-suite.log` contains the detailed output.

## Running the tests from an embedded target
To run the tests on a target device, create an application running on the client or server that runs the tests from `main()`. See sections on adding ports and tests.

## Adding a port
The unit tests run within the port's main application. As a prerequiste, setup a new port application as described in the [porting guide](docs/src/chapter08.md).

For the unit test port, see `wh_test_posix_main.c` and the two `wh_test_posix_*.c` sources as a reference implementation.

### Client
1. Implement `main()` which creates a client context and initializes it with a config such that it can establish communication to a listening server
2. Implement `whTestPort_ResetClient` which resets the context between tests. Can be empty.
3. Call `whTestGroup_Client(&clientCtx)`
4. Optionally call `whTestGroup_Misc()`

For running the more substantial client tests only, no server modifications are required.

### Server
1. Implement main() which declares a server context and initializes it with a config such that it can access basic platform functionality (NVM, etc.)
2. Implement `whTestPort_ResetServer` which resets the context between tests. Can be empty.
3. Call `whTestGroup_Server(&serverCtx)` prior to entering the main request handling loop.
4. Optionally call `whTestGroup_Misc()`

## Adding a multi-port test
Tests are organized as a single registered parent function per source file, which dispatches to one or more `static` sub-tests within that file.

If adding a new test file and/or a new group of tests:
1. Create a function which returns `int` (0 for success) with a context argument (`whClientContext*` for client tests, `whServerContext*` for server tests, or none for misc tests). Inside it, call each sub-test with `WH_TEST_RETURN_ON_FAIL`.
2. In `wh_test_list.c`, add a `WH_TEST_DECL(<entry-point>)` line.
3. In `wh_test_list.c`, add the entry-point to the appropriate `whTestCase` array.

To add an individual test to an existing group:
1. Add sub-tests as `static` functions in the same file. Name them with a leading underscore (e.g. `_whTest_<Group><Case>`).

**Note**: if the test is specific to a platform, do not add it to the common list as shown above. Port-specific tests live within the port (not this directory), and are called from the port-specific code.

## Adding a port-specific test
For tests that exist within a specific port, call `whTestGroup_RunOne()` to utilize the error checking and log formatting from the test framework.

## Migration from `test/`
The legacy unit suite in `wolfHSM/test/` is being incrementally translated to `wolfHSM/test-refactor/` while preserving the original during the transition. Add new tests to `test-refactor/` only, so the legacy suite does not gain coverage that must later be ported.

The `Code Coverage` workflow (`.github/workflows/code-coverage.yml`, nightly and on demand) builds both trees across the same build matrix (default, `DMA=1`, `THREADSAFE=1`, `SHE=1`, `AUTH=1`, `NOCRYPTO=1`). Its `compare` job publishes the `coverage-comparison` artifact, which lists the lines and branches in each source file that only the legacy suite covers, per build config. Use it to confirm a port before removing the legacy test.

### Key differences
- Tests are registered and called based on a list in `wh_test_list.c` rather than manual inline code, making it simpler to add tests.
- Tests accept a client or server context which is initialized outside the test itself, reducing copypasta within the test code, and improving portability.
- Tests are divided into groups, which clarifies the origin and environment of the test.
- Tests are always run against a running server process or core, no sequencing code for single-thread simulation.

### Test mapping
Translated tests:

| Legacy (`wolfHSM/test/`) | New location | Group | Notes |
|---|---|---|---|
| `wh_test_dma.c::whTest_Dma` | `misc/wh_test_dma.c::whTest_Dma` | Misc | |
| `wh_test_comm.c::whTest_Comm` | `misc/wh_test_comm.c::whTest_Comm` | Misc | Sequential mem variant only; pthread mem/tcp/shmem variants remain in the legacy harness |
| `wh_test_keystore_reqsize.c::whTest_KeystoreReqSize` | `misc/wh_test_keystore_reqsize.c::whTest_KeystoreReqSize` | Misc | |
| `wh_test_multiclient.c::whTest_MultiClient` | `misc/wh_test_multiclient.c::whTest_MultiClient` | Misc | Sequential variant only (no legacy pthread variant exists); body is a no-op when `WOLFHSM_CFG_GLOBAL_KEYS` is off |
| `wh_test_lock.c::whTest_LockConfig`, `whTest_LockPosix` | `misc/wh_test_lock.c::whTest_Lock` | Misc | Gated on `WOLFHSM_CFG_THREADSAFE`; only exercised under `make THREADSAFE=1`, otherwise reported SKIPPED. The two public entry points collapse into one registry entry that builds its own POSIX lock config |
| `wh_test_cert.c::whTest_CertRamSim` (`whTest_CertServerCfg`, `whTest_CertServerTrustedRespectsNvmPolicy`, `whTest_CertServerReadTrustedRejectsServerOnly`, `whTest_CertEraseCannotReachNonCertObject`, `whTest_CertPerClientIsolation`) | `server/wh_test_cert.c::{whTest_CertVerify, whTest_CertNvmPolicy, whTest_CertReadRejectsServerOnly, whTest_CertEraseCannotReachNonCert, whTest_CertPerClientIsolation}` | Server | remove ramsim coupling and migrate to server group. Legacy ran FLASH and FLASH_LOG backends; the port runs the plain flash backend only -- FLASH_LOG re-run pending (see Known coverage gaps). The client-side cert flows and the remaining server subtests are not yet migrated |
| `wh_test_crypto.c::whTest_Crypto` | `client-server/wh_test_crypto_{aes,cmac,curve25519,ecc,ed25519,kdf,keypolicy,mldsa,mlkem,rng,rsa,sha,sha3}.c::whTest_Crypto_*` | Client | Split into per-algorithm suites; key revocation is gated by `WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS`. Legacy ran FLASH and FLASH_LOG backends; the port runs the plain flash backend only -- FLASH_LOG re-run pending (see Known coverage gaps). The ML-KEM suite runs every enabled level against both the comm buffer and DMA client APIs from one table of API variants |
| `wh_test_crypto.c::whTest_CryptoKeyUsagePolicies` (AES CTR/ECB/GCM subset) | `client-server/wh_test_crypto_aes.c::whTest_CryptoAesKeyUsagePolicies` | Client | AES-CTR/ECB/GCM key usage enforcement (non-DMA and DMA variants) |
| `wh_test_crypto.c::whTestCrypto_LmsCryptoCb` | `client-server/wh_test_crypto_lms.c::whTest_Crypto_Lms` | Client | DMA-only LMS generate/durability/sign/verify, public-key export+import, private export/import rejection, and the server-only `WH_NVM_FLAGS_TRUSTED` keygen strip regression. Gated by `WOLFHSM_CFG_DMA && WOLFSSL_HAVE_LMS && !WOLFSSL_LMS_VERIFY_ONLY`; reports SKIPPED otherwise. With `WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT` (wolfCrypt refuses `WH_DEV_ID_DMA`) the keygen/sign/verify/sigs-left steps call the `wh_Client_Lms*Dma` APIs directly instead of the cryptoCb |
| `wh_test_crypto.c::whTestCrypto_XmssCryptoCb` | `client-server/wh_test_crypto_xmss.c::whTest_Crypto_Xmss` | Client | DMA-only XMSS generate/durability/sign/verify, public-key export+import, private export/import rejection, and the server-only `WH_NVM_FLAGS_TRUSTED` keygen strip regression. Gated by `WOLFHSM_CFG_DMA && WOLFSSL_HAVE_XMSS && !WOLFSSL_XMSS_VERIFY_ONLY`; reports SKIPPED otherwise. With `WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT` (wolfCrypt refuses `WH_DEV_ID_DMA`) the keygen/sign/verify/sigs-left steps call the `wh_Client_Xmss*Dma` APIs directly instead of the cryptoCb |
| `wh_test_crypto.c::{whTest_KeyCache, whTest_NonExportableKeystore}` | `client-server/wh_test_crypto_keystore.c::whTest_Crypto_Keystore` | Client | Key-cache lifecycle (cache/export, evict, commit/erase, cross-cache eviction/replacement, NVM-backed eviction) and non-exportable-flag enforcement; std and DMA export paths. The `WOLFHSM_CFG_IS_TEST_SERVER` multi-client user-exclusion path is dropped (needs two client contexts) |
| `wh_test_clientserver.c` (echo and server-info paths) | `client-server/wh_test_echo.c::whTest_Echo`, `client-server/wh_test_server_info.c::whTest_ServerInfo` | Client | pthread test ported, sequential test dropped |
| `wh_test_clientserver.c` (NVM CRUD + OOB read clamping paths) | `client-server/wh_test_nvm_ops.c::{whTest_NvmCrud, whTest_NvmReadOob}` | Client | each test cleans up its own slots; OOB test covers UINT16_MAX overflow regression |
| `wh_test_clientserver.c` (NVM DMA CRUD path) | `client-server/wh_test_nvm_dma.c::whTest_NvmCrudDma` | Client | gated on `WOLFHSM_CFG_DMA` |
| `wh_test_clientserver.c::_testClientCounter` | `client-server/wh_test_counter.c::whTest_Counter` | Client | exercises saturate-on-overflow and slot-leak detection |
| `wh_test_wolfcrypt_test.c::whTest_WolfCryptTest` | `client-server/wh_test_wolfcrypt.c::whTest_WolfCryptTest` | Client | |
| `wh_test_flash_ramsim.c::whTest_Flash_RamSim` | `posix/wh_test_flash_ramsim.c::{whTest_FlashWriteLock, whTest_FlashEraseProgramVerify, whTest_FlashUnitOps}` | POSIX port-specific (`whTestGroup_RunOne`) | remove ramsim coupling and migrate to server group |
| `wh_test_nvm_flash.c::{whTest_NvmFlash, whTest_NvmFlash_Recovery, whTest_NvmFlash_Crc16}` | `posix/wh_test_nvm_flash.c::{whTest_NvmAddOverwriteDestroy, whTest_NvmFlashLog, whTest_NvmRecovery, whTest_NvmCrc16}` | POSIX port-specific (`whTestGroup_RunOne`) | remove ramsim coupling and migrate to server group; flash-log backend exercised by `whTest_NvmFlashLog` (skipped unless `WOLFHSM_CFG_SERVER_NVM_FLASH_LOG`); CRC16 integrity checks exercised by `whTest_NvmCrc16` (skipped unless built with `NVM_FLASH_CRC=1`) |
| `wh_test_flash_fault_inject.c` | `posix/wh_test_flash_fault_inject.c` | helper (no test) | fault-injection flash wrapper used by the recovery test |
| `wh_test_posix_threadsafe_stress.c::whTest_ThreadSafeStress` | called directly from `posix/wh_test_posix_main.c` | POSIX port-specific (direct call) | |
| `wh_test_check_struct_padding.c` | `misc/wh_test_check_struct_padding.c` | Build-time (compile-only) | Wire-format `-Wpadded` audit; the POSIX Makefile compiles it with `-Wpadded -DWH_PADDING_CHECK`. Not a runtime test, so not registered in `wh_test_list.c` |
| `wh_test_crypto_affinity.c::whTest_CryptoAffinity` | `misc/wh_test_crypto_affinity.c::whTest_CryptoAffinity` | Misc | Self-contained sequential client+server pair so the subtests can set the server devId. The WithCb subtest configures a HW devId plus a registered cryptoCb to cover the server's HW affinity-to-devId routing; the NoCb subtest uses INVALID_DEVID for the SW fallback. Under WOLFHSM_CFG_DMA both subtests also issue an AES CBC DMA request so the DMA crypto dispatch's affinity routing is covered with the same HW/SW branch matrix as the non-DMA path. Kept out of the client group because the shared port server is fixed at INVALID_DEVID and cannot exercise the HW routing branch. Build with `make CRYPTO_AFFINITY=1` |
| `wh_test_auth.c` (`whTest_AuthMEM` / `whTest_AuthTest` sub-tests) | `client-server/wh_test_auth.c::{whTest_AuthBadArgs, whTest_AuthLogin, whTest_AuthLogout, whTest_AuthAddUser, whTest_AuthDeleteUser, whTest_AuthUserGet, whTest_AuthSetPermissions, whTest_AuthSetCredentials, whTest_AuthRequestAuthorization}` | Client | Under `WOLFHSM_CFG_ENABLE_AUTHENTICATION` the POSIX server installs an auth context + admin user and the client logs in as admin at connect, so the ordinary client tests run authorized; each auth test brackets its own session (logout to start clean, restore admin on exit). Uses the blocking client API; the legacy own-server setup and single-thread manual-pump are dropped. Build with `make AUTH=1`. The NVM persistence, max-users, disconnect, and TCP subtests are not yet migrated |
| `wh_test_she.c` (`whTest_SheMasterEcuKeyFallback`, `whTest_SheReqSizeChecking`) | `server/wh_test_she_server.c::{whTest_SheMasterEcuKeyFallback, whTest_SheReqSizeChecking}` | Server | server-internal checks reworked to use the shared server context; the POSIX server config gains a `whServerSheContext` under `WOLFHSM_CFG_SHE_EXTENSION` |
| `wh_test_she.c::whTest_She` (client flows) | `client-server/wh_test_she.c::whTest_She` | Client | SHE UID/secure-boot state is one-shot per server lifetime, so the three legacy client flows are folded into one test that does `SetUid` plus a single comm-boundary-sized secure boot, then the load-key vectors, UID handling, RND, ECB/CBC/MAC, and write-protect rejection -- all of which only need UID set and secure boot complete. Build with `make SHE=1` |
| `wh_test_server_img_mgr.c::whTest_ServerImgMgr` | `server/wh_test_server_img_mgr.c::whTest_ServerImgMgr` | Server | Per-method subtests (ECC P256, AES-CMAC, RSA2048, wolfBoot RSA4096, wolfBoot RSAPSS4096 under `WC_RSA_PSS`, wolfBoot ECC256, and -- under `WOLFHSM_CFG_CERTIFICATE_MANAGER` -- wolfBoot cert chain for both RSA4096 and RSAPSS4096) run against the shared server context instead of each building its own server/NVM/transport. Each subtest scrubs the NVM objects and key-cache entries it creates so the group's shared NVM stays clean. Legacy ran FLASH and FLASH_LOG backends; the port runs the plain flash backend only -- FLASH_LOG re-run pending (see Known coverage gaps) |
| `wh_test_she.c` (SHE<->keywrap interop + `wh_She_TestWrappedInterop`) | `misc/wh_test_she_keywrap.c::whTest_SheKeywrapInterop` | Misc | needs a server whose NVM carries a `WH_NVM_FLAGS_TRUSTED` KEK, so it runs its own client/server pair with a sequential split-API pump; covers wrap-export by id (incl. the SHE slot-0 gate regression), key-wrap vs data-wrap domain separation, the unwrap-and-export type gate (a SHE-typed blob must not export as plaintext), unwrap-and-cache priming, the counter rollback guard, the LoadKey stale-cache regression, and the two-session reboot interop. Secure boot is driven with raw INIT/UPDATE/FINISH messages (blocking-only client API) |
| `wh_test_she_no_nvm.c::whTest_SheNoNvm` | `misc/wh_test_she_no_nvm.c::whTest_SheNoNvm` | Misc | NULL-NVM server (`whServerConfig.nvm == NULL`), so it runs its own client/server pair with a sequential split-API pump instead of the legacy pthread harness; same end-to-end flow (unwrap-and-cache provisioning incl. SHE slot 0, secure boot, LoadKey cache path, ECB/CBC/CMAC, ExportRamKey, PRNG, KEK immutability) |
| `wh_test_keywrap.c` (sw-KEK round trip, trusted-KEK policy negatives, data-wrap usage) | `client-server/wh_test_keywrap.c::whTest_KeyWrap` | Client | runs against any server: positive KeyWrap/KeyUnwrapAndExport under a plain client KEK, wrap-export/unwrap-and-cache refusal of a non-trusted KEK, the NVM-add / HKDF-cache / key-cache `WH_NVM_FLAGS_TRUSTED` forge negatives, the data-wrap `USAGE_WRAP` negative, and the key/data unwrap underflow bad-args checks. The trusted-KEK positive paths (wrap-export round-trip incl. NONEXPORTABLE enforcement, unwrap-and-cache, and the cache-only check that commit/erase reject an unwrapped key id) run in `misc/wh_test_hwkeystore.c` against the hardware KEK |
| `wh_test_log.c::whTest_Log` (frontend, macros, ring buffer, mock/ringbuf generic harness) | `misc/wh_test_log.c::whTest_Log` | Misc | Portable subset: frontend API, log macros, formatted macros, ring buffer backend, and the backend-agnostic harness against the mock and ring buffer backends. The harness itself lives in `misc/wh_test_log_backend.h` so the POSIX port reuses it |
| `wh_test_log.c` (POSIX file backend, concurrent, client/server) | `posix/wh_test_log_posix.c::{whTest_LogPosixFile_Generic, whTest_LogPosixFile, whTest_LogPosixFileConcurrent, whTest_LogClientServerMemTransport}` | POSIX port-specific (`whTestGroup_RunOne`) | POSIX file backend (via the shared harness and directly), multi-threaded concurrent writers, and a client/server log smoke test over the mem transport. Need pthreads and the host file system, so they run from the port main, not the portable registry |

Not yet migrated (still live in `wolfHSM/test/`):

| Legacy (`wolfHSM/test/`) | Notes |
|---|---|
| `wh_test_comm.c::whTest_Comm` | Pthread mem/tcp/shmem variants only; sequential mem variant has been ported |
| `wh_test_clientserver.c::whTest_ClientServer` | Pthread variant (`whTest_ClientServerClientConfig`): remaining coverage is the client cert flows from `wh_test_cert.c` (next row), the custom-callback round-trip (`_testCallbacks`), the server-side DMA register/copy/allowlist exercise (`_testDma`), and `whTest_NvmFlags`. The sequential test is dropped, as is the FLASH_LOG NVM matrix variant. |
| `wh_test_cert.c::{whTest_CertClient, whTest_CertClientAcert, whTest_CertClientDma_ClientServerTestInternal, whTest_CertClientAcertDma_ClientServerTestInternal}` | Client-side cert verify: invalid single cert, chains A and B, invalid chains, verify and cache the leaf public key, multi-root verify (match, mismatch, absent roots, `numRoots` bounds), attribute certs (`WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT`), and the DMA variant of each (`WOLFHSM_CFG_DMA`). Called from `whTest_ClientServerClientConfig`. Target is `client-server/wh_test_client_certs.c`, which today covers only `wh_Client_CertReadTrusted` with an undersized buffer |
| `wh_test_cert.c::{whTest_CertServerAddTrustedStripsServerFlags, whTest_CertServerVerifyCallback, whTest_CertServerVerifyCallbackRuntime, whTest_CertServerVerifyCache*}` | Remaining server subtests of `whTest_CertRamSim`. The verify-cache subtests need `make CERT_VERIFY_CACHE=1` (`WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE`), which the refactor Makefile does not support yet |
| `wh_test_crypto.c::whTest_Crypto` | Remaining crypto coverage not yet split out: ECC and Curve25519 shared secret into a cached key (`whTest_CryptoEccSharedSecretCacheKey_OneCurve`, `whTest_CryptoCurve25519SharedSecretCacheKey`); the RSA split request/response API (`whTest_CryptoRsaAsync`); and the AES async family (comm-buffer `whTest_CryptoAesAsync`/`AesAsyncKat` + DMA `whTest_CryptoAesDmaAsync`/`AesDmaAsyncKat`, round-trip & KAT). ECC DMA export-public, the ML-DSA wolfCrypt-API path, and ML-KEM (`whTestCrypto_MlKem*`) are now migrated. |
| `wh_test_keywrap.c::whTest_KeyWrapClientConfig` | Policy coverage (sw-KEK round trip, trusted-KEK negatives, data-wrap usage) and the key/data unwrap underflow negatives are ported to `client-server/wh_test_keywrap.c`; the remaining legacy coverage (hardware-KEK cryptocb use of a cached wrapped key, unwrap oversize negatives) is not |
| `wh_test_auth.c::{whTest_AuthMaxUsers, _whTest_Auth_NvmPersistence, _whTest_Auth_NvmSplitObjects, AuthAbruptDisconnect, whTest_AuthTCP}` | Max-user limit, base auth user persistence in NVM (`wh_Auth_BaseLoadFromNvm`, `wh_Auth_BasePersistIndex`), logout on disconnect, and the TCP/client-only variant |
| `wh_test_timeout.c::whTest_TimeoutPosix` | |
| `wh_test_nvmflags.c::whTest_NvmFlags` | Called last from `whTest_ClientServerClientConfig` because it can leave non-destroyable NVM objects |

### Shared helpers pulled from `test/`
- `wh_test_common.c::whTest_NvmCfgBackend` is compiled into the POSIX port build to select an NVM backend (flash or flash-log) over a ramsim flash. Used by `posix/wh_test_nvm_flash.c` and `posix/wh_test_log_posix.c`, and needed to run the server and client groups against the flash-log backend (see Known coverage gaps).

### Known coverage gaps
- FLASH_LOG backend for server/client-group tests. In `test/`, cert (`whTest_CertRamSim`), crypto (`wh_ClientServer_MemThreadTest`), image-manager (`whTest_ServerImgMgr`), and client/server were each run against both the plain flash and flash-log NVM backends. The refactored server/client-group tests consume a single server context (`wh_test_posix_server.c` hard-codes `WH_NVM_FLASH_CB`), so only the plain flash backend is exercised. Restoring parity means selecting the server backend via `whTest_NvmCfgBackend` and running the server + client groups once per backend (flash, then flash-log) from `wh_test_posix_main.c`. Tracked as a follow-up; the port-specific `whTest_NvmFlashLog` already covers the flash-log NVM object lifecycle directly. The coverage comparison shows the lines left uncovered by this gap are in `wh_nvm_flash_log.c` (`wh_NvmFlashLog_List`, `wh_NvmFlashLog_GetAvailable`).
- Tests gated on build flags outside the coverage matrix (`CRYPTO_AFFINITY=1`, `TESTWOLFCRYPT=1`, `NVM_FLASH_CRC=1`, the cert verify cache) report SKIPPED in every coverage config of both trees, so the coverage comparison does not measure them.

### Other improvements
- Add callback from `wh_Server_HandleRequestMessage` to allow sleep and avoid a busy loop
- Add client-only harness to feed invalid server inputs from the test bench with the goal of expanding coverage.
