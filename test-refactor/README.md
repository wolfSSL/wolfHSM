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
The legacy unit suite in `wolfHSM/test/` is being incrementally translated to `wolfHSM/test-refactor/` while preserving the original during the transition. Code coverage Github workflows will be used for confirmation.

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
| `wh_test_cert.c::whTest_CertRamSim` | `server/wh_test_cert.c::whTest_CertVerify` | Server | remove ramsim coupling and migrate to server group. Legacy ran FLASH and FLASH_LOG backends; the port runs the plain flash backend only -- FLASH_LOG re-run pending (see Known coverage gaps) |
| `wh_test_crypto.c::whTest_Crypto` | `client-server/wh_test_crypto_{aes,cmac,curve25519,ecc,ed25519,kdf,keypolicy,mldsa,rng,rsa,sha}.c::whTest_Crypto_*` | Client | Split into per-algorithm suites; key revocation is gated by `WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS`. Legacy ran FLASH and FLASH_LOG backends; the port runs the plain flash backend only -- FLASH_LOG re-run pending (see Known coverage gaps) |
| `wh_test_crypto.c::whTest_CryptoKeyUsagePolicies` (AES CTR/ECB/GCM subset) | `client-server/wh_test_crypto_aes.c::whTest_CryptoAesKeyUsagePolicies` | Client | AES-CTR/ECB/GCM key usage enforcement (non-DMA and DMA variants) |
| `wh_test_crypto.c::whTestCrypto_LmsCryptoCb` | `client-server/wh_test_crypto_lms.c::whTest_Crypto_Lms` | Client | DMA-only LMS generate/durability/sign/verify, public-key export+import, and private export/import rejection. Gated by `WOLFHSM_CFG_DMA && WOLFSSL_HAVE_LMS && !WOLFSSL_LMS_VERIFY_ONLY`; reports SKIPPED otherwise |
| `wh_test_crypto.c::whTestCrypto_XmssCryptoCb` | `client-server/wh_test_crypto_xmss.c::whTest_Crypto_Xmss` | Client | DMA-only XMSS generate/durability/sign/verify, public-key export+import, and private export/import rejection. Gated by `WOLFHSM_CFG_DMA && WOLFSSL_HAVE_XMSS && !WOLFSSL_XMSS_VERIFY_ONLY`; reports SKIPPED otherwise |
| `wh_test_clientserver.c` (echo and server-info paths) | `client-server/wh_test_echo.c::whTest_Echo`, `client-server/wh_test_server_info.c::whTest_ServerInfo` | Client | pthread test ported, sequential test dropped |
| `wh_test_clientserver.c` (NVM CRUD + OOB read clamping paths) | `client-server/wh_test_nvm_ops.c::{whTest_NvmCrud, whTest_NvmReadOob}` | Client | each test cleans up its own slots; OOB test covers UINT16_MAX overflow regression |
| `wh_test_clientserver.c` (NVM DMA CRUD path) | `client-server/wh_test_nvm_dma.c::whTest_NvmCrudDma` | Client | gated on `WOLFHSM_CFG_DMA` |
| `wh_test_clientserver.c::_testClientCounter` | `client-server/wh_test_counter.c::whTest_Counter` | Client | exercises saturate-on-overflow and slot-leak detection |
| `wh_test_wolfcrypt_test.c::whTest_WolfCryptTest` | `client-server/wh_test_wolfcrypt.c::whTest_WolfCryptTest` | Client | |
| `wh_test_flash_ramsim.c::whTest_Flash_RamSim` | `posix/wh_test_flash_ramsim.c::{whTest_FlashWriteLock, whTest_FlashEraseProgramVerify, whTest_FlashUnitOps}` | POSIX port-specific (`whTestGroup_RunOne`) | remove ramsim coupling and migrate to server group |
| `wh_test_nvm_flash.c::{whTest_NvmFlash, whTest_NvmFlash_Recovery}` | `posix/wh_test_nvm_flash.c::{whTest_NvmAddOverwriteDestroy, whTest_NvmFlashLog, whTest_NvmRecovery}` | POSIX port-specific (`whTestGroup_RunOne`) | remove ramsim coupling and migrate to server group; flash-log backend exercised by `whTest_NvmFlashLog` (skipped unless `WOLFHSM_CFG_SERVER_NVM_FLASH_LOG`) |
| `wh_test_flash_fault_inject.c` | `posix/wh_test_flash_fault_inject.c` | helper (no test) | fault-injection flash wrapper used by the recovery test |
| `wh_test_posix_threadsafe_stress.c::whTest_ThreadSafeStress` | called directly from `posix/wh_test_posix_main.c` | POSIX port-specific (direct call) | |
| `wh_test_check_struct_padding.c` | `misc/wh_test_check_struct_padding.c` | Build-time (compile-only) | Wire-format `-Wpadded` audit; the POSIX Makefile compiles it with `-Wpadded -DWH_PADDING_CHECK`. Not a runtime test, so not registered in `wh_test_list.c` |
| `wh_test_auth.c` (`whTest_AuthMEM` / `whTest_AuthTest` sub-tests) | `client-server/wh_test_auth.c::{whTest_AuthBadArgs, whTest_AuthLogin, whTest_AuthLogout, whTest_AuthAddUser, whTest_AuthDeleteUser, whTest_AuthSetPermissions, whTest_AuthSetCredentials, whTest_AuthRequestAuthorization}` | Client | Under `WOLFHSM_CFG_ENABLE_AUTHENTICATION` the POSIX server installs an auth context + admin user and the client logs in as admin at connect, so the ordinary client tests run authorized; each auth test brackets its own session (logout to start clean, restore admin on exit). Uses the blocking client API; the legacy own-server setup and single-thread manual-pump are dropped. Build with `make AUTH=1`. The TCP/client-only variant (`whTest_AuthTCP`) is not ported |
| `wh_test_she.c` (`whTest_SheMasterEcuKeyFallback`, `whTest_SheReqSizeChecking`) | `server/wh_test_she_server.c::{whTest_SheMasterEcuKeyFallback, whTest_SheReqSizeChecking}` | Server | server-internal checks reworked to use the shared server context; the POSIX server config gains a `whServerSheContext` under `WOLFHSM_CFG_SHE_EXTENSION` |
| `wh_test_she.c::whTest_She` (client flows) | `client-server/wh_test_she.c::whTest_She` | Client | SHE UID/secure-boot state is one-shot per server lifetime, so the three legacy client flows are folded into one test that does `SetUid` plus a single comm-boundary-sized secure boot, then the load-key vectors, UID handling, RND, ECB/CBC/MAC, and write-protect rejection -- all of which only need UID set and secure boot complete. Build with `make SHE=1` |
| `wh_test_server_img_mgr.c::whTest_ServerImgMgr` | `server/wh_test_server_img_mgr.c::whTest_ServerImgMgr` | Server | Per-method subtests (ECC P256, AES-CMAC, RSA2048, wolfBoot RSA4096, and -- under `WOLFHSM_CFG_CERTIFICATE_MANAGER` -- wolfBoot cert chain) run against the shared server context instead of each building its own server/NVM/transport. Each subtest scrubs the NVM objects and key-cache entries it creates so the group's shared NVM stays clean. Legacy ran FLASH and FLASH_LOG backends; the port runs the plain flash backend only -- FLASH_LOG re-run pending (see Known coverage gaps) |

Not yet migrated (still live in `wolfHSM/test/`):

| Legacy (`wolfHSM/test/`) | Notes |
|---|---|
| `wh_test_comm.c::whTest_Comm` | Pthread mem/tcp/shmem variants only; sequential mem variant has been ported |
| `wh_test_clientserver.c::whTest_ClientServer` | Pthread variant: remaining coverage is the custom-callback round-trip (`_testCallbacks`) and the server-side DMA register/copy/allowlist exercise (`_testDma`). The sequential test is dropped, as is the FLASH_LOG NVM matrix variant. |
| `wh_test_crypto.c::whTest_Crypto` | Remaining crypto coverage not yet split out: the AES async family (comm-buffer `whTest_CryptoAesAsync`/`AesAsyncKat` + DMA `whTest_CryptoAesDmaAsync`/`AesDmaAsyncKat`, round-trip & KAT). ECC DMA export-public and the ML-DSA wolfCrypt-API path are now migrated. |
| `wh_test_crypto.c::whTest_KeyCache`, `whTest_NonExportableKeystore` | Keystore tests (key-cache lifecycle and non-exportable-flag enforcement) dispatched from the legacy `whTest_Crypto`. The per-algorithm suites use `wh_Client_KeyCache`, but these dedicated keystore tests are not yet split out. |
| `wh_test_crypto_affinity.c::whTest_CryptoAffinity` | |
| `wh_test_keywrap.c::whTest_KeyWrapClientConfig` | |
| `wh_test_lock.c::whTest_LockConfig`, `whTest_LockPosix` | `whTest_LockConfig` to be reworked to fit the Misc group, likely with a context param. |
| `wh_test_log.c::whTest_Log`, `whTest_LogBackend_RunAll` | `whTest_LogBackend_RunAll` to be reworked to fit the Misc group, likely with a context param. |
| `wh_test_timeout.c::whTest_TimeoutPosix` | |
| `wh_test_nvmflags.c::whTest_NvmFlags` | |
| `wh_test_flash_fault_inject.c` | |
| `wh_test_check_struct_padding.c` | |

### Shared helpers pulled from `test/`
- `wh_test_common.c::whTest_NvmCfgBackend` is compiled into the POSIX port build to select an NVM backend (flash or flash-log) over a ramsim flash. Used by `whTest_NvmFlashLog` today; the not-yet-migrated cert, image-manager, auth, and log tests rely on it too, so it is wired in ahead of those migrations.

### Known coverage gaps
- FLASH_LOG backend for server/client-group tests. In `test/`, cert (`whTest_CertRamSim`), crypto (`wh_ClientServer_MemThreadTest`), image-manager (`whTest_ServerImgMgr`), and client/server were each run against both the plain flash and flash-log NVM backends. The refactored server/client-group tests consume a single server context (`wh_test_posix_server.c` hard-codes `WH_NVM_FLASH_CB`), so only the plain flash backend is exercised. Restoring parity means selecting the server backend via `whTest_NvmCfgBackend` and running the server + client groups once per backend (flash, then flash-log) from `wh_test_posix_main.c`. Tracked as a follow-up; the port-specific `whTest_NvmFlashLog` already covers the flash-log NVM object lifecycle directly.

### Other improvements
- Add callback from `wh_Server_HandleRequestMessage` to allow sleep and avoid a busy loop
- Add client-only harness to feed invalid server inputs from the test bench with the goal of expanding coverage.
