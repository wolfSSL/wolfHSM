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
| `wh_test_cert.c::whTest_CertRamSim` | `server/wh_test_cert.c::whTest_CertVerify` | Server | remove ramsim coupling and migrate to server group |
| `wh_test_crypto.c::whTest_Crypto` | `client-server/wh_test_crypto.c::{whTest_CryptoSha256, whTest_CryptoAes, whTest_CryptoEcc256}` | Client | Subset only; remaining cases listed below |
| `wh_test_clientserver.c` (echo and server-info paths) | `client-server/wh_test_echo.c::whTest_Echo`, `client-server/wh_test_server_info.c::whTest_ServerInfo` | Client | pthread test ported, sequential test dropped |
| `wh_test_wolfcrypt_test.c::whTest_WolfCryptTest` | `client-server/wh_test_wolfcrypt.c::whTest_WolfCryptTest` | Client | |
| `wh_test_flash_ramsim.c::whTest_Flash_RamSim` | `posix/wh_test_flash_ramsim.c::{whTest_FlashWriteLock, whTest_FlashEraseProgramVerify, whTest_FlashUnitOps}` | POSIX port-specific (`whTestGroup_RunOne`) | remove ramsim coupling and migrate to server group |
| `wh_test_nvm_flash.c::whTest_NvmFlash` | `posix/wh_test_nvm_flash.c::whTest_NvmAddOverwriteDestroy` | POSIX port-specific (`whTestGroup_RunOne`) | remove ramsim coupling and migrate to server group |
| `wh_test_posix_threadsafe_stress.c::whTest_ThreadSafeStress` | called directly from `posix/wh_test_posix_main.c` | POSIX port-specific (direct call) | |
| `wh_test_check_struct_padding.c` | `misc/wh_test_check_struct_padding.c` | Build-time (compile-only) | Wire-format `-Wpadded` audit; the POSIX Makefile compiles it with `-Wpadded -DWH_PADDING_CHECK`. Not a runtime test, so not registered in `wh_test_list.c` |

Not yet migrated (still live in `wolfHSM/test/`):

| Legacy (`wolfHSM/test/`) | Notes |
|---|---|
| `wh_test_comm.c::whTest_Comm` | Pthread mem/tcp/shmem variants only; sequential mem variant has been ported |
| `wh_test_clientserver.c::whTest_ClientServer` | Pthread variant: remaining client-side coverage (NVM ops, etc.) still needs to be split out as new tests. The sequential test is dropped |
| `wh_test_crypto.c::whTest_Crypto` | RNG, key cache, key-cache enforcement, RSA, CMAC, Curve25519, ML-DSA, key usage policies, key revocation |
| `wh_test_crypto_affinity.c::whTest_CryptoAffinity` | |
| `wh_test_keywrap.c::whTest_KeyWrapClientConfig` | |
| `wh_test_multiclient.c::whTest_MultiClient` | |
| `wh_test_lock.c::whTest_LockConfig`, `whTest_LockPosix` | `whTest_LockConfig` to be reworked to fit the Misc group, likely with a context param. |
| `wh_test_log.c::whTest_Log`, `whTest_LogBackend_RunAll` | `whTest_LogBackend_RunAll` to be reworked to fit the Misc group, likely with a context param. |
| `wh_test_she.c::whTest_She` | |
| `wh_test_timeout.c::whTest_TimeoutPosix` | |
| `wh_test_auth.c::whTest_AuthMEM`, `whTest_AuthTCP` | |
| `wh_test_server_img_mgr.c::whTest_ServerImgMgr` | |
| `wh_test_nvmflags.c::whTest_NvmFlags` | |
| `wh_test_flash_fault_inject.c` | |

### Other improvements
- Add callback from `wh_Server_HandleRequestMessage` to allow sleep and avoid a busy loop
- Add client-only harness to feed invalid server inputs from the test bench with the goal of expanding coverage.
