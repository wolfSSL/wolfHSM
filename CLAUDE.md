# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is wolfHSM

wolfHSM is a portable, open-source client-server framework for hardware security modules (HSMs). It provides a unified abstraction layer for cryptographic operations, non-volatile memory (NVM), and isolated secure processing across different hardware platforms. The client library integrates with wolfCrypt so that crypto operations are transparently offloaded to the server running in a trusted execution environment via RPC.

## Tech Stack

- Language: C (C99; C90-compatible for embedded targets)
- Crypto library: wolfCrypt (wolfSSL) — required unless `WOLFHSM_CFG_NO_CRYPTO` is set
- No database; persistent storage is abstracted through the NVM layer

## Build Commands

All commands are run from the repository root unless noted.

```bash
make              # Build everything (test, benchmark, tools, examples)
make test         # Build test suite
make benchmark    # Build benchmarks
make tools        # Build nvmtool and testcertgen
make examples     # Build POSIX server/client examples
make clean        # Clean all build artifacts
make scan         # Run scan-build static analysis
```

**Running the test suite:**
```bash
cd test
make run          # Build and run all tests
make coverage     # Build with gcov, run, generate HTML report at ../coverage/index.html
```

**Useful test build options (passed to `make` in `test/`):**
| Flag | Effect |
|------|--------|
| `DEBUG=1` | Debug symbols + debug output |
| `DEBUG_VERBOSE=1` | Verbose debug logging |
| `ASAN=1` | AddressSanitizer |
| `TSAN=1` | ThreadSanitizer (see `test/tsan.supp`) |
| `COVERAGE=1` | gcov instrumentation |
| `THREADSAFE=1` | Enable thread-safe server access |
| `SHE=1` | AUTOSAR SHE extension |
| `DMA=1` | DMA support |
| `TLS=1` | TLS transport |
| `NOCRYPTO=1` | Build without wolfCrypt |
| `TESTWOLFCRYPT=1` | Include wolfCrypt test suite as a client |

There is no built-in mechanism to run a single test module from the command line. Tests are compiled together into `Build/wh_test.elf`; to run a subset, include only the desired `wh_test_<module>.c` files in a custom driver.

## Architecture

### Client-Server Model

```
[Client process]                        [Server / TEE]
  wolfCrypt API
       │  (device callback, WH_DEV_ID)
  wh_client.c  ──── wh_comm (transport) ────  wh_server.c
                                                   │
                                              wh_server_crypto.c
                                              wh_nvm.c
                                              wh_server_she.c
```

The client registers a wolfCrypt device callback using `WH_DEV_ID = 0x5748534D`. All crypto operations directed to that device ID are serialized as RPC messages and sent to the server.

### Core Layers

| Layer | Files | Purpose |
|-------|-------|---------|
| Client API | `wolfhsm/wh_client.h`, `src/wh_client.c` | Client context, connection, key/NVM APIs |
| Server Core | `wolfhsm/wh_server.h`, `src/wh_server.c` | Request dispatch, key cache, NVM management |
| Crypto Client | `wolfhsm/wh_client_crypto.h`, `src/wh_client_crypto.c` | wolfCrypt callback handlers (client side) |
| Crypto Server | `src/wh_server_crypto.c` | Crypto operation execution (server side) |
| Communication | `wolfhsm/wh_comm.h`, `src/wh_comm.c` | Transport-agnostic packet layer; 8-byte header + payload |
| Message Protocol | `wolfhsm/wh_message*.h`, `src/wh_message*.c` | Encode/decode for each message group |
| NVM | `wolfhsm/wh_nvm.h`, `src/wh_nvm*.c` | Persistent object store; flash log-structured writes |
| SHE Extension | `wolfhsm/wh_she*.h`, `src/wh_server_she.c` | AUTOSAR Secure Hardware Extension protocol |

### Message Protocol

Messages use a 16-bit kind field: upper byte = group, lower byte = action. Groups: `COMM`, `NVM`, `KEY`, `CRYPTO`, `IMAGE`, `PKCS11`, `SHE`, `COUNTER`, `CUSTOM`, `CRYPTO_DMA`, `CERT`.

### Key Caching

The server maintains a RAM key cache (`wh_server_keycache`). Keys can be loaded, exported, committed to NVM, or evicted. Cache sizes are controlled by `WOLFHSM_CFG_SERVER_KEYCACHE_COUNT`, `WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE`, and the `_BIG*` variants for large keys.

### NVM Storage

`wh_nvm.h` defines the abstract NVM API. Concrete implementations:
- `wh_nvm_flash.c` — log-structured flash storage
- `wh_flash_ramsim.c` — RAM-based flash simulator (testing)
- `port/posix/wh_flash_posixsim.c` — POSIX file-based flash simulator

### Transports (in `port/posix/`)

- `wh_transport_mem.c` — shared-memory (in-process, testing)
- `wh_transport_tcp.c` — TCP sockets
- `wh_transport_shm.c` — POSIX shared memory (inter-process)

New ports implement the transport callbacks in `wolfhsm/wh_comm.h`; see `port/skeleton/` for a template.

## Configuration

All compile-time options are documented in `wolfhsm/wh_settings.h`. Key ones:

- `WOLFHSM_CFG_COMM_DATA_LEN` — max payload per message (default: 1280 bytes)
- `WOLFHSM_CFG_NO_CRYPTO` — exclude wolfCrypt dependency
- `WOLFHSM_CFG_SHE_EXTENSION` — enable AUTOSAR SHE
- `WOLFHSM_CFG_DMA` — enable DMA address validation
- `WOLFHSM_CFG_THREADSAFE` — server-side lock callbacks
- `WOLFHSM_CFG_CERTIFICATE_MANAGER` — certificate chain verification

## Test Structure

- `test/wh_test.c` — main test driver; calls each module's test function
- `test/wh_test_<module>.c` + `test/wh_test_<module>.h` — per-module tests
- `test/config/` — test-specific configuration headers

Tests must be platform-agnostic. POSIX-dependent tests are guarded by `WOLFHSM_CFG_TEST_POSIX`. Tests must use independent oracles (known test vectors, cross-validation) — never use the code under test as its own oracle.

## Conventions

- All public symbols are prefixed `wh_` (functions/types) or `WH_` (macros/constants)
- Configuration macros use the `WOLFHSM_CFG_` prefix; defaults are defined in `wolfhsm/wh_settings.h`
- Header guards follow `WOLFHSM_<MODULE>_H`
- Public headers live in `wolfhsm/`; implementations in `src/`; per-module test pairs in `test/wh_test_<module>.{c,h}`

## External Services

- **wolfCrypt** (wolfSSL): the sole external dependency for cryptographic operations. Must be present on the include/link path unless building with `WOLFHSM_CFG_NO_CRYPTO`.


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
