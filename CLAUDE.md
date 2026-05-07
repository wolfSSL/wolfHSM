# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

wolfHSM is a portable client-server framework for hardware cryptography, non-volatile memory (NVM), and isolated secure processing. The server runs in a trusted environment; clients communicate via a message-based protocol. wolfCrypt APIs are automatically offloaded to the server as remote procedure calls. Targeted at automotive HSM-enabled microcontrollers but runs on any platform with a secure execution environment.

## Build Commands

All builds use Make. wolfSSL must be available at `../../wolfssl` relative to this repo (override with `WOLFSSL_DIR=`).

```bash
# Build and run tests (from repo root or test/)
cd test && make -j && make run

# Common build flags (combine as needed)
make DEBUG=1              # Basic debug output
make DEBUG_VERBOSE=1      # Verbose debug (implies DEBUG)
make ASAN=1               # Address Sanitizer
make TSAN=1               # Thread Sanitizer (requires THREADSAFE=1)
make THREADSAFE=1         # Thread-safe mode with locking
make DMA=1                # DMA support
make SHE=1                # AUTOSAR SHE extensions
make TLS=1                # TLS transport
make COVERAGE=1           # Code coverage instrumentation
make TESTWOLFCRYPT=1      # Run wolfCrypt test suite as client
make CLIENT_ONLY=1        # Client-only (connects to remote server)
make STRESS=1             # Stress testing (requires THREADSAFE=1)

# Coverage report
cd test && make coverage  # Builds, runs, generates ../coverage/index.html

# Static analysis
make scan                 # scan-build (excludes wolfSSL/wolfCrypt)

# Benchmarks
cd benchmark && make -j && make run

# Examples
cd examples/posix/wh_posix_server && make
cd examples/posix/wh_posix_client && make

# NVM tool
cd tools/whnvmtool && make && make test
```

## Code Formatting

Uses clang-format-15 (CI enforced). 4-space indent, 80-column limit, braces on new line after functions only, `else` on new line. Pointer alignment left (`int* p`). Run: `clang-format-15 -i <file>`.

## Architecture

### Client-Server Model

- **Client** (`src/wh_client*.c`, `wolfhsm/wh_client*.h`): Sends requests to the server. Registers wolfCrypt crypto callbacks so wolfCrypt calls are transparently offloaded. Device IDs: `WH_DEV_ID` (0x5748534D) for standard ops, `WH_DEV_ID_DMA` (0x57444D41) for DMA ops.
- **Server** (`src/wh_server*.c`, `wolfhsm/wh_server*.h`): Dispatches incoming requests to handlers for crypto, NVM, keystore, SHE, certificates, image management, counters, and custom callbacks.
- **Communication** (`src/wh_comm.c`, `wolfhsm/wh_comm.h`): 8-byte header + variable payload (default 1280 bytes, configurable via `WOLFHSM_CFG_COMM_DATA_LEN`). Message groups: COMM, NVM, KEY, CRYPTO, IMAGE, PKCS11, SHE, COUNTER, CUSTOM, CRYPTO_DMA, CERT.

### Transport Layer

Pluggable transport backends behind a common interface:
- `wh_transport_mem` — shared memory buffer (used in tests)
- POSIX port: shared memory (pthread), TCP sockets, TLS over TCP

### Non-Volatile Memory (NVM)

Log-based flash storage with crash recovery (`wh_nvm_flash_log.c`). Objects have metadata (ID, access, flags, label). RAM flash simulator (`wh_flash_ramsim.c`) used for testing.

### Key Management

RAM key cache + persistent NVM storage. Keys have access control (per-client), usage policies (encrypt/decrypt/sign/verify/wrap/derive), and flags (non-exportable, sensitive, non-modifiable, etc.).

### Platform Ports

`port/` contains platform-specific implementations. `port/posix/` is the reference port (flash sim, transport, locks, logging). `port/skeleton/` is a template for new ports.

## Configuration

Three-layer configuration (lowest to highest priority):

1. **`wolfhsm/wh_settings.h`** — defaults for all `WOLFHSM_CFG_*` macros
2. **`wolfhsm_cfg.h`** — per-project overrides (included when `WOLFHSM_CFG` is defined). Test version at `test/config/wolfhsm_cfg.h`
3. **Compiler `-D` flags** — set via Makefile variables

wolfCrypt is configured separately via `user_settings.h` (test version at `test/config/user_settings.h`).

## Testing

Tests are in `test/`. Each module has its own `wh_test_<module>.c` file with a corresponding header. The main driver is `wh_test.c`. Tests must be portable (no system dependencies) except POSIX-specific tests gated by `WOLFHSM_CFG_TEST_POSIX`.

## Error Codes

Defined in `wolfhsm/wh_error.h`:
- General: -2000 to -2010 (BADARGS, NOTREADY, ABORTED, TIMEOUT, etc.)
- NVM: -2100 to -2105 (LOCKED, ACCESS, NOTFOUND, NOSPACE, etc.)
- SHE: -2200 to -2211

All wolfHSM functions return `int` where 0 is success (`WH_ERROR_OK`) and negative values are errors.
