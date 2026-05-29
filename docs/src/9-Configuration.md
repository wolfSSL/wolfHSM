# Configuration

wolfHSM is configured entirely at build time through a set of `WOLFHSM_CFG_XXX` preprocessor macros. This chapter is an exhaustive reference for every supported configuration macro: what it does, what its default is, and which subsystem it affects. For an overview of *how* the configuration system is wired together, see [Library Configuration](4-Architecture.md#library-configuration); this chapter focuses on the macros themselves.

## Table of Contents

- [How to Override Configuration Values](#how-to-override-configuration-values)
- [Core Library and Roles](#core-library-and-roles)
- [Communication and Protocol Sizing](#communication-and-protocol-sizing)
- [Time and System Services](#time-and-system-services)
- [Cryptography Features](#cryptography-features)
- [Keystore and Key Cache](#keystore-and-key-cache)
- [NVM Storage](#nvm-storage)
- [Certificate Manager](#certificate-manager)
- [Image Manager](#image-manager)
- [Custom Server Callbacks](#custom-server-callbacks)
- [DMA Support](#dma-support)
- [Authentication](#authentication)
- [Concurrency and Thread Safety](#concurrency-and-thread-safety)
- [Transports](#transports)
- [Logging Subsystem](#logging-subsystem)
- [Debug and Print Configuration](#debug-and-print-configuration)
- [Benchmark Suite](#benchmark-suite)
- [Test Harness](#test-harness)
- [Memory and Cache Porting Macros](#memory-and-cache-porting-macros)

## How to Override Configuration Values

There are two supported ways to override a `WOLFHSM_CFG_XXX` value:

1. **Compiler command line**. Pass `-DWOLFHSM_CFG_XXX=value` (or `-DWOLFHSM_CFG_XXX` for boolean-style flags) when invoking the compiler. This is the simplest approach when only one or two values need to change, and is what the wolfHSM `test/` and `benchmark/` Makefiles use to map their `make` variables (`DMA=1`, `SHE=1`, `THREADSAFE=1`, etc.) onto the corresponding macros.

2. **User configuration header (`wolfhsm_cfg.h`)**. Create a header named `wolfhsm_cfg.h` containing `#define WOLFHSM_CFG_XXX value` statements, place it on the compiler's include search path, and define the top-level `WOLFHSM_CFG` macro when invoking the compiler (`-DWOLFHSM_CFG`). When `WOLFHSM_CFG` is defined, the central `wolfhsm/wh_settings.h` header includes `wolfhsm_cfg.h` first, so user-supplied values override the internal defaults. This is the recommended approach when more than a handful of options are being customized. The reference examples under `examples/posix/` and `test/config/` follow this pattern.

Every wolfHSM source file includes `wolfhsm/wh_settings.h` first. The header walks each `WOLFHSM_CFG_XXX` macro, supplies a default if the user has not defined one, and performs a small amount of cross-checking (for example, refusing to build `WOLFHSM_CFG_KEYWRAP` together with `WOLFHSM_CFG_NO_CRYPTO`). Every option listed in this chapter has a sensible default; the only macro that the user **must** supply is either `WOLFHSM_CFG_PORT_GETTIME` or `WOLFHSM_CFG_NO_SYS_TIME` (see [Time and System Services](#time-and-system-services)).

## Core Library and Roles

These macros select which halves of the wolfHSM library are compiled in, and gate features that are shared by both the client and server.

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_ENABLE_CLIENT` | Undefined | If defined, compile client-side functionality (`wh_Client_*` APIs, crypto callback, message marshalling for client requests). Define this in client-only builds and in combined client/server builds. |
| `WOLFHSM_CFG_ENABLE_SERVER` | Undefined | If defined, compile server-side functionality (`wh_Server_*` APIs, request dispatcher, server-side keystore, NVM, crypto, etc.). Define this in server-only and combined builds. |
| `WOLFHSM_CFG_ENABLE_TIMEOUT` | Undefined | If defined, compile the client-side support for blocking request timeouts (`wh_Client_SetRecvTimeout` and the timeout-aware variants of the blocking client APIs). Requires a working `WH_GETTIME_US()`. |
| `WOLFHSM_CFG_NO_CRYPTO` | Undefined | If defined, build wolfHSM without any wolfCrypt dependency. All crypto-related code, message types, and key-cache crypto paths are excluded; the resulting build is useful for porting and for purely transport/NVM-focused integrations. Incompatible with `WOLFHSM_CFG_KEYWRAP`. |
| `WOLFHSM_CFG_INFOVERSION` | `"01.01.01"` | String reported by the server in response to the version-info request. Override to embed a build- or vendor-specific version stamp. |
| `WOLFHSM_CFG_INFOBUILD` | `"12345678"` | String (typically a short git/build hash) reported by the server in response to the build-info request. |

## Communication and Protocol Sizing

These macros control the over-the-wire sizing of the request/response protocol shared between the client and server. The same value must be used on both ends of any given client/server pair.

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_COMM_DATA_LEN` | `1280` | Maximum length, in bytes, of the data payload portion of a single request or response message. This sets the upper bound on how much data a single non-DMA request (key cache, certificate verify, large block crypto, etc.) can carry; messages larger than this must be split or use a DMA variant. Larger values raise per-context RAM usage and the size of any transport-side buffers. |
| `WOLFHSM_CFG_CUSTOMCB_LEN` | `256` | Maximum size, in bytes, of a single custom-callback message payload (see [Custom Server Callbacks](#custom-server-callbacks)). Independent of `WOLFHSM_CFG_COMM_DATA_LEN`. |

## Time and System Services

wolfHSM relies on a microsecond-resolution system time for benchmark measurements, log timestamps, and (when enabled) request timeouts. Exactly one of the two macros below **must** be supplied by the port.

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_PORT_GETTIME` | None — port must supply | Function-like macro that returns the current system time as a `uint64_t` count of microseconds. wolfHSM wraps it as `WH_GETTIME_US()` and uses it for timestamps and elapsed-time accounting. The POSIX port supplies `posixGetTime`; new ports must provide an equivalent. |
| `WOLFHSM_CFG_NO_SYS_TIME` | Undefined | If defined, all internal calls to obtain the system time return zero, removing the need for the port to supply `WOLFHSM_CFG_PORT_GETTIME`. Disables meaningful benchmark output and log timestamps; intended for very early porting work. |

## Cryptography Features

These macros enable or tune optional cryptographic subsystems built on top of wolfCrypt. All of them are silently ignored when `WOLFHSM_CFG_NO_CRYPTO` is defined.

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_SHE_EXTENSION` | Undefined | If defined, compile the AUTOSAR SHE subsystem (SHE message types, SHE key slots, M1-M5 update protocol, SHE-specific RNG and SREG handling). Requires wolfCrypt built with AES, `WOLFSSL_CMAC`, `WOLFSSL_AES_DIRECT`, and `HAVE_AES_ECB`. |
| `WOLFHSM_CFG_KEYWRAP` | Undefined | If defined, compile the key-wrap subsystem (`wh_Client_KeyWrap*` / server counterparts). Uses AES-GCM internally and therefore requires wolfCrypt built with AES and `HAVE_AESGCM`. Incompatible with `WOLFHSM_CFG_NO_CRYPTO`. |
| `WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE` | `2000` | Maximum size, in bytes, of a key that can be wrapped or unwrapped in a single operation. Only consulted when `WOLFHSM_CFG_KEYWRAP` is defined. |
| `WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE` | `2000` | Maximum size, in bytes, of the plaintext or wrapped payload carried by a single key-wrap request. Only consulted when `WOLFHSM_CFG_KEYWRAP` is defined. |
| `WOLFHSM_CFG_GLOBAL_KEYS` | Undefined | If defined, enable the global-keys feature, allowing keys to be cached so that they are visible to every client rather than scoped to the caching client. See [Global Keys](5-Features.md#global-keys) for a full discussion of the API and security implications. |

## Keystore and Key Cache

These macros size the server-side key cache. The cache is split into "regular" slots (sized for common symmetric and EC keys) and "big" slots (sized for RSA-class keys); both are statically allocated.

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_SERVER_KEYCACHE_COUNT` | `8` | Number of regular RAM key-cache slots on the server. |
| `WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE` | `256` | Size, in bytes, of each regular key-cache slot. |
| `WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT` | `1` | Number of "big" RAM key-cache slots on the server, used for large keys (e.g. RSA, ML-DSA). |
| `WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE` | `1200` | Size, in bytes, of each big key-cache slot. Should be at least the largest key the server is expected to hold (e.g. ~1024 bytes for an RSA-4096 private key). |

## NVM Storage

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_NVM_OBJECT_COUNT` | `32` | Maximum number of objects the NVM directory can hold simultaneously (RAM directory cache *and* the on-disk directory it mirrors). Determines the upper bound on the number of keys, certificates, counters, and user objects that can coexist in NVM at one time. |
| `WOLFHSM_CFG_SERVER_NVM_FLASH_LOG` | Undefined | If defined, compile the log-structured NVM flash backend (`wh_nvm_flash_log`). When enabled it can be selected at runtime as an alternative to the regular flash backend; useful for flash parts that tolerate fewer erases or that prefer append-only update patterns. |

## Certificate Manager

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_CERTIFICATE_MANAGER` | Undefined | If defined, compile the server-side certificate manager (trusted-root storage, chain verification, optional leaf-public-key caching). Required by `WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT`. |
| `WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT` | Undefined | If defined, also compile attribute-certificate (RFC 5755) support into the certificate manager. Requires wolfSSL built with `WOLFSSL_ACERT` and `WOLFSSL_ASN_TEMPLATE`. |
| `WOLFHSM_CFG_MAX_CERT_SIZE` | `WOLFHSM_CFG_COMM_DATA_LEN`, or `4096` when `WOLFHSM_CFG_DMA` is defined | Maximum size, in bytes, of a certificate that the manager will accept. The DMA default is larger because certificate verification requests no longer have to fit inside a single comm-buffer-sized message. |
| `WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS` | `8` | Maximum number of trusted-root NVM IDs accepted in a single `wh_Server_CertVerifyMultiRoot` request. Bounded so that the non-DMA wire request still fits within `WOLFHSM_CFG_COMM_DATA_LEN` alongside the candidate chain, and so the inline DMA request struct remains a fixed-size POD. |

## Image Manager

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_SERVER_IMG_MGR` | Undefined | If defined, compile the server-side image manager (manifest-driven boot/runtime image verification). |
| `WOLFHSM_CFG_SERVER_IMG_MGR_MAX_IMG_COUNT` | `4` | Maximum number of images that a single image-manager configuration can track at one time. |
| `WOLFHSM_CFG_SERVER_IMG_MGR_MAX_SIG_SIZE` | `512` | Maximum signature size, in bytes, that the image manager will allocate buffer space for. The default accommodates RSA-4096; raise it when using signature schemes with larger signatures. |

## Custom Server Callbacks

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT` | `8` | Number of custom-callback dispatch slots reserved on the server. Each registered callback occupies one slot; sets the upper bound on the number of distinct custom callback IDs an application can register. |

## DMA Support

These macros gate and tune DMA-mode crypto and large-buffer operations.

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_DMA` | Undefined | If defined, compile the DMA-capable code paths: the `WH_DEV_ID_DMA` crypto device, DMA message types, pre/post access callbacks, and the address allowlist machinery. Without this macro, DMA APIs are stubbed out. |
| `WOLFHSM_CFG_DMAADDR_COUNT` | `10` | Number of entries in the DMA address allowlist used by the server to validate client-supplied DMA buffers. |
| `WOLFHSM_CFG_DMA_PTR_SIZE` | Compiler-detected (`__SIZEOF_POINTER__`) | Override the assumed DMA pointer size, in bytes (must be `4` or `8`). Auto-detection works for GCC/Clang and IAR; define this explicitly for any toolchain that does not provide `__SIZEOF_POINTER__`. |
| `WOLFHSM_CFG_DMA_ALT_PTR_SIZE` | Undefined | If defined, allows the DMA pointer size to differ from the native CPU pointer size (e.g. a 32-bit-pointer server reachable from a 64-bit-pointer client). When undefined, wh_settings.h refuses to build with a mismatched `WOLFHSM_CFG_DMA_PTR_SIZE`. |
| `WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY` | Undefined | If defined, expose hooks that let the integrator override the client-to-server and server-to-client memory copy used during DMA requests. Useful when DMA buffers live in shared memory that requires custom invalidation or cache maintenance beyond the standard `XCACHE*` macros. |

## Authentication

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_ENABLE_AUTHENTICATION` | Undefined | If defined, compile the authentication manager on both client and server: session establishment, the authorization gate, per-client permissions, and the pluggable auth backend (`wh_Auth_*`). All authenticated message types and the in-request session header are conditional on this macro. |

## Concurrency and Thread Safety

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_THREADSAFE` | Undefined | If defined, compile the lock abstraction (`wh_Lock_*`) into shared server resources: the global key cache, NVM operations, the authentication manager, and any port-supplied shared crypto hardware. Requires the port to supply lock callbacks via `whLockConfig`. When undefined, all lock operations expand to no-ops with zero runtime overhead. See [Concurrency Support](5-Features.md#concurrency-support). |

## Transports

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_TLS` | Undefined | If defined, compile the POSIX TLS transport (`posix_transport_tls`). Used by the POSIX example applications to wrap their client/server connection in wolfSSL TLS or PSK. Requires a wolfSSL build that includes the relevant TLS features (`!NO_PSK` for PSK mode, etc.). |

## Logging Subsystem

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_LOGGING` | Undefined | If defined, compile the server-side logging subsystem (`wh_log_*`): structured log records, the ring-buffer backend, and the optional printf-style sink. Without this macro, the logging APIs are stubbed out. |
| `WOLFHSM_CFG_LOG_MSG_MAX` | `256` | Maximum size, in bytes, of a single log-message buffer, including the null terminator. Formatted log messages longer than this are truncated. |

## Debug and Print Configuration

These macros control the diagnostic output that wolfHSM emits at runtime. They are independent of `WOLFHSM_CFG_LOGGING`, which is a structured-event channel.

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_DEBUG` | Undefined | If defined, enable the base debug print macros (`WH_DEBUG_PRINT`, `WH_DEBUG_CLIENT`, `WH_DEBUG_SERVER`). Without it, every debug print expands to `do {} while (0)`. |
| `WOLFHSM_CFG_DEBUG_VERBOSE` | Undefined | If defined, additionally enable the verbose debug macros (`WH_DEBUG_CLIENT_VERBOSE`, `WH_DEBUG_SERVER_VERBOSE`) which include function name and line number, plus the verbose hexdump helper. Implies the prerequisites of `WOLFHSM_CFG_DEBUG`. |
| `WOLFHSM_CFG_HEXDUMP` | Auto-enabled when either debug macro is set | If defined, compile `wh_Utils_Hexdump`. Pulled in implicitly by either `WOLFHSM_CFG_DEBUG` or `WOLFHSM_CFG_DEBUG_VERBOSE` (and by the verbose hexdump helper), or can be defined manually for use by integrator code. Brings in `<stdio.h>`. |
| `WOLFHSM_CFG_PRINTF` | `printf` (`<stdio.h>`) | Function or function-like macro used as the underlying print primitive for every debug print. Must match the signature `int func(const char* fmt, ...)`. Override this for targets without a working `printf`, or to redirect debug output through a vendor logging API. |

## Benchmark Suite

These macros are consumed only when building the wolfHSM benchmark suite (`benchmark/`). They are documented in more detail in [6-Utilities.md](6-Utilities.md#benchmark-suite) and in `benchmark/README.md`.

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_BENCH_ENABLE` | Undefined | If defined, compile the benchmark suite into the build. Required to use any of the other `BENCH_*` macros. |
| `WOLFHSM_CFG_BENCH_MAIN` | Undefined | If defined together with `WOLFHSM_CFG_BENCH_ENABLE`, also compile the standalone benchmark `main()` (`benchmark/wh_bench_main.c`). |
| `WOLFHSM_CFG_BENCH_CRYPT_ITERS` | `100` | Number of iterations executed per symmetric-crypto benchmark (AES, HMAC, RNG, echo). |
| `WOLFHSM_CFG_BENCH_KG_ITERS` | `10` | Number of iterations executed per key-generation benchmark. |
| `WOLFHSM_CFG_BENCH_PK_ITERS` | `10` | Number of iterations executed per public-key benchmark (ECC sign/verify, RSA sign/verify, ML-DSA, Curve25519 KA). |
| `WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE` | `0x400` (`1024`) | Size, in bytes, of each of the two static input/output buffers used by the data-plane benchmarks. |
| `WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE` | `0x8000` (`32 KiB`) | Size, in bytes, of the static DMA buffer used by DMA benchmarks. Only consulted when `WOLFHSM_CFG_DMA` is defined. |
| `WOLFHSM_CFG_BENCH_CUSTOM_DATA_BUFFERS` | Undefined | If defined, the benchmark suite will not allocate its own input/output buffers and will instead use the addresses supplied by `WOLFHSM_CFG_BENCH_CUSTOM_DATA_IN_BUFFER` and `WOLFHSM_CFG_BENCH_CUSTOM_DATA_OUT_BUFFER`. Useful for placing buffers in a specific memory region (TCM, shared RAM, etc.). |
| `WOLFHSM_CFG_BENCH_CUSTOM_DATA_IN_BUFFER` | None | Address (cast to `void*`) of the user-provided input buffer. Consulted only when `WOLFHSM_CFG_BENCH_CUSTOM_DATA_BUFFERS` is defined. |
| `WOLFHSM_CFG_BENCH_CUSTOM_DATA_OUT_BUFFER` | None | Address of the user-provided output buffer; same conditions as above. |
| `WOLFHSM_CFG_BENCH_CUSTOM_DMA_BUFFER` | Undefined | If defined, evaluates to the address of a user-supplied DMA buffer used in place of the static benchmark DMA buffer. |
| `WOLFHSM_CFG_BENCH_INIT_DATA_BUFFERS` | Undefined | If defined, benchmark modules re-initialize their input/output buffers with deterministic content before each measurement. Slightly slower per iteration, but produces more reproducible numbers. |
| `WOLFHSM_CFG_BENCH_CUSTOM_PRINTF` | Undefined | If defined, overrides the benchmark suite's print primitive with the named function or macro. Required on targets that do not provide a working `printf`. Independent of `WOLFHSM_CFG_PRINTF`. |
| `WOLFHSM_CFG_BENCH_CUSTOM_TIME_FUNC` | Undefined | If defined, overrides the benchmark suite's microsecond timer. The named function must have the signature `uint64_t func(void)`. Required on non-POSIX targets, where the suite has no portable way to obtain a wall-clock time. |

## Test Harness

These macros are consumed only by the wolfHSM test suite (`test/`) and its supporting infrastructure. They have no effect on a release build of the library. Most are toggled by `make` variables in `test/Makefile` (e.g. `make DMA=1 THREADSAFE=1 STRESS=1`).

| Macro | Default | Description |
|---|---|---|
| `WOLFHSM_CFG_TEST_POSIX` | Undefined | If defined, compile tests and benchmark scaffolding that depend on POSIX APIs (pthreads, sockets, file-based flash, etc.). Set automatically by the POSIX test/benchmark builds. |
| `WOLFHSM_CFG_TEST_CLIENT_ONLY` | Undefined | If defined, build the unit tests as a client-only driver that expects to connect to an externally running server (e.g. one started by another process). Set by the `CLIENT_ONLY=1` make variable. |
| `WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP` | Undefined | Variant of the above that constrains the client-only build to the TCP transport, used by the integration harness that pairs a local client driver with a remote TCP server. |
| `WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY` | Undefined | If defined, tests that exercise large data payloads only run the DMA variant; the non-DMA equivalents are compiled out. Used on targets where the comm-buffer sizing cannot accommodate the large-data non-DMA path. |
| `WOLFHSM_CFG_TEST_WOLFCRYPTTEST` | Undefined | If defined, integrate the upstream `wolfcrypt/test/test.c` suite into the wolfHSM test driver and run it through the wolfHSM crypto callback. Set by the `TESTWOLFCRYPT=1` make variable. |
| `WOLFHSM_CFG_TEST_UNIT_NO_MAIN` | Undefined | If defined, suppress the default `main()` provided by the test harness, allowing the test functions to be linked into an application that supplies its own entry point. |
| `WOLFHSM_CFG_TEST_STRESS` | Undefined | If defined, compile and run the POSIX thread-safety stress test (`test/wh_test_posix_threadsafe_stress.c`). Requires `WOLFHSM_CFG_THREADSAFE` and `WOLFHSM_CFG_TEST_POSIX`. Set by the `STRESS=1` make variable. |
| `WOLFHSM_CFG_TEST_STRESS_TSAN` | Undefined | If defined, force the stress test to emit additional ThreadSanitizer annotations. Set automatically by the `make TSAN=1 STRESS=1` combination. |
| `WOLFHSM_CFG_TEST_STRESS_PHASE_ITERATIONS` | `800` | Number of iterations executed within a single phase of the threadsafe stress test. |
| `WOLFHSM_CFG_TEST_STRESS_PHASE_TIMEOUT_SEC` | Undefined (no timeout) | If defined, the stress test bails out of any single phase that has not finished within this many wall-clock seconds, reporting a timeout failure. |
| `WOLFHSM_CFG_TEST_ASSERT_FUNC` | stdlib `assert()` | If defined, overrides the macro used by the test harness to evaluate `WH_TEST_ASSERT(...)`. Useful for redirecting assertion failures into a target-specific failure reporter. |
| `WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS` | Undefined | If defined, NVM-touching tests are allowed to leave persistent artifacts behind (objects, counters, keys) between runs, which lets a separate test phase verify them. Otherwise NVM is reset between tests. Used by the POSIX test build. |
| `WOLFHSM_CFG_TEST_CRYPTSVR_CFG` | Implicitly defined | The crypto-server test pulls in its standard wolfCrypt test configuration unless `NO_WOLFHSM_CFG_TEST_CRYPTSVR_CFG` is defined at build time, in which case the integrator must supply their own configuration. |
| `WOLFHSM_CFG_IS_TEST_SERVER` | Undefined | If defined, the client-side unit tests assume they are talking to a server that is running additional test-only instrumentation (exercising edge cases that cannot be triggered against a standard server). Set automatically for the combined client/server POSIX test build; should not be defined outside of that harness. |

## Memory and Cache Porting Macros

For completeness, wolfHSM also relies on a small number of `X*` porting macros that are normally supplied alongside the `WOLFHSM_CFG_*` macros in `wolfhsm_cfg.h` even though they do not share the prefix:

- `XMEMFENCE()` — sequential memory fence (defaults to `__atomic_thread_fence(__ATOMIC_SEQ_CST)` on GCC/Clang; otherwise a no-op with a build warning).
- `XCACHELINE` — cache-line size in bytes (default `32`).
- `XCACHEFLUSH(p)` / `XCACHEFLUSHBLK(p, n)` — flush one line / a range; defaults are no-op and `wh_Utils_CacheFlush` respectively.
- `XCACHEINVLD(p)` / `XCACHEINVLDBLK(p, n)` — invalidate one line / a range; defaults are no-op and `wh_Utils_CacheInvalidate` respectively.

These are the only knobs needed to make the shared-memory transports and DMA crypto paths safe on systems with separate I-cache/D-cache and on multicore SoCs without hardware cache coherency.
