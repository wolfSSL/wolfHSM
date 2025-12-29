# Utilities

This chapter describes the auxiliary tools that ship alongside the wolfHSM client and server libraries. These utilities are not part of the runtime library but support the workflows around it — provisioning an NVM image for a device, measuring the performance of a configured server, and validating that a port or build configuration behaves correctly. Each section describes *what* the utility does and *how* to drive it on the supported platforms; the underlying subsystems exercised by these tools are covered in [5-Features.md](5-Features.md) and the API references.

## Table of Contents

- [NVM Provisioning Tool](#nvm-provisioning-tool)
- [Benchmark Suite](#benchmark-suite)
    - [Benchmark Suite Overview](#benchmark-suite-overview)
    - [Running Benchmarks on POSIX](#running-benchmarks-on-posix)
    - [Running Benchmarks on Real Hardware](#running-benchmarks-on-real-hardware)
- [Test Suite](#test-suite)
    - [Test Suite Overview](#test-suite-overview)
    - [Running Tests on POSIX](#running-tests-on-posix)
    - [Running Tests on Real Hardware](#running-tests-on-real-hardware)

## NVM Provisioning Tool

The NVM provisioning tool (`tools/whnvmtool/`) is a host-side utility that builds a pre-populated wolfHSM NVM image from a configuration file. It is intended for device provisioning: rather than having the server populate its NVM at runtime, the integrator describes the desired initial contents — a set of NVM objects and keys, each with its metadata ID, access permissions, flags, label, and a path to the binary payload — and the tool produces a single image file that can be programmed into the device's flash at manufacture or used in place to back a `whNvmFlash` provider in simulation. Currently the tool targets the `whNvmFlash` provider; the generated image is binary, and can be converted to Intel HEX with the standard `objcopy` workflow for use with automated programmers.

Because the on-flash layout depends on build-time configuration, the tool must be compiled against the same wolfHSM version as the target server and with a matching `WOLFHSM_CFG_NVM_OBJECT_COUNT`, and the `--size` argument must match the server's `whNvmFlash` partition size. For the full configuration file schema, command-line options, hex conversion recipe, and test workflow, see [`tools/whnvmtool/README.md`](../tools/whnvmtool/README.md).

## Benchmark Suite

### Benchmark Suite Overview

The benchmark suite (`benchmark/`) is a standalone wolfHSM client application that measures the round-trip cost of cryptographic operations against a configured wolfHSM server, from the perspective of a client. The numbers it reports therefore reflect the end-to-end performance a real client would observe in the same runtime environment: server-side computation, transport overhead, and any port-specific acceleration all rolled together.

The benchmark app consists of individual modules that each measure the various cryptographic algorithms that wolfHSM exposes. Each module runs its operation a configurable number of iterations, and the framework reports either operations per second or throughput in bytes per second, depending on the algorithm class.

The same client application builds and runs against any supported port: on POSIX the client and server run in separate threads of the host process, and on embedded targets the application links into the port's runtime alongside a board-specific timer and `printf`. Iteration counts, data buffer sizes, DMA buffers, and timing/printing hooks are all overridable through `WOLFHSM_CFG_BENCH_*` macros so the suite can be tuned to the constraints of the target.

For the full list of configuration macros, the module interface, instructions for adding a new benchmark, and the internal layout of the framework, see [`benchmark/README.md`](../benchmark/README.md).

### Running Benchmarks on POSIX

To compile and run the benchmark application on a POSIX host system using the POSIX server port:

```sh
cd benchmark
make clean
make
make run
```

To use the DMA versions of algorithms that support it, pass the `DMA=1` environment variable to the build command:

```
make clean
make DMA=1
make run
```


### Running Benchmarks on Real Hardware

Each hardware port ships with its own instructions for compiling and running the benchmark application on the target — refer to the README under the corresponding `port/<vendor>/<chip>/` directory for board-specific details such as toolchain setup, linker scripts, and timer configuration. At a high level, integrating the suite into a port-specific application reduces to three steps.

**1. Compile the framework sources alongside the application.** Add `benchmark/wh_bench.c`, `benchmark/wh_bench_ops.c`, and `benchmark/wh_bench_data.c` to the build, together with the per-algorithm modules under `benchmark/bench_modules/`. The standalone CLI wrapper in `benchmark/wh_bench_main.c` assumes a POSIX command-line environment and is typically omitted on embedded targets, where the application invokes the benchmark entry points directly.

**2. Define the required configuration macros.** At a minimum, define `WOLFHSM_CFG_BENCH_ENABLE` to compile the suite in. On non-POSIX targets the framework has no portable way to obtain wall-clock time, so the port must supply a microsecond timer with the signature `uint64_t timer(void)` and point `WOLFHSM_CFG_BENCH_CUSTOM_TIME_FUNC` at its name. If the platform lacks a working `printf`, define `WOLFHSM_CFG_BENCH_CUSTOM_PRINTF` to a port-supplied formatted-print routine. Iteration counts (`WOLFHSM_CFG_BENCH_CRYPT_ITERS`, `WOLFHSM_CFG_BENCH_KG_ITERS`, `WOLFHSM_CFG_BENCH_PK_ITERS`), buffer sizes (`WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE`, `WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE`), and buffer placement (`WOLFHSM_CFG_BENCH_CUSTOM_DATA_BUFFERS`, `WOLFHSM_CFG_BENCH_CUSTOM_DMA_BUFFER`) are all optional overrides used to fit the suite into the target's resource budget.

**3. Drive the benchmark client from the application.** The benchmark utility is purely client-side: it issues requests to a wolfHSM server and times the responses. The server it talks to can be any wolfHSM server instance that is listening on the same transport — most commonly the application's own production server, which exercises the exact configuration whose performance you are trying to measure. For convenience the suite also exposes `wh_Bench_ServerCfgLoop(whServerConfig*)`, a minimal server processing loop that dispatches incoming client requests until the client disconnects, which can be used in lieu of a production server when one is not yet available. On the client side, `wh_Bench_ClientCfg(whClientConfig*, int transport)` initializes a client, runs the full suite, and tears the client down; `wh_Bench_ClientCtx(whClientContext*, int transport)` is the equivalent entry point when the application already manages the client context lifecycle. How the client and the server are scheduled relative to each other — separate cores, separate tasks, or cooperatively from a main loop — is determined by the port.

## Test Suite

### Test Suite Overview

The test suite (`test/`) is a standalone wolfHSM application that exercises the library's unit and integration tests against a configured client and server. Tests are grouped one-per-component (NVM, comm, crypto, keystore, certificates, SHE, image manager, authentication, etc.), each in its own `wh_test_*.c` source file, and are wired together by the top-level driver in `wh_test.c`. The suite validates wolfHSM itself rather than wolfCrypt; the full wolfCrypt test suite can additionally be run as a wolfHSM client by enabling `WOLFHSM_CFG_TEST_WOLFCRYPTTEST`, which exercises the crypto callback path end-to-end.

The same test sources build for POSIX hosts and for embedded targets. Tests that depend on POSIX facilities (sockets, pthreads, file-backed flash) are compiled in only when `WOLFHSM_CFG_TEST_POSIX` is defined, so an embedded port pulls in just the portable subset and selects whichever modules its configuration supports. Output goes through `WOLFHSM_CFG_PRINTF` and assertions go through `WOLFHSM_CFG_TEST_ASSERT_FUNC`, so both can be redirected to port-supplied implementations.

For the full list of test modules, supported build options, and code coverage workflow, see [`test/README.md`](../test/README.md).

### Running Tests on POSIX

To compile and run the full test suite on a POSIX host system using the POSIX server port:

```sh
cd test
make clean
make
make run
```

Feature-specific builds are selected with the same makefile variables documented in [11-Configuration.md](11-Configuration.md) — for example `DMA=1`, `SHE=1`, `AUTH=1`, `TLS=1`, `THREADSAFE=1`, `TESTWOLFCRYPT=1`. Development and CI builds also commonly set `ASAN=1` (address sanitizer), `TSAN=1` (thread sanitizer, mutually exclusive with `ASAN`), `DEBUG=1`, or `COVERAGE=1` (instruments the build for `gcovr`; see `make coverage`).

To build a client-only driver that connects to an already-running server over TCP (or TLS when `TLS=1` is set), pass `CLIENT_ONLY=1`:

```sh
make clean
make CLIENT_ONLY=1
make run
```


### Running Tests on Real Hardware

Each hardware port ships with its own instructions for compiling and running the test suite on the target — refer to the README under the corresponding `port/<vendor>/<chip>/` directory for board-specific details. At a high level, integrating the suite into a port-specific application reduces to three steps.

**1. Compile the framework sources alongside the application.** Add `test/wh_test.c`, `test/wh_test_common.c`, and the per-module `test/wh_test_*.c` files for the components you wish to validate. Each module is independent, so an embedded port can pick a subset (e.g. crypto, keystore, certificates) and omit modules whose features the build does not enable. Leave `WOLFHSM_CFG_TEST_POSIX` undefined so the POSIX-only paths (sockets, pthreads, file-backed flash) are excluded.

**2. Define the required configuration macros.** Define `WOLFHSM_CFG_TEST_UNIT_NO_MAIN` to suppress the default `main()` so the application can call the test entry points itself. If the platform lacks a working stdlib `assert()`, define `WOLFHSM_CFG_TEST_ASSERT_FUNC` to a port-supplied assertion routine; output is already routed through `WOLFHSM_CFG_PRINTF` (see [11-Configuration.md](11-Configuration.md)). Enable individual test categories by defining the same feature macros that gate them in the library (e.g. `WOLFHSM_CFG_DMA`, `WOLFHSM_CFG_SHE_EXTENSION`, `WOLFHSM_CFG_TEST_WOLFCRYPTTEST`).

**3. Drive the test entry points from the application.** Like the benchmark suite, the tests are purely client-side: they issue requests to a wolfHSM server and validate the responses. The server can be any wolfHSM server listening on the same transport — typically the application's own production server. To run the full client-side test set against a client the application has already configured, call `whTest_ClientConfig(whClientConfig*)`; individual modules expose their own client entry points (`whTest_CryptoClientConfig`, `whTest_SheClientConfig`, `whTest_TimeoutClientConfig`, etc.) when only a subset is desired. The suite also exposes `whTest_ServerCfgLoop(whServerConfig*)`, a minimal server processing loop suitable for in-process or co-resident-core test runs when no production server is available. How the client and server are scheduled relative to each other — separate cores, separate tasks, or cooperatively from a main loop — is determined by the port.
