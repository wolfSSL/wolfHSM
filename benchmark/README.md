# WolfHSM Benchmarks

This directory contains benchmark code for measuring the performance of wolfHSM cryptographic operations.

## Overview

The wolfHSM benchmarks provide a framework for testing and measuring the performance of cryptographic operations across various algorithms. The benchmark suite includes tests for:

- Symmetric ciphers (AES: ECB, CBC, GCM)
- Hash functions (SHA-2, SHA-3)
- Message Authentication Codes (HMAC, CMAC)
- Public Key Cryptography (RSA, ECC, Curve25519)
- Post-Quantum Cryptography (ML-DSA)
- Basic communication (Echo)

The benchmark system measures the runtime of registered operations, as well as reports the throughput in either operations per second or bytes per second depending on the algorithm.

## Module Structure

The benchmark code is organized as follows:

- **Main Entry Point**:
  - `wh_bench_main.c`: main function wrapper for the benchmark application

- **Core Benchmark Framework**:
  - `wh_bench.h`/`wh_bench.c`: Entry point and core benchmark functionality and client/server setup
  - `wh_bench_ops.h`/`wh_bench_ops.c`: Operations tracking, timing, and results reporting
  - `wh_bench_mod.h`: Defines the benchmark module interfaces

- **Benchmark Modules**:
  - `bench_modules/wh_bench_mod_*.c`: Individual benchmark implementations
  - `bench_modules/wh_bench_mod_all.h`: Function declarations for all available benchmark modules

## How It Works

The benchmark application runs various wolfHSM client operations against a running wolfHSM sever instance. On POSIX platforms, separate threads are created for client and server

1. The client registers a list of benchmark operations and runs them
2. Each benchmark module performs a specific operation a configurable number of times
3. Timing information is collected for each operation
4. Results are displayed on completion showing performance metrics

## Configuring the Benchmarks

### Compilation Options

You can build and run the benchmarks with make

```bash

make

```

You can also configure the benchmarks using various make options:

```bash

# Build with DMA support
make DMA=1

# Build with SHE extensions
make SHE=1
```

### Configuration options

The benchmark suite has a number of configuration macros that can be defined or overridden to change the default behavior. These configuration macros are named `WOLFHSM_CFG_BENCH_XXX` and can be defined by the end user in `wolfhsm_cfg.h` or in the compiler options.

#### Custom timer

For non-POSIX ports, you must supply a custom platform-specific microsecond timer function so that the benchmark suite can time operations.

1. Define your custom function with the signature: `uint64_t myCustomTimeFunction(void);`. For example:

```c
uint64_t myCustomTimeFunction(void) {
    // Platform-specific code to get time in microseconds
    return TIMER_US->ticks;
}
```

2. When compiling, define `WOLFHSM_CFG_BENCH_CUSTOM_TIME_FUNC` to your function name, either in `wolfhsm_cfg.h` or in your compiler options:

```bash
/* in wolfhsm_cfg.h */
#define WOLFHSM_CFG_BENCH_CUSTOM_TIME_FUNC myCustomTimeFunction
```

#### Custom printf functions

For platforms that don't support standard printf, or if you want a unique printf just for benchmarks, you can provide a custom implementation.

1. To customize printf, define `WOLFHSM_CFG_BENCH_CUSTOM_PRINTF` to your function name:

```c
/* in wolfhsm_cfg.h */
#define WOLFHSM_CFG_BENCH_CUSTOM_PRINTF myCustomPrintf
```

Your custom function should have the same signature as the standard C counterpart and support standard format specifiers (including floating point).

#### Data Buffer Configuration

The benchmark suite uses standardized data buffers for cryptographic operations. These can be configured with the following options:

- `WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE`: Defines the size of the standard input/output data buffers used for benchmarks
- `WOLFHSM_CFG_BENCH_CUSTOM_DATA_BUFFERS`: When defined, allows you to provide your own custom data buffers instead of using the built-in ones. If defined you should also define `WOLFHSM_CFG_BENCH_CUSTOM_DATA_IN_BUFFER` and `WOLFHSM_CFG_BENCH_CUSTOM_DATA_OUT_BUFFER` to globally accessible pointers to your custom buffers
- `WOLFHSM_CFG_BENCH_INIT_DATA_BUFFERS`: When defined, initializes input buffers with non-zero data
- `WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE`: Defines the size of the DMA buffer used for DMA operations
- `WOLFHSM_CFG_BENCH_CUSTOM_DMA_BUFFER`: When defined, allows you to specify a custom DMA buffer location instead of using the built-in one. This should be set to a pointer to your globally accessible custom buffer

#### Number of benchmark iterations

You can adjust the number of iterations ran for various types of benchmark operations by overriding the following options:

- `WOLFHSM_CFG_BENCH_CRYPT_ITERS`: Number of iterations for cryptographic operations (symmetric ciphers, HMAC, CMAC, etc.)
- `WOLFHSM_CFG_BENCH_KG_ITERS`: Number of iterations for key generation operations
- `WOLFHSM_CFG_BENCH_PK_ITERS`: Number of iterations for public key operations (encrypt/decrypt/sign/verify/shared secret)

## Running the Benchmarks

To build and run the benchmarks:

```bash
cd benchmark
make run
```

This will compile the benchmark suite and execute it.

## Adding a New Benchmark

To add a new benchmark module:

1. Create a new file in `bench_modules/` (e.g., `wh_bench_mod_newcomp.c`)
2. Implement the benchmark module function following this pattern:

```c
#include "benchmark/wh_bench_mod.h"

int wh_Bench_Mod_NewOp(whClientContext* client, BenchOpContext* benchCtx, int id, void* params)
{
    int ret = 0;
    int i;

    /* Do any module-specific setup here */

    /* Run operation multiple times for statistics */
    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        /* Start timing */
        ret = wh_Bench_StartOp(benchCtx, id);
        if (ret != 0) {
            break;
        }

        /* Perform the actual operation */
        ret = wh_Client_YourOperation(client, ...);

        /* Stop timing */
        ret = wh_Bench_StopOp(benchCtx, id);
        if (ret != 0) {
            break;
        }
    }

    /* Cleanup */

    return ret;
}
```

3. Add your function prototype to `wh_bench_mod_all.h`
4. Add your benchmark to the `g_benchModules` array in `wh_bench.c`:

```c
[BENCH_MODULE_IDX_NEW_OP] = {"New-Operation", wh_Bench_Mod_NewOp, BENCH_THROUGHPUT_TYPE, 0, NULL},
```

5. Add the module index in the `BenchModuleIdx` enum in `wh_bench.c`:

```c
typedef enum BenchModuleIdx {
    /* existing entries */
    BENCH_MODULE_IDX_NEW_OP,
    /* after your entry */
    BENCH_MODULE_IDX_COUNT
} BenchModuleIdx;
```

6. Add your module to the `SRC_C` list in the Makefile

## Notes

- Ensure the `MAX_BENCH_OPS` value in `wh_bench_ops.h` is large enough to accommodate all benchmark modules
- For throughput calculations, you need to specify the data size using `wh_Bench_SetDataSize()`
