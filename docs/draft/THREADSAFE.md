# Thread Safety in wolfHSM

## Overview

wolfHSM supports server-side thread safety via the `WOLFHSM_CFG_THREADSAFE` build flag. When enabled, the server can safely process requests from multiple clients concurrently, with each request processing loop running on a separate thread and communicating through its own server context.

The thread safety model serializes access to shared resources like NVM storage and the global key cache using a single lock embedded in the NVM context. Multiple server contexts can safely share a single NVM context, with the lock ensuring atomic access to shared state.

The thread safety feature does NOT imply that a single server context can be shared across threads, as it only serializes internal access to shared resources between multiple server contexts that would occur internally as a consequence of using the server API. Concurrent access to a single server context is not currently supported.

## Build Configuration

Thread safety is enabled when building with `WOLFHSM_CFG_THREADSAFE` defined.

To enable thread safety in the posix test harness, you can build with:

```bash
make -C test THREADSAFE=1
```

When `WOLFHSM_CFG_THREADSAFE` is not defined, all locking operations compile to no-ops with zero overhead.

## What Is Protected

Currently only the global NVM context is protected by a lock, guaranteeing thread safe access to:

- **NVM operations**: All operations on non-volatile storage
- **Global key cache**: Keys marked as global (shared across clients) via `WOLFHSM_CFG_GLOBAL_KEYS`
- **Local key cache**: Per-server key cache operations that must synchronize with NVM

The lock does **not** protect:

- Transport layer operations (each server has its own comm context)
- Per-request scratch memory (allocated per-handler)
- Server context fields that are not shared

## Architecture

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Server 1   │  │  Server 2   │  │  Server 3   │
│ (localCache)│  │ (localCache)│  │ (localCache)│
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │    NVM Context    │
              │  ┌─────────────┐  │
              │  │    Lock     │  │
              │  ├─────────────┤  │
              │  │ Global Keys │  │
              │  ├─────────────┤  │
              │  │  NVM Backend│  │
              │  └─────────────┘  │
              └───────────────────┘
```

## Lock Lifecycle

The lock is initialized and cleaned up with the NVM context:

```c
whNvmConfig nvmConfig = {
    .cb       = &nvmFlashCb,
    .context  = &flashContext,
    .config   = &flashConfig,
#ifdef WOLFHSM_CFG_THREADSAFE
    .lockConfig = &lockConfig,  /* Platform-specific lock config */
#endif
};

wh_Nvm_Init(&nvmContext, &nvmConfig);   /* Initializes lock */
/* ... use NVM ... */
wh_Nvm_Cleanup(&nvmContext);            /* Cleans up lock */
```

## Request Handler Locking

Request handlers in the server acquire the lock around compound operations. The pattern is:

```c
case SOME_ACTION: {
    /* Translate request (no lock needed) */
    wh_MessageFoo_TranslateRequest(magic, req_packet, &req);

    /* Acquire lock for atomic compound operation */
    ret = WH_SERVER_NVM_LOCK(server);
    if (ret == WH_ERROR_OK) {
        /* Perform work while holding lock */
        ret = wh_Server_KeystoreXxx(server, ...);
        if (ret == WH_ERROR_OK) {
            ret = wh_Nvm_Xxx(server->nvm, ...);
        }

        /* Release lock */
        (void)WH_SERVER_NVM_UNLOCK(server);
    }
    resp.rc = ret;

    /* Translate response (no lock needed) */
    wh_MessageFoo_TranslateResponse(magic, &resp, resp_packet);
}
```

Key points:
- Lock acquired **after** request translation
- Lock released **before** response translation
- All NVM and keystore operations within the lock are atomic
- The lock ensures multi-step operations (e.g., check-then-modify) are not interleaved

## Server-Side Development

When developing server-side code that accesses shared resources outside the request handling pipeline, you must manually acquire the lock.

### Using the Server Lock Macros

```c
int my_server_function(whServerContext* server)
{
    int ret;

    ret = WH_SERVER_NVM_LOCK(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Access NVM or global keystore while holding lock */
    ret = wh_Nvm_Read(server->nvm, id, offset, len, buffer);
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_KeystoreCacheKey(server, &meta, keyData);
    }

    (void)WH_SERVER_NVM_UNLOCK(server);
    return ret;
}
```

### Using the NVM Lock Macros Directly

If you only have access to the NVM context:

```c
int my_nvm_function(whNvmContext* nvm)
{
    int ret;

    ret = WH_NVM_LOCK(nvm);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Access NVM while holding lock */
    ret = wh_Nvm_GetMetadata(nvm, id, &meta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Nvm_Read(nvm, id, 0, meta.len, buffer);
    }

    (void)WH_NVM_UNLOCK(nvm);
    return ret;
}
```

### Lock Macro Behavior

| Macro | THREADSAFE defined | THREADSAFE not defined |
|-------|-------------------|------------------------|
| `WH_SERVER_NVM_LOCK(server)` | Calls `wh_Server_NvmLock()` | Returns `WH_ERROR_OK` |
| `WH_SERVER_NVM_UNLOCK(server)` | Calls `wh_Server_NvmUnlock()` | Returns `WH_ERROR_OK` |
| `WH_NVM_LOCK(nvm)` | Calls `wh_Nvm_Lock()` | Returns `WH_ERROR_OK` |
| `WH_NVM_UNLOCK(nvm)` | Calls `wh_Nvm_Unlock()` | Returns `WH_ERROR_OK` |

Using these macros ensures code compiles and runs correctly regardless of whether thread safety is enabled.

## Platform-Specific Lock Implementation

The lock abstraction is a generic interface that relies on callbacks for the actual implementation, allowing platform-specific implementations. wolfHSM provides a reference POSIX implementation using pthreads for use in the POSIX port:

```c
#include "port/posix/posix_lock.h"

static posixLockContext lockCtx;
static const whLockCb   lockCb = POSIX_LOCK_CB;

whLockConfig lockConfig = {
    .cb      = &lockCb,
    .context = &lockCtx,
    .config  = NULL,  /* Use default mutex attributes */
};
```

To implement for another platform, you can implement your own callbacks matching the `whLockCb` interface:

```c
typedef struct whLockCb_t {
    whLockInitCb    init;    /* Initialize lock resources */
    whLockCleanupCb cleanup; /* Free lock resources */
    whLockAcquireCb acquire; /* Acquire exclusive lock (blocking) */
    whLockReleaseCb release; /* Release exclusive lock */
} whLockCb;
```

## Testing Thread Safety on the POSIX port

Run the standard test suite with DMA, SHE, and thread safety enabled

```bash
make -C test clean && make -j -C test DMA=1 THREADSAFE=1 && make -C test run
```

Run the multithreaded stress test with the same functionality under ThreadSanitizer to detect data races:

```bash
make -C test clean && make -j -C test STRESS=1 TSAN=1 DMA=1 SHE=1 THREADSAFE=1 && make -C test run TSAN=1
```

The stress test runs multiple client threads against multiple server contexts sharing a single NVM context, exercising contention patterns across keystore, NVM, counter, and certificate APIs.
