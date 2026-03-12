# Timeout Functionality: Client Perspective

## Overview

The response timeout feature is primarily designed to prevent the client from blocking indefinitely when the server fails to respond to a request. This is most relevant for **blocking operations** such as wolfCrypt cryptographic calls, where the client sends a request and polls for a response in a tight loop. Without a timeout, a non-responsive server would cause the client to hang forever.

Since the timeout is checked inside `wh_CommClient_RecvResponse`, it **can** also apply to the split (async) API where the caller manually polls `RecvResponse`. However, in the async case the timeout is only evaluated each time the caller invokes `RecvResponse` -- it does not proactively notify the caller or fire asynchronously. If the caller is not actively polling, the timeout has no effect.

## 1. Configuration at Init Time

The timeout feature uses a callback-based abstraction (similar to the lock feature) that allows platform-specific timer implementations without introducing OS dependencies in core wolfHSM code. A platform port provides a callback table implementing the timer operations, and the core timeout module delegates to these callbacks.

The timeout lives in the comm layer. When creating a client, you provide a `whTimeoutConfig` in the `whCommClientConfig`:
```c
/* Platform-specific setup (e.g. POSIX) */
posixTimeoutContext posixCtx = {0};
posixTimeoutConfig  posixCfg = {.timeoutUs = WH_SEC_TO_USEC(5)};
whTimeoutCb         timeoutCbTable = POSIX_TIMEOUT_CB;

/* NOTE: The callback table, platform context, and expiredCtx must remain valid
 * for the lifetime of the whCommClient/whTimeout instance. Do not use stack
 * locals that go out of scope while the client is still in use. */
whTimeoutConfig timeoutCfg = {
    .cb         = &timeoutCbTable,     /* platform callback table */
    .context    = &posixCtx,           /* platform context */
    .config     = &posixCfg,           /* platform-specific config */
    .expiredCb  = myTimeoutHandler,    /* optional app callback on expiry */
    .expiredCtx = myAppContext,        /* context passed to app callback */
};
whCommClientConfig commConfig = {
    .transport_cb      = &transportCb,
    .transport_context = &transportCtx,
    .transport_config  = &transportCfg,
    .client_id         = 1,
    .respTimeoutConfig = &timeoutCfg,  /* attach timeout config */
};
whClientConfig clientCfg = {
    .comm = &commConfig,
};
wh_Client_Init(&clientCtx, &clientCfg);
```

During `wh_CommClient_Init`, the timeout is initialized via `wh_Timeout_Init()`. This calls the platform `init` callback to set up timer resources but doesn't start any timer yet.
If `respTimeoutConfig` is NULL (or `cb` is NULL), the timeout enters no-op mode and never expires.

## 2. How the Timeout Works

The timeout is handled transparently in the comm layer:

1. **`wh_CommClient_SendRequest`**: After a successful send, starts the response timer via `wh_Timeout_Start()`.
2. **`wh_CommClient_RecvResponse`**: When the transport returns `WH_ERROR_NOTREADY`, checks `wh_Timeout_Expired()`. If expired, returns `WH_ERROR_TIMEOUT`. On successful receive, stops the timer via `wh_Timeout_Stop()`.

For blocking (synchronous) client APIs, this means the internal `do { ... } while (ret == WH_ERROR_NOTREADY)` polling loop automatically gets timeout support -- the client will return `WH_ERROR_TIMEOUT` instead of spinning forever if the server does not respond within the configured deadline.

For split (async) APIs where the application calls `SendRequest` and `RecvResponse` separately, the timeout check occurs each time `RecvResponse` is called and returns `WH_ERROR_NOTREADY`. The timeout does **not** interrupt the caller or provide out-of-band notification -- it is purely poll-based.

```
Client App                      CommClient                       whTimeout
    |                                |                                |
    |-- wh_Client_AesCbc() -------->|                                |
    |                                |-- SendRequest ------> cb->start()
    |                                |                                |
    |                                |-- RecvResponse (NOTREADY)      |
    |                                |-- Expired? -------> cb->expired() -> no
    |                                |-- RecvResponse (NOTREADY)      |
    |                                |-- Expired? -------> cb->expired() -> no
    |                                |   ...                          |
    |                                |-- RecvResponse (NOTREADY)      |
    |                                |-- Expired? -------> cb->expired() -> YES
    |                                |                                |-- expiredCb()
    |<-- WH_ERROR_TIMEOUT -----------|                                |
```

## 3. What the Client Sees

From the application's perspective, any client API that waits for a server response can now return `WH_ERROR_TIMEOUT` (-2010) instead of hanging indefinitely. The application can then decide how to handle it -- retry, log, fail gracefully, etc.
The `expiredCb` fires *before* the error is returned, so you can use it for logging or cleanup without needing to check the return code first.

## 4. Overriding Expiration via the Callback

The application expired callback receives a pointer to the `isExpired` flag and can override it by setting `*isExpired = 0`. This suppresses the expiration for the current check, allowing the polling loop to continue. A common use case is to extend the timeout deadline: clear the flag, then call `wh_Timeout_Start()` to restart the timer.

The callback can also return a non-zero error code to signal a failure. When it does, `wh_Timeout_Expired()` propagates that error directly to the caller instead of returning the expired flag.

```c
static int myOverrideCb(whTimeout* timeout, int* isExpired)
{
    int* retryCount = (int*)timeout->expiredCtx;
    if (retryCount == NULL) {
        return WH_ERROR_BADARGS;
    }

    (*retryCount)++;

    if (*retryCount <= 1) {
        /* First expiration: suppress and restart the timer */
        *isExpired = 0;
        wh_Timeout_Start(timeout);
    }
    /* Subsequent expirations: allow the timeout to fire */
    return WH_ERROR_OK;
}

int retryCount = 0;
posixTimeoutContext posixCtx = {0};
posixTimeoutConfig  posixCfg = {.timeoutUs = WH_SEC_TO_USEC(5)};
whTimeoutCb         timeoutCbTable = POSIX_TIMEOUT_CB;

whTimeoutConfig timeoutCfg = {
    .cb         = &timeoutCbTable,
    .context    = &posixCtx,
    .config     = &posixCfg,
    .expiredCb  = myOverrideCb,
    .expiredCtx = &retryCount,
};
```

## 5. Design Notes
- **Primary use case: blocking wolfCrypt operations.** The timeout is designed to prevent indefinite hangs when the server fails to respond to blocking client API calls, which currently only exist when using the wolfCrypt API for crypto. These calls internally poll `RecvResponse` in a tight loop, and the timeout provides automatic protection against a non-responsive server.
- **Async API compatibility.** The timeout mechanism also works with the split wolfHSM `SendRequest`/`RecvResponse` API, but only checks for expiration when `RecvResponse` is called by the application. It is purely poll-driven, and there is no callback, signal, or interrupt that fires independently. If the application stops calling `RecvResponse`, the timeout will not trigger.
- **The timeout is per-comm-client, not per-call.** All operations for a given client share the same `respTimeout` context with the same duration. You can call `wh_Timeout_Set()` to change the duration between calls, but there's no per-operation override.
- **Timer starts on send, checks on receive.** The timer window begins when a request is successfully sent, measuring the full round-trip wait.
