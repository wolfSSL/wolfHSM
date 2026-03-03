# Timeout Functionality: Client Perspective

## 1. Configuration at Init Time

The timeout feature uses a callback-based abstraction (similar to the lock feature) that allows platform-specific timer implementations without introducing OS dependencies in core wolfHSM code. A platform port provides a callback table implementing the timer operations, and the core timeout module delegates to these callbacks.

The timeout lives in the comm layer. When creating a client, you provide a `whTimeoutConfig` in the `whCommClientConfig`:
```c
/* Platform-specific setup (e.g. POSIX) */
posixTimeoutContext posixCtx = {0};
posixTimeoutConfig  posixCfg = {.timeoutUs = WH_SEC_TO_USEC(5)};
whTimeoutCb         timeoutCbTable = POSIX_TIMEOUT_CB;

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

This means every `do { ... } while (ret == WH_ERROR_NOTREADY)` loop in the codebase automatically gets timeout support -- crypto, NVM, keystore, cert, SHE, keywrap, and all other client operations.

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
- **The timeout is per-comm-client, not per-call.** All operations for a given client share the same `respTimeout` context with the same duration. You can call `wh_Timeout_Set()` to change the duration between calls, but there's no per-operation override.
- **Timer starts on send, checks on receive.** The timer window begins when a request is successfully sent, measuring the full round-trip wait.
