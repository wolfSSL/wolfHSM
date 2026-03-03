# Timeout Functionality: Client Perspective

## 1. Configuration at Init Time

The timeout feature uses a callback-based abstraction (similar to the lock feature) that allows platform-specific timer implementations without introducing OS dependencies in core wolfHSM code. A platform port provides a callback table implementing the timer operations, and the core timeout module delegates to these callbacks.

When creating a client, you provide a `whTimeoutConfig` specifying the platform callbacks, platform context, and an optional application-level expired callback:
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
whClientConfig clientCfg = {
    .comm              = &commConfig,
    .respTimeoutConfig = &timeoutCfg,  /* attach timeout config */
};
wh_Client_Init(&clientCtx, &clientCfg);
```

During `wh_Client_Init`, the config is used to initialize an embedded `whTimeout respTimeout` inside the client context via `wh_Timeout_Init()`. This calls the platform `init` callback to set up timer resources but doesn't start any timer yet.
If `respTimeoutConfig` is NULL (or `cb` is NULL), the timeout is disabled and all operations become no-ops (timeout never expires).

## 2. What Happens During a Crypto Call

Before the timeout feature, every crypto function in `wh_client_crypto.c` had this pattern after sending a request:
```c
/* Old pattern -- infinite busy-wait */
do {
    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len, dataPtr);
} while (ret == WH_ERROR_NOTREADY);
```

If the server never responded, the client would spin forever.
This is replaced with a single helper `_recvCryptoResponse()` (`src/wh_client_crypto.c`):
```c
static int _recvCryptoResponse(whClientContext* ctx,
                               uint16_t* group, uint16_t* action,
                               uint16_t* size, void *data)
{
    int ret;
#ifdef WOLFHSM_CFG_ENABLE_TIMEOUT
    ret = wh_Client_RecvResponseBlockingWithTimeout(ctx, group, action,
                                                     size, data);
#else
    do {
        ret = wh_Client_RecvResponse(ctx, group, action, size, data);
    } while (ret == WH_ERROR_NOTREADY);
#endif
    return ret;
}
```

When timeout is enabled, it delegates to `wh_Client_RecvResponseBlockingWithTimeout`. When disabled, the old infinite-loop behavior is preserved.

## 3. The Timeout Receive Loop
`wh_Client_RecvResponseBlockingWithTimeout` (`src/wh_client.c`) does this:
1. **Starts the timer** -- calls `wh_Timeout_Start()` which delegates to the platform `start` callback (e.g. captures the current time).
2. **Polls for a response** -- calls `wh_Client_RecvResponse()` in a loop.
3. **On each `WH_ERROR_NOTREADY`**, checks `wh_Timeout_Expired()`:
   - Delegates to the platform `expired` callback to check elapsed time
   - If expired: invokes the application `expiredCb` (if set), then returns `WH_ERROR_TIMEOUT`
   - If not expired: loops again
4. **On any other return value** (success or error), returns immediately.
```
Client App                    _recvCryptoResponse                 whTimeout
    |                                |                                |
    |-- wh_Client_AesCbc() --------> |                                |
    |                                |-- wh_Timeout_Start --------> cb->start()
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

## 4. What the Client Sees
From the application's perspective, the crypto APIs (`wh_Client_AesCbc`, `wh_Client_RsaFunction`, `wh_Client_EccSign`, etc.) now return `WH_ERROR_TIMEOUT` (-2010) instead of hanging indefinitely. The application can then decide how to handle it -- retry, log, fail gracefully, etc.
The `expiredCb` fires *before* the error is returned, so you can use it for logging or cleanup without needing to check the return code first.

## 5. Overriding Expiration via the Callback

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

## 6. Scope Limitations
A few things to note about the current design:
- **Only crypto responses are covered.** Non-crypto client calls (key management, NVM operations, comm init) still use the old infinite-wait pattern. The timeout is specifically wired into `_recvCryptoResponse`.
- **The timeout is per-client, not per-call.** All crypto operations for a given client share the same `respTimeout` context with the same duration. You can call `wh_Timeout_Set()` to change the duration between calls, but there's no per-operation override.
