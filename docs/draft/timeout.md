# Timeout Functionality: Client Perspective

## 1. Configuration at Init Time

When creating a client, you provide a `whTimeoutConfig` specifying the timeout duration and an optional callback:
```c
whTimeoutConfig timeoutCfg = {
    .timeoutUs = WH_SEC_TO_USEC(5),   /* 5-second timeout */
    .expiredCb = myTimeoutHandler,      /* optional callback on expiry */
    .cbCtx     = myAppContext,          /* context passed to callback */
};
whClientConfig clientCfg = {
    .comm              = &commConfig,
    .respTimeoutConfig = &timeoutCfg,   /* attach timeout config */
};
wh_Client_Init(&clientCtx, &clientCfg);
```

During `wh_Client_Init` (`src/wh_client.c:84-89`), the config is copied into an embedded `whTimeoutCtx respTimeout[1]` inside the client context via `wh_Timeout_Init()`. This stores the timeout duration and callback but doesn't start any timer yet.
If `respTimeoutConfig` is NULL, the timeout context is left zeroed and effectively disabled (a `timeoutUs` of 0 means "never expires").

## 2. What Happens During a Crypto Call

Before this PR, every crypto function in `wh_client_crypto.c` had this pattern after sending a request:
```c
/* Old pattern -- infinite busy-wait */
do {
    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len, dataPtr);
} while (ret == WH_ERROR_NOTREADY);
```

If the server never responded, the client would spin forever.
The PR replaces all ~30 of these with a single helper `_recvCryptoResponse()` (`src/wh_client_crypto.c:165-180`):
```c
static int _recvCryptoResponse(whClientContext* ctx,
                               uint16_t* group, uint16_t* action,
                               uint16_t* size, void *data)
{
    int ret;
#ifdef WOLFHSM_CFG_ENABLE_TIMEOUT
    ret = wh_Client_RecvResponseTimeout(ctx, group, action, size, data,
                                        ctx->respTimeout);
#else
    do {
        ret = wh_Client_RecvResponse(ctx, group, action, size, data);
    } while (ret == WH_ERROR_NOTREADY);
#endif
    return ret;
}
```

When timeout is enabled, it delegates to `wh_Client_RecvResponseTimeout`. When disabled, the old infinite-loop behavior is preserved.

## 3. The Timeout Receive Loop
`wh_Client_RecvResponseTimeout` (`src/wh_client.c:211-231`) does this:
1. **Starts the timer** -- calls `wh_Timeout_Start()` which snapshots the current time via `WH_GETTIME_US()` into `timeout->startUs`.
2. **Polls for a response** -- calls `wh_Client_RecvResponse()` in a loop.
3. **On each `WH_ERROR_NOTREADY`**, checks `wh_Timeout_Expired()`:
   - Gets the current time via `WH_GETTIME_US()`
   - Computes `(now - startUs) >= timeoutUs`
   - If expired: invokes the `expiredCb` (if set), then returns `WH_ERROR_TIMEOUT`
   - If not expired: loops again
4. **On any other return value** (success or error), returns immediately.
```
Client App                    _recvCryptoResponse                 wh_Timeout
    |                                |                                |
    |-- wh_Client_AesCbc() --------> |                                |
    |                                |-- wh_Timeout_Start --------> capture time
    |                                |                                |
    |                                |-- RecvResponse (NOTREADY)      |
    |                                |-- Expired? ------------------> no
    |                                |-- RecvResponse (NOTREADY)      |
    |                                |-- Expired? ------------------> no
    |                                |   ...                          |
    |                                |-- RecvResponse (NOTREADY)      |
    |                                |-- Expired? ------------------> YES
    |                                |                                |-- expiredCb()
    |<-- WH_ERROR_TIMEOUT -----------|                                |
```

## 4. What the Client Sees
From the application's perspective, the crypto APIs (`wh_Client_AesCbc`, `wh_Client_RsaFunction`, `wh_Client_EccSign`, etc.) now return `WH_ERROR_TIMEOUT` (-2010) instead of hanging indefinitely. The application can then decide how to handle it -- retry, log, fail gracefully, etc.
The `expiredCb` fires *before* the error is returned, so you can use it for logging or cleanup without needing to check the return code first.

## 5. Scope Limitations
A few things to note about the current design:
- **Only crypto responses are covered.** Non-crypto client calls (key management, NVM operations, comm init) still use the old infinite-wait pattern. The timeout is specifically wired into `_recvCryptoResponse`.
- **The timeout is per-client, not per-call.** All crypto operations for a given client share the same `respTimeout` context with the same duration. You can call `wh_Timeout_Set(ctx->respTimeout, newValue)` to change it between calls, but there's no per-operation override.
