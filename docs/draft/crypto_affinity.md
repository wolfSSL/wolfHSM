# Crypto Affinity Client API

The crypto affinity feature allows a client to control and query whether the server uses **software** or **hardware** cryptographic implementations.

## Affinity Values

```c
enum WH_CRYPTO_AFFINITY_ENUM {
    WH_CRYPTO_AFFINITY_SW = 0,  // Use software crypto (devId = INVALID_DEVID)
    WH_CRYPTO_AFFINITY_HW = 1,  // Attmept to use hardware crypto (devId = configured value)
};
```

## SetCryptoAffinity

### Blocking API (simplest)

```c
int wh_Client_SetCryptoAffinity(whClientContext* c, uint32_t affinity,
        int32_t* out_rc, uint32_t* out_affinity);
```

### Non-blocking (async) API

```c
// Send request
int wh_Client_SetCryptoAffinityRequest(whClientContext* c, uint32_t affinity);

// Receive response
int wh_Client_SetCryptoAffinityResponse(whClientContext* c, int32_t* out_rc,
        uint32_t* out_affinity);
```

## GetCryptoAffinity

### Blocking API (simplest)

```c
int wh_Client_GetCryptoAffinity(whClientContext* c,
        int32_t* out_rc, uint32_t* out_affinity);
```

### Non-blocking (async) API

```c
// Send request
int wh_Client_GetCryptoAffinityRequest(whClientContext* c);

// Receive response
int wh_Client_GetCryptoAffinityResponse(whClientContext* c, int32_t* out_rc,
        uint32_t* out_affinity);
```

## Usage Example

```c
int32_t  server_rc;
uint32_t current_affinity;

// Query current crypto affinity
int rc = wh_Client_GetCryptoAffinity(client,
        &server_rc,
        &current_affinity);

if (rc == WH_ERROR_OK && server_rc == WH_ERROR_OK) {
    // current_affinity contains the active affinity
}

// Switch to software crypto
rc = wh_Client_SetCryptoAffinity(client,
        WH_CRYPTO_AFFINITY_SW,
        &server_rc,
        &current_affinity);

if (rc == WH_ERROR_OK && server_rc == WH_ERROR_OK) {
    // Server is now using software crypto
    // current_affinity == WH_CRYPTO_AFFINITY_SW
}

// Switch to hardware crypto
rc = wh_Client_SetCryptoAffinity(client,
        WH_CRYPTO_AFFINITY_HW,
        &server_rc,
        &current_affinity);

if (rc == WH_ERROR_OK) {
    if (server_rc == WH_ERROR_OK) {
        // Server is now using hardware crypto
    } else if (server_rc == WH_ERROR_NOTIMPL) {
        // HW crypto not available (server wasn't configured with a valid devId)
    }
}
```

## Return Values

| Value | Description |
|-------|-------------|
| `rc` (function return) | Transport/communication errors |
| `server_rc` (output parameter) | Server-side result |

### Server Return Codes (SetCryptoAffinity)

| Code | Description |
|------|-------------|
| `WH_ERROR_OK` | Affinity changed successfully |
| `WH_ERROR_NOTIMPL` | HW requested but no HW crypto configured, `WOLF_CRYPTO_CB` is not defined, or `WOLFHSM_CFG_NO_CRYPTO` is defined |
| `WH_ERROR_BADARGS` | Invalid affinity value |
| `WH_ERROR_ABORTED` | Server crypto context is NULL |

### Server Return Codes (GetCryptoAffinity)

| Code | Description |
|------|-------------|
| `WH_ERROR_OK` | Affinity queried successfully |
| `WH_ERROR_ABORTED` | Server crypto context is NULL |
| `WH_ERROR_NOTIMPL` | Not implemented (returned when `WOLFHSM_CFG_NO_CRYPTO` is defined) |

## Server Behavior

When affinity is set:

| Affinity | Server Action |
|----------|---------------|
| `WH_CRYPTO_AFFINITY_SW` | `server->crypto->devId = INVALID_DEVID` (wolfCrypt uses software) |
| `WH_CRYPTO_AFFINITY_HW` | `server->crypto->devId = server->crypto->defaultDevId` (wolfCrypt uses registered crypto callback) |

When affinity is queried (Get), the server reads the current `devId` and returns the corresponding affinity value without modifying any state.

The `defaultDevId` is stored at server init from `config->devId`.
