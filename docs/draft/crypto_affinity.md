# Crypto Affinity Client API

The crypto affinity feature allows a client to control whether the server uses **software** or **hardware** cryptographic implementations on a per-request basis.

Affinity is stored as **client-local state** and is transmitted to the server in every crypto request message header. There is no dedicated round-trip required to change affinity -- setting it is instantaneous and takes effect on the next crypto operation. Affinity persists for all subsequent requests once changed.

## Affinity Values

```c
enum WH_CRYPTO_AFFINITY_ENUM {
    WH_CRYPTO_AFFINITY_HW = 0,  // Attempt to use hardware crypto (devId = configured value)
    WH_CRYPTO_AFFINITY_SW = 1,  // Use software crypto (devId = INVALID_DEVID)
};
```

The default affinity after client initialization is `WH_CRYPTO_AFFINITY_HW`.

## API

### SetCryptoAffinity

```c
int wh_Client_SetCryptoAffinity(whClientContext* c, uint32_t affinity);
```

Sets the client's crypto affinity. This is a **local operation** that does not communicate with the server. The new affinity value will be included in all subsequent crypto request messages.

**Parameters:**
- `c` -- Client context
- `affinity` -- `WH_CRYPTO_AFFINITY_SW` or `WH_CRYPTO_AFFINITY_HW`

**Returns:**
- `WH_ERROR_OK` -- Affinity set successfully
- `WH_ERROR_BADARGS` -- NULL context or invalid affinity value

### GetCryptoAffinity

```c
int wh_Client_GetCryptoAffinity(whClientContext* c, uint32_t* out_affinity);
```

Retrieves the client's current crypto affinity. This is a **local operation** that does not communicate with the server.

**Parameters:**
- `c` -- Client context
- `out_affinity` -- Pointer to receive the current affinity value

**Returns:**
- `WH_ERROR_OK` -- Affinity retrieved successfully
- `WH_ERROR_BADARGS` -- NULL context or NULL output pointer

## Usage Example

```c
uint32_t affinity;

/* Default affinity is WH_CRYPTO_AFFINITY_SW after wh_Client_Init() */
wh_Client_GetCryptoAffinity(client, &affinity);
/* affinity == WH_CRYPTO_AFFINITY_SW */

/* Switch to hardware crypto -- takes effect immediately, no round-trip */
int rc = wh_Client_SetCryptoAffinity(client, WH_CRYPTO_AFFINITY_HW);
if (rc == WH_ERROR_OK) {
    /* All subsequent crypto operations will request HW acceleration */
}

/* Perform a crypto operation -- affinity is sent in the request header */
wc_AesCbcEncrypt(&aes, out, in, len);
/* If server has a valid devId, hardware crypto callback is used */

/* Switch back to software crypto */
wh_Client_SetCryptoAffinity(client, WH_CRYPTO_AFFINITY_SW);
/* Subsequent crypto operations use software implementation */
```

## Server Behavior

When the server receives a crypto request, it reads the affinity field from the generic crypto request header and selects the appropriate `devId`:

| Affinity in Request | Server Action |
|---------------------|---------------|
| `WH_CRYPTO_AFFINITY_SW` | Uses `INVALID_DEVID` (wolfCrypt software implementation) |
| `WH_CRYPTO_AFFINITY_HW` | Uses `server->defaultDevId` if valid, otherwise falls back to `INVALID_DEVID` |

The `defaultDevId` is configured at server initialization from `config->devId`. If the server was not configured with a valid hardware `devId`, hardware affinity requests will silently fall back to software crypto.

## Protocol Details

Affinity is transmitted in the `affinity` field of `whMessageCrypto_GenericRequestHeader`, which is included at the start of every crypto request message. This means:

- Each crypto operation independently specifies its desired affinity
- Multiple clients can use different affinities concurrently without interference
- No server-side affinity state is maintained per-client
- Changing affinity has zero latency (no communication overhead)
