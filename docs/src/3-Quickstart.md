# Quickstart

This quickstart example demonstrates a minimal, end-to-end overview of how to bring up wolfHSM and begin using it from both the client and server sides. It walks through the essential initialization steps required to initialize and run the wolfHSM server and process requests, as well as how to connect a client application to it using a supported transport.

This quickstart uses the built-in shared memory transport for communication, and the NVM flash implementation for NVM object storage. The actual flash drivers bound to the NVM flash layer are not defined, as they would be hardware specific.

The client and server are shown as two separate programs, mirroring a typical deployment where the server runs on a trusted HSM core and the client runs on an application core. Because the shared memory transport exchanges data through two shared buffers, both programs must reference the *same* physical memory: on real hardware these buffers live in a shared SRAM region placed at addresses agreed upon by both cores. Fully runnable POSIX versions (using the TCP and POSIX shared memory transports) are provided in [Examples and Demos](7-Examples.md).

Enough with the high level concepts and jargon, let's dive straight into the code...


## Client Quickstart

```c
#include <stdio.h>  /* for printf() */
#include <string.h> /* for strlen(), memcmp() */

#include "wolfhsm/wh_error.h"          /* WH_ERROR_OK and friends */
#include "wolfhsm/wh_client.h"         /* Client API (includes comm config) */
#include "wolfhsm/wh_transport_mem.h"  /* Shared-memory transport */

#define SHARED_BUFFER_SIZE 4096

/* Request and response buffers shared with the server core. The client writes
 * requests to gReqBuffer and reads responses from gRespBuffer. On real hardware
 * these must be placed (e.g. via the linker) in a memory region shared with the
 * server, so that both cores reference the identical buffers. */
uint8_t gReqBuffer[SHARED_BUFFER_SIZE];
uint8_t gRespBuffer[SHARED_BUFFER_SIZE];

int main(void)
{
    int rc;

    /* 1. Describe the shared-memory transport and its callback table */
    whTransportMemConfig transportCfg[1] = {{
        .req       = gReqBuffer,
        .req_size  = SHARED_BUFFER_SIZE,
        .resp      = gRespBuffer,
        .resp_size = SHARED_BUFFER_SIZE,
    }};
    whTransportClientCb         transportCb[1]  = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext transportCtx[1] = {0};

    /* 2. Bind the transport to the client comm configuration */
    whCommClientConfig commCfg[1] = {{
        .transport_cb      = transportCb,
        .transport_context = (void*)transportCtx,
        .transport_config  = (void*)transportCfg,
        .client_id         = 1, /* unique client identifier (1-15) */
    }};

    /* 3. Assemble the client configuration */
    whClientConfig clientCfg[1] = {{
        .comm = commCfg,
    }};

    /* 4. Initialize the client context */
    whClientContext client[1] = {0};
    rc = wh_Client_Init(client, clientCfg);
    if (rc != WH_ERROR_OK) {
        printf("wh_Client_Init failed: %d\n", rc);
        return 1;
    }

    /* 5. Connect to the server (exchanges client and server IDs) */
    rc = wh_Client_CommInit(client, NULL, NULL);
    if (rc != WH_ERROR_OK) {
        printf("wh_Client_CommInit failed: %d\n", rc);
        return 1;
    }

    /* 6. Use the client API. Here we send a blocking echo request. */
    {
        const char sendBuffer[] = "Hello, wolfHSM!";
        uint16_t   sendLen      = (uint16_t)strlen(sendBuffer);
        char       recvBuffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
        uint16_t   recvLen      = 0;

        rc = wh_Client_Echo(client, sendLen, sendBuffer, &recvLen, recvBuffer);
        if (rc == WH_ERROR_OK && recvLen == sendLen &&
            memcmp(sendBuffer, recvBuffer, sendLen) == 0) {
            printf("Server echoed: %.*s\n", recvLen, recvBuffer);
        }
        else {
            /* Error: we weren't echoed back exactly what we sent */
            printf("Echo failed: rc=%d\n", rc);
        }
    }

    /* 7. Close the connection and release the client context */
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);

    return 0;
}
```

## Server Quickstart

```c
#include <stdio.h> /* for printf() */

#include "wolfhsm/wh_error.h"          /* WH_ERROR_OK and friends */
#include "wolfhsm/wh_server.h"         /* Server API */
#include "wolfhsm/wh_transport_mem.h"  /* Shared-memory transport */
#include "wolfhsm/wh_nvm.h"            /* NVM abstraction */
#include "wolfhsm/wh_nvm_flash.h"      /* NVM-on-flash implementation */
#include "wolfhsm/wh_flash.h"          /* whFlashCb interface */

#define SHARED_BUFFER_SIZE 4096

/* The same shared buffers referenced by the client (see the client example).
 * The server reads requests from gReqBuffer and writes responses to
 * gRespBuffer. Both programs must reference the identical physical memory. */
uint8_t gReqBuffer[SHARED_BUFFER_SIZE];
uint8_t gRespBuffer[SHARED_BUFFER_SIZE];

/* The low-level flash driver is supplied by the platform port: a whFlashCb
 * callback table plus port-defined context and configuration structures. The
 * actual driver is hardware-specific and omitted here. On a host you can drop
 * in the bundled RAM simulator (wolfhsm/wh_flash_ramsim.h, WH_FLASH_RAMSIM_CB)
 * to run this example without real flash. */
extern const whFlashCb myFlashCb;
extern void*           myFlashContext;
extern const void*     myFlashConfig;

int main(void)
{
    int rc;

    /* 1. Describe the shared-memory transport and its callback table */
    whTransportMemConfig transportCfg[1] = {{
        .req       = gReqBuffer,
        .req_size  = SHARED_BUFFER_SIZE,
        .resp      = gRespBuffer,
        .resp_size = SHARED_BUFFER_SIZE,
    }};
    whTransportServerCb         transportCb[1]  = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext transportCtx[1] = {0};

    /* 2. Bind the transport to the server comm configuration */
    whCommServerConfig commCfg[1] = {{
        .transport_cb      = transportCb,
        .transport_context = (void*)transportCtx,
        .transport_config  = (void*)transportCfg,
        .server_id         = 1, /* server identifier */
    }};

    /* 3. Build the NVM context on top of the NVM-flash layer and flash driver */
    whNvmFlashConfig nvmFlashCfg[1] = {{
        .cb      = &myFlashCb,
        .context = myFlashContext,
        .config  = myFlashConfig,
    }};
    whNvmFlashContext nvmFlashCtx[1] = {0};
    whNvmCb           nvmCb[1]       = {WH_NVM_FLASH_CB};

    whNvmConfig nvmCfg[1] = {{
        .cb      = nvmCb,
        .context = nvmFlashCtx,
        .config  = nvmFlashCfg,
    }};
    whNvmContext nvm[1] = {0};

    rc = wh_Nvm_Init(nvm, nvmCfg);
    if (rc != WH_ERROR_OK) {
        printf("wh_Nvm_Init failed: %d\n", rc);
        return 1;
    }

    /* 4. Initialize wolfCrypt and seed the server's crypto context RNG */
    whServerCryptoContext crypto[1] = {0};
    wolfCrypt_Init();
    wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID);

    /* 5. Assemble the server configuration */
    whServerConfig serverCfg[1] = {{
        .comm_config = commCfg,
        .nvm         = nvm,
        .crypto      = crypto,
        .devId       = INVALID_DEVID, /* software crypto; use a crypto-callback
                                       * devId to offload to hardware */
    }};

    /* 6. Initialize the server context */
    whServerContext server[1] = {0};
    rc = wh_Server_Init(server, serverCfg);
    if (rc != WH_ERROR_OK) {
        printf("wh_Server_Init failed: %d\n", rc);
        return 1;
    }

    /* 7. Mark the transport connected once the shared memory is ready */
    wh_Server_SetConnected(server, WH_COMM_CONNECTED);

    /* 8. Service client requests. HandleRequestMessage is non-blocking and
     * returns WH_ERROR_NOTREADY when no request is pending. */
    while (1) {
        rc = wh_Server_HandleRequestMessage(server);
        if (rc != WH_ERROR_OK && rc != WH_ERROR_NOTREADY) {
            break; /* fatal transport error */
        }
    }

    wh_Server_Cleanup(server);
    return 0;
}
```

## Deep Dive

Now that you have seen the code, lets dive a little deeper and explain what is going on. We will use the server-side code as an example unless otherwise noted, as it also contains the majority of the steps necessary to initialize the client side.

### Transport Configuration

The transport is responsible for moving raw bytes between the client and the server. This example uses the built-in two-buffer shared-memory transport declared in `wolfhsm/wh_transport_mem.h`: the client writes requests into one buffer and reads responses from the other, while the server does the reverse.

`whTransportMemConfig` binds the two shared buffers and their sizes, while the `WH_TRANSPORT_MEM_SERVER_CB` macro (and `WH_TRANSPORT_MEM_CLIENT_CB` on the client) populates a callback table that adapts this concrete transport to the abstract transport interface that the comm layer consumes. Because both sides operate on the same two buffers, the memory referenced by `.req` and `.resp` must be physically shared between the client and server. wolfHSM ships with additional transports (TCP and POSIX shared memory) that plug in the exact same way by swapping the config, context, and callback structures. See [Communication Layer and Transports](5-Features.md#communication-layer-and-transports) for the full list and details.

### Comm Layer Configuration

The communication layer sits directly above the transport and implements the request/response protocol: message framing, sequence numbers, and endianness handling. The server binds its transport into a `whCommServerConfig`, providing the callback table, the transport context, the transport config, and a `server_id`. The client's `whCommClientConfig` is analogous but carries a `client_id` instead.

The `client_id` is significant: the server learns each client's identifier during the connection handshake, and uses it to keep per-client key caches and other resources isolated from one another. The request/response protocol these structures drive is the **split-transaction, non-blocking** model described in [Client/Server Communication](4-Architecture.md#clientserver-communication).

### NVM Configuration

Non-volatile storage is layered. From the bottom up:

1. A platform **flash driver** implements the `whFlashCb` callbacks (read/program/erase) for a specific device. This is the hardware-specific piece omitted from the example above; wolfHSM also bundles a RAM-backed simulator (`wolfhsm/wh_flash_ramsim.h`, `WH_FLASH_RAMSIM_CB`) that is handy for running on a host.
2. The **NVM flash** implementation (`whNvmFlashConfig` + `WH_NVM_FLASH_CB`) turns that raw flash into an object store with wear-aware, power-fail-safe semantics. It is bound to the flash driver via the `.cb`, `.context`, and `.config` fields.
3. The generic **NVM context** (`whNvmConfig` + `whNvmContext`) presents the high-level object API to the rest of the server. `wh_Nvm_Init()` initializes it from the configuration before the server is started.

This is the same callback-driven layering used throughout wolfHSM, so the NVM flash backend can be swapped for another NVM implementation without touching the server code. See [Non-Volatile Memory (NVM)](5-Features.md#non-volatile-memory-nvm) and [Flash Abstraction](5-Features.md#flash-abstraction).

### wolfCrypt Initialization

The server performs cryptographic operations with wolfCrypt, so `wolfCrypt_Init()` must be called before `wh_Server_Init()`. The server's `whServerCryptoContext` owns a wolfCrypt random number generator that must be seeded with `wc_InitRng_ex()`.

Passing `INVALID_DEVID` makes the server perform crypto in software. To offload to a hardware accelerator instead, register a wolfCrypt crypto callback and pass its device ID both to `wc_InitRng_ex()` and to the `.devId` field of the server configuration. Note that the client does *not* initialize wolfCrypt for offloaded operations: it transparently routes wolfCrypt API calls to the server by using its device ID — set in the client config's `.devId` field, or the default `WH_DEV_ID` when left `0` — read with `WH_CLIENT_DEVID(client)` after `wh_Client_Init()`. See [Cryptography and wolfCrypt Integration](5-Features.md#cryptography-and-wolfcrypt-integration).

### Initializing the Server Context

`whServerConfig` aggregates the three pieces configured above — the comm config (`.comm_config`), the initialized NVM context (`.nvm`), and the crypto context (`.crypto`) — into a single configuration. `wh_Server_Init()` wires them into the `whServerContext`, which from then on serves as the handle for all server operations.

After initialization, the server must be told when the underlying transport is actually ready for communication by calling `wh_Server_SetConnected(server, WH_COMM_CONNECTED)`. Until the server is connected, `wh_Server_HandleRequestMessage()` returns `WH_ERROR_NOTREADY`. On the client side, the corresponding steps are simply `wh_Client_Init()` followed by `wh_Client_CommInit()`.

### Processing Requests

Once connected, the server services requests by repeatedly calling `wh_Server_HandleRequestMessage()`. This function is non-blocking: it returns `WH_ERROR_NOTREADY` when no request is pending, processes and responds to a request when one is available, and only returns a hard error when the underlying transport fails. Errors that occur while *servicing* a request are reported back to the client inside the response message rather than failing the call, so the server loop only needs to break on fatal transport errors.

In this example the loop polls in a busy wait, which is fine for illustration; on real hardware this poll is typically driven by an inter-core interrupt so the HSM core can sleep between requests.

The client side mirrors this. `wh_Client_Echo()` used above is a blocking convenience helper that sends a request and polls for the matching response internally. For finer control, every client operation also exposes the underlying non-blocking split-transaction API as a `wh_Client_*Request()` / `wh_Client_*Response()` pair (for example, `wh_Client_EchoRequest()` and `wh_Client_EchoResponse()`), letting the caller send a request and poll for its response separately.
