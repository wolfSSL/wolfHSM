# Getting Started With wolfHSM

The most common use case for wolfHSM is adding HSM-enabled functionality to an existing application that runs on one of the application cores of a multi-core device with an HSM coprocessor.

The first step required to run wolfHSM on a device is to follow the steps in the specific wolfHSM port to get the reference server running on the HSM core. Once the wolfHSM server app is loaded on the device and boots, client applications can link against the wolfHSM client library, configure an instance of the wolfHSM client structure, and interact with the HSM through the wolfHSM client API and through the wolfCrypt API.

Each wolfHSM port contains a client demo app showing how to set up the default communication channel and interact with the server. The server reference implementation can also be customized through [server callbacks](./chapter07.md) to extend its functionality, which can be invoked through client requests.

## Basic Client Configuration

Configuring a wolfHSM client involves allocating a client context structure and initializing it with a valid client configuration that enables it to communicate with a server.

The client context structure `whClientContext` holds the internal state of the client and its communication with the server. All client APIs take a pointer to the client context.

The client configuration structure holds the communication layer configuration (`whCommClientConfig`) that will be used to configure and initialize the context for the server communication. The `whCommClientConfig` structure binds an actual transport implementation (either built-in or custom) to the abstract comms interface for the client to use.

The general steps to configure a client are:

1. Allocate and initialize a transport configuration structure, context, and callback implementation for the desired transport
2. Allocate comm client configuration structure and bind it to the transport configuration from step 1 so it can be used by the client
3. Allocate and initialize a client configuration structure using the comm client configuration in step 2
4. Allocate a client context structure
5. Initialize the client with the client configuration by calling `wh_Client_Init()`
6. Use the client APIs to interact with the server

Here is a bare-minimum example of configuring a client application to use the built-in shared memory transport to send an echo request to the server.

```c
#include <string.h> /* for memcmp() */
#include "wolfhsm/client.h"  /* Client API (includes comm config) */
#include "wolfhsm/wh_transport_mem.h" /* transport implementation */

/* Step 1: Allocate and initialize the shared memory transport configuration */
/* Shared memory transport configuration */
static whTransportMemConfig transportMemCfg = { /* shared memory config */ };
/* Shared memory transport context (state) */
whTransportMemClientContext transportMemClientCtx = {0};
/* Callback structure that binds the abstract comm transport interface to
 * our concrete implementation */
whTransportClientCb transportMemClientCb = {WH_TRANSPORT_MEM_CLIENT_CB};

/* Step 2: Allocate client comm configuration and bind to the transport */
/* Configure the client comms to use the selected transport configuration */
whCommClientConfig commClientCfg = {
             .transport_cb      = transportMemClientCb,
             .transport_context = (void*)transportMemClientCtx,
             .transport_config  = (void*)transportMemCfg,
             .client_id         = 123, /* unique client identifier */
};

/* Step 3: Allocate and initialize the client configuration */
whClientConfig clientCfg= {
   .comm = commClientCfg,
};

/* Step 4: Allocate the client context */
whClientContext clientCtx = {0};

/* Step 5: Initialize the client with the provided configuration */
wh_Client_Init(&clientCtx, &clientCfg);

/* Step 6: Use the client APIs to interact with the server */

/* Buffers to hold sent and received data */
char recvBuffer[WH_COMM_DATA_LEN] = {0};
char sendBuffer[WH_COMM_DATA_LEN] = {0};

uint16_t sendLen = snprintf(&sendBuffer,
                            sizeof(sendBuffer),
                            "Hello World!\n");
uint16_t recvLen = 0;

/* Send an echo request and block on receiving a response */
wh_Client_Echo(client, sendLen, &sendBuffer, &recvLen, &recvBuffer);

if ((recvLen != sendLen ) ||
    (0 != memcmp(sendBuffer, recvBuffer, sendLen))) {
    /* Error, we weren't echoed back what we sent */
}
```

For more information, refer to [Chapter 5: Client Library](./chapter05.md).

## Basic Server Configuration

*Note: A wolfHSM port comes with a reference server application that is already configured to run on the HSM core and so manual server configuration is not required.*

Configuring a wolfHSM server involves allocating a server context structure and initializing it with a valid client configuration that enables it to perform the requested operations. These operations usually include client communication, cryptographic operations, managing keys, and non-volatile object storage. Depending on the required functionality, not all of these configuration components need to be initialized.


The steps required to configure a server that supports client communication, NVM object storage using the NVM flash configuration, and local crypto (software only) are:

1. Initialize the server comms configuration
    1\. Allocate and initialize a transport configuration structure, context, and callback implementation for the desired transport
    2\. Allocate and initialize a comm server configuration structure using the transport configuration from step 1.1
2. Initialize the server NVM context
    1\. Allocate and initialize a config, context, and callback structure for the low-level flash storage drivers (the implementation of these structures is provided by the port)
    2\. Allocate and initialize an NVM flash config, context, and callback strucure and bind the port flash configuration from step 2.1 to them
    3\. Allocate an NVM context structure and initialize it with the configuration from step 2.2 using `wh_Nvm_Init()`
3.  Allocate and initialize a crypto context structure for the server
4. Initialize wolfCrypt (before initializing the server)
5. Allocate and initialize a server config structure and bind the comm server configuration, NVM context, and crypto context to it
6. Allocate a server context structure and initialize it with the server configuration using `wh_Server_Init()`
7. Set the server connection state to connected using `wh_Server_SetConnected()` when the underlying transport is ready to be used for client communication (see [wolfHSM Examples](https://github.com/wolfSSL/wolfHSM/tree/main/examples) for more information)
8. Process client requests using `wh_Server_HandleRequestMessage()`

The server may be configured to support NVM object storage using NVM flash configuration. Include the steps to [initialize NVM](./chapter04.md#NVM-Architecture) on the server after step 1.

```c
#include <string.h> /* for memcmp() */
#include "wolfhsm/server.h"  /* Server API (includes comm config) */
#include "wolfhsm/wh_transport_mem.h" /* transport implementation */

/* Step 1.1: Allocate and initialize the shared memory transport configuration */
/* Shared memory transport configuration */
static whTransportMemConfig transportMemCfg = { /* shared memory config */ };

/* Shared memory transport context (state) */
whTransportMemServerContext transportMemServerCtx = {0};

/* Callback structure that binds the abstract comm transport interface to
 * our concrete implementation */
whTransportServerCb transportMemServerCb = {WH_TRANSPORT_MEM_SERVER_CB};

/* Step 1.2: Allocate a comm server configuration structure and bind to the
 * transport */
/* Configure the server comms to use the selected transport configuration*/
whCommServerConfig commServerCfg = {
        .transport_cb       = transportMemServerCb,
        .transport_context  = (void*)transportMemServerCtx,
        .transport_config   = (void*)transportMemCfg,
        .server_id          = 456, /* unique server identifier */
};

/* Initialize the server NVM context */

/* Step 2.1: Allocate and initialize context and config for port-specific
 * flash storage drivers */

/* Port Flash context (structure names are port-specific)  */
MyPortFlashContext portFlashCtx = {0}

/* Port Flash config */
MyPortFlashConfig portFlashCfg = { /* port specific configuration */ };

/* NVM Flash callback implementation for Port Flash */
whFlashCb portFlashCb = { /* port flash implementation of NVM Flash callbacks */

/* Step 2.2: Allocate and initialize NVM flash config structure and bind to port
 * configuration from step 2.1 */
whNvmFlashConfig nvmFlashCfg = {
    .cb         = portFlashCb,
    .context    = portFlashCtx,
    .config     = portFlashCfg,
};
whNvmFlashContext nfc = {0};

/* Step 2.3: Allocate NVM context, config, and callback structure and initialize
 * with NVM flash configuration from step 2.2 */
whNvmCb nvmFlashCb = {WH_NVM_FLASH_CB};

whNvmConfig nvmConf = {
    .cb      = nvmFlashCb;
    .context = nfc;
    .config  = nvmFlashCfg,
};
whNvmContext nvmCtx = {0};

wh_Nvm_Init(&nvmCtx, &whNvmConfig);

/* Step 3: Allocate and initialize a crypto context structure */
whServerCryptoContext cryptoCtx = {0};

/* Allocate and initialize the Server configuration*/
whServerConfig serverCfg = {
        .comm   = commServerCfg,
        .nvm    = nvmCtx,
        .crypto = &cryptoCtx,
        .devId  = INVALID_DEVID, /* or set to custom crypto callback devID */
};

/* Step 4: Initialize wolfCrypt*/
wolfCrypt_Init();

/* Step 5: Allocate and initialize server config structure and bind the comm
 * server configuration and crypto context to it*/
whServerContext server = {0};
wh_Server_Init(&server, &serverCfg);

/* Set server connection state to connected when transport is ready (e.g.
 * shared memory buffers cleared) */
wh_Server_SetConnected(&server, WH_COMM_CONNECTED);

/* Process client requests*/
while (1) {
    wh_Server_HandleRequestMessage(&server);
}
```

