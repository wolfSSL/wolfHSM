# Customizing wolfHSM

wolfHSM provides multiple points of customization via build time options and user-supplied callbacks, enabling it to to be tailored to a wide range of use cases and environments without requiring changes to the core library code. This chapter provides an overview of the customization options available in wolfHSM, including:

- [Library Configuration](#library-configuration): Compile-time options that can be used to enable or disable specific features in the library.
- [DMA Callbacks](#dma-callbacks): Custom callbacks that can be registered with the server to perform operations before and after accessing client memory directly.
- [DMA Address Allow List](#dma-address-allow-list): A mechanism for the server to restrict the client's access to specific memory regions.
- [Custom Callbacks](#custom-callbacks): Custom callbacks that can be registered with the server and invoked by the client to perform specific operations that are not covered by the default HSM capabilities.

## Library Configuration

The wolfHSM library has a number of build options that can be turned on or off though compile time definitions. The library expects these configuration macros to be defined in a configuration header named `wh_config.h`. This file should be defined by applications using wolfHSM and located in a directory in the compilers include path.

An example `wh_config.h` is distributed with every wolfHSM port providing a known good configuration.

For a full list of wolfHSM configuration settings that can be defined in `wh_config.h`, refer to the [API documentation](appendix01.md).

## DMA Callbacks

The Direct Memory Access (DMA) callback feature in wolfHSM provides hooks on the server side for custom operations before and after accessing client memory directly. This is often required when porting to a new shared memory architecture. The feature is particularly useful for scenarios where the server needs to perform specific actions such as cache invalidation, address translation, or other custom memory manipulations to ensure coherency between client and server memory.

Callbacks can be registered with a server using the `wh_Server_DmaRegisterCb32()` and `wh_Server_DmaRegisterCb64()` functions, which bind the supplied callback to all DMA operations on the server context.

Separate callback functions for handling 32 and 64-bit addresses are required, corresponding to the distinct 32 and 64-bit client DMA API functions. Callback functions are of type `whServerDmaClientMem32Cb` and `whServerDmaClientMem64Cb`, respectively, defined as:

```c
typedef int (*whServerDmaClientMem32Cb)(struct whServerContext_t* server,
                                        uint32_t clientAddr, void** serverPtr,
                                        uint32_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);
typedef int (*whServerDmaClientMem64Cb)(struct whServerContext_t* server,
                                        uint64_t clientAddr, void** serverPtr,
                                        uint64_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);
```

The DMA callback functions receive the following arguments:

- `server`: A pointer to the server context.
- `clientAddr`: The client memory address to be accessed.
- `serverPtr`: A pointer to a the server memory address (also a pointer), which the callback will set after applying any necessary transformations/remappings
- `len`: The length of the requested memory operation in bytes
- `oper`: The type of memory operation (injection point in the next section) that is about to be performed on the transformed server address
- `flags`: Additional flags for the memory operation. Right now these are reserved for future use and should be ignored.

The callback should return `WH_ERROR_OK` on success, or an error code if an error occurs. The server will propagate the error code back to the client if the callback fails.

### Callback Locations

The DMA callbacks are at four distinct points around the server's memory access:

- Pre-Read: Callback is invoked before reading data from the client memory. The server should use the callback to perform any necessary pre-read operations, such as address translation or cache invalidation.
- Post-Read: Callback is invoked after reading data from the client memory. The server should use the callback to perform any necessary post-read operations, such as cache synchronization.
- Pre-Write: Callback is invoked before writing data to the client memory. The server should use the callback to perform any necessary pre-write operations, such as address translation or cache invalidation.
- Post-write: Callback is invoked after writing data to the client memory. The server should use the callback to perform any necessary post-write operations, such as cache synchronization.

The point at which the callback is invoked is passed into the callback through the `oper` argument, which can take the following values:

```c
typedef enum {
    WH_SERVER_DMA_OPER_PRE_READ,  /* Pre-read operation */
    WH_SERVER_DMA_OPER_POST_READ, /* Post-read operation */
    WH_SERVER_DMA_OPER_PRE_WRITE, /* Pre-write operation */
    WH_SERVER_DMA_OPER_POST_WRITE /* Post-write operation */
} whServerDmaOper;
```

This enables the callback to `switch` on the `oper` value and perform custom logic based on the type of memory operation being performed. An example DMA callback implementation is shown below:

```c
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"

/* Example DMA callback for 32-bit client addresses */
int myDmaCallback32(whServerContext* server, uint32_t clientAddr,
                    void** xformedCliAddr, uint32_t len,
                    whServerDmaOper oper, whServerDmaFlags flags)
{
    /* Optionally transform client address to server address space, e.g. memmap() */
    *xformedCliAddr = (void*)clientAddr; /* do transformation */

    switch (oper) {
        case WH_DMA_OPER_CLIENT_READ_PRE:
            /* Pre-Read Operation here, e.g. cache invalidation */
            break;
        case WH_DMA_OPER_CLIENT_READ_POST:
            /* Post-Read Operation here */
            break;
        case WH_DMA_OPER_CLIENT_WRITE_PRE:
            /* Pre-Write Operation here */
            break;
        case WH_DMA_OPER_CLIENT_WRITE_POST:
            /* Post-Write Operation here, e.g. cache flush */
            break;
        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}
```

### Callback Registration

The callback can be registered with the server context, either at initialization through the server configuration structure, or at any time after initialization using the callback registration functions.

To register the callback at initialization, the callback function should be included in the DMA configuration structure within the server configuration structure. Note that the callback functions are optional, so unused callbacks can be set to `NULL`.

```c
#include "wolfhsm/wh_server.h"

/* Example of initializing a server config structr with a DMA32 callback then initializing the server */
int main(void)
{
    whServerDmaConfig dmaCfg = {0};
    dmaCfg.dma32Cb = myDmaCallback32;


    whServerConfig serverCfg = {
        .dmaCfg = dmaCfg,

        /* other configuration omitted for brevity */
    };

    whServerContext serverCtx;

    wh_Server_Init(&serverCtx, &serverCfg);

    /* server app logic */
}
```

To register the callback after initialization, first initialize the server context with the desired configuration, then call the appropriate registration function.

```c
#include "wolfhsm/wh_server.h"

int main(void)
{

    whServerConfig serverCfg =  { /* server config */ };

    whServerContext serverCtx;

    wh_Server_Init(&serverCtx, &serverCfg);

    /* register the callback defined above */
    wh_Server_DmaRegisterCb32(&serverCtx, myDmaCallback32);

    /* server app logic */
}
```

## DMA Address Allow List

wolfHSM also exposes an "allow list" for client DMA addresses, providing a mechanism for the server to restrict the client's access to a pre-configured list of specific memory regions. This feature is particularly useful in scenarios where the server needs to limit the client's access to certain memory regions to prevent unauthorized access or to ensure that the client only accesses memory that is safe to access. For example, in a multicore system with one client running per-core, it is most likely that clients should not be able to access each others memory regions, nor read out server memory which could contain sensitive information like cryptographic keys.

It is important to note that the software allow list feature is meant to work as a second layer of protection on top of device-specific memory protection mechanisms, and should not be considered a first line of defense in preventing unauthorized memory accesses. It is imperative that the user configure the device-specific memory protection mechanisms required to enforce the isolation of their applications and segment the HSM core and associated memory from the rest of the system.

### Registering an Allow List

Similar to the DMA callbacks, the allow list can be registered with the server context, either at initialization through the server configuration structure, or at any time after initialization using the allow list registration functions.

To register the list at initialization, the list should be populated in the DMA configuration structure inside the server configuration structure.

```c
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"

/* Define the allowed memory regions */
const whServerDmaAddrAllowList allowList = {
    .readList = {
        {(void*)0x20001000, 0x100},  /* Allow read from 0x20001000 to 0x200010FF */
        {(void*)0x20002000, 0x200},  /* Allow read from 0x20002000 to 0x200021FF */
    },
    .writeList = {
        {(void*)0x20003000, 0x100},  /* Allow write from 0x20003000 to 0x200030FF */
        {(void*)0x20004000, 0x200},  /* Allow write from 0x20004000 to 0x200041FF */
    },
};

int main()
{
    whServerConfig config;


    whServerDmaConfig dmaCfg = {0};
    dmaCfg.allowList = &allowList;

    whServerConfig serverCfg = {
        .dmaCfg = dmaCfg,
        /* other configuration omitted for brevity */
    };

    whServerContext server;

    wh_Server_Init(&server, &config);

    /* Server is now configured with the allowlist */
    /* Perform other server operations */

    /* Allow list can also be registered after initialization if the
     * list is not present in the server configuration struct using:
     *
     *    wh_Server_DmaRegisterAllowList(&server, &allowList);
     */
}
```

Once registered, all DMA operations requested of the server by the client will be checked against the allow list. If the client attempts to access a memory region that is not in the allow list, the server will return an error to the client, and the operation will not be performed.

## Custom Callbacks

The custom callback feature in wolfHSM allows developers to extend the functionality of the library by registering custom callback functions on the server. These callbacks can then be invoked by clients to perform specific operations that are not covered by the default HSM capabilities such as enabling or disabling peripheral hardware, implementing custom monitoring or authentication routines, staging secure boot for an additional core, etc.

### Server side

The server can register custom callback functions that define specific operations. These functions must be of type `whServerCustomCb`.

```c
/* wh_server.h */

/* Type definition for a custom server callback  */
typedef int (*whServerCustomCb)(
    whServerContext* server,   /* points to dispatching server ctx */
    const whMessageCustomCb_Request* req, /* request from client to callback */
    whMessageCustomCb_Response*      resp /* response from callback to client */
);

```

Custom server callback functions are associated with unique identifiers (IDs), which correspond to indices into the server's custom callback dispatch table. The client will refer to the callback by it's ID when it requests invocation.

The custom callback has access to data passed from the client by value or by reference (useful in a shared memory system) through the `whMessageCustomCb_Request` argument passed into the callback function. The callback can act on the input data and produce output data that can be passed back to the client through th e`whMessageCustomCb_Response` argument. The custom callback does not need to handle sending or receiving any of the input / output client data, as this is handled externally by wolfHSM. The response structure also contains fields for an error code and return code to propagate back to the client. The error code should be populated by the callback, and the return code will be set the return value from the custom callback.

### Client Side

Clients can send requests to the server to invoke these custom callbacks. The API provides a request and response function similar to the other functions in the client API. The client should declare an instance of a custom request structure, populate it with its custom data, and then send it to the server using `wh_Client_CustomCbRequest()`. The server response can then be polled using `wh_Client_CustomCbResponse()`, and the response data will populate the output `whMessageCustomCb_Response()` on successful receipt.

The client can also check the registration status of a given callback ID using the `wh_Client_CustomCheckRegistered()` family of functions. This function queries the server for whether a given callback ID is registered in its internal callback table. The server responds with a true or false indicating the registration status.

### Custom Messaging

The client is able to pass data in and receive data from the custom callbacks through the custom request and response message data structures.
These custom request and response messages are structured to include a unique ID, a type indicator, and a data payload.  The ID corresponds to the index in the server's callback table. The type field indicating to the custom callback how the data payload should be interpreted.
The data payload is a fixed size data buffer that the client can use in any way it wishes. The response structure contains additional error code values described above.

```c
/* request message to the custom server callback */
typedef struct {
    uint32_t               id;   /* indentifier of registered callback  */
    uint32_t               type; /* whMessageCustomCb_Type */
    whMessageCustomCb_Data data;
} whMessageCustomCb_Request;

/* response message from the custom server callback */
typedef struct {
    uint32_t id;   /* indentifier of registered callback  */
    uint32_t type; /* whMessageCustomCb_Type */
    int32_t  rc;   /* Return code from custom callback. Invalid if err != 0 */
    int32_t  err;  /* wolfHSM-specific error. If err != 0, rc is invalid */
    whMessageCustomCb_Data data;
} whMessageCustomCb_Response;
```

### Defining Custom Data Types

Custom data types can be defined using the `whMessageCustomCb_Data` union, which provides several helpful predefined structures for common data types (e.g., dma32, dma64) and a raw data buffer (buffer) for user-defined schemas. Clients can indicate to the server callback how it should interpret the data in the union through the `type` field in the request. wolfHSM reserves the first few type indices for internal use, with the remainder of the type values available for custom client types.


### Custom Callback Example

In this example, a custom callback is implemented that is able to process three types of client requests, one using the built-in DMA-style addressing type, and two that use custom user defined types.

First, common messages shared between the client and server should be defined:

```c
/* my_custom_cb.h */

#include "wolfhsm/wh_message_customcb.h"

#define MY_CUSTOM_CB_ID 0

enum {
	MY_TYPE_A = WH_MESSAGE_CUSTOM_CB_TYPE_USER_DEFINED_START,
	MY_TYPE_B,
} myUserDefinedTypes;

typedef struct {
	int foo;
	int bar;
} myCustomCbDataA;

typedef struct {
	int noo;
	int baz;
} myCustomCbDataB;
```

On the server side, the callback must be defined and then registered with the server context before processing requests. Note that the callback can be registered at any time, not necessarily before processing the first request.

```c
#include "wolfhsm/wh_server.h"
#include "my_custom_cb.h"

int doWorkOnClientAddr(uint8_t* addr, uint32_t size) {
	/* do work */
}

int doWorkWithTypeA(myCustomTypeA* typeA) {
	/* do work */
}

int doWorkWithTypeB(myCustomTypeB* typeB) {
	/* do work */
}

static int customServerCb(whServerContext*                 server,
                          const whMessageCustomCb_Request* req,
                          whMessageCustomCb_Response*      resp)
{
	int rc;

	resp->err = WH_ERROR_OK;

	/* detect and handle DMA request */
    if (req->type == WH_MESSAGE_CUSTOM_CB_TYPE_DMA32) {
		uint8_t* clientPtr = (uint8_t*)((uintptr_t)req->data.dma32.client_addr);
		size_t clientSz = req->data.dma32.client_sz;

		if (clientPtr == NULL) {
			resp->err = WH_ERROR_BADARGS;
		}
		else {
			rc = doWorkOnClientAddr(clientPtr, clientSz);
		}
    }
	else if (req->type == MY_TYPE_A) {
		myCustomCbDataA *data = (myCustomCbDataA*)((uintptr_t)req->data.data);
		rc = doWorkWithTypeA(data);
		/* optionally set error code of your choice */
		if (/* error condition */) {
			resp->err = WH_ERROR_ABORTED;
		}
	}
	else if (req->type == MY_TYPE_B) {
		myCustomCbDataB *data = (myCustomCbDataB)((uintptr_t)req->data.data);
		rc = doWorkWithTypeB(data);
		/* optionally set error code of your choice */
		if (/* error condition */) {
			resp->err = WH_ERROR_ABORTED;
		}
	}

    return rc;
}


int main(void) {

	whServerContext serverCtx;

	whServerConfig serverCfg = {
		/* your server configuration */
	};

	wh_Server_Init(&serverCtx, &serverCfg);

	wh_Server_RegisterCustomCb(&serverCtx, MY_CUSTOM_CB_ID, customServerCb));

	/* process server requests (simplified) */
	while (1) {
		wh_Server_HandleRequestMessage(&serverCtx);
	}

}
```

Now the client is able to check the registration of the custom callback, as well as invoke it remotely:

```c
#include "wh_client.h"
#include "my_custom_cb.h"

whClientContext clientCtx;
whClientConfig  clientCfg = {
	/* your client configuration */
};

whClient_Init(&clientCtx, &clientCfg);

bool isRegistered = wh_Client_CustomCheckRegistered(&client, MY_CUSTOM_CB_ID);

if (isRegistered) {
	uint8_t buffer[LARGE_SIZE] = {/* data*/};
	myCustomCbDataA typeA = {/* data */};
	myCustomCbDataB typeB = {/* data */};

	whMessageCustomCb_Request req = {0};
	whMessageCustomCb_Request resp = {0};

	/* send custom request with built-in DMA type */
	req.id = MY_CUSTOM_CB_ID;
    req.type                   = WH_MESSAGE_CUSTOM_CB_TYPE_DMA32;
    req.data.dma32.client_addr = (uint32_t)((uintptr_t)&data);
    req.data.dma32.client_sz   = sizeof(data);
    wh_Client_CustomCbRequest(clientCtx, &req);
    wh_Client_CustomCbResponse(clientCtx, &resp);
	/* do stuff with response */

	/* send custom request with a user defined type */
	memset(req, 0, sizeof(req));
	req.id = MY_CUSTOM_CB_ID;
    req.type = MY_TYPE_A;
	memcpy(&req.data.data, typeA, sizeof(typeA));
    wh_Client_CustomCbRequest(clientCtx, &req);
    wh_Client_CustomCbResponse(clientCtx, &resp);
	/* do stuff with response */

	/* send custom request with a different user defined type */
	memset(req, 0, sizeof(req));
	req.id = MY_CUSTOM_CB_ID;
    req.type = MY_TYPE_B;
	memcpy(&req.data.data, typeA, sizeof(typeB));
    wh_Client_CustomCbRequest(clientCtx, &req);
    wh_Client_CustomCbResponse(clientCtx, &resp);
	/* do stuff with response */
}

```

