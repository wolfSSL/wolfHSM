# wolfHSM
wolfHSM provides a software framework to improve portability of code related to
hardware-provided cryptographic resources as well as non-volatile storage.
wolfHSM is intended to simplify the challenge of moving between hardware with
enhanced security features without being tied to any vendor-specific library
calls.

Although initially targeted to automotive-style HSM-enabled microcontrollers,
wolfHSM provides an extensible solution to support future capabilities of
platforms while still supporting standardized interfaces and protocols such as
PKCS11 and AUTOSAR SHE.

# wolfHSM Internals
To support easily porting wolfHSM to different hardware platforms and build
environments, wolfHSM components are designed to have a common initialization, 
configuration, and context storage architecture to allow compile-time, link-
time, and/or run-time selection of functional components.  Hardware specifics
are abstracted from the logical operations by associating callback functions
with untyped context structures, referenced as a void*.
 
## Example component initialization
The prototypical compile-time static instance configuration and initialization
sequence of a ported component is:

```
#include "wolfhsm/component.h"        /* wolfHSM abstract API reference for a component */
#include "port/vendor/mycomponent.h"  /* Platform specific definitions of configuration
                                       * and context structures, as well as declarations of
                                       * callback functions */ 

/* Provide the lookup table for function callbacks for mycomponent. Note the type
is the abstract type provided in wolfhsm/component.h */
whComponentCb my_cb[1] = {MY_COMPONENT_CB};

/* Fixed configuration data.  Note that pertinent data is copied out of the structure 
 * during init() */
const myComponentConfig my_config = {
    .my_number = 3,
    .my_string = "This is a string",
}

/* Static allocation of the dynamic state of the myComponent. */
myComponentContext my_context[1] = {0};

/* Initialization of the component using platform-specific callbacks */
const whComponentConfig comp_config[1] = {
        .cb = my_cb,
        .context = my_context,
        .config = my_config
    };
whComponentContext comp_context[1] = {0};
int rc = wh_Component_Init(comp_context, comp_config);

rc = wh_Component_DoSomething(comp_context, 1, 2, 3);
rc = wh_Component_CleanUp(comp_context);
```

## wolfHSM Functional Components
The wolfHSM server provides the combination of non-volatile object storage,
persistent key and counter management, boot image management, and offloaded 
(hardware accelerated) cryptographic operations within an isolated and securable
environment that is tailored to available hardware features.  
### API's
wh_NvmInit();
wh_NvmCleanup();

wh_KcInit();
wh_KcCleanup();

wh_ImageInit();
wh_ImageCleanup();

wh_CryptoInit();
wh_CryptoCleanup();


## Client/Server Roles
The wolfHSM client library and server application provide top-level features 
that combine the communication and message handling functions to simplify usage.
The wolfHSM server application follows a strict startup sequence and 
## Communication Client/Server 
The wolfHSM server responds to with multiple clients' requests via communication 
interfaces.  All communications are packet-based with a fixed-size header that
a transport provides to the library for message processing.  The split request 
and response processing supports synchronous polling of message reception or
asynchronous handling based on interrupt/event support.

### API's
wh_CommClientInit();
wh_CommClientSendRequest();
wh_CommClientRecvResponse();
wh_CommClientCleanup();

wh_CommServerInit();
wh_CommServerRecvRequest();
wh_CommServerSendResponse();
wh_CommServerCleanup();

### Example Split Transaction Processing
```
wh_ClientInit(context, config);

uint16_t req_magic = wh_COMM_MAGIC_NATIVE;
uint16_t req_type = 123;
uint16_t request_id;
char* req_data = "RequestData";
rc = wh_ClientSendRequest(context, req_magic, req_type, &request_id, 
                    sizeof(req_data), req_data);
/* Do other work */

uint16_t resp_magic, resp_type, resp_id, resp_size;
char response_data[20];
while((rc = wh_ClientRecvResponse(context,&resp_magic, &resp_type, &resp_id,
                    &resp_size, resp_data)) == WH_ERROR_NOTREADY) {
        /* Do other work or yield */
}
```


## Messages
Messages comprise a header with a variable length payload.  The header indicates
the sequence id, and type of a request or response.  The header also provides 
additional fields to provide auxiliary flags or session information. Each client
is only allowed a single outstanding request to the server at a time.  The
server will process a single request at a time to ensure client isolation.

Messages are used to encapsulate the request data necessary for the server to 
execute the desired function and for the response to provide the results of the
function execution back to the client.  Message types are grouped based on the 
component that is performing the function and uniquely identify which of the
enumerated functions is being performed.  To ensure compatibility (endianness,
and version), messages include a Magic field which has known values used to 
indicate what operations are necessary to demarshall data passed within the 
payload for native processing.  Each functional component has a "remote" 
implementation that converts between native values and the "on-the-wire" message
formats.  The servers ensures the response format matches the request format.

In addition to passing data contents within messages, certain message types also
support passing shared or mapped memory pointers, especially for performance-
critical operations where the server component may be able to directly access
the data in a DMA fashion.  To avoid integer pointer size (IPS) and size_t
differences, all pointers and sizes should be sent as uint64_t when
possible.

Messages are encoded in the "on-the-wire" format using the Magic field of the 
header indicating the specified endianness of structure members as well as the
version of the communications header (currently 0x01).  Server components that 
process request messages translate the provided values into native format, 
perform the task, and then reencode the result into the format of the request.
Client response handling is not required to process messages that do not match
the request format. Encoded messages assume the same size and layout as the
native structure, with the endianness specified by the Magic field.

Transport errors passed into the message layer are expected to be fatal and the
client/server should Cleanup any context as a result.

 
## Transport
Transports provide intact packets (byte sequences) of variable size (up to a
maximum MTU), to the messaging layer for the library to process as a request or 
response.  

## Resources
[wolfHSM Examples](https://www.github.com/wolfSSL/wolfHSM-examples)

### API's
wh_TransportInit();
wh_TransportSend();
wh_TransportRecv();
wh_TransportCleanup();
