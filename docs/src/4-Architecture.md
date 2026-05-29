# Architecture

## Client/server libraries

wolfHSM is built as two cooperating libraries:

- Client library: linked into a client application and exposes an API for key management, NVM object storage, certificate chain verification, and other core functionality. It also integrates with wolfCrypt and allows client applications to use the wolfCrypt cryptography API directly with transparent offload to the HSM server.
- Server library: linked into a server application running in a trusted environment, typically on an isolated CPU core, and owns the actual cryptographic material, key caches, NVM storage, and hardware integration points.

## Code and API organization

The codebase has the following organizational layout:

- `wolfhsm/`: Header files, both external and internal
- `src/`: Core library source code
- `test/`: Test suite
- `benchmark/`: Benchmark suite
- `examples/`: Example POSIX server and client applications, as well as client-facing demo functions for core features
- `port/`: Public platform port code. Currently only contains POSIX port, as all hardware platforms are behind vendor NDA
- `tools/`: Tools and utilities
- `docs/`: Documentation

### Client API

The core client API is defined in `wolfhsm/wh_client.h`. Public client functions are prefixed with `wh_Client_`. Most client applications only need the interfaces provided by this header and the wolfCrypt API. The AUTOSAR SHE client compatibility interface is defined separately in `wolfhsm/wh_client_she.h`.

A client’s connection to a server is represented by the `whClientContext` structure. After initialization with the appropriate transport configuration, this context serves as the handle for all client-side wolfHSM operations, ensuring that requests and responses are routed through the correct communication interface. For most operations, state is held by the client, unless the state is cryptographically sensitive.

### Server API

The server API is divided across multiple header files in `wolfhsm/wh_server*.h` and may be consumed on a per-module basis. Core server functionality like initialization, teardown, and request processing are defined in `wolfhsm/wh_server.h`. Additional capabilities are exposed through module-specific headers.

A server’s connection to a client is represented by the `whServerContext` structure. Unlike the client context, which primarily encapsulates a single communication interface, the server context aggregates a wider set of stateful and platform-specific resources. This includes runtime-initialized callbacks for module implementations, persistent and transient state required to service client requests, and integrations with platform services such as NVM, DMA access, and logging. Some of these resources and state are per-client and others are global.

Once initialized with the appropriate use-case-specific configuration, the server context serves as the central handle for all server-side wolfHSM operations, ensuring that requests and responses are routed through the correct communication interface and processed using the appropriate module implementations and platform resources.

### Important Source Modules

- `src/wh_client*.c`: client-side API, request construction, and crypto callback integration.
- `src/wh_server*.c`: server-side functionality including request processing, crypto, key cache control, etc.
- `src/wh_comm.c`: high level communication layer abstraction for server and client.
- `src/wh_transport*.c`: low level transport abstraction with pluggable back-ends (memory buffers, TCP, POSIX shared memory).
- `src/wh_message*.c`: protocol encoding/decoding, fixed-size message framing, and command identifiers.
- `src/wh_nvm*.c`: non-volatile storage abstraction with pluggable back-ends.

### Compiling Source Files

When building wolfHSM for the client or server, it is safe to wildcard include all C source files in the `src/` directory and pass them to your compiler. All wolfHSM code is internally protected by library configuration macros ensuring that only relevant code will be conditionally compiled based on the supplied configuration. For more information see [Library Configuration](#library-configuration).

## Client/Server Communication

All client/server communication follows a strict request/response model. A request is a message sent from a client to a server, and a response is the corresponding reply from the server to that specific request. Each response uniquely maps to a single outstanding request.

### Client Communication

The client API uses a **split-transaction, non-blocking** communication model composed of two explicit phases:

1. **Send Request**: The client invokes an API function to transmit a request to the server. The function returns immediately and may report a “not ready” condition if the underlying transport is unable to accept the request, in which case the caller is expected to retry.

2. **Receive Response**: The client invokes the corresponding receive API to poll for the server’s response to a previously sent request. This operation is non-blocking and may return “not ready” if the response has not yet arrived.

Each request is tagged with a sequence number that is internally validated against the received response, ensuring that the client processes the correct reply and does not consume a stale or mismatched message.

### Server Communication

The server is designed to operate within an event-driven loop for each connected client, continuously polling for pending requests.

After initialization, the server repeatedly calls `wh_Server_HandleRequestMessage()` on a given `whServerContext` to check for incoming requests in a non-blocking manner. The function returns “not ready” when no request is pending. When a request is available, it is processed internally and dispatched to the appropriate module handler, which generates the corresponding response message that is sent back to the client.

Errors that occur while servicing a client request are treated as non-fatal and are reported to the client as part of the response. The `wh_Server_HandleRequestMessage()` function itself only fails when an error occurs in the underlying communication stack while receiving or transmitting a request.

### Communication Stack

wolfHSM's communication is structured as a two-layer stack that sits beneath every client and server API. The **comm layer** owns the request/response framing described above: the versioned packet header, sequence numbering, and the send/receive primitives that the higher-level APIs build on. Beneath it, the **transport layer** is a thin, pluggable interface whose only responsibility is to move a single packet between the two endpoints. The comm layer reaches the underlying medium exclusively through this interface, so the same client and server code runs unchanged whether packets travel over shared memory on a multi-core SoC, a hardware mailbox, TCP, or anything else — supporting a new medium means supplying a transport, not modifying the core library.

The stack is symmetric across the client/server boundary:

```
                       client                                                    server
  ┌────────────┐    ┌────────────┐    ┌────────────┐        ┌────────────┐    ┌────────────┐    ┌────────────┐
  │ Client API │<──>│ Comm layer │<──>│ Transport  │<══════>│ Transport  │<──>│ Comm layer │<──>│ Server API │
  └────────────┘    └────────────┘    └────────────┘   │    └────────────┘    └────────────┘    └────────────┘
                                                       │
                                          underlying transport medium
                                       (shared memory, TCP, mailbox, …)
```

For the packet header layout, sequence-numbering rules, and the reference transports wolfHSM ships with, see [Communication Layer and Transports](5-Features.md#communication-layer-and-transports).

## Library Configuration

wolfHSM is configured at build time using a set of `WOLFHSM_CFG_XXX` preprocessor macros. These configuration macros are used to:

- Enable or disable library features
- Control sizing and resource limits (e.g. message buffer size, NVM object count, key cache size, etc.)
- Specify user-supplied override functions for platform-specific behavior (e.g. cache operations, system time retrieval, `printf` and stdout functionality, etc.)

Each configuration option provides a sane default that allows the library to build and operate in its default configuration without user intervention. All options may be overridden at build time to customize the library for a specific use case or platform.

The only configuration that **must** be supplied by the user is a mechanism to obtain the system time, either by defining `WOLFHSM_CFG_PORT_GETTIME` or by explicitly disabling system time support with `WOLFHSM_CFG_NO_SYS_TIME`. In practice, this requirement is typically handled by the port layer provided with a given platform and is only relevant when porting wolfHSM to a new environment.

Configuration macros may be provided directly on the compiler command line, or more commonly, via a user-defined configuration header named `wolfhsm_cfg.h`. When using a configuration header (recommended when more than a small number of options are being customized), the user must:

1. Create a file named `wolfhsm_cfg.h` containing `#define` statements for the desired `WOLFHSM_CFG_XXX` values
2. Ensure the file resides in a directory included in the compiler’s header search path (for example, via `-I`)
3. Define the `WOLFHSM_CFG` macro when invoking the compiler (for example, `-DWOLFHSM_CFG`)

Once these steps are completed, wolfHSM will use the user-defined configuration values in place of the internal defaults.

Note that the default base configuration and global library settings are defined in `wolfhsm/wh_settings.h`. Every wolfHSM source file includes this header first to establish the configuration environment. When `WOLFHSM_CFG` is defined, `wh_settings.h` conditionally includes `wolfhsm_cfg.h`, ensuring that user-supplied overrides are applied before any internal defaults are used.

For an exhaustive list of all wolfHSM config macros, see [9-Configuration.md](9-Configuration.md).

## Internals Deep Dive: Modular Architecture

wolfHSM is highly modular and built around an internal architecture that uses generic interfaces for core subsystems such as communications/transport, non-volatile memory (NVM) storage, and logging. Concrete implementations of these interfaces are selected and bound at runtime through a configuration structure supplied upon initialization. This design enables independent selection of both software and hardware implementations for each subsystem.

Put another way: Instead of binding to a single implementation or hardware driver stack, each system-facing module exposes an interface that is implemented via callbacks. The core library depends only on these interfaces, not on any platform specifics.

The following snippet is an abstract example of how this looks for an arbitrary wolfHSM "component":

```c
#include "wolfhsm/component.h"        /* wolfHSM abstract API reference for a component */
#include "port/vendor/mycomponent.h"  /* Platform specific definitions of configuration
                                       * and context structures, as well as declarations of
                                       * callback functions */

/* Provide the lookup table (vtable) for function callbacks for mycomponent.
 *Note the type is the abstract type provided in wolfhsm/component.h */
whComponentCb my_cb = {MY_COMPONENT_CB};

/* Fixed configuration data.  Note that pertinent data is copied out of the structure
 * during init() */
const myComponentConfig my_config = {
    .my_number = 3,
    .my_string = "This is a string",
}

/* Static allocation of the dynamic state of the myComponent. */
myComponentContext my_context = {0};

/* Initialization of the component using platform-specific callbacks */
const whComponentConfig comp_config = {
        .cb = my_cb,
        .context = my_context,
        .config = my_config
    };
whComponentContext comp_context = {0};
int rc = wh_Component_Init(comp_context, comp_config);

rc = wh_Component_DoSomething(comp_context, 1, 2, 3);
rc = wh_Component_CleanUp(comp_context);
```

Modules in wolfHSM that are currently implemented in this way are:

- Transports: define how bytes move between client and server. The core library only cares about send/receive semantics and state management.
- NVM: define how persistent storage on the server is formatted and accessed.
- Logging: Internal logging uses configurable logging backends that implement their own schema and read/write/erase/export operations.
- Mutex abstraction: Internal resource serialization is written against a generic "lock" interface that uses port-specific mutex abstractions.

