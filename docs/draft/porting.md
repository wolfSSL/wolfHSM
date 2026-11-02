# Porting wolfHSM

This guide describes how to port wolfHSM to a new platform. A port provides
platform-specific implementations of transport, flash/NVM, and the `wh_Port_*`
generic API so that the platform-independent client and server examples in
`examples/generic/` can run on your hardware.

The POSIX port in `port/posix/` serves as a reference implementation throughout
this guide.

## Directory Layout

A port lives under `port/<platform>/` and typically has this structure:

```
port/<platform>/
├── Makefile                    # Top-level: delegates to client/ and server/
├── <shared transport/util>.c/h # Platform-specific shared code
├── client/
│   ├── Makefile
│   ├── wolfhsm_cfg.h          # wolfHSM compile-time configuration
│   ├── user_settings.h         # wolfSSL compile-time configuration
│   └── wh_<platform>_client_port.c  # wh_Port_* client implementation
└── server/
    ├── Makefile
    ├── wolfhsm_cfg.h
    ├── user_settings.h
    └── wh_<platform>_server_port.c  # wh_Port_* server implementation
```

The client and server are built as separate binaries with separate configuration
headers. This separation is important because the client and server typically
have different wolfSSL feature sets, crypto algorithm support, and wolfHSM roles.

## Step 1: Implement a Transport

wolfHSM communicates between client and server through a transport layer. You
must provide callback tables that match these interfaces (defined in
`wolfhsm/wh_comm.h`):

### Client Transport Callbacks

```c
typedef struct {
    int (*Init)(void* context, const void* config,
            whCommSetConnectedCb connectcb, void* connectcb_arg);
    int (*Send)(void* context, uint16_t size, const void* data);
    int (*Recv)(void* context, uint16_t *out_size, void* data);
    int (*Cleanup)(void* context);
} whTransportClientCb;
```

### Server Transport Callbacks

```c
typedef struct {
    int (*Init)(void* context, const void* config,
            whCommSetConnectedCb connectcb, void* connectcb_arg);
    int (*Recv)(void* context, uint16_t *out_size, void* data);
    int (*Send)(void* context, uint16_t size, const void* data);
    int (*Cleanup)(void* context);
} whTransportServerCb;
```

### Return Codes

All transport callbacks must return:

- `WH_ERROR_OK` (0) — Success.
- `WH_ERROR_BADARGS` — NULL context/config or invalid parameters.
- `WH_ERROR_NOTREADY` — Operation cannot complete yet; caller should retry.
- `WH_ERROR_ABORTED` — Fatal error; caller should clean up.

### Guidelines

- `Init` must store the `connectcb` and call it with `WH_COMM_CONNECTED` when
  the transport link is established. The generic server loop relies on this
  notification to know when a client has connected.
- `Send` and `Recv` should be non-blocking. Return `WH_ERROR_NOTREADY` if the
  operation cannot complete immediately.
- Transport implementations typically define a macro (e.g. `PTT_CLIENT_CB`,
  `PTT_SERVER_CB`) that expands to the callback table initializer.

See `port/posix/posix_transport_tcp.c` for a TCP socket-based reference
implementation.

wolfHSM also provides a shared memory transport (`wh_transport_mem`) that uses a
shared memory region containing request and response buffers plus an optional DMA
block. One side creates the shared region; the other maps it by name or address.
The DMA region allows the client to use DMA-style requests by setting its DMA
base address to the mapped address of the shared block. This transport is well
suited for platforms where client and server share an address space or have
hardware-mapped shared memory (e.g. dual-core HSM designs).

## Step 2: Implement Flash and NVM (Server Only)

The server requires a flash backend for NVM storage. Implement the `whFlashCb`
callback table defined in `wolfhsm/wh_flash.h`:

```c
typedef struct {
    int (*Init)(void* context, const void* config);
    int (*Cleanup)(void* context);
    uint32_t (*PartitionSize)(void* context);
    int (*WriteLock)(void* context, uint32_t offset, uint32_t size);
    int (*WriteUnlock)(void* context, uint32_t offset, uint32_t size);
    int (*Read)(void* context, uint32_t offset, uint32_t size, uint8_t* data);
    int (*Program)(void* context, uint32_t offset, uint32_t size,
                   const uint8_t* data);
    int (*Erase)(void* context, uint32_t offset, uint32_t size);
    int (*Verify)(void* context, uint32_t offset, uint32_t size,
                  const uint8_t* data);
    int (*BlankCheck)(void* context, uint32_t offset, uint32_t size);
} whFlashCb;
```

For development and testing, wolfHSM provides `wh_flash_ramsim` — a RAM-based
flash simulator that can be used on any platform. The POSIX server port uses
this. For production, you will typically implement callbacks that talk to your
platform's actual flash hardware.

The flash backend is wired into NVM through `whNvmFlashConfig` and
`whNvmFlashContext`, then into the server via `whNvmConfig`. See
`port/posix/server/wh_posix_server_port.c` (`wh_Port_ConfigureServer`) for the
full wiring example.

## Step 3: Implement the wh_Port_* API

The `wh_Port_*` functions (declared in `wolfhsm/wh_port.h`) are the glue
between the generic examples and your platform. You implement them in your
port's `wh_<platform>_client_port.c` and `wh_<platform>_server_port.c`.

### Common Functions

```c
int wh_Port_InitBoard(void);
```

Called once at startup. Initialize any shared platform resources: crypto
libraries, IPC mechanisms, signal handlers, or hardware peripherals.

```c
int wh_Port_CleanupBoard(void);
```

Called at shutdown. Release resources allocated by `InitBoard`.

### Client Functions

```c
int wh_Port_ConfigureClient(whClientConfig* clientCfg);
```

Populate `clientCfg` with transport callbacks, transport context/config, client
ID, and optionally a connect callback. The transport context and configuration
structures must be statically allocated (they must outlive the client).

```c
int wh_Port_InitClient(whClientConfig* clientCfg, whClientContext* clientCtx);
```

Initialize the client context and establish communication. Typically calls
`wh_Client_Init()` followed by `wh_Client_CommInit()`.

```c
int wh_Port_RunClient(whClientContext* clientCtx);
```

Execute the client workload. This is where your application logic goes — echo
requests, key operations, crypto operations, etc. Should call
`wh_Client_CommClose()` and `wh_Client_Cleanup()` before returning.

### Server Functions

```c
int wh_Port_ConfigureServer(size_t instance, whServerConfig* serverCfg);
```

Populate `serverCfg` with transport, NVM, and crypto configuration for the given
server instance. The `instance` parameter supports multiple server instances
(e.g. serving multiple clients concurrently).

```c
int wh_Port_InitServer(size_t instance, whServerConfig* serverCfg,
                       whServerContext* serverCtx);
```

Initialize a server instance. Typically calls `wh_Server_Init()`.

```c
int wh_Port_CleanupServer(size_t instance, whServerContext* serverCtx);
```

Clean up a server instance. Typically calls `wh_Server_Cleanup()`.

```c
int wh_Port_ClientConnected(size_t instance);
int wh_Port_ClientDisconnected(size_t instance);
```

Polling functions that return 1 **once** when a client connects or disconnects
from the given server instance, and 0 otherwise. The generic server loop uses
these to decide when to initialize or tear down server instances.

How you implement the notification mechanism is platform-specific. The POSIX port
uses a named FIFO: the client's `connect_cb` writes a byte to the FIFO on
connect/disconnect, and the server reads from it in these polling functions.
Other ports might use shared memory flags, hardware interrupts, or mailbox
registers.

## Step 4: Create Configuration Headers

### wolfhsm_cfg.h

This header defines wolfHSM compile-time options. It must be on the include path
before any wolfHSM headers are included (achieved by putting the project
directory first in `-I` flags).

**Required defines:**

| Define | Description |
|--------|-------------|
| `WOLFHSM_CFG_ENABLE_CLIENT` | Enable client functionality (client build) |
| `WOLFHSM_CFG_ENABLE_SERVER` | Enable server functionality (server build) |
| `WOLFHSM_CFG_COMM_DATA_LEN` | Max comm payload size in bytes |
| `WOLFHSM_CFG_NVM_OBJECT_COUNT` | Max NVM objects (must match client and server) |

**Port-specific defines** (naming convention: `WOLFHSM_CFG_PORT_*`):

| Define | Description |
|--------|-------------|
| `WOLFHSM_CFG_PORT_GETTIME` | Function returning current time in microseconds (`uint64_t`) |
| `WOLFHSM_CFG_PORT_CLIENT_ID` | Client identifier byte |
| `WOLFHSM_CFG_PORT_SERVER_ID` | Server identifier byte |
| `WOLFHSM_CFG_PORT_SERVER_COUNT` | Number of server instances |

You may define additional `WOLFHSM_CFG_PORT_*` macros for your platform's
transport configuration (IP addresses, ports, memory regions, etc.).

**Server-specific defines** (see `wolfhsm/wh_settings.h` for full list):

| Define | Description |
|--------|-------------|
| `WOLFHSM_CFG_SERVER_KEYCACHE_COUNT` | Number of key cache slots |
| `WOLFHSM_CFG_SERVER_KEYCACHE_SIZE` | Size of each key cache slot |
| `WOLFHSM_CFG_SERVER_DMAADDR_COUNT` | Number of DMA address entries |
| `WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT` | Number of custom callback slots |

**Optional test/benchmark defines:**

| Define | Description |
|--------|-------------|
| `WOLFHSM_CFG_PORT_ENABLE_WOLFHSM_TESTS` | Build and run wolfHSM tests |
| `WOLFHSM_CFG_PORT_ENABLE_BENCHMARK` | Build and run benchmarks |
| `WOLFHSM_CFG_TEST_POSIX` | Enable POSIX-specific test infrastructure |
| `WOLFHSM_CFG_TEST_CLIENT_ONLY` | Suppress combined client+server test code |

### user_settings.h

This header defines wolfSSL compile-time options. Both client and server need
one, but they will differ.

**Common required defines:**

```c
#define WOLF_CRYPTO_CB              /* CryptoCB support */
#define WOLFSSL_KEY_GEN             /* Key DER export/import */
#define WOLFSSL_ASN_TEMPLATE        /* ASN.1 template support */
#define WOLFSSL_BASE64_ENCODE       /* Base64 encoding */
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
#define NO_INLINE                   /* C90 compatibility */
#define TFM_TIMING_RESISTANT        /* Side-channel resistance */
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
```

Then enable the crypto algorithms your application needs (`HAVE_ECC`,
`HAVE_AESGCM`, `HAVE_CURVE25519`, etc.).

**Important:** `WOLFHSM_CFG_NVM_OBJECT_COUNT` and `WOLFHSM_CFG_COMM_DATA_LEN`
must have the same values in both client and server configurations. Mismatches
cause runtime failures.

## Step 5: Create the Build System

Your Makefile needs to:

1. Put the project directory (containing `wolfhsm_cfg.h` and `user_settings.h`)
   **first** on the include path.
2. Define `-DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG` so the libraries pick up your
   configuration headers.
3. Compile and link:
   - wolfSSL/wolfCrypt sources (unless building without crypto)
   - wolfHSM sources from `src/`
   - Your port's shared code
   - Your port's `wh_Port_*` implementation
   - The generic entry point (`examples/generic/wh_generic_client.c` or
     `wh_generic_server.c`)
   - Test and benchmark sources if enabled

See `port/posix/client/Makefile` for a complete example.

## Checklist

- [ ] Transport callbacks implemented (Init, Send, Recv, Cleanup)
- [ ] Flash callbacks implemented (or using `wh_flash_ramsim` for development)
- [ ] `wh_Port_InitBoard` / `wh_Port_CleanupBoard` implemented for both sides
- [ ] `wh_Port_ConfigureClient` / `wh_Port_InitClient` / `wh_Port_RunClient`
      implemented
- [ ] `wh_Port_ConfigureServer` / `wh_Port_InitServer` / `wh_Port_CleanupServer`
      implemented
- [ ] `wh_Port_ClientConnected` / `wh_Port_ClientDisconnected` implemented
- [ ] `wolfhsm_cfg.h` created for client and server with matching
      `WOLFHSM_CFG_COMM_DATA_LEN` and `WOLFHSM_CFG_NVM_OBJECT_COUNT`
- [ ] `user_settings.h` created for client and server
- [ ] Build system compiles and links both binaries
- [ ] Client can connect, send echo requests, and disconnect cleanly
