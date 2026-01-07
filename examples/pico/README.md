# Pico-2 Dual-Core Echo Demo

## Overview

This demo shows dual-core communication using wolfHSM on the Raspberry Pi Pico-2:
- **Core 0**: Runs the wolfHSM server, receives requests and echoes responses
- **Core 1**: Runs the wolfHSM client, sends test messages and displays echoed responses

## How It Works

1. Core 0 initializes shared memory and starts the server
2. Core 1 connects to the shared memory transport and sends requests
3. Server receives "Hello from Core 1" and responds with "Echo: Hello from Core 1"
4. Client receives 5 additional echoed requests in a loop

## Shared Memory Layout

```
Header (32 bytes)    - Initialization flags and metadata
Request Buffer       - 1KB, client to server
Response Buffer      - 1KB, server to client
```

## Building

```bash
cd $WOLF_HSM_DIR
mkdir -p build && cd build && cmake -GNinja -DBUILD_PICO2_DEMOS=ON -DPICO_SDK_PATH=/path/to/pico-sdk .. && ninja
```

The UF2 file will be at `build/lib/pico2_demo_dual.uf2`.

## Configuration

Edit these values in `pico2_demo_dual.c` if needed:

```c
#define SHARED_MEM_SIZE (4 * 1024)    // Total shared memory
#define REQ_SIZE 1024                 // Request buffer size
#define RESP_SIZE 1024                // Response buffer size
```

## Output

Expected serial output:

```
=== Pico-2 Dual-Core wolfHSM Demo ===
Shared memory @0x20040000 size 4096
Server running on Core 0, client on Core 1
Server handled message 1
Server handled message 2
...
Server handled message 6
Client received response 0: Echo: Hello from Core 1
Client received response 1: Echo: Request 0 from Core 1
...
```

## Requirements

- Raspberry Pi Pico-2 board
- Pico SDK 2.2.0+
- wolfSSL and wolfHSM libraries
- ARM GCC toolchain

