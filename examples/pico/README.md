# Pico-2 Dual-Core wolfHSM Demos

This directory contains examples demonstrating dual-core communication using wolfHSM on the Raspberry Pi Pico-2.
- **Echo Demo** (`pico2_demo_dual`): A simple client-server echo test.
- **SHA256 Demo** (`pico2_demo_sha256`): Offloading SHA256 hashing from the client (Core 1) to the server (Core 0).

## Shared Memory Transport

Both demos use a shared memory region to pass messages between cores:
- **Core 0**: Runs the wolfHSM server.
- **Core 1**: Runs the wolfHSM client.

**Memory Layout:**
```
Header (32 bytes)    - Initialization flags and metadata
Request Buffer       - 1KB, client to server
Response Buffer      - 1KB, server to client
```

## Building

You can choose which demo to build using CMake flags.

1. **Setup environment**
   ```bash
   cd $WOLF_HSM_DIR
   mkdir -p build && cd build
   ```

2. **Configure (Choose one)**

   *For Echo Demo:*
   ```bash
   cmake -GNinja -DBUILD_PICO2_DEMOS=ON -DWOLFHSM_DEMO_DUAL=ON -DPICO_SDK_PATH=/path/to/pico-sdk ..
   ```

   *For SHA256 Demo:*
   ```bash
   cmake -GNinja -DBUILD_PICO2_DEMOS=ON -DWOLFHSM_DEMO_SHA256=ON -DPICO_SDK_PATH=/path/to/pico-sdk ..
   ```

3. **Build**
   ```bash
   ninja
   ```

The output UF2 file will be at `examples/pico/pico2_demo_dual.uf2` or `examples/pico/pico2_demo_sha256.uf2`.

## Demo 1: Echo Server/Client

### Overview
- **Core 0** (Server): Initializes transport, listens for requests, and echoes the payload back with an "Echo: " prefix.
- **Core 1** (Client): Connects to the transport, sends test strings, and verifies the echoed response.

### Expected Output
```
Server running on Core 0, client on Core 1
Client initialized
Sent: Hello from Core 1
Received: Echo: Hello from Core 1
...
```

## Demo 2: SHA256 Offload

### Overview
- **Core 0** (Server): Runs the full wolfHSM server with a software crypto backend (using wolfCrypt).
- **Core 1** (Client): Uses the standard `wolfCrypt` API (e.g., `wc_InitSha256_ex`) with `WH_DEV_ID`. This transparently marshals the crypto operation to the server via the shared memory transport.

### Configuration
Edit `pico2_demo_sha256.c` or `user_settings.h` to adjust buffer sizes or enable/disable specific algorithms.

### Expected Output
```
=== Pico-2 Dual-Core wolfHSM SHA256 Demo (wolfCrypt API) ===
Shared memory @20001838 size 4096
Server running on Core 0, client on Core 1

=== Core 1: Client start ===
Client initializing...
Client initialized via wh_Client_Init

--- Starting SHA256 Demo ---

Input [0]: "Hello from Core 1" (17 bytes)
SHA256 Initialized Successfully
SHA256 Update Successful
SHA256 Finalizing...
SHA256 Hash: 975ddc4c55e2da9e7efdaffb72a1e221d67ade221e1767fe0e525e80d926ce02

Input [1]: "The quick brown fox" (19 bytes)
SHA256 Initialized Successfully
SHA256 Update Successful
SHA256 Finalizing...
SHA256 Hash: 5cac4f980fedc3d3f1f99b4be3472c9b30d56523e632d151237ec9309048bda9

Input [2]: "wolfHSM SHA256 Demo" (19 bytes)
SHA256 Initialized Successfully
SHA256 Update Successful
SHA256 Finalizing...
SHA256 Hash: df504e1687a32bf2389f3a07a99e845393d4b7fe40c26c88cca658e36717f73b

Input [3]: "Pico2 Dual Core" (15 bytes)
SHA256 Initialized Successfully
SHA256 Update Successful
SHA256 Finalizing...
SHA256 Hash: 520283eac4ef94cbfdeee0c9c595aebae13499d0492fde20ce86424b913d23e9

Input [4]: "SHA256 Hash Test" (16 bytes)
SHA256 Initialized Successfully
SHA256 Update Successful
SHA256 Finalizing...
SHA256 Hash: b3a9b0be905013ea129ac28877883f8d68aa3df8b1df8a205023c608568c9cd3

--- Demo Complete ---
Core 1 done
```

## Requirements

- Raspberry Pi Pico-2 board (RP2350)
- Pico SDK 2.0.0+
- wolfSSL and wolfHSM libraries
- ARM GCC toolchain

