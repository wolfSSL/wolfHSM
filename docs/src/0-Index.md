# wolfHSM Documentation

A portable, open-source client-server framework for hardware cryptography, non-volatile memory, and secure processing.

## Table of Contents

### [1. Overview](1-Overview.md)
Introduction to wolfHSM, its feature set, and supported hardware platforms.

- Overview
- Features
- Supported Platforms

### [2. FAQs](2-FAQs.md)
Answers to common questions about wolfHSM's purpose, scope, dependencies, and capabilities.

### [3. Quickstart](3-Quickstart.md)
Step-by-step guide to getting a client and server up and running.

- Client Quickstart
- Server Quickstart
- Deep Dive: Transport, Comm Layer, NVM, wolfCrypt init, server context, request processing

### [4. Architecture](4-Architecture.md)
Architectural overview of the client/server libraries and communication stack.

- Client/Server libraries
- Code and API organization (Client API, Server API, source modules, compilation)
- Client/Server communication and communication stack
- Library configuration
- Internals deep dive: modular architecture

### [5. Features](5-Features.md)
Detailed reference for each major wolfHSM subsystem.

- Cryptography and wolfCrypt integration (offload, algorithms, hardware acceleration, blocking/non-blocking, request timeouts)
- Non-Volatile Memory (NVM interface, metadata, backends, flash abstraction)
- Keystore (key cache, key IDs, global keys, wrapped keys, usage policies)
- Certificate management (trusted roots, chain verification, verify cache, Acert support)
- Communication layer and transport backends
- DMA support (DMA crypto device, callbacks, allowlisting, 32/64-bit addressing)
- AUTOSAR SHE subsystem
- Non-volatile monotonic counters
- Image manager (image/firmware verification, verify methods and actions, wolfBoot images)
- Custom callbacks (application-defined server operations)
- Concurrency support (per-context threading model, lock abstraction)
- Authentication manager (PIN/certificate login, permissions; experimental)

### [6. Utilities](6-Utilities.md)
Tools shipped with wolfHSM for provisioning and validation.

- NVM Provisioning Tool (`whnvmtool`)
- Benchmark Suite (POSIX, real hardware)
- Test Suite (POSIX, real hardware)

### [7. Examples](7-Examples.md)
Reference applications demonstrating wolfHSM usage.

- POSIX example server and client (building, transport selection, NVM init)
- Demo client library (philosophy, demo categories)

### [8. Integration](8-Integration.md)
Guides for integrating wolfHSM with the wider wolfSSL ecosystem.

### [9. Client API Reference](9-API-docs-client.md)
Reference documentation for the wolfHSM client-side API.

### [10. Server API Reference](10-API-docs-server.md)
Reference documentation for the wolfHSM server-side API.

### [11. Configuration](11-Configuration.md)
Build-time and runtime configuration options for wolfHSM.
