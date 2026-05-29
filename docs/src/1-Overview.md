# wolfHSM Documentation

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Supported Platforms](#supported-platforms)

## Overview

wolfHSM is a software framework that provides a portable and open-source client-server
abstraction for hardware cryptography, non-volatile memory, and isolated secure processing
that maximizes security and performance. It consists of a client-server library architecture,
where the wolfHSM server application runs in a trusted environment, and client applications
communicate with the server through the wolfHSM client library. wolfHSM is intended to simplify
the challenge of moving between hardware with enhanced security features without being tied to
any vendor-specific library calls. wolfHSM also dramatically simplifies client HSM applications
by allowing direct use of wolfCrypt APIs, with the framework automatically offloading all sensitive
cryptographic operations to the wolfHSM server as remote procedure calls with no additional logic
required by the client app.

Although initially targeted to automotive-style HSM-enabled microcontrollers,
wolfHSM can run on any platform that provides a secure/trusted execution environment
for the server. wolfHSM provides an extensible solution to support future capabilities
of any platform while still supporting standardized interfaces and protocols such as AUTOSAR SHE.

## Features

* Unified client and server library APIs abstracting common HSM operations
* Transport-agnostic architecture with reference implementations for shared memory buffers, POSIX TCP sockets, wolfSSL TLS on top of TCP, and POSIX inter-process shared memory
* Non-volatile object store with fail-safe atomic updates and fine-grained access control policies
* Per-client and global key stores supporting non-volatile and RAM-backed key slots, configurable usage policies, and encrypted (wrapped) keys
* Tight integration with the wolfCrypt cryptography library
    * Client applications may use the wolfCrypt API directly, with supported algorithms and key storage transparently offloaded to the HSM server
    * Server applications gain access to all wolfCrypt software algorithms, with optional device-specific hardware acceleration where available
    * Support for Post-Quantum Cryptography (PQC) algorithms
* DMA support for shared-memory systems, including address allowlisting and configurable pre- and post-access callbacks for cache synchronization and address remapping
* X.509 certificate chain verification, including support for RFC 5755 attribute and authorization certificates
* Server image manager for authenticating firmware images or arbitrary regions of memory with customizable post-verification actions
* Extensible server behavior via user-defined callbacks for runtime functionality and message handling
* Non-volatile monotonic counters
* AUTOSAR Secure Hardware Extension (SHE) interface support
* Support for user authentication with full role-based access control

## Supported Platforms

### Infineon

- TC2xx
- TC3xx
- TC4xx

### ST Microelectronics

- Stellar SR6G
- SPC58N Bernina
- STM32H5 Trust Zone

### Texas Instruments

- TDA4VH

### Renesas

- Renesas RH850

### Microchip

- PIC32CZ

### AMD/Xilinx

- Zynq UltraScale+

### Planned Ports

- Microchip PIC32CN
- NXP S32K3 and S32G
- AMD/Xilinx Versal

