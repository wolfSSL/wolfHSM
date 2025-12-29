# FAQ

## What is wolfHSM?

wolfHSM is a portable, open-source client-server framework for cryptography,
non-volatile memory (NVM), and isolated secure processing. A server application runs in a trusted environment (physical HSM core, trust zone secure wordl, remote server, etc.) while client applications use a library API that can offload cryptographic and storage operations to the server. The core library exposes a client and server API to help developers stitch together their own HSM applications using a curated set of ready-to-use and secure
components.

## Why would I need wolfHSM?

wolfHSM was initially designed for developers targeting automotive-style SoCs that include a dedicated HSM core with secure resources such as protected memory regions and hardware cryptographic accelerators, however can generalize to any application scenario where operations must be delegated to a secure programmable secure environment. It enables applications running in an untrusted environment to securely leverage the HSM without requiring a custom, ground-up implementation, while still allowing flexibility to tailor HSM functionality to specific product requirements.

When building security-sensitive products on these platforms, developers typically face two common approaches:

The first option is to build everything from scratch. This is a daunting undertaking that involves developing a custom application to run on the HSM core, managing non-volatile memory, implementing cryptographic algorithms in software or writing hardware accelerator drivers, and creating a bespoke messaging or RPC framework to communicate between cores. In many cases, silicon vendors provide minimal reference code, limited documentation, and little direct support for HSM software development.

The second option is to rely on vendor-provided, fixed-function HSM binaries. These solutions are typically expensive and expose only a narrow, predefined API. While convenient for simple use cases, they are often inflexible and difficult to adapt. Algorithm support is usually fixed or constrained to available hardware accelerators, large chunks of system memory are reserved for opaque internal use, and feature sets are limited by the vendor’s design choices.

wolfHSM provides a practical middle ground. It offers a flexible, open-source framework that implements commonly required HSM functionality while empowering users to build their own HSM applications. The core library is hardware agnostic, extensible, auditable, and modular, exposing essential building blocks that can be composed to meet specific security and system requirements. wolfHSM is built on top of wolfCrypt, leveraging a mature, well-tested cryptographic foundation while adding key management, policy enforcement, transport abstraction, and secure storage capabilities.

Building a custom HSM application sounds scary if you are used to a "black box" HSM solutions, but fear not! We took care of the hard part! Once you realize the freedom and flexibility that full control over the HSM-side provides, you will never want to go back. wolfHSM empowers your team to build a bespoke HSM solution that is right for YOU!

## What is an HSM client and server?

The HSM server is an application that runs in a trusted or secure execution environment, typically on a dedicated HSM core. It is responsible for performing cryptographic operations, managing keys, and accessing non-volatile memory (NVM) on behalf of clients.

An HSM client is an application that consumes these services from outside of the secure environment. Clients communicate with the server using a linked client library that marshals requests over a defined transport and returns responses. This architecture allows applications to use the wolfHSM and wolfCrypt APIs transparently, without requiring direct interaction with or management of the secure execution environment.

## How is wolfHSM different from other vendor solutions?

wolfHSM is a library framework rather than a proprietary, fixed-function firmware. It is designed to enable users to build their own custom HSM applications instead of being constrained to a predefined feature set. The library is vendor-agnostic and open-source, with a clean abstraction layer and pluggable transports. For users who just want an out-of-the-box solution, each wolfHSM port ships with a "reference server" with default functionality that can be directly loaded onto HSM hardware and used by client applications.

wolfHSM also differs from other solutions due to its inherent portability. Client applications can use wolfHSM and wolfCrypt APIs directly, with sensitive operations transparently offloaded to the HSM, avoiding proprietary interfaces and simplifying portability across HSM-enabled platforms. When migrating between platforms, the same high-level application logic can be retained, requiring only the registration of platform-specific transport and non-volatile storage drivers.

## What is the difference between wolfHSM and wolfSSL/wolfCrypt

wolfSSL/wolfCrypt is a standalone library that provides a TLS stack (wolfSSL) alongside an integrated cryptography library (wolfCrypt). wolfHSM is a separate library that is built on top of wolfSSL/wolfCrypt, using it internally as its cryptographic provider. Think about it like a remote procedure call framework for wolfCrypt with some extra HSM-specific functionality on top. Put more formally: wolfHSM wraps wolfCrypt within a client–server framework, allowing applications to offload cryptographic operations to a secure server while adding key management, non-volatile memory (NVM) management, transport abstraction, and policy enforcement layers on top of wolfSSL/wolfCrypt's standard cryptographic functionality.

## What is the difference between wolfHSM and wolfBoot?

wolfBoot is a secure bootloader focused on authenticated boot and firmware updates. wolfHSM is an HSM framework for runtime cryptography, key storage, and secure processing. However, wolfBoot and wolfHSM are best friends! wolfBoot has deep integration with wolfHSM and can be configured to run both as a wolfHSM client to accelerate and offload secure boot crypto and key storage, or to run on the HSM server core to verify the HSM server application. wolfHSM also knows how to verify wolfBoot images for scenarios where the HSM controls the boot flow on a multicore SoC.

## Is wolfHSM open source?

Yes. wolfHSM is open source under wolfSSL's dual licensing terms. See `LICENSING` for details.

## Does wolfHSM have any external dependencies?

The core wolfHSM library depends only on wolfSSL/wolfCrypt. Platform-specific reference ports may additionally rely on operating system or vendor libraries for startup code, configuration, transport mechanisms, and storage drivers, but no other third-party dependencies are required by the core library.

Due to wolfHSM’s modular design, reference platform code can be easily replaced with user-provided transport or storage drivers if the supplied implementations do not meet specific system requirements.

## Does wolfHSM require dynamic memory allocation?

No. wolfHSM is designed to avoid dynamic memory allocation. The library itself does not ever allocate from the heap. wolfCrypt, a dependency of wolfHSM, **does** require allocation for *some* functionality, however this can be configured to use statically allocated fixed-size memory pools, eliminating the nead for a runtime heap. See [chapter04](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter04.html#static-buffer-allocation-option) of the wolfSSL manual for more details on wolfCrypt static memory. When wolfCrypt is configured to use the static memory feature, wolfHSM applications are guaranteed to never allocate from the heap.

## What is a wolfHSM "port"?

A wolfHSM "port" contains the platform-specific **reference code** that demonstrates how to bring up and run the wolfHSM library on a given device or execution environment. While the core wolfHSM library itself is written in OS-agnostic C and contains no direct hardware or operating system dependencies, the port is what supplies the concrete implementations and drivers required to operate on real hardware.

A typical wolfHSM port includes reference implementations for low-level services such as client–server transport mechanisms, non-volatile storage access, startup and initialization logic, and any required platform or OS configuration. On platforms with hardware cryptographic accelerators or dedicated secure resources, the port may also include example drivers or integration logic to expose those capabilities to the wolfHSM server.

These ports are intentionally modular and illustrative rather than prescriptive. They are provided to show how wolfHSM can be integrated on a specific hardware platform, not to dictate a required architecture. Due to wolfHSM’s modular design, all port components can be easily replaced or customized with user-provided implementations while retaining the full functionality of the core wolfHSM library.

Most wolfHSM port implementations are not open source because they interact directly with silicon vendor–specific security hardware and reference device-specific registers, peripherals, and SDK components that are typically covered by the silicon vendor's security-related non-disclosure agreements. This limitation is a practical consequence of working with secure hardware platforms and is not a policy choice by wolfSSL, Inc. For most platforms, wolfSSL only needs to verify that you hold a valid NDA for the device in question in order to share the corresponding port. If you are interested in obtaining a wolfHSM port for a specific platform, please contact facts@wolfssl.com

## I looked at wolfHSM and don't see my specific hardware platform, where is it?

Some platform ports are public (for example, POSIX and STM32H5). The majority of hardware ports are vendor-NDA restricted and are not in this repository. If you do not see your platform, you can either implement a new port using the transport/NVM/flash abstractions or contact wolfSSL for access to restricted ports.

Most wolfHSM port implementations are not open source because they interact directly with silicon vendor–specific security hardware and reference device-specific registers, peripherals, and SDK components that are typically covered by the silicon vendor's security-related non-disclosure agreements. This limitation is a practical consequence of working with secure hardware platforms and is not a policy choice by wolfSSL, Inc. For most platforms, wolfSSL only needs to verify that you hold a valid NDA for the device in question in order to share the corresponding port. If you are interested in obtaining a wolfHSM port for a specific platform, please contact facts@wolfssl.com


## Does wolfHSM support operating system X?

The core wolfHSM library does not rely on operating system primitives and is written in portable C99. It can run in bare-metal environments as well as on operating systems in 32-bit and larger architectures. Nothing OS-specific should prohibit usage of wolfHSM on a given platform as long as the appropriate transport and storage drivers are supplied.

## Does wolfHSM support compiler X?

wolfHSM (and wolfCrypt) is written in portable C and is designed to build with a wide range of embedded and cross-compilation toolchains. Official support is provided for common, flagship toolchains associated with each device port, and most additional toolchains can be enabled with minimal changes. If you would like to see a specific toolchain officially supported, please contact facts@wolfssl.com

## Does wolfHSM support device/platform X?

In general, yes. Reference ports currently exist for the listed [supported platforms](1-Overview.md#supported-platforms). Most platform ports are NDA-restricted by the silicon vendor and must distributed separately as their own bundle. If a port does not exist for your platform, adding support  can typically be accomplished by in a matter of weeks, depending on the complexity of the device and desired use case. wolfSSL also routinely adds ports to new devices on request as part of a consulting engagment.

If you are interested in obtaining a restricted port for a platform, or want to see a new device supported, contact facts@wolfssl.com.

## Does wolfHSM support concurrency or multithreading?

The core wolfHSM library does not internally use any threading or parallelism.

The wolfHSM client API is safe to use in a multithreaded environment as long as access to each client context is properly serialized. The client context is not meant to be shared across threads without caller serialization.

The wolfHSM server API is safe to use in a multithreaded environment as long as access to each server context is properly serialized. The server context is not meant to be shared across threads without caller serialization. Global shared resources accessible across server contexts through the server API ARE safe to use in concurrent scenarios as the server library will properly serialize access internally using the internal port-specific mutex abstraction.

For example, two threads must NOT use the server API on one server context shared between the threads. However, it is perfectly acceptable for two threads to poll their own server contexts in parallel, even if the two threads are handling requests that reference the same keys or NVM objects.

## What is the bare minimum my client application needs to do in order to use wolfHSM?

At a minimum, a client application must link against the wolfHSM client library and provide a platform-specific transport that enables communication with the wolfHSM server running in a secure environment. The transport is configured and bound to the client context through a series of configuration structures. Once initialized, the application can call wolfHSM APIs or supported wolfCrypt APIs directly, with cryptographic operations, key access, and secure storage transparently offloaded to the HSM server. The client does not need to manage keys, hardware resources, or the secure execution environment.

See [3-Quickstart.md](3-Quickstart.md) for a concise quickstart example

## What is the bare minimum my server application needs to do in order to use wolfHSM?

At a minimum, a server application must link against the wolfHSM server library, initialize the server context by registering the platform-specific drivers for transport, non-volatile storage, and optionally hardware crypto, then start the request-processing loop, calling `wh_Server_HandleRequestMessage` on a server context to poll for requests from the corresponding client.

Once initialized, the server handles all cryptographic operations, key management, and secure storage on behalf of connected clients. No application-specific logic is required beyond initialization and transport handling, although the server can be extended with custom memory access patterns, callbacks, or services as needed.

## How do I do X with wolfHSM?

First, checkout the quickstart guide in [3-Quickstart.md](3-Quickstart.md) and the descriptions of each high level feature in [5-Features.md](5-Features.md). You can also look at the example server and client applications in `examples/posix/wh_posix_server` and `examples/posix/wh_posix_client` as well as the individual feature demo examples in `examples/demo/client`.

If you still have questions, reach out to our engineers for direct support at support@wolfssl.com.

