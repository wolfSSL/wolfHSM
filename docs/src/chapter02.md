# Overview

wolfHSM is a software framework that provides a unified API for HSM operations
such as cryptographic operations, key management, and non-volatile storage.
It is designed to improve portability of code related to HSM applications,
easing the challenge of moving between hardware with enhanced security
features without being tied to any vendor-specific library calls. It
dramatically simplifies client applications by allowing direct use of wolfCrypt
APIs, with the library automatically offloading all sensitive cryptographic
operations to the HSM core as remote procedure calls with no additional logic
required by the client app.

Although initially targeted to automotive-style HSM-enabled microcontrollers,
wolfHSM provides an extensible solution to support future capabilities of
platforms while still supporting standardized interfaces and protocols such as
PKCS11 and AUTOSAR SHE. It has no external dependencies other than wolfCrypt and
is portable to almost any runtime environment.

## Features

- Secure non-volatile object storage with user-based permissions
- Cryptographic key management with support for hardware keys
- Hardware cryptographic support for compatible devices
- Fully asynchronous client API
- Flexible callback architecture enables custom use cases without modifying library
- Use wolfCrypt APIs directly on client, with automatic offload to HSM core
- Image manager to support chain of trust
- Integration with AUTOSAR
- Integration with SHE+
- PKCS11 interface available
- TPM 2.0 interface available
- Secure OnBoard Communication (SecOC) module integration available
- Certificate handling
- Symmetric and Asymmetric keys and cryptography
- Supports "crypto agility" by providing every algorithm implemented in wolfCrypt, not just those implemented by your silicon vendor
- FIPS 140-3 available

## Architecture

wolfHSM employs a client-server architecture where the server runs in a trusted
and secure environment (typically on a secure coprocessor) and the client is a library
that can be linked against user applications. This architecture ensures that
sensitive cryptographic operations and key management are handled securely
 within the server, while the client library abstracts away the lower level
communication with the server.

- Server: The server component of wolfHSM is a standalone application that runs
 on the HSM core. It handles cryptographic operations, key management, and
 non-volatile storage within a secure environment. The server is responsible
 for processing requests from clients and returning the results.

- Client: The client component of wolfHSM is a library that can be linked
 against user applications. It provides APIs for sending requests to the
 server and receiving responses. The client abstracts the complexities of
 communication and ensures that the application can interact with the HSM
 securely and efficiently.

## Ports

wolfHSM itself is not executable and it does not contain any code to interact with any specific hardware. In order for wolfHSM to run on a specific device, the library must be configured with the necessary hardware drivers and abstraction layers so that the server application can run and communicate with the client. Specifically, getting wolfHSM to run on real hardware requires the implementation of the following:

- Server application startup and hardware initialization
- Server wolfCrypt configuration
- Server non-volatile memory configuration
- Server and client transport configuration
- Server and client connection handling

The code that provides these requirements and wraps the server API into a bootable application is collectively referred to as a wolfHSM "port".

Official ports of wolfHSM are provided for various supported architectures, with each port providing the implementation of the wolfHSM abstractions tailored to the specific device. Each port contains:

- Standalone Reference Server Application: This application is meant to run on the HSM core and handle all secure operations. It comes fully functional out-of-the-box but can also be customized by the end user to support additional use cases
- Client Library: This library can be linked against user applications to facilitate communication with the server

### Supported Ports

wolfHSM has supported ports for the following devices/environments:

- POSIX runtime
- ST Micro SPC58N\*
- Infineon Aurix TC3xx\*
- Infineon Aurix TC4xx\* (coming soon)
- Infineon Traveo T2G\* (coming soon)
- Renesas RH850\* (coming soon)
- Renesas RL78\* (coming soon)
- NXP S32\* (coming soon)

With additional ports on the way.

\* These ports, unfortunately, require an NDA with the silicon vendor to obtain any information about the HSM core. Therefore, the wolfHSM ports for these platforms are not public and are only available to qualified customers. If you wish to access a restricted wolfHSM port, please contact us at support@wolfssl.com.
