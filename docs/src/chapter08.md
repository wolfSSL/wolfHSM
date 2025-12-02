# WolfHSM Porting

This porting section aims to provide you with wolfHSM porting-related material and information.
We will cover the following:

- WolfHSM Porting Overview
- WolfHSM Ports
- WolfHSM Porting Interface

## WolfHSM Porting Overview

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

## WolfHSM Ports

### Infineon Aurix TC3XX

The distribution of this  port is restricted by the vendor. Please contact support@wolfssl.com for access.

**Infineon Aurix TC3xx**

- Up to 6x 300MHz TriCore application cores
- 1x 100MHz ARM Cortex M3 HSM core
- Crypto offload: TRNG, AES128, ECDSA, ED25519, SHA

### ST SPC58NN

The distribution of this  port is restricted by the vendor. Please contact support@wolfssl.com for access.

** ST SPC58NN**

- 3x 200MHz e200z4256 PowerPC application cores
- 1x 100MHz e200z0 PowerPC HSM core with NVM
- Crypto offload: TRNG, AES128

### POSIX

The POSIX port provides multiple and fully functional implementations of different wolfHSM abstractions that can be used to better understand the exact functionality expected for different hardware abstractions.

The POSIX port provides:
- Memory buffer transport
- TCP transport
- Unix domain transport
- RAM-based and file-based NVM flash simulators

### Skeleton

The Skeleton port source code provides a non-functioning layout to be used as a starting point for future hardware/platform ports.  Each function provides the basic description and expected flow with error cases explained so that ports can be used interchangeably with consistent results.

The Skeleton port provides stub implementations of:
- Transport callbacks
- NVM Flash callbacks
- Crypto callbacks

## WolfHSM Porting Interface

Ports must implement hardware-specific interfaces:
- NVM flash interface

Crypto Hardware
- TRNG, Keys, symmetric/asymmetric crypto

Platform Interface
- Boot sequence, application core reset, memory limitations
- Port and configuration are selected at compile time
