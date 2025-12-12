# wolfHSM Server Library

The wolfHSM server library is a server-side implementation of the wolfCrypt cryptography library.
It provides an interface for applications to offload cryptographic operations to a
dedicated server, which runs the wolfHSM server software. This allows the application to perform
cryptographic operations without having to manage the cryptographic keys or perform the
operations locally.

## Getting Started
TODO

## Architecture
TODO

## API Reference
TODO

## Key Management
TODO

## Cryptographic

wolfHSM uses wolfCrypt for all cryptographic operations, which means wolfHSM can offload any algorithm supported by wolfCypt to run on the wolfHSM server. This includes the Chinese government mandated ShāngMì ciphers (SM2, SM3, SM4), as well as post-quantum algorithms such as Kyber, LMS, XMSS, and more!

