# Integration

This chapter describes how wolfHSM integrates with other wolfSSL libraries and products. wolfHSM is designed to slot into an existing wolfSSL-based stack rather than replace it: the same wolfCrypt API drives the cryptographic work, the same TLS stack secures network links, and the same firmware authentication tooling produces signed images. The sections below summarize the integration surface with each library, and refer the reader to the documentation for that library when the details live there.

## Table of Contents

- [wolfSSL and wolfCrypt](#wolfssl-and-wolfcrypt)
- [wolfBoot](#wolfboot)
    - [wolfBoot as a wolfHSM Client](#wolfboot-as-a-wolfhsm-client)
    - [wolfBoot on the wolfHSM Server](#wolfboot-on-the-wolfhsm-server)
    - [Verifying wolfBoot Images from a Server Application](#verifying-wolfboot-images-from-a-server-application)
- [wolfIP](#wolfip)
- [wolfGuard (WireGuard Transport)](#wolfguard-wireguard-transport)
- [wolfSentry](#wolfsentry)
- [wolfTPM](#wolftpm)

## wolfSSL and wolfCrypt

wolfSSL/wolfCrypt is a hard dependency of wolfHSM and is used in three distinct roles, all of which are covered in detail elsewhere in this manual:

- **Cryptographic provider** on both sides of the client/server boundary. The client crypto callback routes wolfCrypt API calls to the server, and the server uses wolfCrypt to perform the actual cryptographic work. See [Cryptography and wolfCrypt Integration](5-Features.md#cryptography-and-wolfcrypt-integration) and the broader discussion in [Architecture](4-Architecture.md).
- **Certificate and ASN.1 handling** behind the certificate manager — chain verification, leaf public key extraction, and acert parsing are all delegated to wolfSSL. See [Certificate Management](5-Features.md#certificate-management).
- **TLS transport** for client/server links that cross an untrusted network. The `posix_transport_tls` reference transport wraps the plain POSIX TCP transport in a wolfSSL-secured session (with optional PSK), with no change to the framing above. See [Transport Backends](5-Features.md#transport-backends).

Because wolfCrypt is already covered exhaustively in the architecture and feature chapters, this chapter does not repeat the integration details. Treat wolfSSL/wolfCrypt as a prerequisite of every wolfHSM build, and refer to those chapters when configuring it.

## wolfBoot

[wolfBoot](https://github.com/wolfSSL/wolfBoot) is wolfSSL's portable secure bootloader. wolfBoot and wolfHSM are designed to work together: when both are present on a platform, wolfBoot can use wolfHSM for all of the cryptographic work and key storage it performs during firmware authentication, eliminating the need for wolfBoot to handle key material directly. The integration is bidirectional — wolfBoot can act as a wolfHSM *client*, or it can host an embedded wolfHSM *server* — and a wolfHSM server application can independently verify wolfBoot-formatted images on behalf of its own clients. This section summarizes the integration surface; For more information, refer to [wolfBoot's `docs/wolfHSM.md`](https://github.com/wolfSSL/wolfBoot/blob/master/docs/wolfHSM.md), which covers per-platform configuration, build options, and HAL requirements in detail.

### wolfBoot as a wolfHSM Client

In **client mode**, wolfBoot is a wolfHSM client like any other application: it links the wolfHSM client library, opens a transport to a separate wolfHSM server, and offloads firmware signature verification (and the hashing that feeds it) through the standard wolfCrypt crypto callback. Image signing keys are provisioned onto the server in advance, and wolfBoot references them by `keyId` rather than holding the key material itself. The build option `WOLFBOOT_ENABLE_WOLFHSM_CLIENT` selects this mode, and `WOLFBOOT_USE_WOLFHSM_PUBKEY_ID` together with the keygen `--nolocalkeys` option produces a keystore that contains only key metadata, with the actual public key resident on the HSM.

The wolfBoot HAL supplies the wolfHSM client context, the transport configuration, and the device/key identifiers (`hsmClientCtx`, `hsmDevIdHash`, `hsmDevIdPubKey`, `hsmKeyIdPubKey`) that wolfBoot uses to direct crypto callback calls at the right wolfHSM resources. wolfBoot's algorithm support over wolfHSM covers RSA-2048/3072/4096, ECDSA P-256/P-384/P-521, ML-DSA at security levels 2/3/5, and SHA-256, with the actual set available on a given target gated by the HAL.

This mode is the natural fit for a multi-core SoC where wolfBoot runs on the application core and the wolfHSM server runs on a separate secure core, communicating over the platform's shared-memory or mailbox transport. It is also the mode used by the wolfBoot simulator, which talks to the example POSIX TCP server over loopback.

### wolfBoot on the wolfHSM Server

In **server mode**, wolfBoot links the wolfHSM *server* library and runs an embedded wolfHSM server inside the bootloader itself, using the wolfHSM server API directly rather than over a transport. There is no external HSM in this configuration; wolfBoot owns the NVM, the keystore, and the crypto subsystem, and any wolfHSM features it needs (notably certificate chain verification) are invoked locally. The build option `WOLFBOOT_ENABLE_WOLFHSM_SERVER` selects this mode, and is mutually exclusive with the client-mode option.

Server mode is the right choice when the bootloader has no separate secure core to delegate to but still benefits from wolfHSM's keystore, certificate manager, and NVM abstraction — for example, when the application that runs after boot is itself a wolfHSM server and the bootloader needs to share its provisioning. The HAL supplies the server context, NVM initialization, and the NVM IDs of any pre-provisioned root CA certificates used for certificate chain verification.

### Verifying wolfBoot Images from a Server Application

Independently of which mode wolfBoot itself is running in, a wolfHSM **server application** can verify wolfBoot-formatted images on behalf of its clients using the [image manager](5-Features.md#image-manager). The image manager understands the wolfBoot TLV header natively and exposes two verify methods specifically for wolfBoot images:

- `WH_IMG_MGR_IMG_TYPE_WOLFBOOT` — verifies the image against a key resident in the server's keystore, matching wolfBoot's standard signing model.
- `WH_IMG_MGR_IMG_TYPE_WOLFBOOT_CERT` — verifies a certificate chain embedded in the wolfBoot header against a trusted root in NVM and then uses the leaf public key to verify the image, matching wolfBoot's cert-chain signing mode.

The full mechanism — header parsing, signature TLV extraction, public-key-hint validation, and the DMA-aware payload reads that make verifying multi-megabyte images practical — is documented in [wolfBoot Image Support](5-Features.md#wolfboot-image-support). The practical upshot is that a wolfBoot client and a wolfHSM-equipped system can share a single image format and a single trust anchor: the same `.bin` that wolfBoot would verify locally can be verified by a wolfHSM server through the image manager, and the same root CA provisioned on the HSM works for both flows.

## wolfIP

Coming soon ;-)

## wolfGuard (WireGuard Transport)

Coming soon ;-)

## wolfSentry

Coming soon ;-)

## wolfTPM

Coming soon ;-)
