# Features

This chapter provides a detailed overview of the high level features that wolfHSM provides. Each section is intended to convey *what* a given feature does, what functionality it exposes, and what a developer can build with it. Concrete API usage and signatures are deferred to the client and server API references in [10-API-docs-client.md](10-API-docs-client.md) and [11-API-docs-server.md](11-API-docs-server.md).

## Table of Contents

- [Cryptography and wolfCrypt Integration](#cryptography-and-wolfcrypt-integration)
    - [Transparent Offload via Crypto Callbacks](#transparent-offload-via-crypto-callbacks)
    - [Supported Algorithms](#supported-algorithms)
    - [Referencing Keys by ID](#referencing-keys-by-id)
    - [Hardware Acceleration and Crypto Affinity](#hardware-acceleration-and-crypto-affinity)
    - [Blocking and Non-Blocking Interfaces](#blocking-and-non-blocking-interfaces)
    - [Crypto Operation Timeouts](#crypto-operation-timeouts)
- [Non-Volatile Memory (NVM)](#non-volatile-memory-nvm)
    - [High Level NVM Interface](#high-level-nvm-interface)
    - [Object Metadata and Access Attributes](#object-metadata-and-access-attributes)
    - [NVM Backends](#nvm-backends)
    - [Flash Abstraction](#flash-abstraction)
    - [Optional NVM Backing](#optional-nvm-backing)
- [Keystore](#keystore)
    - [Key Cache, Key IDs, and NVM Backing Store](#key-cache-key-ids-and-nvm-backing-store)
    - [Global Keys](#global-keys)
    - [Wrapped Keys](#wrapped-keys)
    - [Key Usage Policies](#key-usage-policies)
- [Certificate Management](#certificate-management)
    - [Trusted Root Storage](#trusted-root-storage)
    - [Chain Verification](#chain-verification)
        - [Caching the Leaf Public Key](#caching-the-leaf-public-key)
        - [DMA Variants](#dma-variants)
    - [Trusted Certificate Verify Cache](#trusted-certificate-verify-cache)
    - [Attribute Certificate (Acert) Support](#attribute-certificate-acert-support)
- [Communication Layer and Transports](#communication-layer-and-transports)
    - [Communication Layer](#communication-layer)
    - [Transport Backends](#transport-backends)
- [DMA Support](#dma-support)
    - [DMA Dispatch Mode (`wh_Client_SetDmaMode`)](#dma-dispatch-mode-wh_client_setdmamode)
    - [Pre-Access and Post-Access Callbacks](#pre-access-and-post-access-callbacks)
    - [Address Allowlisting](#address-allowlisting)
    - [32-bit vs. 64-bit Address Handling](#32-bit-vs-64-bit-address-handling)
- [AUTOSAR SHE Subsystem](#autosar-she-subsystem)
    - [Client API and Command Set](#client-api-and-command-set)
    - [SHE Key Slots and the wolfHSM Keystore](#she-key-slots-and-the-wolfhsm-keystore)
    - [Encrypted Key Update Protocol (M1–M5)](#encrypted-key-update-protocol-m1m5)
    - [Secure Boot](#secure-boot)
    - [Deterministic PRNG](#deterministic-prng)
    - [Status Register (SREG)](#status-register-sreg)
    - [Integration with the Rest of wolfHSM](#integration-with-the-rest-of-wolfhsm)
- [Non-Volatile Monotonic Counters](#non-volatile-monotonic-counters)
    - [Counter Semantics](#counter-semantics)
    - [Counter Identifiers and Storage](#counter-identifiers-and-storage)
    - [Client API](#client-api)
- [Image Manager](#image-manager)
    - [Image Configuration](#image-configuration)
    - [Verify Methods](#verify-methods)
    - [Verify Actions](#verify-actions)
    - [wolfBoot Image Support](#wolfboot-image-support)
    - [In-Place Access via DMA](#in-place-access-via-dma)
- [Custom Callbacks](#custom-callbacks)
    - [Server-Side Registration and Dispatch](#server-side-registration-and-dispatch)
    - [Client-Side Invocation](#client-side-invocation)
    - [Request and Response Messages](#request-and-response-messages)
    - [Constraints](#constraints)
    - [Example](#example)
- [Concurrency Support](#concurrency-support)
    - [Per-Context Threading Model](#per-context-threading-model)
    - [The Lock Abstraction](#the-lock-abstraction)
    - [Concurrent Server Pattern](#concurrent-server-pattern)
    - [Transports and Concurrency](#transports-and-concurrency)
    - [Crypto Under Concurrency](#crypto-under-concurrency)
- [Authentication Manager](#authentication-manager)
    - [Authentication Methods](#authentication-methods)
    - [Sessions and the Authorization Gate](#sessions-and-the-authorization-gate)
    - [Permissions](#permissions)
    - [User Management Invariants](#user-management-invariants)
    - [Pluggable Backend](#pluggable-backend)

## Cryptography and wolfCrypt Integration

wolfHSM uses wolfCrypt as its cryptographic provider on both sides of the client/server boundary. On the client, applications call the standard wolfCrypt API directly and the operation runs transparently on the server. On the server, the full set of wolfCrypt's software algorithms is available out of the box, with optional acceleration from port-supplied hardware drivers.

### Transparent Offload via Crypto Callbacks

Clients can use the wolfCrypt API directly because of wolfCrypt's [crypto callback (cryptoCb)](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter06.html#crypto-callbacks-cryptocb) framework. Crypto callbacks let you override selected algorithms at runtime by registering a callback against a device identifier (`devId`). Most wolfCrypt functions take a `devId`, and when it matches a registered device the call is dispatched through that callback instead of running locally.

The wolfHSM client library registers a crypto callback that turns each supported wolfCrypt call into a request/response exchange with the server. The same wolfCrypt source can be retargeted to the HSM by changing only the `devId` — nothing else in the application changes. Each client context registers a device ID chosen by the application in the `.devId` field of `whClientConfig`; leaving the field `0` selects the default `WH_DEV_ID`. `wh_Client_Init()` registers the ID and binds it to that context, and `wh_Client_Cleanup()` unregisters it. At a wolfCrypt call site the application can either read the ID back from the context with the `WH_CLIENT_DEVID(client)` macro, or simply pass the same constant it placed in the config — convenient where the client context is not in scope. Because each client can own a distinct `devId`, a single process can run multiple client connections (to one server or several) and each wolfCrypt call is serviced by exactly the client whose `devId` it was initialized with; a multi-client process must configure a distinct, nonzero `devId` for every client.

In addition to the configured per-client ID, every `wh_Client_Init()` registers the two process-global device IDs:

- `WH_DEV_ID` is registered with the same unified callback as a configured `devId`, so it behaves identically — including honoring the [DMA dispatch mode](#dma-dispatch-mode-wh_client_setdmamode). It is also the ID a client is bound to when its config leaves `.devId` 0.
- `WH_DEV_ID_DMA` (present only with `WOLFHSM_CFG_DMA`) is registered with the DMA-only callback: operations always use the DMA request forms, and algorithms without a DMA variant fail rather than falling back to the standard path. It is reserved for this purpose and is not valid as a configured `.devId`.

The global IDs preserve the behavior of earlier wolfHSM releases: an application with a **single client per process** needs no devId configuration at all and can keep passing `WH_DEV_ID` (or `WH_DEV_ID_DMA`) straight to wolfCrypt functions, exactly as before — they are always registered and available after `wh_Client_Init()`. Because these registrations are process-global and keyed on the integer value, each `wh_Client_Init()` rebinds them to the most recently initialized client, and **any** client's `wh_Client_Cleanup()` unregisters them. In a multi-client process they are therefore unreliable and should not be passed to wolfCrypt; use the per-client configured IDs instead. Both values are overridable at compile time (see [Configuration](9-Configuration.md#cryptography-features)).

Registered device IDs occupy slots in wolfCrypt's fixed-size crypto-callback table (`MAX_CRYPTO_DEVID_CALLBACKS`, default 8): the global IDs occupy one slot each, shared by all clients in the process (every init rebinds the same table entries), and each distinct configured `devId` adds one more. `wh_Client_Cleanup()` releases the client's slots. Applications that run many simultaneous clients in one process may need to raise the wolfCrypt limit.

In effect the callback layer is a transparent RPC framework for wolfCrypt: clients write ordinary wolfCrypt code, and wolfHSM handles request marshaling, transport, dispatch, and response delivery underneath. It also makes prototyping easy — develop against a local wolfCrypt instance, then switch to the HSM by toggling one parameter once the server is available.

### Supported Algorithms

The wolfHSM server exposes the full set of wolfCrypt software algorithms, and the client crypto callback supports transparent offload for the most commonly used algorithm families:

- **Symmetric ciphers**: AES in CBC, CTR, ECB, GCM, and CCM modes; AES key wrap
- **Hashing**: SHA-1, SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512), SHA-3
- **Message authentication**: HMAC (over the supported hash functions) and CMAC
- **Asymmetric**: RSA (encryption, signing, key generation), ECC (ECDSA, ECDH), Ed25519, Curve25519
- **Random number generation**: DRBG/RNG backed by the server's entropy source
- **Post-quantum cryptography**: ML-DSA (FIPS 204) and ML-KEM (FIPS 203)

For the authoritative list of algorithms, parameter ranges, and options, see the [wolfCrypt API reference](https://www.wolfssl.com/documentation/manuals/wolfssl/index.html). An algorithm not yet wired through the crypto callback can still be used locally against the client's own wolfCrypt instance — only operations dispatched to the client's `devId` are offloaded.

### Referencing Keys by ID

When a client offloads an operation, it usually does *not* send the key with the request. The key lives in the server [keystore](#keystore) under a numeric **key ID**, and the client refers to it by that ID alone. The bytes never cross the client/server boundary — the client holds only the ID, and the server looks up the material when it runs the operation. This is what lets an HSM guard a private key while still letting a client sign or decrypt with it.

A wolfCrypt key object is tied to a server-side key ID with a per-algorithm `SetKeyId` call. Every offloaded algorithm has one — `wh_Client_RsaSetKeyId`, `wh_Client_EccSetKeyId`, `wh_Client_AesSetKeyId`, `wh_Client_Ed25519SetKeyId`, `wh_Client_Curve25519SetKeyId`, `wh_Client_CmacSetKeyId`, `wh_Client_MlDsaSetKeyId`, and so on (each with a matching `GetKeyId`). You initialize an ordinary wolfCrypt key struct with the client's devId, associate it with a key ID instead of loading key bytes, and call wolfCrypt as usual:

```c
RsaKey  rsa;
whKeyId keyId = 4; /* keyId 4 must be resident on the server */

/* Initialize the RSA key context to use wolfHSM offload via the
 * devId of an initialized client context */
wc_InitRsaKey_ex(&rsa, NULL, WH_CLIENT_DEVID(client));

/* Bind the key object to the server-side key */
wh_Client_RsaSetKeyId(&rsa, keyId);

/* Use wolfCrypt as normal — signing runs on the server and the
 * private key never leaves the HSM */
sigLen = wc_RsaSSL_Sign(msg, msgLen, sig, sizeof(sig), &rsa, &rng);
```

The same ID can name a key the client just cached, one provisioned into NVM at the factory, or one the server generated and never exported — the client uses it the same way in every case. How IDs are assigned and structured is covered under [Keystore](#keystore).

### Hardware Acceleration and Crypto Affinity

Many of the platforms wolfHSM targets ship a dedicated crypto accelerator alongside their secure core. The server can use these accelerators per-algorithm through the same crypto callback mechanism: a port-supplied callback, registered at server init, redirects supported operations to the vendor's hardware driver, and anything not implemented in hardware falls back to wolfCrypt software. Which algorithms are accelerated depends on the silicon and is documented in each platform's port.

Clients control whether a given crypto request should prefer hardware or software execution through the **crypto affinity** API. Affinity is a per-client setting with two values:

- `WH_CRYPTO_AFFINITY_HW` (default): the server attempts to execute the operation using the configured hardware crypto device. If the server was not configured with a valid hardware device ID, or if the requested algorithm is not implemented in hardware, the request transparently falls back to wolfCrypt's software implementation.
- `WH_CRYPTO_AFFINITY_SW`: the server always executes the operation using wolfCrypt's software implementation, bypassing any registered hardware device.

Affinity is stored on the client and sent in the header of every crypto request, so a change takes effect on the next operation with no extra round-trip.

The affinity is set and queried using `wh_Client_SetCryptoAffinity` and `wh_Client_GetCryptoAffinity`. See the [client API reference](10-API-docs-client.md) for the precise signatures.

### Blocking and Non-Blocking Interfaces

Operations invoked through the standard wolfCrypt API are **blocking**: the call does not return until the server responds (or the transport fails). This matches what applications already expect from wolfCrypt and is the simplest way to port existing code to wolfHSM.

For non-blocking, split-transaction behavior, wolfHSM also exposes native client crypto APIs in `wolfhsm/wh_client_crypto.h` that follow the same send-request / receive-response pattern as the rest of the client API. These come as paired `wh_Client_<Algorithm>Request` and `wh_Client_<Algorithm>Response` calls, so a caller can issue a request, do other work, and poll for the result later. They cover a subset of algorithms (see the [client API reference](10-API-docs-client.md)), and blocking and non-blocking calls must not be interleaved on the same `whClientContext` while a request is outstanding.

> **Note**: Because the standard wolfCrypt API is blocking on the client side, applications that need to overlap crypto work with other activity should either use the native non-blocking client API, or run their wolfCrypt calls from a dedicated thread with its own `whClientContext`. See [Concurrency Support](#concurrency-support) for guidance on multi-threaded usage.

### Crypto Operation Timeouts

A blocking call waits until the server responds (see [Blocking and Non-Blocking Interfaces](#blocking-and-non-blocking-interfaces)). If the server never answers — it crashed, or the transport stalled — the call would otherwise wait forever. The optional request-timeout feature (`WOLFHSM_CFG_ENABLE_TIMEOUT`) bounds that wait: once the timeout elapses the call returns `WH_ERROR_TIMEOUT` instead of hanging, and the client context stays usable so the application can recover or retry. It is purely client-side — the server is unaware of it — and applies to any blocking request/response, offloaded crypto being the main case.

A timeout is configured per client through the `respTimeoutConfig` field of the `whCommClientConfig`. The client starts the timer when it sends a request, checks it while polling for the response, and stops it once the response arrives. Setting `respTimeoutConfig` to `NULL` disables the timeout (the client waits indefinitely), so the feature can be compiled in but left off for individual clients.

wolfHSM has no built-in notion of time, so the actual time measurement is supplied by the platform through a small callback table (`whTimeoutCb`) of init, set, start, stop, and check-expired functions. This keeps the core free of OS dependencies. The POSIX port ships a ready-made implementation (`POSIX_TIMEOUT_CB`, based on `CLOCK_MONOTONIC`); other platforms supply their own. Durations are expressed in microseconds, with `WH_MSEC_TO_USEC()`, `WH_SEC_TO_USEC()`, and `WH_MIN_TO_USEC()` helper macros for readability. An application may also register an optional expired callback that runs when the timer elapses and can override the expiration — for example, restart the timer to grant a legitimately slow operation more time.

## Non-Volatile Memory (NVM)

wolfHSM exposes persistent storage to the rest of the server as an object store rather than as raw bytes. Keys, certificates, monotonic counters, and any other long-lived state that the server needs to survive a reset are stored as discrete objects in this store, each addressed by a stable identifier and carrying its own metadata. The object store sits on top of a pluggable backend, which in turn talks to platform flash through a thin abstraction provided by the port. This layered design keeps the higher-level subsystems (keystore, certificate manager, image manager, counters) independent of the specifics of any particular flash device.

The NVM library is engineered for fail-safe operation: every mutating operation is structured so that interruption at any point — including loss of power partway through a write or erase — leaves the store in a recoverable state on the next initialization. This property is what allows the rest of wolfHSM to treat NVM as a reliable substrate for security-critical state.

### High Level NVM Interface

The NVM library presents non-volatile storage as a collection of opaque, variable-sized **objects**. Each object has three parts:

- A unique 16-bit identifier (`whNvmId`) that the rest of the server uses to refer to it
- A fixed-size **metadata** record describing the object (see [Object Metadata and Access Attributes](#object-metadata-and-access-attributes))
- A variable-length **payload** of arbitrary bytes

Applications and higher-level subsystems do not address NVM by byte offset; they create, read, enumerate, and destroy whole objects through the `wh_Nvm_*` API. This object orientation is what allows the keystore, certificate manager, and counter subsystems to share a single backing store without colliding: each subsystem owns a range of identifiers and a set of metadata flags, and the underlying NVM layer is unaware of what the objects mean.

The core operations exposed by the interface are:

- **Add**: write a new object with caller-supplied metadata and payload. Duplicate identifiers are accepted at the NVM layer; the most recently written instance is the one returned on subsequent reads, which provides an in-place update semantic at higher layers.
- **Read**: retrieve all or part of an object's payload by identifier and byte offset, allowing large objects (firmware images, certificate chains) to be streamed out incrementally.
- **List / GetMetadata**: enumerate objects matching an access/flags filter and retrieve metadata for a specific identifier without touching the payload, which is what the server uses to drive directory-style operations and policy enforcement.
- **Destroy**: remove one or more objects. Removal is implemented as a regeneration of the partition with the listed objects omitted, which both deletes the entries and reclaims their space in a single atomic operation.
- **GetAvailable**: query free space and the amount of space that would be reclaimed by a compaction, so callers can make informed decisions before issuing large writes.

All mutating operations are **atomic and power-loss tolerant**: any interruption either leaves the store as it was before the operation or, if the operation completed past its commit point, as it was after. The NVM library does not return success until the new state is durably committed to flash. This guarantee is what makes it safe for the server to commit a key, increment a counter, or update a certificate without an intervening cleanup pass if the system is reset mid-operation.

The library also exposes an explicit **compaction / reclamation** model. Because objects are added by writing into free space rather than overwriting in place (a property of the underlying flash semantics), space occupied by destroyed or superseded objects is not immediately reusable. Compaction can be triggered implicitly by `wh_Nvm_AddObjectWithReclaim()` when the next add would otherwise fail for lack of space, or explicitly by calling `wh_Nvm_DestroyObjects()` with an empty list. Either path regenerates the active partition with only the live objects present and reclaims everything else.

When wolfHSM is built with `WOLFHSM_CFG_THREADSAFE`, each NVM context carries an embedded lock. The lock's lifecycle is managed by `wh_Nvm_Init()` and `wh_Nvm_Cleanup()`, but acquiring and releasing it around operations is the caller's responsibility — the NVM API functions deliberately do not lock internally so that multiple operations can be grouped under a single critical section. See [Concurrency Support](#concurrency-support) for the broader threading model.

### Object Metadata and Access Attributes

Every NVM object is described by a `whNvmMetadata` record carrying:

- `id`: the unique `whNvmId` identifier
- `len`: the payload length in bytes
- `label`: a fixed-size (`WH_NVM_LABEL_LEN`) byte array that callers may use as a user-defined name or tag for the object
- `access`: a bitfield of access permissions (`whNvmAccess`) describing who may interact with the object
- `flags`: a bitfield of `whNvmFlags` describing policy and behavior

The metadata is written alongside the payload and travels with the object for its entire lifetime. Higher-level subsystems use these fields both to identify objects (the keystore, for example, decodes the structure of `id` to distinguish keys from certificates and counters) and to enforce policy on every access.

The flags field carries the policy attributes that subsystems use to gate operations:

- `WH_NVM_FLAGS_NONMODIFIABLE`: the object cannot be overwritten or destroyed through the policy-checked APIs
- `WH_NVM_FLAGS_NONDESTROYABLE`: the object cannot be destroyed (but may still be modified)
- `WH_NVM_FLAGS_NONEXPORTABLE`: the object's payload cannot be read back out through the policy-checked APIs
- `WH_NVM_FLAGS_SENSITIVE`: marks the object as holding secret material, so subsystems can apply zeroization and audit behavior accordingly
- `WH_NVM_FLAGS_EPHEMERAL`: the object should not be cached or committed
- `WH_NVM_FLAGS_LOCAL`: the object was generated locally on the server (as opposed to imported)
- `WH_NVM_FLAGS_USAGE_*`: key usage policy bits (`ENCRYPT`, `DECRYPT`, `SIGN`, `VERIFY`, `WRAP`, `DERIVE`) consumed by the keystore to constrain how a key may be used; see [Key Usage Policies](#key-usage-policies)

The NVM library exposes both a raw and a policy-checked variant of the mutating and reading APIs (`wh_Nvm_AddObject` vs. `wh_Nvm_AddObjectChecked`, `wh_Nvm_DestroyObjects` vs. `wh_Nvm_DestroyObjectsChecked`, `wh_Nvm_Read` vs. `wh_Nvm_ReadChecked`). The checked variants honor the flags above and return `WH_ERROR_ACCESS` when the requested operation would violate them; the unchecked variants are used by server-internal code paths that need to manage the state itself (for example, to clear `NONMODIFIABLE` during a controlled revocation flow). Because policy enforcement happens server-side at the NVM layer, no client request can bypass it.

The access field is used to express coarser-grained permissions (owner / other / user buckets, with read/write/exec/special bits) that higher layers may consult, and is the primary filter used by `wh_Nvm_List()` when enumerating objects.

### NVM Backends

The `wh_Nvm_*` API is implemented against a backend callback table (`whNvmCb`) that abstracts the details of how objects are actually laid out on storage. The core library does not depend on any particular backend — selecting a backend is part of server configuration, and ports or applications can supply their own implementations against the same interface. wolfHSM ships with two reference backends, both built on top of the [flash abstraction](#flash-abstraction):

- **`nvm_flash`** (`wh_nvm_flash.c`): the default backend, suitable for flash devices with small write granularity (8 bytes or less). It manages two equal-sized partitions in flash, with one designated as active at any time. New objects are added by programming directly into free space at the end of the active partition, which keeps write amplification low for read-heavy and append-dominated workloads. A directory of object state is cached in RAM and rebuilt from flash at initialization. Destruction of objects (and explicit compaction) is performed by regenerating the inactive partition with only the surviving objects, then atomically switching the active partition pointer and erasing the old one. An interruption before the switch leaves the previous partition intact; an interruption after the switch is recovered by completing the erase of the now-inactive partition on the next boot.
- **`nvm_flash_log`** (`wh_nvm_flash_log.c`): an alternative backend designed for flash devices with **large write granularity** (e.g. 64 bytes) where every program operation must be aligned and padded to that boundary. It also uses a two-partition layout, but caches the entire active partition in RAM and rewrites the whole inactive partition on every mutation. Each partition header carries a monotonic epoch counter, and the partition with the highest epoch is treated as authoritative on the next initialization. The implementation favors simplicity and a uniform write pattern at the cost of higher write amplification, which is acceptable on the read-heavy workloads it is intended for. Selected at build time via `WOLFHSM_CFG_SERVER_NVM_FLASH_LOG`.

Both backends bind to a `whFlashCb` flash driver supplied by the port; the choice between them is a function of the underlying flash device's program granularity and the application's write profile, not of any user-facing feature. Ports targeting microcontrollers with conventional NOR flash typically use `nvm_flash`; ports targeting devices whose program operation is fundamentally a 32- or 64-byte page write are better served by `nvm_flash_log`.

### Flash Abstraction

The lowest layer of the NVM stack is the `whFlashCb` interface, a small callback table that the port supplies to describe how to read, program, erase, and verify the platform's flash. The NVM backends — and any user-supplied backend — speak only through this interface, which keeps them entirely portable across flash devices.

The interface comprises:

- `Init` / `Cleanup`: lifecycle management for the underlying driver
- `PartitionSize`: returns the partition size, which is also the minimum erase granularity and the alignment used by the NVM backends
- `Read`: copy bytes out of flash at a given offset
- `Program`: write bytes into previously-erased flash at a given offset
- `Erase`: erase one or more partitions back to their blank state
- `Verify`: compare flash contents against a buffer, used after programming to confirm the write succeeded
- `BlankCheck`: confirm that a region is in the erased state, used during recovery and partition selection
- `WriteLock` / `WriteUnlock`: optional protection against accidental programming or erasure of a region

wolfHSM ships with two reference flash drivers usable on host platforms and in testing:

- **POSIX file-backed flash** (`port/posix/posix_flash_file.c`): persists flash contents to a host file, suitable for development, simulation, and the POSIX server example
- **RAM-backed flash simulator** (`wolfhsm/wh_flash_ramsim.h`): emulates flash semantics (erase-then-program, partition alignment, configurable erased-byte value) entirely in RAM, used by the test suite and useful when bringing up a new port

Vendor-supplied flash drivers ship with the platform ports under `port/<vendor>/`. New platforms are integrated into wolfHSM by implementing the `whFlashCb` callback set against the device's flash controller; nothing in the NVM library above this layer needs to change.

**Write-through requirement (port maintainers).** wolfHSM's power-loss guarantees assume the port's `Program` and `Verify` callbacks are write-through to the physical medium: `Program` must make the data durable before it returns, and `Verify` must read back from the medium rather than from any volatile write cache. A backend that buffers writes in a cache that can be lost on power failure breaks this assumption — on the next boot a committed object can roll back to a prior value. For stateless key material this is only a durability concern, but for **stateful or monotonic objects it is a security issue**: a rolled-back LMS or XMSS private key reuses a one-time signature index, enabling forgery, and a rolled-back monotonic counter defeats anti-rollback and replay protection. wolfHSM cannot detect or enforce this property, so a port whose flash controller caches writes must either disable that caching or issue an explicit flush before `Program`/`Verify` return.

### Optional NVM Backing

The NVM subsystem described above is **optional**. A server can be initialized with `whServerConfig.nvm == NULL`, in which case it runs with no persistent object store at all. This suits clients and cores that only need cached-key cryptography and have no flash available for an NVM partition — at the cost of a reduced feature set, since everything that depends on persistent storage becomes unavailable.

With no NVM, the [keystore](#keystore) is effectively cache-only. A key is served from the RAM [key cache](#key-cache-key-ids-and-nvm-backing-store) when present; a cache miss would normally fall back to NVM, but with no NVM configured it simply reports `WH_ERROR_NOTFOUND` — the same result as if the key were absent from the store. Keys are made available by *priming* the cache out of band: either by caching key material directly on the server, or by having the client supply [wrapped keys](#wrapped-keys) that are unwrapped directly into the cache.

What works with no NVM:

- Cryptographic operations against keys that are primed in the cache.
- Key caching, eviction, and (cache-only) erase.
- SHE encrypt/decrypt/CMAC and secure boot against keys primed in the cache.
- Key wrap/unwrap and unwrap-and-cache, provided the wrapping key (KEK) is primed in the cache.

What requires NVM, and so fails gracefully at runtime when it is absent (returning an error rather than crashing):

- The NVM object request API (list/read/add/destroy).
- [Certificate-chain verification](#certificate-management) against trusted roots stored in NVM.
- [Monotonic counters](#non-volatile-monotonic-counters).
- Committing a cached key to persistent storage (`wh_Server_KeystoreCommitKey`).
- [SHE](#autosar-she-subsystem) key persistence and the SHE PRNG seed (`LOAD_KEY` of non-RAM keys, `INIT_RND`, `EXTEND_SEED`), and image-signature loading.

> **Note**: When [global keys](#global-keys) (`WOLFHSM_CFG_GLOBAL_KEYS`) are enabled, the shared global key cache normally lives inside the NVM context. With no NVM there is no shared store, so global keys (USER `0`) are served from the per-context local cache instead. They remain usable when primed, but are not shared across server contexts as they would be with NVM present.

When NVM **is** configured, all of the above behavior is unchanged.

## Keystore

The keystore manages the lifecycle of cryptographic key material on the server. It sits on top of [NVM](#non-volatile-memory-nvm) and is the layer every crypto operation goes through to reference a key. Clients refer to keys by a stable 16-bit identifier, not by the key bytes; the material stays server-side and is only returned through explicit, policy-checked operations. This is what lets the server enforce per-key usage policy, isolate keys between clients, and offload bulk crypto to hardware without exposing key bytes outside the trust boundary.

The keystore has three responsibilities that the rest of this section covers in turn:

- Managing a fast working set of keys in RAM (the **key cache**) layered over the slower NVM object store, with explicit commit and load operations between the two
- Enforcing **isolation between clients**, so that a key cached by one client is not visible to another — and, optionally, relaxing this isolation for explicitly designated [global keys](#global-keys)
- Implementing **wrapped keys** that can leave the server under the protection of a server-resident key encryption key, and **usage policies** that constrain how every individual key may be used at every crypto request

### Key Cache, Key IDs, and NVM Backing Store

The keystore is two-tier: a fixed-size **key cache** in server RAM holds the working set of keys, and persistent **NVM** behind it holds the keys that must survive a reset. Every key in use lives in the cache; NVM is the durable copy, loaded into a cache slot on demand.

Keys are named by a 16-bit identifier (`whKeyId`), which has two forms — a simple one the client uses and a fuller one the server uses internally:

- **Client-side**: Each client gets a dedicated namespace of 255 key identifiers that are specific to and only accessible by that client. These IDs range from `[1, 255]`, where `0` is the reserved sentinel value `WH_KEYID_ERASED` used internally to mark empty key slots (this sentinel value is also used to request a dynamically assigned ID for a key cache operation — see the keystore API documentation for more information). The client can also set a flag bit in the keyId top byte to ask for special handling — bit 8 for a [global key](#global-keys), bit 9 for a [wrapped key](#wrapped-keys). That is all a client ever deals with, and the `WH_CLIENT_KEYID_MAKE_*` macros in `wolfhsm/wh_client.h` set those flags for it.
- **Server-side**: internally every key has a globally unique id that also encodes *what* the key is and *who* owns it. When a request arrives, the server expands the client's provided keyId number into this full form, and collapses it back on the way out (`wh_KeyId_TranslateFromClient()` and its inverse). Client code never touches the internal fields.

The server-side `whKeyId` packs three fields into its 16 bits:

- **TYPE** (top 4 bits): the kind of object — `WH_KEYTYPE_CRYPTO` for ordinary crypto keys, `WH_KEYTYPE_SHE` for AUTOSAR SHE keys, `WH_KEYTYPE_COUNTER` for monotonic counters, `WH_KEYTYPE_WRAPPED` for wrapped-key metadata, and `WH_KEYTYPE_NVM` for non-key NVM objects that share the same id space.
- **USER** (middle 4 bits): the owning client. Value `0` is reserved for the global-key namespace when `WOLFHSM_CFG_GLOBAL_KEYS` is enabled.
- **ID** (low 8 bits): the number the client chose.

The USER field is what gives each client its own private key space. The server fills it with the connection's client id (assigned at init and checked against `WH_CLIENT_ID_MAX`), so when two clients both use "key 5" they map to different `whKeyId` values and cannot touch each other's key. Every client sees the same `[1, 255]` range, and the ranges never overlap.

Turning to the cache itself: it is statically allocated inside the server context (wolfHSM uses no dynamic memory) and sized at build time by two pairs of macros:

- `WOLFHSM_CFG_SERVER_KEYCACHE_COUNT` × `WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE`: the number of *regular* slots and the largest key that fits in one
- `WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT` × `WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE`: the number of *big* slots and the largest key that fits in one

The two tiers keep one large key (e.g. an an ML-DSA-87 private key) from dictating the slot size for every smaller key. A cached key goes to the regular cache if it fits and the big cache otherwise; both follow the same eviction and policy rules.

Each cached key carries its full `whNvmMetadata` record alongside the key bytes, plus an internal **committed flag** marking whether a copy also exists in NVM. This flag is what makes the cache a true working set: when it needs a slot and none is free, the keystore evicts a key that is already committed (and can be reloaded later), but never an uncommitted one. Uncommitted keys are RAM-only, so the caller must commit them to survive eviction or reset; if the cache fills with uncommitted keys, the next cache operation returns `WH_ERROR_NOSPACE` instead of silently dropping material.

A client drives this tier with five operations:

- **Cache**: write key bytes and metadata into a server cache slot. The key is usable immediately but RAM-only.
- **Commit**: copy a cached key into NVM as a durable object. The cache copy is marked committed and becomes a candidate for eviction.
- **Evict**: drop the cache copy. If the key was committed, the NVM copy remains and reloads on the next reference; if it was uncommitted, the key is gone.
- **Export**: read a cached key's bytes back to the client, subject to `WH_NVM_FLAGS_NONEXPORTABLE`.
- **Erase**: remove the key from both cache and NVM in one operation.

Operations that take a `whKeyId` don't care whether the key is in the cache or only in NVM: on first use the server loads it from NVM into a cache slot — the implementation calls this *freshening* — and serves later operations from the cache until eviction.

Two more behaviors round out the cache model:

- A key whose metadata carries `WH_NVM_FLAGS_EPHEMERAL` is never committed to NVM, no matter what the caller requests. This suits short-lived material (session keys, transient keypairs) where an NVM write is never warranted.
- The 24-byte `label` field travels with the key for its whole lifetime in both cache and NVM. It is opaque to the keystore — a caller-supplied name or tag — and is returned alongside the key on export, so applications can tell keys apart without keeping their own mapping. The exception to this is in the SHE layer, where it is used to store SHE-specific metadata.

### Global Keys

By default a key cached by one client is invisible to every other client, thanks to the USER field in `whKeyId`. But sometimes clients on a single HSM genuinely need to share key material. Copying such a key into every client's namespace would waste cache and NVM and complicate provisioning.

The optional **global keys** feature (`WOLFHSM_CFG_GLOBAL_KEYS`) adds a parallel keystore namespace shared by all clients. Global keys live in their own cache and their own NVM id range, but are otherwise used exactly like local keys: any operation that takes a `whKeyId` — including the wolfCrypt crypto callback — accepts a global keyId unchanged.

Internally, global keys reserve USER field value `0` (`WH_KEYUSER_GLOBAL`) — a value no client can hold if the global key feature is enabled. The global cache lives in the NVM context (`whNvmContext::globalCache`), not a server context, because server contexts are per-connection while NVM and global keys are shared across them. On each keystore operation the server checks the keyId: USER `0` routes to the global cache, anything else to the connection's local cache. There is no separate global API — `wh_Client_KeyCache`, `wh_Client_KeyCommit`, `wh_Client_KeyExport`, and the crypto callbacks all work transparently with global keyIds.

Clients designate a key as global by setting the `WH_KEYID_CLIENT_GLOBAL_FLAG` bit (bit 8) in the request keyId. The recommended way to do this is via the `WH_CLIENT_KEYID_MAKE_GLOBAL()` macro:

- `whKeyId k = WH_CLIENT_KEYID_MAKE_GLOBAL(5)` constructs a client-facing global keyId for numeric ID 5
- Passing this keyId to `wh_Client_KeyCache` causes the server to store the key in the global cache and (on commit) in the global NVM range
- Passing the same keyId from any other connected client retrieves the same key

Global keys interact with the cache and NVM tiers in the same way as local keys, including the commit/evict/freshen flow, eviction of committed-only slots, and policy enforcement at the NVM layer. The only practical differences are the cache they occupy and the visibility they grant.

> **Security note**: Because a global key is reachable by every client connected to the server, the security boundary it provides is the server itself, not any particular client. Global keys should be reserved for material that is genuinely shared across the trust domains of the connected clients — typically vendor-provisioned roots and shared symmetric keys for inter-client communication — and should not be used as a workaround for per-client key management. Per-key usage flags (see [Key Usage Policies](#key-usage-policies)) apply to global keys exactly as they do to local keys, and should be used to constrain how a shared key may be used regardless of which client invokes the operation.

### Wrapped Keys

A key that lives entirely inside the server is protected by its trust boundary: only the server can read its bytes, and policy is enforced before every use. Some workflows still need to move key material outside that boundary — to back keys up to off-device storage, to transport a key between systems during provisioning, or even to support wolfHSM on an HSM platform without dedicated NVM. wolfHSM's **wrapped keys** feature (`WOLFHSM_CFG_KEYWRAP`) does this safely, with the server mediating every step.

A *wrapped key* is a key whose payload — the key bytes and its `whNvmMetadata` — has been encrypted and authenticated under another key resident on the server, the **key encryption key (KEK)**. Because the KEK never leaves the server, the wrapped blob can be handed to the client, stored on a host filesystem, sent over an untrusted channel, or pushed to off-device storage, and only the server (with the same KEK) can recover the original key.

The wrap format used by wolfHSM is a length-prefixed, authenticated encryption blob. AES-GCM is the currently supported wrap cipher and is requested by passing `WC_CIPHER_AES_GCM` to the wrap APIs; the on-wire layout is:

```
[ IV (12 bytes) | AuthTag (16 bytes) | AES-GCM( metadata || key ) ]
```

The metadata is bound into the authenticated plaintext so that the wrapped blob carries not only the key bytes but also its policy, label, and identifier — a recipient cannot strip or substitute metadata without invalidating the authentication tag. The on-wire constants `WH_KEYWRAP_AES_GCM_IV_SIZE`, `WH_KEYWRAP_AES_GCM_TAG_SIZE`, and `WH_KEYWRAP_AES_GCM_HEADER_SIZE` are defined in `wolfhsm/wh_common.h` and may be used by callers to size wrap output buffers. The maximum wrappable key size is controlled by `WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE`.

The lifecycle exposed to clients consists of three primary operations:

- **Wrap**: the client supplies plaintext key bytes, a metadata template, and the keyId of a server-resident KEK; the server encrypts the (metadata || key) blob with the KEK and returns the wrapped blob to the client. The plaintext is not written to NVM as part of this operation.
- **Unwrap-and-export**: the client supplies a wrapped blob and the KEK's keyId; the server decrypts the blob, authenticates the tag, and returns the recovered metadata and key bytes to the client. This is the operation used by host-side workflows that need to consume the key off-device, for example to inject it into a non-HSM peer.
- **Unwrap-and-cache**: the client supplies a wrapped blob and the KEK's keyId; the server decrypts the blob and installs the recovered key directly into the keystore cache as if `wh_Client_KeyCache` had been called locally with the recovered bytes. This is the more common operation in production deployments, since it lets a key live on disk in encrypted form and be hydrated into the HSM at runtime without the plaintext ever transiting the client. Unwrapped keys are cache-only and cannot be committed to NVM.

In all three operations the KEK is identified by its existing keyId in the keystore, must carry the `WH_NVM_FLAGS_USAGE_WRAP` usage flag, and is enforced server-side by the keystore policy machinery. A key without the `WRAP` usage flag cannot be used to wrap or unwrap regardless of any client request.

A parallel pair of APIs — `wh_Client_DataWrap` and `wh_Client_DataUnwrap` — applies the same construction to arbitrary application data rather than key material. These are useful when a client needs the same authenticated-encryption guarantee for non-key payloads using a key resident in the HSM.

> **Note**: Wrapped key identifiers are signaled on the wire by setting `WH_KEYID_CLIENT_WRAPPED_FLAG` (bit 9) in the request keyId, which the server translates internally to `WH_KEYTYPE_WRAPPED`. Clients construct wrapped-key identifiers using `WH_CLIENT_KEYID_MAKE_WRAPPED()`, and the combined wrapped-and-global form using `WH_CLIENT_KEYID_MAKE_WRAPPED_GLOBAL()`; both are defined in `wolfhsm/wh_client.h`.

### Key Usage Policies

A key's `whNvmMetadata` carries a `flags` field that the keystore checks on every server-side operation to constrain how the key may be used. The flags fall into two groups: **lifecycle flags** that govern whether a key may be modified, destroyed, exported, or cached at all, and **usage flags** that govern which cryptographic operations it may take part in.

The lifecycle flags are the same `whNvmFlags` bits described in [Object Metadata and Access Attributes](#object-metadata-and-access-attributes) and are enforced uniformly across NVM objects: `WH_NVM_FLAGS_NONMODIFIABLE`, `WH_NVM_FLAGS_NONDESTROYABLE`, `WH_NVM_FLAGS_NONEXPORTABLE`, `WH_NVM_FLAGS_SENSITIVE`, and `WH_NVM_FLAGS_EPHEMERAL`. For keys specifically, the most consequential of these is `NONEXPORTABLE`, which prevents `wh_Client_KeyExport` and the full per-algorithm export helpers from returning the key bytes to the client. The public-only export path is deliberately exempt from this flag because public key material is non-sensitive; the corollary is that a key marked `NONEXPORTABLE` can still be made useful for client-side verification by exporting only its public half.

The usage flags constrain which cryptographic operations a given key may participate in:

- `WH_NVM_FLAGS_USAGE_ENCRYPT`: the key may be used to encrypt
- `WH_NVM_FLAGS_USAGE_DECRYPT`: the key may be used to decrypt
- `WH_NVM_FLAGS_USAGE_SIGN`: the key may be used to produce signatures or MACs
- `WH_NVM_FLAGS_USAGE_VERIFY`: the key may be used to verify signatures or MACs
- `WH_NVM_FLAGS_USAGE_WRAP`: the key may be used as a KEK for [wrapped keys](#wrapped-keys) or for data wrapping
- `WH_NVM_FLAGS_USAGE_DERIVE`: the key may be used as input to a key derivation function

Multiple usage flags may be combined, and `WH_NVM_FLAGS_USAGE_ANY` is a convenience constant equal to the bitwise OR of all USAGE bits. A key whose metadata carries no USAGE bits at all is treated as not permitted for any cryptographic use — attempting to use it returns `WH_ERROR_USAGE`. This is intentional: a default-zero metadata does not silently grant access; the application must explicitly opt in to each operation a key may perform.

Policy enforcement happens server-side on every relevant operation. Every wolfCrypt request that flows through the crypto callback routes through the keystore's usage check before the underlying primitive runs, and the operation is rejected with `WH_ERROR_USAGE` if the flag for that operation is not set. Because enforcement is server-side, and because the metadata is bound into the wrapped blob for wrapped keys, no client request can bypass it.

Lifecycle and usage flags are bound to a key at the moment it is first cached or generated and travel with the key into NVM on commit. They cannot be edited in place through the standard client API — once a key has been created with `USAGE_SIGN` only, the only way to also grant `USAGE_VERIFY` is to erase the key and recreate it (or, for a public verification key, to extract the public half through the public-only export path and use it as an independent key). This non-editability is what makes the policy useful as a security control: an attacker who compromises a client cannot loosen the policy on an already-provisioned key.

The keystore additionally provides a **revocation** operation (`wh_Client_KeyRevoke`) that clears all `USAGE_*` bits and sets `WH_NVM_FLAGS_NONMODIFIABLE` on a key without destroying the underlying storage. After revocation, every cryptographic use of the key returns `WH_ERROR_USAGE`, and the key cannot be re-enabled. Revocation is persisted to NVM for committed keys and survives reset; for cache-only keys, eviction has the same effect since the key cannot be reloaded. This makes revocation useful for emergency rotation (taking a compromised signing key out of circulation without immediately reclaiming its NVM slot) and for staged decommissioning, while still leaving the key bytes in place for audit or forensic recovery.

Concrete examples of policy-driven scenarios that this machinery supports:

- A **signing-only** key for code signing: `USAGE_SIGN | NONEXPORTABLE | NONMODIFIABLE`. The key can produce signatures but never leaves the HSM and cannot be silently replaced.
- A **verification-only** public key: `USAGE_VERIFY`. Attempting to use it for signing returns `WH_ERROR_USAGE` even though the key object is cryptographically capable of either.
- A **KEK** for wrapped-key workflows: `USAGE_WRAP | NONEXPORTABLE`. The key can wrap and unwrap other keys but cannot itself be exported or used for general encryption.
- A **derivation root** for session keys: `USAGE_DERIVE | NONEXPORTABLE | SENSITIVE`. The root is bound to the HSM and is consumed only by KDF operations that produce shorter-lived material.

## Certificate Management

wolfHSM provides a server-resident **certificate manager** that handles the storage of trusted root certificates and the verification of X.509 certificate chains against them. Clients submit a candidate chain and the NVM id of a trusted root — or a list of root ids, with the multi-root API — and the server validates the chain and returns a single yes/no answer, optionally extracting the leaf's public key into the keystore for later crypto operations. The feature is enabled with `WOLFHSM_CFG_CERTIFICATE_MANAGER`. Two opt-ins extend it: `WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT` adds [RFC 5755 attribute certificates](#attribute-certificate-acert-support), and `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE` adds the [trusted certificate verify cache](#trusted-certificate-verify-cache).

Under the hood, chain verification is delegated to wolfSSL's `WOLFSSL_CERT_MANAGER`, which the server instantiates per request and populates with the requested root(s). This means that the full set of X.509 validation behaviors that wolfSSL implements can be leveraged through wolfHSM.

### Trusted Root Storage

Trusted root certificates are stored as ordinary NVM objects (see [Non-Volatile Memory](#non-volatile-memory-nvm)). Each root is a DER-encoded X.509 certificate written into NVM under a caller-chosen `whNvmId` with full `whNvmMetadata` — access bits, flags, and label — so that the same access-control machinery that applies to keys also applies to roots.

The lifecycle operations exposed to clients are:

- **Add trusted**: write a root certificate into NVM under a caller-supplied id with the requested metadata. Roots are commonly added with `WH_NVM_FLAGS_NONMODIFIABLE` (and optionally `WH_NVM_FLAGS_NONEXPORTABLE`) so that a compromised client cannot tamper with the trust anchor after provisioning.
- **Erase trusted**: destroy a previously installed root. Subject to the same policy bits as other NVM destroy operations, so a root marked `NONDESTROYABLE` will not be removed.
- **Read trusted**: read a stored root back out to the client. Read access is gated on `WH_NVM_FLAGS_NONEXPORTABLE`: if the root was provisioned non-exportable, the read request returns `WH_ERROR_ACCESS` regardless of who issued it.

The maximum size of an individual root is bounded by `WOLFHSM_CFG_MAX_CERT_SIZE`.

### Chain Verification

A candidate certificate chain is presented to the server as a single buffer of concatenated DER-encoded X.509 certificates ordered from CA-down-to-leaf, such that each certificate appears in the buffer after the certificate that signed it. The server walks the buffer one ASN.1 SEQUENCE at a time, verifies each certificate against the current trust store, and if the certificate is itself a CA, promotes it into the trust store so the next certificate in the chain can chain to it. The single certificate that is *not* marked as a CA is treated as the leaf, and the verification succeeds only if the leaf chains all the way back to a trusted root that was installed in NVM.

Two verification variants are exposed:

- **Single-root verify** (`wh_Client_CertVerify`): the client gives the NVM id of one trusted root. The chain must anchor to that root.
- **Multi-root verify** (`wh_Client_CertVerifyMultiRoot`): the client gives a list of up to `WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS` root ids. The chain is accepted if it anchors to *any* of them. Ids not present in NVM are skipped, and the order does not matter.

Multi-root verify lets a client send one fixed list of acceptable roots and run unchanged on any device, no matter which of those roots that device actually has. For example, every device in a fleet can be shipped the same root list while each holds only its own subset. The matching server-side functions are `wh_Server_CertVerify` and `wh_Server_CertVerifyMultiRoot`.

Verification returns a single status code: `WH_ERROR_OK` on a trusted chain, `WH_ERROR_CERT_VERIFY` if no anchor matches, `WH_ERROR_NOTFOUND` if the multi-root call found none of the supplied root ids in NVM, or a more specific error for malformed input.

#### Caching the Leaf Public Key

A common pattern in HSM-mediated workflows is to verify a peer's certificate chain and then use the leaf's public key for subsequent cryptographic operations (signature verification, key exchange, etc.). To support this without round-tripping the public key through the client, every verify call accepts a `WH_CERT_FLAGS_CACHE_LEAF_PUBKEY` flag and an associated keyId:

- If the flag is set and the supplied keyId is `WH_KEYID_ERASED`, the server allocates a fresh unique keyId, extracts the leaf's SubjectPublicKeyInfo into the keystore's "big" cache slot under that id, and returns the keyId to the client.
- If the flag is set and the supplied keyId is a concrete value, the server caches the public key under that id (subject to keystore policy).
- The metadata applied to the cached key is supplied by the caller via the `cachedKeyFlags` argument, so the leaf key inherits an appropriate usage policy (e.g. `WH_NVM_FLAGS_USAGE_VERIFY | WH_NVM_FLAGS_NONEXPORTABLE`) as soon as it is materialized.

The cached key behaves like any other key in the [keystore](#keystore) from that point on: it can be used in wolfCrypt operations, committed to NVM by the client, evicted, and so on. The plaintext key bytes never leave the server during this flow — the chain enters and the keyId comes out. Both variants offer a convenience call that sets the flag for you: `wh_Client_CertVerifyAndCacheLeafPubKey` and `wh_Client_CertVerifyMultiRootAndCacheLeafPubKey` (each with a DMA form).

#### DMA Variants

When `WOLFHSM_CFG_DMA` is enabled, parallel DMA variants of all certificate operations let the server read the chain (or write the root, in the case of add/read trusted) directly from client memory rather than copying it through the message buffer. This lifts the per-chain size ceiling above what `WOLFHSM_CFG_COMM_DATA_LEN` would otherwise allow and is the recommended path for verifying long chains or large root certificates. The DMA allowlist applies as it does for any DMA-backed feature — the server will refuse to read a client buffer outside its configured allowed regions. See [DMA Support](#dma-support).

### Trusted Certificate Verify Cache

Every verify runs a signature check at each link in the chain. When the same CA certificates keep showing up — many clients chaining through one issuing CA, or one client re-checking the same peer over and over — that work repeats even though the result never changes. The optional **trusted certificate verify cache** (`WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE`) remembers CAs that have already verified and skips the signature check when they reappear.

Each cache entry is the SHA-256 hash of a verified CA, tagged with the set of trusted-root ids that were loaded at the time. As the server walks a chain, it hashes each certificate and checks the cache first. A hit skips the signature check; everything else proceeds normally (the CA is still added to the trust store, the leaf key is still extracted if asked). A miss verifies the certificate the usual way, then caches it if it is a CA.

**Only CAs are cached, never leaf certificates.** Caching a leaf would be unsafe: a later request that sends the leaf on its own could get a cache hit and pass, even though its issuer isn't loaded and the signature check would have failed. CAs are safe to cache because each one is verified as a link in a full chain before it is trusted.

The root-id tag is what makes a cached result safe to reuse. A lookup hits only if the entry's roots are all among the roots the current caller has loaded. This is safe because adding trusted roots can never undo a verify that already passed — so if the original roots are still trusted, the cached result still holds. Single-root verifies make the most reusable entries (one root, easy to match); multi-root verifies make narrower ones that need more roots to match. Both kinds share the same cache.

When a trusted root is added or erased, the server automatically drops every entry that referenced that id. It drops the whole entry rather than just that one id, because the removed root may have been the anchor that made the chain pass. This stops a reused id from producing a stale hit under a root that is no longer there.

The cache is on by default once compiled in, and clients can manage it at runtime:

- **Clear** (`wh_Client_CertVerifyCacheClear`): empty the cache. The next verify re-checks and re-caches.
- **Enable/disable** (`wh_Client_CertVerifyCacheSetEnabled`): turn caching off (which also empties it) or back on. Disable it when you want every verify to run the full signature check.

When full, the cache overwrites the oldest entry first. It holds `WOLFHSM_CFG_CERT_VERIFY_CACHE_COUNT` entries, and each entry tracks up to `WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS` roots.

By default each client has its own cache. Defining `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL` makes one shared cache (with its own lock), so a CA verified by one client can hit for another, and clear/disable then apply to every client. This stays safe: each hit is still checked against the caller's own loaded roots, so no client can borrow another's trust anchors.

> **Note**: A cache hit skips wolfSSL's verify path, so it also skips any verify callback you registered (`whServerCertConfig.verifyCb`, or `wh_Server_CertSetVerifyCb` at runtime). If your callback must run on every chain, leave the cache disabled.

### Attribute Certificate (Acert) Support

When built with `WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT`, wolfHSM also accepts and verifies [RFC 5755](https://www.rfc-editor.org/rfc/rfc5755) **attribute certificates**. An attribute certificate (acert) is a short-lived, separately signed assertion of *attributes* — typically roles, group memberships, or authorization claims — bound to a holder identified by a conventional X.509 identity certificate.

The server-side verification model for acerts is deliberately narrower than for ordinary X.509 chains: an acert is verified directly against the public key of a single trusted root certificate stored in NVM, rather than being walked through a chain. The server reads the trusted root by id, extracts its public key and algorithm, and calls `wc_VerifyX509Acert` to validate the acert's signature. Successful verification means the acert was signed by the holder of the named root, with the validity period, holder binding, and other RFC 5755 fields enforced by wolfCrypt's acert parser; semantic interpretation of the contained attributes is left to the application.

## Communication Layer and Transports

The communication layer is the substrate that carries every client request to the server and every server response back. It sits between the high-level client/server APIs and the platform-specific medium that actually moves bytes between them, and is responsible for everything that has to be true for those APIs to behave as a coherent request/response protocol regardless of where the two sides are physically located. Concretely, it provides a fixed-MTU packet framing with a versioned header, a sequence-numbering scheme that lets the client match each response to its outstanding request, and a pluggable transport interface that the platform implements once and the rest of the library never has to know about.

The stack is two layers:

- The **comm layer** (`whCommClient` and `whCommServer`, declared in `wolfhsm/wh_comm.h`) provides packet framing, sequence numbering, and the public send/receive functions that the higher-level APIs build on.
- The **transport layer** (`whTransportClientCb` and `whTransportServerCb`) is a small callback table that delivers complete packets between the two endpoints. The comm layer speaks to it through this interface and never touches the underlying medium directly.

Higher-level wolfHSM APIs — the keystore client, the wolfCrypt callback, the NVM client, and every other client subsystem — all build their requests and responses on top of `whCommClient`/`whCommServer` and are agnostic to which transport is in use underneath.

### Communication Layer

Each request or response is a single packet composed of an 8-byte `whCommHeader` followed by up to `WOLFHSM_CFG_COMM_DATA_LEN` bytes of payload. The header carries:

- A **magic** field that combines a 1-byte endianness marker and a 1-byte protocol version. The endianness marker lets the receiving side detect a mismatched byte order and use the protocol's translation helpers (`wh_Translate16`/`32`/`64`) to byte-swap multi-byte fields as it parses them, so heterogeneous client/server pairings on a single SoC do not need a separate framing layer to agree on byte order.
- A **kind** field that identifies the message: an 8-bit group naming the subsystem (`COMM`, `NVM`, `KEY`, `CRYPTO`, `CERT`, `SHE`, `COUNTER`, `AUTH`, `CUSTOM`, …) and an 8-bit action within that group. The server uses the group to dispatch the packet to the correct subsystem handler and the action to invoke the specific operation. This is what allows a single transport connection to be multiplexed across every wolfHSM feature.
- A **seq** field, incremented on each client request and copied verbatim onto the matching response. The client validates the sequence number on receipt and rejects mismatched or stale packets, which is what makes the split-transaction client API safe in the face of late or duplicated responses.
- An **aux** field that conveys a session identifier (or `NORESP` for fire-and-forget requests) on the way out and a coarse outcome code (`OK`, `ERROR`, `FATAL`, `UNSUPP`) on the way back, separately from any payload-carried return code.

The comm layer itself is **stateless** in the protocol sense: each request/response transaction stands alone, no session state is required for the server to interpret it, and the only client-side state that persists between calls is the next sequence number and whether a request is currently outstanding. Higher-level features that do require session state (authentication, monotonic counters, etc.) layer it on top of the comm packets rather than embedding it in the protocol itself. The practical consequence is that a single server can serve multiple independent clients over multiple independent transport instances without those clients sharing any state at the comm layer.

The comm layer is also **non-blocking and split-transaction** end-to-end: `wh_CommClient_SendRequest` and `wh_CommClient_RecvResponse` return `WH_ERROR_NOTREADY` rather than waiting on the transport, and the same convention is propagated up through every higher-level client API. Transport errors below this layer surface as either `WH_ERROR_NOTREADY` (retry) or `WH_ERROR_ABORTED` (fatal — clean up and reinitialize the connection), and the higher-level APIs distinguish between the two so applications can implement appropriate retry or recovery logic. See [Client/Server Communication](4-Architecture.md#clientserver-communication) for the broader request/response model that this layer implements.

### Transport Backends

The transport interface — `whTransportClientCb` on the client side and `whTransportServerCb` on the server side — is a four-function callback table (`Init`, `Send`, `Recv`, `Cleanup`) that delivers complete, MTU-sized packets between client and server. The comm layer speaks only through this interface, so wolfHSM is integrated into a new platform by supplying a transport implementation rather than by modifying the core library. Transports are expected to deliver packets reliably and in order, one at a time and up to `WH_COMM_MTU` bytes; framing, sequencing, dispatch, and policy enforcement are all handled above.

wolfHSM ships with several reference transports that between them cover the most common system topologies:

- **Memory buffer transport** (`wolfhsm/wh_transport_mem.h`): the canonical transport for systems where the client and server share memory — typically a multi-core SoC where the server runs on a secure core and clients run on application cores. Two pre-allocated buffers, one for requests and one for responses, hold the active packet alongside a small control/status header used for flow control. The implementation is small and dependency-free so that ports can use it directly or layer hardware notification (mailbox, interrupt) on top.
- **POSIX TCP transport** (`port/posix/posix_transport_tcp.h`): carries the packet exchange over a length-prefixed TCP stream. The server listens on a configured port and the client connects to it. This is the default transport for the POSIX server example and the recommended development transport, because the client and server can live in separate host processes — or on separate machines — without any additional platform integration.
- **POSIX shared memory transport** (`port/posix/posix_transport_shm.h`): hosts the same request/response buffer layout used by the memory buffer transport in a named POSIX shared memory object, with optional space for DMA-style buffers alongside it. This lets the client and server run as independent processes on the same host while exercising the shared-memory code paths a multi-core SoC would use in production.
- **TLS-over-TCP transport** (`port/posix/posix_transport_tls.h`): wraps the POSIX TCP transport in a wolfSSL-secured channel, with support for certificate-based authentication and PSK. It is intended for deployments where the client and server are physically separated and the link between them cannot be trusted. The packet framing above the TLS session is identical to the plain TCP transport, so higher-level code does not change between the two.
- **ARMv8-M TrustZone NSC bridge transport** (`port/armv8m-tz/wh_transport_nsc.h`): a synchronous transport for ARMv8-M Cortex-M parts where the server runs in the secure world and clients run in the non-secure world. The non-secure client `Send` calls a single `cmse_nonsecure_entry` veneer (`wcs_wolfhsm_transmit`) the integrator provides; that veneer hands the request to the secure-side server inline and returns the response in the same call, which `Recv` then yields. There is no polling or shared-memory ring. The transport is target-agnostic across ARMv8-M parts; the veneer, flash/NVM adapter, and server init are supplied by the secure-side integration. The reference integration is the wolfBoot STM32H5 port.

Beyond the reference transports, platform ports for embedded targets typically supply hardware-specific transports — silicon mailboxes, interrupt-driven inter-core channels, vendor IPC blocks — by implementing the same callback interface. The comm-layer contract is purely "deliver one packet, in order," so a transport need only marshal bytes between the two sides.

Choosing a transport is primarily a function of system topology:

- **Single SoC, server on a secure core**: the memory buffer transport (or a port-supplied hardware mailbox transport built on the same packet model) is the natural choice.
- **Development against a host-side server, or remote production access**: the POSIX TCP transport for trusted links and the TLS-over-TCP transport when confidentiality or authentication on the link is required.
- **Multi-process workloads on a single host**: the POSIX shared memory transport keeps the client and server in separate address spaces while preserving shared-memory packet semantics, which is useful both for testing port-supplied shared-memory transports and for validating client integrations against an example server without modifying either.

The choice of transport does not affect any other part of the system — the same client code, the same wolfCrypt calls, and the same server initialization sequence work across every transport.

## DMA Support

Every request that travels through the [communication layer](#communication-layer-and-transports) is bounded by `WOLFHSM_CFG_COMM_DATA_LEN`, and operations that exceed that bound must otherwise be split across multiple round-trips. For workloads that have direct memory-sharing pathways between client and server — most commonly a multi-core SoC where the secure core can address the application core's RAM, or a host environment with shared memory — wolfHSM provides an optional **DMA** mode in which the server reads and writes the client's buffers in place rather than marshaling them through the message buffer. The feature is enabled with `WOLFHSM_CFG_DMA` and is layered onto the existing client/server protocol: a parallel set of DMA-aware request kinds carry pointers and lengths into the client's address space instead of inline data, and the server resolves those pointers under server-enforced policy before touching the underlying memory.

The motivating use cases all involve payloads that are either too large or too inconveniently placed to copy through the comm buffer:

- **Bulk symmetric crypto** over multi-kilobyte messages (AES-CBC/CTR/GCM/ECB, CMAC, streaming SHA-2 updates) where the cost of two copies dominates the cost of the cryptographic primitive.
- **Bulk asymmetric crypto** over large messages or signature buffers (ML-DSA sign/verify, Ed25519 sign/verify) and the associated key import/export paths.
- **Large NVM objects** (`wh_Client_NvmAddObjectDma`, `wh_Client_NvmReadDma`) where the object payload is larger than `WOLFHSM_CFG_COMM_DATA_LEN`.
- **Certificate chain verification** (see [DMA Variants](#dma-variants)) where the chain itself may be several kilobytes and the application already holds it in its own memory.
- **In-place image verification** by the [image manager](#image-manager), which is the canonical case: the image being authenticated is already mapped in flash or RAM, and copying it through the comm buffer would defeat the purpose.

### DMA Dispatch Mode (`wh_Client_SetDmaMode`)

For wolfCrypt-mediated operations, opt-in to DMA is a per-client dispatch mode rather than a separate device ID: the application calls `wh_Client_SetDmaMode(client, 1)` (or sets `.preferDma` in the client's `whClientDmaConfig` at init), and subsequent wolfCrypt calls made with `WH_CLIENT_DEVID(client)` construct DMA-flavored requests whose payloads carry pointers and lengths into the client's address space rather than inline data. The server-side dispatcher recognizes the DMA request kind and, for each referenced buffer, hands the pointer to the server's DMA address-processing path (described below) before invoking the underlying wolfCrypt primitive. The set of algorithms that have a DMA path mirrors the most performance-sensitive subset of the supported algorithms; with DMA mode preferred, an algorithm without a DMA path automatically falls back to the standard (non-DMA) request, so no call-site changes are needed. The mode can be toggled at any time — `wh_Client_SetDmaMode(client, 0)` returns the client to standard dispatch, and `wh_Client_GetDmaMode()` reads the current setting.

The global `WH_DEV_ID_DMA` device ID is also always registered when `WOLFHSM_CFG_DMA` is enabled and always produces DMA-flavored requests for the most recently initialized client; unlike the DMA dispatch mode, it does not fall back to the standard path for algorithms without a DMA variant. See [Transparent Offload via Crypto Callbacks](#transparent-offload-via-crypto-callbacks) for the global device IDs' single-client-per-process scope.

For the non-crypto subsystems (NVM, certificate manager, image manager, key cache/export, and the data-wrap API) the DMA-aware request kinds are exposed as `*Dma` variants of the corresponding client API functions — `wh_Client_NvmAddObjectDma`, `wh_Client_KeyCacheDma`, `wh_Client_KeyExportDma`, `wh_Client_CertVerifyDma`, and so on. See the [client API reference](10-API-docs-client.md) for the full set.

### Pre-Access and Post-Access Callbacks

A pointer that is valid in the client's address space is not necessarily valid in the server's. On a multi-core SoC the two cores may have distinct memory maps, distinct cache hierarchies that need to be synchronized before and after a shared-buffer access, or both. wolfHSM does not bake any particular assumption about this relationship into the server; instead, it exposes a port-supplied callback that the server invokes around every client-memory access, paired with optional flags to control cache behavior. The callback is registered at server initialization via `wh_Server_DmaRegisterCb` (or as part of `whServerDmaConfig`).

The callback signature is:

```c
int whServerDmaClientMemCb(whServerContext* server,
                           uintptr_t        clientAddr,
                           void**           serverPtr,
                           size_t           len,
                           whServerDmaOper  oper,
                           whServerDmaFlags flags);
```

It is called twice per access — once before, once after — with the `oper` argument distinguishing the four phases:

- `WH_DMA_OPER_CLIENT_READ_PRE` — the server is about to read `len` bytes from `clientAddr`. The callback should translate the address into a server-accessible pointer in `*serverPtr` and, on a system with caches, invalidate or flush the corresponding cache lines so the subsequent read sees up-to-date client memory.
- `WH_DMA_OPER_CLIENT_READ_POST` — the read has completed. Tear-down hook for any state the PRE callback set up.
- `WH_DMA_OPER_CLIENT_WRITE_PRE` — the server is about to write `len` bytes to `clientAddr`. The callback translates the address and may perform whatever cache preparation the platform requires (flushing dirty lines from the server cache, for example, so the subsequent write is the authoritative copy).
- `WH_DMA_OPER_CLIENT_WRITE_POST` — the write has completed. On a system where the client must observe the write through its own cache, this is the hook that invalidates the client-visible cache lines.

If no callback is registered, the server uses the client address directly as `*serverPtr`, which is the right behavior for a system with a flat shared address space and coherent caches. Ports that need either address translation or cache maintenance supply a callback that handles both; the callback is the single extension point for both concerns.

For platforms where the client buffer is not directly memcpy-able even after address translation — for example, when the only path to client memory is through a hardware FIFO or register window — wolfHSM additionally exposes a `whServerDmaMemCopyCb` callback under `WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY`. When registered (via `wh_Server_DmaRegisterMemCopyCb`), this callback replaces the internal `memcpy` between server and client memory entirely, and is the only operation that touches the client side of the transfer.

The same PRE/POST callback model is also available on the **client side** through `wh_Client_DmaRegisterCb`, with an identical `whClientDmaClientMemCb` signature. The client callback is invoked before the request is sent and after the response is received, and is the right place for any work that has to happen in the client's address space before the server is ever told about a buffer — pinning pages, flushing the client's view of a cache line, or substituting the application's pointer with one that lives in a region the server can actually reach. The POSIX shared-memory transport illustrates the last case: an application buffer allocated from the process's ordinary heap is not visible to the server because it lies outside the mapped shared-memory segment, so the transport's client callback (`posixTransportShm_ClientStaticMemDmaCallback`) detects that the supplied address falls outside the DMA region, allocates a bounce buffer inside the shared segment on `*_READ_PRE`/`*_WRITE_PRE`, copies the application data into it for the read direction, and reports the in-segment offset as the address the server should use. The matching POST phase copies any server-written bytes back to the original application buffer and frees the bounce buffer. From the application's perspective the original wolfCrypt call is unchanged; the client callback transparently bridges the gap between the application's address space and the address space the server can address. Client-side and server-side callbacks are independent — a port may register either, both, or neither, depending on which side needs the translation.

The `whDmaFlags` argument carries per-request hints supplied by the client. Currently the only defined flag is `cacheForceInvalidate`, which the client sets when it has reason to believe the server should not trust any cached view of the buffer (after a DMA write by another agent, for example). Additional flags are reserved for future protocol extensions.

### Address Allowlisting

Because DMA gives the server the ability to read or write any address the client passes, an unconstrained DMA path would let a compromised or buggy client direct the server to access memory it has no business touching — kernel memory, other processes' buffers, peripherals mapped into the address space. wolfHSM accordingly enforces, in the server, an **allowlist** of address ranges that DMA requests are permitted to reference. The allowlist is supplied by the port at server initialization (`wh_Server_DmaRegisterAllowList` or `whServerDmaConfig::dmaAddrAllowList`) and is consulted on every PRE phase of every DMA operation.

The allowlist is two parallel tables — one for client reads (server reads from client memory) and one for client writes (server writes to client memory) — so that a region can be made readable without being writable. Each entry is a `{addr, size}` pair, and a DMA request is accepted only if the requested range is **fully contained** within at least one entry in the relevant table. Partial overlap is treated as a failure, and a request that fails the check is rejected with `WH_ERROR_ACCESS` before any access actually occurs. POST phases skip the check on the assumption that the address was already validated at PRE.

When the allowlist is not registered the server allows every address, which is appropriate only for tightly trusted single-application systems and for development. **Production deployments should always supply an allowlist** that covers exactly the shared-memory regions the application is permitted to use; the allowlist is the primary mechanism that bounds the blast radius of a misbehaving client and is the difference between DMA being a performance feature and DMA being an exfiltration channel. The size of the allowlist is bounded at compile time by `WOLFHSM_CFG_DMAADDR_COUNT` entries per direction; a zero-sized entry is treated as unused.

A symmetric `whDmaAddrAllowList` is also available on the client side for clients that wish to validate addresses locally before issuing a DMA request (`whClientDmaConfig::dmaAddrAllowList`). Client-side validation is advisory — the server's check is the authoritative one — but it lets a client fail fast when its own code accidentally constructs an out-of-range pointer.

### 32-bit vs. 64-bit Address Handling

The DMA path is designed so that a 32-bit client can interoperate with a 64-bit server, and vice versa, without either side losing information. All DMA pointers on the wire are 64-bit (`uint64_t`) regardless of the native pointer size on either endpoint: the client zero-extends its address into the request and the server narrows on receipt if its pointers are 32-bit (with an overflow check that rejects out-of-range values). The runtime callback signatures use `uintptr_t` so the platform's native pointer width drives address translation. The build distinguishes the two cases via `WH_DMA_IS_32BIT` and `WH_DMA_IS_64BIT`, derived automatically from the system pointer size or set explicitly via `WOLFHSM_CFG_DMA_PTR_SIZE` when the build needs to override that default.

This wire-format choice is what makes asymmetric topologies — a 64-bit secure host serving a 32-bit application core, for example — work without special-case message structures.

## AUTOSAR SHE Subsystem

The AUTOSAR Secure Hardware Extension (SHE) is an automotive industry specification for a small, fixed-function security module embedded alongside an ECU's application core. It defines a set of 128-bit AES key slots, an encrypted key update protocol, a deterministic PRNG, and a CMAC-based secure boot mechanism — together intended to give an ECU the minimum trusted-crypto surface needed for in-vehicle networks. wolfHSM ships an optional SHE implementation, enabled with `WOLFHSM_CFG_SHE_EXTENSION`, that layers a spec-compliant SHE server and client API on top of the existing wolfHSM stack. The intent is that an application written against the SHE command set can use wolfHSM as its SHE module without modification, while still benefiting from the broader wolfHSM keystore, NVM, and transport infrastructure underneath.

The SHE extension is independent of the rest of the crypto API: a server can be built with both SHE and the generic wolfCrypt offload enabled, and clients can mix SHE commands with ordinary wolfCrypt calls over the same connection. SHE keys and native crypto keys share the underlying NVM store but live in disjoint namespaces in the keystore's [type field](#key-cache-key-ids-and-nvm-backing-store), so the two subsystems cannot collide. The primary use case is automotive ECU firmware that needs to remain conformant with AUTOSAR's SHE expectations — secure boot, MAC-authenticated CAN traffic, encrypted key provisioning — while running on hardware (or a software emulation) that does not provide a dedicated SHE peripheral.

### Client API and Command Set

The SHE client API is declared in `wolfhsm/wh_client_she.h` and maps one-to-one onto the AUTOSAR SHE command set. Each spec command is exposed as a `wh_Client_She*` function, with the same `Request` / `Response` split-transaction variants that the rest of the wolfHSM client API uses (see [Blocking and Non-Blocking Interfaces](#blocking-and-non-blocking-interfaces)). The full set comprises:

- **Secure boot**: `wh_Client_SheSecureBoot` (`CMD_SECURE_BOOT`) — drives the three-phase INIT/UPDATE/FINISH state machine and reports the boot result through the status register
- **Key update**: `wh_Client_SheLoadKey` (`CMD_LOAD_KEY`) — performs the encrypted M1–M5 key update protocol against any slot other than `RAM_KEY`
- **Plain key update**: `wh_Client_SheLoadPlainKey` (`CMD_LOAD_PLAIN_KEY`) and `wh_Client_SheExportRamKey` (`CMD_EXPORT_RAM_KEY`) — load the volatile `RAM_KEY` directly, and export it as an M1–M5 blob bound to the master ECU key for transfer to a peer
- **PRNG**: `wh_Client_SheInitRnd` (`CMD_INIT_RNG`), `wh_Client_SheRnd` (`CMD_RND`), and `wh_Client_SheExtendSeed` (`CMD_EXTEND_SEED`) — initialize, draw from, and reseed the spec's deterministic PRNG
- **Bulk crypto**: `wh_Client_SheEncEcb` / `wh_Client_SheEncCbc` / `wh_Client_SheDecEcb` / `wh_Client_SheDecCbc` (`CMD_ENC_*` / `CMD_DEC_*`) — AES-ECB and AES-CBC encrypt and decrypt against a selected key slot
- **MAC**: `wh_Client_SheGenerateMac` / `wh_Client_SheVerifyMac` (`CMD_GENERATE_MAC` / `CMD_VERIFY_MAC`) — CMAC generation and verification against a selected key slot
- **Status**: `wh_Client_SheGetStatus` (`CMD_GET_STATUS`) — reads the SHE status register (SREG)

In addition to the spec commands, wolfHSM exposes two non-standard helpers that fill gaps left by the spec's assumption of dedicated hardware:

- `wh_Client_SheSetUid`: explicitly programs the 15-byte ECU UID that the key update protocol binds against. The AUTOSAR spec assumes this value is hardware-fused; wolfHSM needs a software path to install it, and rejects most SHE operations until it has been set.
- `wh_Client_ShePreProgramKey`: writes a key directly into a SHE NVM slot, bypassing the encrypted M1–M5 protocol. This exists to support initial provisioning on a blank device — once a `MASTER_ECU_KEY` exists, all subsequent updates can go through the spec-compliant protocol.

All SHE commands return one of the spec's `WH_SHE_ERC_*` error codes (`SEQUENCE_ERROR`, `KEY_NOT_AVAILABLE`, `WRITE_PROTECTED`, `KEY_UPDATE_ERROR`, etc.) alongside the wolfHSM transport return code, so applications can distinguish protocol-level failures from communication failures.

### SHE Key Slots and the wolfHSM Keystore

The AUTOSAR SHE specification defines sixteen 128-bit AES key slots, identified by IDs 0 through 15, with fixed roles for several of them:

- **`SECRET_KEY`** (ID 0): the master secret consumed by the PRNG derivation
- **`MASTER_ECU_KEY`** (ID 1): the ECU's identity key, used as the authorization key for key updates
- **`BOOT_MAC_KEY`** (ID 2): the key used to compute the bootloader CMAC during secure boot
- **`BOOT_MAC`** (ID 3): the expected CMAC digest of the bootloader, compared against during secure boot
- **`KEY_4`…`KEY_13`** (IDs 4–13): ten general-purpose user key slots
- **`RAM_KEY`** (ID 14): a volatile slot that lives only in the cache and is lost on power cycle
- **`PRNG_SEED`** (ID 15): the persistent PRNG seed state

wolfHSM does not implement these slots as a parallel storage layer; they are stored as ordinary objects in the [NVM and keystore](#keystore), with the SHE-specific roles encoded in the keyId. Each SHE key is given a `whKeyId` constructed with the `WH_KEYTYPE_SHE` type field, the connection's client ID in the USER field, and the SHE slot number in the ID field. The `WH_KEYTYPE_SHE` type means SHE objects are distinct from `WH_KEYTYPE_CRYPTO` keys even when they share the same numeric slot number, and the USER field gives every connected client its own independent set of sixteen SHE slots — a property that follows directly from the keystore's per-client isolation model and that the SHE spec itself does not require but that wolfHSM provides for free.

The SHE spec also requires every key to carry a 28-bit monotonic update counter and a 5-bit set of protection flags (`WRITE_PROTECT`, `BOOT_PROTECT`, `DEBUGGER_PROTECTION`, `USAGE`, `WILDCARD`). wolfHSM stores these by repurposing the first eight bytes of the NVM `label` field as a `whSheMetadata` record holding the counter and flags in big-endian order; conversion is done by `wh_She_Meta2Label` / `wh_She_Label2Meta`. This means SHE keys need no additional NVM machinery beyond what the generic object store already provides: the counter and protection flags survive resets exactly like the key payload itself, and the SHE-side update logic — counter strictly-increasing checks, `WRITE_PROTECT` enforcement, and the rest — is implemented on top of the existing metadata round-trip.

`RAM_KEY` is the one exception to NVM-backed storage. The spec defines it as volatile, so the server caches the loaded key in its [key cache](#key-cache-key-ids-and-nvm-backing-store) but never calls into the NVM layer for it; eviction or reset clears it. All other slots, including `PRNG_SEED`, persist.

### Encrypted Key Update Protocol (M1–M5)

The most intricate piece of the SHE spec is the encrypted key update protocol that runs underneath `CMD_LOAD_KEY`. wolfHSM implements it as specified: the client constructs three input messages (M1, M2, M3) by encrypting and CMACing the new key and its metadata under keys derived from a chosen authorization key, sends them to the server, and receives two response messages (M4, M5) that prove the server stored the new key correctly.

The protocol uses a key derivation function based on the **Miyaguchi-Preneel** one-way compression construction (`wh_She_AesMp16` in `wh_she_crypto.c`), with the exact derivation constants — `KEY_UPDATE_ENC_C`, `KEY_UPDATE_MAC_C`, `PRNG_KEY_C`, `PRNG_SEED_KEY_C` — that the AUTOSAR specification mandates. From the authorization key the server derives an encryption key (K1) and a MAC key (K2) for verifying the request, and from the *new* key it derives a separate pair (K3, K4) for proving storage in the response.

The server-side handler enforces all of the spec's update constraints in addition to verifying M3 and decrypting M2: the new counter must be strictly greater than the previous counter for that slot (rollback protection), the existing `WRITE_PROTECT` flag must not be set, the UID in M1 must match the ECU's configured UID (unless the existing key has `WILDCARD` set and M1 carries the all-zero UID), and the authorization key referenced by the AID field in M1 must exist. Only after all of these pass is the new key written into NVM and the response constructed.

### Secure Boot

SHE secure boot is implemented as a three-phase state machine that the client drives via `CMD_SECURE_BOOT`:

1. **INIT**: the client supplies the total bootloader length; the server reads `BOOT_MAC_KEY` from NVM, initializes a CMAC with a 12-byte zero prefix followed by the length, and transitions to the UPDATE state.
2. **UPDATE**: the client streams the bootloader into the CMAC in arbitrary-sized chunks; the server feeds each chunk into the running CMAC and stays in UPDATE until the cumulative length matches the value declared in INIT.
3. **FINISH**: the server finalizes the CMAC and compares it byte-for-byte against the stored `BOOT_MAC` (slot ID 3). A match sets `WH_SHE_SREG_BOOT_OK` in the status register; a mismatch leaves `BOOT_OK` clear. Either outcome sets `BOOT_FINISHED` and transitions the state machine to a terminal state.

While the state machine is in any state other than `SUCCESS`, the SHE handler refuses every non-boot command except `CMD_GET_STATUS` and `CMD_SET_UID`, returning `WH_SHE_ERC_SEQUENCE_ERROR`. This is what allows the SHE module to gate cryptographic services on a successful boot measurement: once boot has succeeded, the rest of the SHE command set unlocks; on a boot failure the keys remain inaccessible and only status queries are honored.

The bootloader bytes are supplied through the standard message buffer in chunks of up to `WOLFHSM_CFG_COMM_DATA_LEN`. For large bootloaders this is the natural place to opt into [DMA](#dma-support) — a future variant of the secure boot handler could read the bootloader image directly out of flash using the DMA address-translation path — but the current implementation is purely buffer-based.

### Deterministic PRNG

The SHE PRNG is deterministic, seeded from the master `SECRET_KEY` and a persisted `PRNG_SEED`, and is meant to be used both for spec-defined operations (the M5 verification path, internal nonce generation) and as a standards-compliant entropy source for the application:

- `CMD_INIT_RNG`: the server reads `SECRET_KEY` and `PRNG_SEED` from NVM, derives `PRNG_KEY` and a new state via the spec's Miyaguchi-Preneel construction, advances the seed, and writes the new seed back to NVM. After this completes `WH_SHE_SREG_RND_INIT` is set in the status register.
- `CMD_RND`: each invocation runs an AES-CBC encryption of the current PRNG state under `PRNG_KEY` to produce 16 bytes of output and advance the state.
- `CMD_EXTEND_SEED`: mixes 16 bytes of caller-supplied entropy into the state via the same Miyaguchi-Preneel compression and writes the updated seed back to NVM, so reseeding survives reboots.

The PRNG's `state` and derived `prngKey` live in the per-connection `whServerSheContext`, while the persisted `PRNG_SEED` (slot ID 15) lives in NVM exactly like any other SHE key. This is the only piece of SHE that maintains live cryptographic state in the server context rather than in the keystore.

### Status Register (SREG)

The SHE status register is an 8-bit field that reports the module's current secure-boot and PRNG state. The wolfHSM implementation maps the spec's bits as follows:

- `SECURE_BOOT` (bit 1): set if a `BOOT_MAC_KEY` has been provisioned for the connected client
- `BOOT_FINISHED` (bit 3): set after secure boot has completed, regardless of outcome
- `BOOT_OK` (bit 4): set only if secure boot succeeded
- `RND_INIT` (bit 5): set after `CMD_INIT_RNG` has succeeded for the current session

The `BUSY` (bit 0), `BOOT_INIT` (bit 2), `EXT_DEBUGGER` (bit 6), and `INT_DEBUGGER` (bit 7) positions are reserved and not currently driven by the implementation; the corresponding spec-defined behaviors (debugger-presence interlocks, asynchronous busy reporting) are intentionally out of scope for the software implementation and would be supplied by a hardware-backed port if needed.

### Integration with the Rest of wolfHSM

The SHE extension is built on top of the same infrastructure as every other wolfHSM feature, with a few specific touchpoints worth calling out:

- **NVM**: SHE keys are ordinary NVM objects under the `WH_KEYTYPE_SHE` namespace; they inherit fail-safe atomicity, partition compaction, and the rest of the [NVM](#non-volatile-memory-nvm) guarantees. The 24-byte `label` field carries SHE-specific counter and flag metadata.
- **Keystore**: SHE keys live in the same per-client `whKeyId` space as crypto keys, with the TYPE field disambiguating the two. SHE keys do not currently consume the per-key [usage flag policy](#key-usage-policies) machinery — usage constraints are expressed through the SHE-spec flag set in the label instead — but lifecycle flags like `NONMODIFIABLE` apply at the NVM layer just as they do for any other object.
- **Communication layer**: every SHE command is a packet under the `WH_MESSAGE_GROUP_SHE` group and is dispatched through the [comm layer](#communication-layer-and-transports) like any other request. SHE clients work over every available transport without modification.
- **Global keys** and **wrapped keys**: not currently supported for SHE keys — the SHE keyId namespace uses the per-client USER field and does not interpret `WH_KEYUSER_GLOBAL` or the wrapped flag. Applications that need to share a key across clients must do so by provisioning it into each client's SHE namespace separately.

A typical automotive deployment uses the SHE extension end-to-end: the bootloader and `BOOT_MAC` are programmed into NVM at production using `wh_Client_ShePreProgramKey`, the device's UID is set on first boot with `wh_Client_SheSetUid`, secure boot is run on every reset via `wh_Client_SheSecureBoot`, in-field key updates flow through the encrypted `CMD_LOAD_KEY` protocol, and CAN message authentication uses `wh_Client_SheGenerateMac` / `wh_Client_SheVerifyMac` against pre-provisioned user-slot keys.

## Non-Volatile Monotonic Counters

wolfHSM provides **non-volatile monotonic counters**: server-resident 32-bit values that are guaranteed never to decrease across resets and power cycles. They are the building block for anti-rollback checks on firmware versions, replay protection, audit tallies, and unique-per-boot nonces — anywhere an application needs a persistent, strictly-increasing value that a client cannot rewind. 

### Counter Semantics

A counter is a 32-bit unsigned value supporting four operations:

- **Init**: create the counter with a caller-supplied starting value, or overwrite an existing counter. **Reset** is the same call with value zero. This is the only path that can lower a counter, intended for provisioning rather than runtime use.
- **Increment**: atomically read, add one, and write back. Returns the new value.
- **Read**: return the current value without modifying it.
- **Destroy**: remove the counter from NVM. Subsequent reads and increments return `WH_ERROR_NOTFOUND` until it is re-initialized.

Increment **saturates at `UINT32_MAX`** rather than rolling over: once the counter reaches the maximum it stays there, and no NVM write is performed. Silent rollover would defeat the monotonicity guarantee, so the subsystem refuses to wrap even at the cost of losing further increments. Applications approaching saturation should treat the counter as exhausted and rotate to a new identifier.

Every mutating operation is committed by the NVM layer before the response is returned, so a power loss leaves the counter at either its pre- or post-increment value but never in between. The implementation uses `wh_Nvm_AddObjectWithReclaim`, so the partition is compacted in place as needed and a frequently-incremented counter does not accumulate dead entries.

### Counter Identifiers and Storage

A counter is referenced by a 16-bit `whNvmId` supplied by the caller, with `WH_KEYID_ERASED` (0) reserved as invalid. Internally the server encodes it as a `whKeyId` with TYPE = `WH_KEYTYPE_COUNTER`, USER = the connection's client id, and ID = the supplied value. This means counters inherit the keystore's [per-client isolation](#key-cache-key-ids-and-nvm-backing-store) — each client has its own counter namespace — and that counter id 5 and key id 5 are distinct objects in the same NVM store.

The 32-bit value is stored in the **`label` field of the object's `whNvmMetadata`** with a zero-length payload. A counter therefore lives entirely in the metadata that the NVM layer already reads on every directory operation, so an increment is a single metadata write and a read is satisfied by `wh_Nvm_GetMetadata` alone. The remainder of the label and the access/flags fields are unused by the counter subsystem. Counters share the `WOLFHSM_CFG_NVM_OBJECT_COUNT` object budget with keys and other NVM objects.

### Client API

The operations are exposed in `wolfhsm/wh_client.h`:

- `wh_Client_CounterInit(ctx, counterId, &value)` — create or overwrite with the supplied initial value
- `wh_Client_CounterReset(ctx, counterId, &value)` — initialize to zero
- `wh_Client_CounterIncrement(ctx, counterId, &value)` — atomically increment, return the new value
- `wh_Client_CounterRead(ctx, counterId, &value)` — read without modifying
- `wh_Client_CounterDestroy(ctx, counterId)` — remove from NVM

Each function has split-transaction `Request` / `Response` counterparts for non-blocking use. Requests are dispatched under `WH_MESSAGE_GROUP_COUNTER` through the standard [communication layer](#communication-layer-and-transports).

## Image Manager

The image manager is a server-side facility for authenticating an arbitrary region of memory — typically a firmware image, but equally a data blob, a configuration record, or any other contiguous payload — against a cryptographic signature or MAC using a key resident in the server. It is enabled with `WOLFHSM_CFG_SERVER_IMG_MGR` and is the canonical mechanism by which a wolfHSM-equipped system can drive HSM-mediated secure boot of an application core, gate execution of a dynamically loaded image, or perform a periodic runtime integrity check of a code or data region without ever exposing the verifying key or the signature to the client.

The verification model is straightforward: each managed image is described by a pointer and length into the memory the server can address, plus the [keyId](#key-cache-key-ids-and-nvm-backing-store) of the verification key and either an [NVM id](#non-volatile-memory-nvm) for the signature or an indication that the signature is embedded in the image itself. At verification time, the server reads the image (in place, via [DMA](#dma-support), when available), loads the key from the keystore, retrieves the signature, runs a verify method against the configured algorithm, and invokes an application-supplied action callback with the result.

### Image Configuration

Images are registered at server initialization through a `whServerImgMgrConfig` that points to an array of `whServerImgMgrImg` records. The maximum number of managed images is bounded at compile time by `WOLFHSM_CFG_SERVER_IMG_MGR_MAX_IMG_COUNT`. Each `whServerImgMgrImg` carries:

- `addr` / `size`: the location and size of the image payload in server-addressable memory
- `hdrAddr` / `hdrSize`: for image formats whose signature is embedded in the image itself (such as wolfBoot), the location of the header from which the signature and ancillary metadata are extracted
- `keyId`: the [keyId](#key-cache-key-ids-and-nvm-backing-store) of the verification key
- `sigNvmId`: for image types whose signature lives in NVM, the `whNvmId` of the signature object; for cert-chain image types, the `whNvmId` of the trusted root certificate
- `imgType`: one of `WH_IMG_MGR_IMG_TYPE_RAW`, `WH_IMG_MGR_IMG_TYPE_WOLFBOOT`, or `WH_IMG_MGR_IMG_TYPE_WOLFBOOT_CERT`, which tells the framework how to load the key and signature
- `verifyMethod`: the verify callback that runs the actual cryptographic check
- `verifyAction`: the post-verification callback invoked with the verify result

Once registered, an image can be verified individually by reference (`wh_Server_ImgMgrVerifyImg`), by index into the registered array (`wh_Server_ImgMgrVerifyImgIdx`), or in bulk against every registered image (`wh_Server_ImgMgrVerifyAll`). All three calls return both the cryptographic outcome and the action callback's return value through a `whServerImgMgrVerifyResult` so the caller can distinguish a verification failure from an action failure.

### Verify Methods

A *verify method* is the callback that performs the cryptographic check against a `(image, key, signature)` triple. The signature is:

```c
int verifyMethod(whServerImgMgrContext* ctx,
                 const whServerImgMgrImg* img,
                 const uint8_t* key, size_t keySz,
                 const uint8_t* sig, size_t sigSz);
```

A verify method returns `WH_ERROR_OK` on a successful verification, `WH_ERROR_NOTVERIFIED` when the signature does not match, or a negative error code for an operational failure (DMA error, malformed input, missing key). wolfHSM ships with several built-in verify methods:

- `wh_Server_ImgMgrVerifyMethodEccWithSha256`: ECDSA P-256 signature over the SHA-256 hash of the image
- `wh_Server_ImgMgrVerifyMethodRsaSslWithSha256`: RSA PKCS#1 v1.5 signature over the SHA-256 hash of the image
- `wh_Server_ImgMgrVerifyMethodAesCmac`: AES-128 CMAC over the image bytes
- `wh_Server_ImgMgrVerifyMethodWolfBootRsa4096WithSha256`: RSA-4096 verification of a wolfBoot-formatted image (see [wolfBoot Image Support](#wolfboot-image-support))
- `wh_Server_ImgMgrVerifyMethodWolfBootCertChainRsa4096WithSha256`: cert-chain-based RSA-4096 verification of a wolfBoot image

Applications can supply their own verify method to support algorithms not represented in the built-in set, or to layer additional checks on top of an existing one — for example, validating a monotonic counter against a [non-volatile counter](#non-volatile-monotonic-counters) inside a wrapper verify method to add anti-rollback protection. The maximum signature size handled by the framework is `WOLFHSM_CFG_SERVER_IMG_MGR_MAX_SIG_SIZE`, whose default accommodates RSA-4096.

### Verify Actions

The *verify action* is the application-supplied callback invoked after the verify method completes, with the result of verification as an argument. Its signature is:

```c
int verifyAction(whServerImgMgrContext* ctx,
                 const whServerImgMgrImg* img,
                 int verifyResult);
```

The action callback is the extension point through which the image manager produces an externally visible effect. Typical actions include releasing reset on the application core whose image was just verified, jumping to the verified image's entry point, latching a hardware "verified" signal, or simply logging the outcome. Because the action receives the verify result, it is the right place to implement both success and failure handling: a boot-time action might release reset on success and assert a fault pin on failure, while a periodic-integrity action might do nothing on success and force a reset on failure.

A default no-op action, `wh_Server_ImgMgrVerifyActionDefault`, is provided for cases where the caller wants the verification result back but does not need any side effect.

### wolfBoot Image Support

wolfHSM understands the [wolfBoot](https://github.com/wolfSSL/wolfBoot) image header format natively so that a wolfHSM-equipped system can serve as the verifier for a wolfBoot-staged image without the client having to parse the header itself. Two wolfBoot image types are recognized:

- `WH_IMG_MGR_IMG_TYPE_WOLFBOOT`: the signature is extracted from the wolfBoot TLV header and verified against a key resident in the server's keystore (identified by `keyId`). This corresponds to the standard wolfBoot signing model where the signing key is known in advance and provisioned into the HSM.
- `WH_IMG_MGR_IMG_TYPE_WOLFBOOT_CERT`: the image carries a certificate chain inside its wolfBoot header; the chain is verified against a trusted root in NVM (identified by `sigNvmId`) using the [certificate manager](#certificate-management), and the leaf certificate's public key is then used to verify the image signature. This matches the wolfBoot cert-chain mode and is the right choice when the signing key is rotated independently of the on-device trust anchor.

In both cases the framework parses the header at `hdrAddr`, locates the signature TLV, validates the wolfBoot magic and public key hint, and feeds the appropriate `(image, key, signature)` triple into the wolfBoot verify method. The application's `verifyAction` is invoked exactly as for a raw image.

### In-Place Access via DMA

The image manager is fully [DMA](#dma-support)-aware. When `WOLFHSM_CFG_DMA` is enabled, the server reads the image header and payload directly from the address the caller registered, rather than having to copy the image through the comm message buffer. This is essential in practice because firmware images are typically megabytes in size, are already mapped into flash or RAM by the client, and would be impractical to ship over the comm protocol.

The DMA path runs the standard [pre- and post-access callbacks](#pre-access-and-post-access-callbacks) around every read of the image, so any cache maintenance and address translation the platform requires is handled by the same port-supplied hook that DMA crypto uses. The DMA [address allowlist](#address-allowlisting) is consulted on every access, so the image manager cannot be coerced into reading from a region the port has not explicitly permitted.

The image manager is not gated on `WOLFHSM_CFG_DMA`, and the same verification flow works in builds without DMA. In that configuration the server dereferences the registered image and header addresses directly instead of routing them through the pre- and post-access callbacks, so no address translation, cache maintenance, or allowlist check is performed. This mode is appropriate when the image already lives in memory the server can address natively — for example, an image resident in the server's own flash, or a single-address-space build where client and server share a memory map — and the caller is responsible for ensuring that `img->addr` and `img->hdrAddr` (and the lengths derived from them) refer to memory the server is permitted to read. Systems with a real client/server address-space boundary should enable DMA so the allowlist and translation callbacks apply.

## Custom Callbacks

wolfHSM's built-in feature set covers the common HSM workload, but it cannot anticipate every application-specific service that an embedded system may need to run in its secure environment. The **custom callback** feature is wolfHSM's extension point for these cases: an application registers one or more callback functions in the server's dispatch table, and clients invoke them by ID through the same request/response pipeline that carries every other wolfHSM operation. The wire framing, dispatch, and byte-order translation are handled by the library; the contents of the request and response payload are defined entirely by the application.

The mechanism is intended for operations that naturally belong on the secure side of the trust boundary but are not part of the standard HSM API. Typical uses include proprietary key derivation routines that consume on-device material, application-specific authentication or monitoring protocols that need to run alongside the standard crypto offload, and anything else specific to hardware or proprietary application functionality. Because custom callbacks reuse the standard [communication layer](#communication-layer-and-transports), the same callback works over every supported transport, and the server's normal polling loop dispatches custom requests interchangeably with built-in ones.

### Server-Side Registration and Dispatch

A custom callback is a function of type `whServerCustomCb`, defined in `wolfhsm/wh_server.h`:

```c
typedef int (*whServerCustomCb)(
    whServerContext* server,
    const whMessageCustomCb_Request* req,
    whMessageCustomCb_Response*      resp
);
```

The callback receives the dispatching server context, a translated request structure populated from the client's message, and an output response structure that wolfHSM will marshal back to the client when the callback returns. The callback populates `resp->data` with any output payload and may set `resp->err` to a wolfHSM error code; the callback's own return value is reported to the client as `resp->rc`. The library does not interpret either field — they are simply propagated to the client unchanged, with the convention that `rc` is invalid whenever `err` is non-zero.

Callbacks are registered against a 16-bit **action ID** in the server's dispatch table:

```c
int wh_Server_RegisterCustomCb(whServerContext* server, uint16_t action,
                               whServerCustomCb handler);
```

The table is statically sized at build time by `WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT`, and the action ID is the index into it. Action IDs are application-defined: they have no meaning to wolfHSM beyond identifying which slot in the table to dispatch to. Registration may occur at any point in the server's lifetime — there is no requirement to install all callbacks before the server starts handling requests — so a server application can register or replace handlers dynamically based on its own state. A request that arrives for an action ID with no registered handler is reported back to the client with `resp->err == WH_ERROR_NOHANDLER`.

### Client-Side Invocation

A client invokes a registered callback by populating a `whMessageCustomCb_Request` and sending it through the standard split-transaction client API:

- `wh_Client_CustomCbRequest()` dispatches the request to the server
- `wh_Client_CustomCbResponse()` polls for the matching response

The two functions follow the same non-blocking pattern as the rest of the client API. Because dispatch is by action ID, the client must agree with the server on the meaning of each ID — application code typically defines a shared header that names every action ID and the data layout for each.

To allow a client to query the server before invoking a callback whose presence it is unsure of, `wh_Client_CustomCbCheckRegistered()` returns `WH_ERROR_OK` if the supplied action ID has a handler installed and `WH_ERROR_NOHANDLER` if it does not.

### Request and Response Messages

The request and response messages are declared in `wolfhsm/wh_message_customcb.h`:

```c
typedef struct {
    uint32_t               id;
    uint32_t               type;
    whMessageCustomCb_Data data;
} whMessageCustomCb_Request;

typedef struct {
    uint32_t id;
    uint32_t type;
    int32_t  rc;
    int32_t  err;
    whMessageCustomCb_Data data;
} whMessageCustomCb_Response;
```

The `id` field carries the action ID, echoed back unchanged on the response for client-side bookkeeping. The `type` field is a hint to the callback describing how to interpret `data`. The response additionally carries `rc` (the callback's own return value) and `err` (a wolfHSM-defined error code populated by the framework or by the callback).

The `data` field is a union that exposes three pre-defined shapes plus a raw buffer for application-specific schemas:

```c
typedef union {
    struct { uint32_t client_addr, client_sz, server_addr, server_sz; } dma32;
    struct { uint64_t client_addr, client_sz, server_addr, server_sz; } dma64;
    struct { uint8_t data[WOLFHSM_CFG_CUSTOMCB_LEN]; } buffer;
} whMessageCustomCb_Data;
```

The `dma32` and `dma64` variants carry pointer-and-length pairs for systems where the client wants the server to operate directly on its memory; the `buffer` variant is a fixed-size opaque payload, sized by `WOLFHSM_CFG_CUSTOMCB_LEN`, into which the application encodes whatever structure it likes. Custom callbacks do **not** automatically run the server's [DMA address-translation or allowlist machinery](#dma-support) for the `dma*` shapes — they are simply a convention for passing addresses, and the callback is responsible for any address handling or policy enforcement it needs.

The `type` field is an enum (`whMessageCustomCb_Type`) whose first eight values are reserved by wolfHSM (`WH_MESSAGE_CUSTOM_CB_TYPE_DMA32`, `WH_MESSAGE_CUSTOM_CB_TYPE_DMA64`, the internal `WH_MESSAGE_CUSTOM_CB_TYPE_QUERY`, and several reserved slots), with application-defined types beginning at `WH_MESSAGE_CUSTOM_CB_TYPE_USER_DEFINED_START` (value 8). The framework recognizes the reserved types for byte-order translation of the corresponding `data` union variant, but **user-defined types are passed through unmodified, so a callback that needs to interoperate between endpoints of different endianness must perform its own translation**.

### Constraints

- The maximum number of registered callbacks is fixed at build time by `WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT`. Valid action IDs are in the range `[0, WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT)`.
- The data payload in either direction is bounded by `WOLFHSM_CFG_CUSTOMCB_LEN`. Operations whose payload exceeds this limit must either split across multiple requests or use the `dma32` / `dma64` shapes to point at a larger buffer in shared memory.
- The callback's return value is reported to the client through `resp->rc`; wolfHSM error semantics are conveyed by the library separately through `resp->err`. Callbacks should reserve `err` for genuine wolfHSM-defined failures (the `WH_ERROR_*` set) and use `rc` for application-defined results.

### Example

This example registers a single callback under action ID 0 that handles three kinds of request: a DMA32 payload describing a buffer in client memory, and two application-defined types each carrying a different struct in the `buffer` variant. A shared header defines the action ID, the user-defined type values, and the per-type payload structs:

```c
/* my_custom_cb.h - shared between client and server */
#include "wolfhsm/wh_message_customcb.h"

#define MY_CUSTOM_CB_ID 0

enum {
    MY_TYPE_A = WH_MESSAGE_CUSTOM_CB_TYPE_USER_DEFINED_START,
    MY_TYPE_B,
};

typedef struct { int foo; int bar; } myCustomCbDataA;
typedef struct { int noo; int baz; } myCustomCbDataB;
```

The server registers the callback and then enters its standard request-handling loop:

```c
#include "wolfhsm/wh_server.h"
#include "my_custom_cb.h"

static int myCustomCb(whServerContext*                 server,
                      const whMessageCustomCb_Request* req,
                      whMessageCustomCb_Response*      resp)
{
    int rc = 0;
    resp->err = WH_ERROR_OK;

    switch (req->type) {
        case WH_MESSAGE_CUSTOM_CB_TYPE_DMA32: {
            uint8_t* ptr = (uint8_t*)((uintptr_t)req->data.dma32.client_addr);
            rc = doWorkOnClientAddr(ptr, req->data.dma32.client_sz);
            break;
        }
        case MY_TYPE_A:
            rc = doWorkWithTypeA((myCustomCbDataA*)req->data.buffer.data);
            break;
        case MY_TYPE_B:
            rc = doWorkWithTypeB((myCustomCbDataB*)req->data.buffer.data);
            break;
        default:
            resp->err = WH_ERROR_BADARGS;
            break;
    }
    return rc;
}

int main(void) {
    whServerContext serverCtx;
    whServerConfig  serverCfg = { /* server config */ };

    wh_Server_Init(&serverCtx, &serverCfg);
    wh_Server_RegisterCustomCb(&serverCtx, MY_CUSTOM_CB_ID, myCustomCb);

    while (1) {
        wh_Server_HandleRequestMessage(&serverCtx);
    }
}
```

The client verifies the callback is registered, then issues requests against the supported types:

```c
#include "wolfhsm/wh_client.h"
#include "my_custom_cb.h"

int main(void) {
    whClientContext clientCtx;
    whClientConfig  clientCfg = { /* client config */ };
    int err = 0;

    wh_Client_Init(&clientCtx, &clientCfg);

    if (wh_Client_CustomCbCheckRegistered(&clientCtx, MY_CUSTOM_CB_ID, &err)
            != WH_ERROR_OK) {
        return -1; /* callback not registered on this server */
    }

    whMessageCustomCb_Request  req  = {0};
    whMessageCustomCb_Response resp = {0};

    /* DMA-style invocation: hand the server a pointer in our address space */
    uint8_t buf[LARGE_SIZE] = { /* ... */ };
    req.id   = MY_CUSTOM_CB_ID;
    req.type = WH_MESSAGE_CUSTOM_CB_TYPE_DMA32;
    req.data.dma32.client_addr = (uint32_t)((uintptr_t)buf);
    req.data.dma32.client_sz   = sizeof(buf);
    wh_Client_CustomCbRequest(&clientCtx, &req);
    wh_Client_CustomCbResponse(&clientCtx, &resp);

    /* Application-defined invocation: pass a struct in the buffer payload */
    myCustomCbDataA a = { /* ... */ };
    memset(&req, 0, sizeof(req));
    req.id   = MY_CUSTOM_CB_ID;
    req.type = MY_TYPE_A;
    memcpy(req.data.buffer.data, &a, sizeof(a));
    wh_Client_CustomCbRequest(&clientCtx, &req);
    wh_Client_CustomCbResponse(&clientCtx, &resp);
}
```

The same pattern scales naturally: each action ID can dispatch to a different callback, and a single callback can multiplex any number of `type` values to handle distinct sub-operations behind one ID.

## Concurrency Support

Many systems that integrate an HSM have multiple threads, cores, or subsystems issuing cryptographic operations at the same time. wolfHSM is designed to support these workloads while keeping the request/response protocol simple and predictable. Concurrency is achieved by the server processing requests from multiple **independent client sessions in parallel**: each session still handles requests sequentially, but the sessions themselves can be scheduled concurrently. wolfHSM v1.4.0 introduced the locking infrastructure that makes this safe; everything described in this section applies from that version onward.

The library itself never spawns threads or assumes a particular runtime — the embedding application controls scheduling. wolfHSM provides the building blocks (per-session context structures, an internal lock abstraction, a transport interface that does not constrain dispatch) and lets the application choose between a simple round-robin loop, an event-driven dispatcher, or one thread per session.

### Per-Context Threading Model

The unit of concurrency on both sides of the connection is the context:

- A `whClientContext` represents a single client session with the server. It must be used by **one thread at a time**: there is at most one in-flight request per session, and the matching response must be received before the next request can be issued. Applications that want to issue requests in parallel create multiple client contexts — typically one per worker thread — each connected to its own server session.
- A `whServerContext` represents the server side of a single client session. It is likewise **single-threaded from the caller's perspective**: the application must not call `wh_Server_HandleRequestMessage()` for the same context from two threads at once. Concurrency across sessions is achieved by creating multiple server contexts and dispatching them independently.

Shared server-side state — the [NVM](#non-volatile-memory-nvm) object store, the [global key cache](#global-keys), the [authentication](#authentication-manager) state, and anything else that lives outside a single session — is protected by the internal lock infrastructure described below, so multiple server contexts can safely operate against the same backing store at the same time.

### The Lock Abstraction

To keep the core library free of OS dependencies, wolfHSM serializes access to shared resources through a generic lock abstraction declared in `wolfhsm/wh_lock.h`. Each shared resource embeds its own `whLock` instance, and the platform port supplies a callback table (`whLockCb`) that implements the four lifecycle operations against the native synchronization primitive of choice:

- `init` / `cleanup` — set up and tear down the platform-specific lock state
- `acquire` / `release` — blocking exclusive lock and unlock

Reference implementations cover the common cases:

- **POSIX pthread mutexes** (`port/posix/posix_lock.h`), used by the POSIX server example and the threadsafe stress tests
- Ports for embedded RTOS targets are expected to register a callback table backed by FreeRTOS mutexes, atomic spinlocks, or any other primitive the platform already provides

The feature is gated by `WOLFHSM_CFG_THREADSAFE`. When the macro is undefined, all locking calls compile to no-ops and the build has zero overhead from the concurrency machinery; Single-threaded deployments pay nothing for the abstraction. When the macro is defined but no callback table is registered for a given resource, the runtime also degrades to no-op locking; this is the right behavior for a thread-safe build that nonetheless drives a particular subsystem from a single thread.

Locking is scoped per resource rather than global, so the topology is flexible: a deployment can share one mutex across all subsystems, give each shared resource its own mutex, or anywhere in between.

### Concurrent Server Pattern

The reference servers shipped with most platform ports use a single-threaded round-robin loop: one thread iterates over each registered `whServerContext` and processes at most one request per pass. This is the simplest model and is sufficient for many embedded deployments.

When more concurrency is needed, a common pattern is to dedicate one thread to each server context:

```c
int main(void)
{
    whServerContext serverA;
    whServerContext serverB;

    whServerConfig serverConfigA = { /* server configuration */ };
    whServerConfig serverConfigB = { /* server configuration */ };

    ThreadType threadA;
    ThreadType threadB;

    /* Bind server configuration to the transports, NVM, and platform locks
     * for shared resources - omitted for clarity */

    /* Initialize server contexts, binding to configuration */
    wh_Server_Init(&serverA, &serverConfigA);
    wh_Server_Init(&serverB, &serverConfigB);

    /* Create one processing thread per client connection */
    threadA = thread_create(serverThread, &serverA);
    threadB = thread_create(serverThread, &serverB);

    thread_join(threadA);
    thread_join(threadB);

    return 0;
}

/* Blocking request-processing loop for a single client */
void* serverThread(void* arg)
{
    whServerContext* server = (whServerContext*)arg;
    int ret = WH_ERROR_OK;

    while (ret == WH_ERROR_OK) {
        ret = wh_Server_HandleRequestMessage(server);
    }
    return NULL;
}
```

Each client is serviced by a dedicated thread, so requests from different clients can execute in parallel; scheduling priority is left entirely to the underlying OS or runtime. Production systems may replace the tight loop with a blocking wait on a transport-specific event or interrupt, calling `wh_Server_HandleRequestMessage()` only when work is available. Other valid strategies include dispatching from a transport interrupt, an event-driven reactor, or a worker pool — the API does not impose a scheduling model.

### Transports and Concurrency

Server-side concurrency is independent of the transport layer. The [transport](#communication-layer-and-transports) only moves bytes between client and server; it does not determine how the server schedules request handling.

Because each client/server pair allows only one in-flight request, concurrency comes from running **multiple clients** in parallel, not from pipelining requests within a single session. Transports that serialize messages from many clients through a single shared channel — a hardware mailbox or MPSC ring buffer, for example — therefore do not increase server concurrency on their own; they would require an additional dispatch layer to fan messages back out to per-client server contexts. The highest practical concurrency on these platforms is typically achieved with the shared-memory transport, where each client owns a dedicated request/response buffer and the per-client server contexts can execute truly in parallel.

### Crypto Under Concurrency

How a cryptographic operation behaves under concurrency depends on whether it is served by software or hardware:

- **Software crypto** runs entirely inside wolfCrypt using ephemeral per-request operation contexts, so it works naturally across concurrent server threads without any additional coordination.
- **Hardware crypto** can be approached in several ways. The most common is to rely on wolfCrypt's hardware abstraction layer, which serializes accelerator access using its own mutex mechanisms. Alternatively, the server application can restrict hardware access to a single privileged client by registering the hardware crypto callback only for that session — useful in safety-critical or real-time deployments where one client needs deterministic uncontended access. A third option is to use the [crypto affinity](#hardware-acceleration-and-crypto-affinity) feature and let clients themselves coordinate hardware use, which fits trusted-client environments with a cooperative allocation policy.

The right choice depends on the platform, the accelerator, and the application's contention profile; wolfHSM intentionally supports all three.

## Authentication Manager

> **Note**: The authentication manager is currently **experimental** and has known issues. It is not yet suitable as a production security boundary.

wolfHSM provides an optional **authentication manager**, enabled with `WOLFHSM_CFG_ENABLE_AUTHENTICATION`, that authenticates clients to the server and checks every incoming request against a per-user permission model. It is transport-agnostic: the same login flow and authorization check apply over every supported transport.

The subsystem has three responsibilities:

- **Authentication**: verify a client's identity using a PIN or an X.509 certificate
- **Session tracking**: bind the authenticated identity to the client's connection so that subsequent requests carry that identity automatically
- **Authorization**: on every request, check that the active identity is permitted to invoke the requested operation, and reject the request if not

### Authentication Methods

A client authenticates by calling `wh_Client_AuthLogin` with a username and one of two credential methods:

- **PIN** (`WH_AUTH_METHOD_PIN`): the client supplies a PIN; the server hashes it with SHA-256 and compares the digest in constant time against the stored hash.
- **Certificate** (`WH_AUTH_METHOD_CERTIFICATE`): the client supplies a DER-encoded X.509 certificate; the server verifies it against the trusted CA stored as that user's credential using the [certificate manager](#certificate-management). Requires `WOLFHSM_CFG_CERTIFICATE_MANAGER`.

A successful login returns a `whUserId` and records that identity as the active session for the connection. A failed login leaves the connection unauthenticated. `wh_Client_AuthLogout` clears the session, and the server also clears it automatically when the comm channel is closed so that a reconnecting client cannot inherit a stale identity.

### Sessions and the Authorization Gate

Each server context carries at most one authenticated session at a time — the `whAuthContext` embedded in the server context holds the active `whUserId` and the user's permissions. A client that needs to operate as a different user must log out and log back in.

Every request received by the server is checked against the active session before it is dispatched to the corresponding subsystem handler:

- If no user is logged in, only [comm-layer](#communication-layer-and-transports) requests and the `LOGIN` action are permitted; every other request returns `WH_AUTH_PERMISSION_ERROR`.
- If a user is logged in, `LOGOUT` is always permitted, and every other request is gated against the user's permissions.

The gate lives in the server's front-end request handler, so individual subsystems do not need to perform their own auth checks. When the auth manager is compiled in but no auth context is configured at server initialization, the gate is skipped entirely and the server processes all requests without enforcement; this preserves compatibility with builds that do not need authentication.

### Permissions

A user's permissions are described by a `whAuthPermissions` record with three pieces:

- **Group bitmap**: a per-group allow boolean. A request whose [message group](#communication-layer-and-transports) is not allowed is rejected without further checks.
- **Action bitmap**: for each allowed group, a 256-bit mask of which actions within that group are permitted. A request is allowed only if both its group and its action bit are set.
- **Admin flag**: a separate capability that gates user-management operations (`UserAdd`, `UserDelete`, `UserSetPermissions`) and cross-user logout. The core forbids non-admin sessions from promoting another user to admin regardless of backend behavior.

The helper macros `WH_AUTH_SET_ALLOWED_GROUP`, `WH_AUTH_SET_ALLOWED_ACTION`, `WH_AUTH_CLEAR_ALLOWED_GROUP`, and `WH_AUTH_CLEAR_ALLOWED_ACTION` build permission sets at provisioning time, and `WH_AUTH_SET_IS_ADMIN` toggles the admin flag.

`whAuthPermissions` also carries a small per-user `keyIds` allowlist and the data model includes a `CheckKeyAuthorization` callback intended to constrain which keys a user may exercise. Per-key authorization is a placeholder in the current implementation — the callback is defined but no crypto or key handler invokes it yet.

Holding an action bit lets a session issue a request, but the backend still enforces per-target authorization on top of it. In the default base backend, `USER_SET_CREDENTIALS` lets a non-admin update its **own** credentials only (a cross-user credential change additionally requires admin and otherwise fails with `WH_ERROR_ACCESS`), while `USER_DELETE` and `USER_SET_PERMISSIONS` remain admin-only regardless of the action bit. The caller's `whUserId` is passed to the backend as `current_user_id` so it can distinguish a self-service change from a cross-user one. A custom auth backend may implement a different per-target policy.

### User Management Invariants

Beyond the group/action gate, the core enforces a fixed set of invariants on user-management operations before the request reaches the storage backend. These checks live in `wh_Auth_UserAdd` (and its peers in `wh_auth.c`) so that they hold for every backend, including custom ones, and a backend cannot accidentally relax them.

When a session adds a user with `wh_Auth_UserAdd`, the following rules apply to a **non-admin** caller. An admin caller is exempt from rules 1 through 3 and is passed straight through to the backend.

1. **Only an admin can create an admin.** A non-admin caller that requests the admin flag on the new user is rejected with `WH_AUTH_PERMISSION_ERROR`. This complements the existing rule that a non-admin cannot promote an existing user to admin.
2. **New permissions must be a subset of the caller's own.** Every group bit, every action bit, and every entry in the new user's `keyIds` allowlist must already be held by the creating user. If the new user would gain any group, action, or key the caller does not itself possess, the request fails with `WH_AUTH_PERMISSION_ERROR`. A non-admin can therefore only ever delegate down, and cannot mint a user more privileged than itself.
3. **Non-admins cannot create credential-less users.** A non-admin caller must supply non-empty credentials for the new user. A `NULL` or zero-length credential is rejected with `WH_AUTH_PERMISSION_ERROR`. This prevents a non-admin from creating a back-door account that anyone can assume without authenticating. An admin may still create a user with no credentials, for example to provision the credential separately.
4. **No duplicate usernames.** The base backend rejects an add whose username matches an existing user with `WH_ERROR_BADARGS`, regardless of the caller's privilege.

Credential updates through `wh_Auth_UserSetCredentials` add a further check on top of the self-service rule described under [Permissions](#permissions). When the target user already has a credential set, the caller must also present the matching **current** credential. The base backend verifies it in constant time before accepting the replacement, and a missing or mismatched current credential fails with `WH_ERROR_ACCESS`. PINs are hashed with SHA-256 for both the comparison and storage, so the plaintext PIN is never retained.

`wh_Auth_UserDelete` and `wh_Auth_UserSetPermissions` remain admin-only operations in the base backend.

### Pluggable Backend

The authentication manager does not own the user database itself. All operations that read or modify user state — login, user add/delete, permission updates, credential updates — are dispatched through a `whAuthCb` callback table that the application supplies at server initialization. The storage backend is therefore a port-time decision: an in-memory table for development, an NVM-backed store for production, or a connector to an external identity service.

wolfHSM ships with a default in-memory backend (`wh_auth_base.c`) used by the POSIX server example and the test suite. It holds up to `WH_AUTH_BASE_MAX_USERS` users in a static array, hashes PINs with SHA-256, and runs certificate verification against the user's stored CA when the certificate manager is built in. The base backend is intentionally simple and is **not** persisted to NVM — deployments that need user records to survive reset must supply their own backend.

Custom backends implement the `whAuthCb` vtable and register their context through `whAuthConfig`. The core handles locking, session state, and the request-time authorization gate; the backend is responsible for storage, credential verification, and any backend-specific overrides through the optional `CheckRequestAuthorization` and `CheckKeyAuthorization` callbacks. These overrides see the core's preliminary decision and can flip it either way, which lets a backend layer additional policy (time-of-day restrictions, audit hooks, per-key allowlists) on top of the default group/action check.

