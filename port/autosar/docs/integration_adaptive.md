# Adaptive Platform Integration

How to register the wolfHSM CryptoProvider with an AUTOSAR Adaptive
runtime (R22-11).

## Why a parallel namespace

The AUTOSAR Adaptive `ara/crypto/*` headers are licensed by the AUTOSAR
Consortium and cannot be redistributed under GPLv3. The wolfHSM
provider therefore exposes a **shape-compatible** API in the
`wolfhsm::ara_crypto` namespace. The integrator writes a thin adapter,
inside their AP application, that derives from their AP runtime's
`ara::crypto::cryp::CryptoProvider` and forwards each method to the
matching method on `wolfhsm::ara_crypto::WolfhsmCryptoProvider`.

## Adapter skeleton

```cpp
// integrator-owned glue. NOT shipped by wolfHSM.
#include <ara/crypto/cryp/crypto_provider.h>     // vendor / AP runtime
#include <wolfhsm/ara_crypto/crypto_provider.hpp> // from this port

class WolfhsmAraProviderAdapter
    : public ara::crypto::cryp::CryptoProvider {
 public:
    WolfhsmAraProviderAdapter(whClientContext* c) : impl_(c) {}

    ara::core::Result<RandomGeneratorCtx::Uptr>
    CreateRandomGeneratorCtx(ara::crypto::CryptoAlgId, bool) override {
        // convert wolfhsm::ara_crypto::Result<...> to ara::core::Result<...>
        auto p = impl_.CreateRandomGeneratorCtx();
        // wrap p in an ara::crypto::cryp::RandomGeneratorCtx derived
        // implementation that forwards Generate() to p->Generate().
        ...
    }

    // similar overrides for CreateHashFunctionCtx, etc.

 private:
    wolfhsm::ara_crypto::WolfhsmCryptoProvider impl_;
};
```

The forwarding is purely mechanical because each `wolfhsm::ara_crypto`
type mirrors its `ara::crypto` counterpart. The integrator absorbs the
AUTOSAR-licensed glue inside their own product, keeping wolfHSM's
upstream source free of those headers.

## Manifest registration

`manifest/wolfhsm_crypto_provider.json` declares the provider UUID,
version, and the supported algorithm IDs. Convert it to the manifest
format expected by your AP execution-manager tool (CMakeLists for
Vector ADAPTIVE MICROSAR, ApexAI plugin descriptors, etc.).

## Execution model: synchronous only

The `wolfhsm::ara_crypto` provider exposes a **synchronous** surface. Each
context method (`Generate`, `Update`, `ProcessBlocks`, `Sign`, `Verify`,
`AgreeKey`, `Derive`, …) issues a wolfHSM client request and blocks until
the matching response is received. No `ara::core::Future` is returned by
this layer.

AP runtimes that expose asynchronous CryptoProvider methods (returning
`ara::core::Future<…>`) absorb the threading in the adapter the
integrator writes: typically by posting each provider call onto a
worker-thread pool that owns a dedicated `whClientContext`. wolfHSM's
client-side transport contract is **one request in flight per
`whClientContext`**, so the adapter must either serialise calls on a
single context or hand each worker thread its own context. Sharing one
context across concurrent threads is undefined behaviour.

For ECUs that need raw async dispatch - `Crypto_JobType` with
`CRYPTO_PROCESSING_ASYNC` and `Crypto_MainFunction`-driven completion
callbacks - use the **Classic** port (`port/autosar/classic/`); that
layer implements wolfHSM's `*Request` / `*Response` split natively.

## Context rules

Each `Create*` factory returns `nullptr` for an algorithm ID it does
not handle, or for a key ID that is 0 or carries a global, wrapped or
hardware flag bit. Pass plain client key IDs.

- `ProcessBlocks` takes whole 16-byte blocks. CBC and CTR need a
  16-byte IV; ECB ignores it.
- `AuthCipherCtx` accepts GCM tags of 12 to 16 bytes. A shorter tag
  returns `kInvalidInputSize`, and a tag that does not verify returns
  `kAuthTagMismatch`.
- `MessageAuthnCodeCtx::Generate` returns the 16-byte AES-CMAC.
  `Verify` compares the leading `macLen` bytes and accepts 8 to 16;
  other lengths return `kInvalidInputSize`.
- ECDSA and RSA `Sign` and `Verify` take a 32, 48 or 64-byte SHA-2
  digest. Ed25519 and ML-DSA take the message.
- A length above `UINT32_MAX` returns `kInvalidInputSize`.

## Key storage

`KeyStorageProvider::SaveKey` caches a key with
`WH_NVM_FLAGS_USAGE_ANY`. The key is non-exportable unless the caller
passes `exportable = true`. `LoadKey` returns the plaintext key, so it
works only on exportable keys, and every failure maps to
`kUnknownIdentifier`. `Commit` writes a cached key to NVM.

Shared secrets, derived keys and loaded keys come back in a plain
`std::vector`. Wipe them with `wh_Utils_ForceZero` before the vector
goes out of scope.

`Erase` removes the key from the cache and from NVM. If the server
refuses the erase, for example for a `WH_NVM_FLAGS_NONDESTROYABLE` key,
`Erase` revokes the key instead and returns `kAccessViolation`. The
key can no longer be used, but its bytes stay stored.

## Building

```bash
cd port/autosar/adaptive
cmake -S . -B build -DWOLFHSM_DIR=../../.. -DWOLFSSL_DIR=/path/to/wolfssl
cmake --build build
```

Produces `libwolfhsm_ara_crypto.a` (and `.so` if `BUILD_SHARED_LIBS=ON`
is set). Link this into your adapter binary.

## Licensing

GPLv3, same model as the rest of wolfHSM. The adapter you write to
bridge to `ara::crypto` is your code - licensing is determined by your
project's overall license posture (commercial wolfHSM license + AUTOSAR
Adaptive runtime EULA, typically).
