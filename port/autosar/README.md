# wolfHSM AUTOSAR Port

This port exposes the wolfHSM client API as standard AUTOSAR Crypto interfaces:

- **Classic Platform** (`classic/`) — implements `AUTOSAR_SWS_CryptoDriver`
  R22-11. Drop-in replacement for an OEM/vendor Crypto Driver, sits below
  CryIf in any AUTOSAR Classic BSW (MICROSAR / RTA-BSW / EB tresos).
- **Adaptive Platform** (`adaptive/`) — implements an `ara::crypto`
  `CryptoProvider` per `AUTOSAR_SWS_Cryptography` R22-11. Registered via an
  AP Execution Manifest, plugs into any AP runtime supporting providers.

Both layers translate AUTOSAR-shaped calls into `wh_Client_*` calls against
a wolfHSM server running on the secure core. Key material never leaves the
server; only handles cross the boundary.

## Layout

```
port/autosar/
├── common/          algorithm and key-id mapping between AUTOSAR and wolfHSM
├── classic/         AUTOSAR Classic Crypto Driver (C, R22-11)
├── adaptive/        AUTOSAR Adaptive CryptoProvider (C++17, R22-11)
└── docs/            integration notes and algorithm coverage table
```

## Status

- **Classic** — hash (SHA-256 / 384 / 512), AES (ECB/CBC/CTR/GCM), CMAC,
  ECDSA P-256, Ed25519, RSA-PKCS#1-v1.5, ECDH P-256, HKDF, CMAC-KDF, RNG,
  key management. Sync and real-async dispatch through `Crypto_MainFunction`
  driving wolfHSM `*Request` / `*Response`.
- **Adaptive** — `WolfhsmCryptoProvider` with 9 context classes:
  `RandomGeneratorCtx`, `HashFunctionCtx`, `SymmetricBlockCipherCtx`,
  `AuthCipherCtx`, `MessageAuthnCodeCtx`, `SignerPrivateCtx` /
  `VerifierPublicCtx`, `KeyAgreementPrivateCtx`,
  `KeyDerivationFunctionCtx`, `KeyStorageProvider`.
- **Tests**: `classic/examples/csm_smoke/` (per-category C harness, ~25
  tests) and `adaptive/examples/ap_smoke/` (per-cluster C++ harness, 9
  tests). Both run against `examples/posix/wh_posix_server` over TCP and
  are wired into `.github/workflows/build-and-test-autosar.yml`.

See `docs/algorithm_coverage.md` for the per-primitive matrix (sync /
async / Adaptive coverage), and `docs/client_workarounds.md` for the one
client-side translation kept while wolfHSM's verify-handler return
contract evolves.

## Quickstart

```sh
# Terminal 1 — run the wolfHSM POSIX server.
cd examples/posix/wh_posix_server && make
./Build/wh_posix_server.elf --type tcp

# Terminal 2 — build and run csm_smoke (Classic).
cd port/autosar/classic/examples/csm_smoke && make
./Build/csm_smoke

# Restart the server, then build and run ap_smoke (Adaptive).
cd port/autosar/adaptive/examples/ap_smoke
cmake -S . -B build && cmake --build build
./build/ap_smoke
```

Both binaries print one OK line per test category and `all tests passed`
on success.

## Licensing

This port is GPLv3 like the rest of wolfHSM (`../../LICENSE`). Commercial
integrators ship under wolfSSL's commercial license — same dual-license
model as wolfSSL / wolfCrypt. The port contains no vendor-supplied BSW
headers; `Crypto.h` and the `ara/crypto` headers are written from the
public AUTOSAR SWS documents.

"AUTOSAR-conformant" labeling is restricted to AUTOSAR Partners. This port
**implements** the AUTOSAR R22-11 interfaces; conformance certification is
out of scope.
