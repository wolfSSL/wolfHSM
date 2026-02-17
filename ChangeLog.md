# wolfHSM Release v1.4.0 (February 16, 2026)

Due to NDA restrictions, access to the Infineon, ST Micro, TI, and Renesas ports is limited. Please contact [support@wolfssl.com](mailto:support@wolfssl.com) for access.

## New Feature Additions
* Added TLS transport for authentication between client and server peers in https://github.com/wolfSSL/wolfHSM/pull/227
* Added global keystore enabling cryptographic keys to be shared across multiple clients with automatic cache routing in https://github.com/wolfSSL/wolfHSM/pull/224
* Added key usage policy flags (encrypt, decrypt, sign, verify, wrap, derive) set by clients and enforced by the server in https://github.com/wolfSSL/wolfHSM/pull/233
* Added server thread safety with NVM locking abstraction, enabling multiple server contexts to safely share NVM and global keystore resources in https://github.com/wolfSSL/wolfHSM/pull/275
* Added logging framework with callback-based backend, ring buffer, and POSIX file log engines in https://github.com/wolfSSL/wolfHSM/pull/253
* Added NVM object flag enforcement including non-destroyable flag and key revocation support in https://github.com/wolfSSL/wolfHSM/pull/263
* Added ED25519 signature scheme support with DMA in https://github.com/wolfSSL/wolfHSM/pull/254
* Added NIST SP 800-108 CMAC KDF support in https://github.com/wolfSSL/wolfHSM/pull/228
* Added generic data wrap/unwrap for server-side data wrapping in https://github.com/wolfSSL/wolfHSM/pull/226

## Bug Fixes
* Fixed potential DMA buffer handling errors where request buffer sizes were overwritten by server responses in https://github.com/wolfSSL/wolfHSM/pull/284
* Fixed potential buffer overflow in key cache by capping label size and corrected variable name logic error in `wh_Client_CommInfoResponse` in https://github.com/wolfSSL/wolfHSM/pull/234
* Fixed CMAC DMA message struct padding, alignment bugs in SHE code, and test key cache leaks in https://github.com/wolfSSL/wolfHSM/pull/285
* Fixed ECDH without DERIVE flag with `WOLF_CRYPTOCB_ONLY_ECC` in https://github.com/wolfSSL/wolfHSM/pull/251
* Fixed compilation with `NO_AES` defined and removed extra printfs in https://github.com/wolfSSL/wolfHSM/pull/260
* Fixed wrong `#endif` placement in `wh_client_crypto.c` and `#include` order in `nvm_flash_log.h` in https://github.com/wolfSSL/wolfHSM/pull/243
* Fixed SHE NVM metadata struct initialization so flags are set to 0 in https://github.com/wolfSSL/wolfHSM/pull/273
* Added NULL checks to message translation functions and additional input sanitization to server request handlers in https://github.com/wolfSSL/wolfHSM/pull/236 and https://github.com/wolfSSL/wolfHSM/pull/240

## Enhancements and Optimizations
* Refactored CMAC to use client-held state instead of persisting state on the server, and deprecated the cancellation API in https://github.com/wolfSSL/wolfHSM/pull/279
* Refactored debug macros to replace all printf usage with `WOLFHSM_CFG_PRINTF`-based wrappers in https://github.com/wolfSSL/wolfHSM/pull/207
* Expanded static memory DMA offset feature to CMAC, SHA-224, SHA-384, SHA-512, and ML-DSA in https://github.com/wolfSSL/wolfHSM/pull/191
* Changed wrap object size argument from input-only to in/out in https://github.com/wolfSSL/wolfHSM/pull/241
* Added scan-build static analysis GitHub Action in https://github.com/wolfSSL/wolfHSM/pull/195
* Added ECDSA cross-validation test with software implementation in https://github.com/wolfSSL/wolfHSM/pull/277

# wolfHSM Release v1.3.0 (October 24, 2025)

Due to NDA restrictions, access to the Infineon, ST Micro, TI, and Renesas ports is limited. Please contact [support@wolfssl.com](mailto:support@wolfssl.com) for access.

## New Feature Additions
* Introduced key wrap client/server APIs with demos and tests in https://github.com/wolfSSL/wolfHSM/pull/157 and https://github.com/wolfSSL/wolfHSM/pull/185
* Added HKDF key derivation with cached-key reuse support in https://github.com/wolfSSL/wolfHSM/pull/204 and https://github.com/wolfSSL/wolfHSM/pull/211
* Added image manager module for authenticated firmware handling in https://github.com/wolfSSL/wolfHSM/pull/129
* Added non-exportable object support and basic NVM access controls in https://github.com/wolfSSL/wolfHSM/pull/147
* Added flash-log based NVM backend for large write granularities in https://github.com/wolfSSL/wolfHSM/pull/179
* Added SHA-224/384/512 crypto support across client and server in https://github.com/wolfSSL/wolfHSM/pull/144
* Expanded DMA coverage to AES-GCM, RNG seeding, and shared-memory offset transfers in https://github.com/wolfSSL/wolfHSM/pull/158, https://github.com/wolfSSL/wolfHSM/pull/213, and https://github.com/wolfSSL/wolfHSM/commit/36862ce7e6829c3f996345cad880fdfe516d751f

## Bug Fixes
* Enforced NVM object boundaries during reads in https://github.com/wolfSSL/wolfHSM/pull/182
* Prevented stale data reads from erased flash pages in https://github.com/wolfSSL/wolfHSM/pull/181
* Corrected NVM flash state handling when recovery is required in https://github.com/wolfSSL/wolfHSM/pull/175
* Fixed AES-CTR temporary buffer sizing in https://github.com/wolfSSL/wolfHSM/pull/183
* Restored AES-GCM DMA post-write callbacks and optional output handling in https://github.com/wolfSSL/wolfHSM/pull/215 and https://github.com/wolfSSL/wolfHSM/pull/221
* Fixed POSIX TCP socket error handling in https://github.com/wolfSSL/wolfHSM/pull/203

## Enhancements and Optimizations
* Added GitHub Action based code coverage reporting in https://github.com/wolfSSL/wolfHSM/pull/201
* Added clang-format and clang-tidy automation in https://github.com/wolfSSL/wolfHSM/pull/176 and https://github.com/wolfSSL/wolfHSM/pull/167
* Added ASAN configuration to example builds and CI workflows in https://github.com/wolfSSL/wolfHSM/pull/218
* Improved benchmark tooling and shared memory transport configurability in https://github.com/wolfSSL/wolfHSM/pull/158

# wolfHSM Release v1.2.0 (June 27, 2025)

Due to NDA restrictions, access to the Infineon, ST Micro, and Renesas ports is limited. Please contact [support@wolfssl.com](mailto:support@wolfssl.com) for access.

## New Feature Additions
* Basic X509 certificate support in https://github.com/wolfSSL/wolfHSM/pull/96
* DMA support for CMAC in https://github.com/wolfSSL/wolfHSM/pull/97
* attribute certificate support in https://github.com/wolfSSL/wolfHSM/pull/101
* Add benchmark framework in https://github.com/wolfSSL/wolfHSM/pull/107
* client/server-only builds + relocate examples in https://github.com/wolfSSL/wolfHSM/pull/122

## Bug Fixes
* Fix flashunit program in https://github.com/wolfSSL/wolfHSM/pull/104
* Keycache test fixes in https://github.com/wolfSSL/wolfHSM/pull/125

## Enhancements and Optimizations
* Refactor DMA API to be generic across all address sizes in https://github.com/wolfSSL/wolfHSM/pull/102
* Remove whPacket union in https://github.com/wolfSSL/wolfHSM/pull/103
* set RNG on curve25519 keys to support blinding in https://github.com/wolfSSL/wolfHSM/pull/109
* new x509 API: verify and cache pubKey in https://github.com/wolfSSL/wolfHSM/pull/110
* Add hierarchical makefiles in https://github.com/wolfSSL/wolfHSM/pull/124

# wolfHSM Release v1.1.0 (January 23, 2025)
Due to NDA restrictions, access to the Infineon and ST Micro ports is limited. Please contact support@wolfssl.com for access.

## New Feature Additions
* Added support for ML-DSA (PR#84 and PR#86)
* Added support for DMA-based keystore operations (PR#85)

## Bug Fixes
* Fixes memory error in ECC verify (PR#81)
* Removes unused argument warnings on 32 bit targets (PR#82)
* Fixes memory leak in SHE test (PR#88)

## Enhancements and Optimizations
* Improved handling of Curve25519 DER encoded keys using new wolfCrypt APIs (PR#83)


# wolfHSM Release v1.0.1 (October 21, 2024)
Bug-fix release. Due to NDA restrictions, access to the Infineon and ST Micro ports is limited. Please contact support@wolfssl.com for access.

## New Feature Additions
* Initial release of whnvmtool to pre-build NVM images (PR#77)

## Bug Fixes
* Corrected FreshenKey server function to load keys from NVM when not in cache (PR#78)

## Enhancements and Optimizations
* Updated RSA key handling to support private-only and public-only keys (PR#76)


# wolfHSM Release v1.0.0 (October 17, 2024)
Initial release after internal and early evaluator testing. Due to NDA restrictions, access to the Infineon and ST Micro ports is limited. Please contact support@wolfssl.com for access.

## New Feature Additions
* POSIX simulator and test environment
* Memory fencing and cache controls for memory transport
* Support for Aurix Tricore TC3xx and ST SPC58NN
* DMA support for SHA2 and NVM objects
* Cancellation for CMAC
* Support NO_MALLOC and STATIC_MEMORY
* SHE+ interface

## Enhancements and Optimizations
* Reduction in static server memory requirements
* Hardware offload for AURIX and ST C3 modules
