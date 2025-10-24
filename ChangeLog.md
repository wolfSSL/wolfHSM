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
