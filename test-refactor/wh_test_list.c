/*
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Registry of every test function. To add a test:
 *   1. Add a WH_TEST_DECL(name); line below so the test has a
 *      weak skip stub when its feature gate is off.
 *   2. Add a row to the appropriate per-group array (Misc /
 *      Server / Client) so the runner picks it up.
 *
 * The weak stub returns WH_TEST_SKIPPED; the real test, when
 * compiled in, provides a strong symbol that the linker picks
 * instead.
 *
 * Per-file crypto suites are aggregated into a single whTest_Crypto_*
 * entry point per source file; the per-subtest functions are file-static
 * and run via WH_TEST_RUN_SUBTEST from inside the group entry point.
 */

#include "wh_test_list.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/* Test declarations and weak skip implementations. */
WH_TEST_DECL(whTest_ClientDevId);
WH_TEST_DECL(whTest_Comm);
WH_TEST_DECL(whTest_Dma);
WH_TEST_DECL(whTest_KeystoreReqSize);
WH_TEST_DECL(whTest_MultiClient);
WH_TEST_DECL(whTest_CertVerify);
WH_TEST_DECL(whTest_NvmOptional);
WH_TEST_DECL(whTest_ClientCerts);
WH_TEST_DECL(whTest_Counter);
WH_TEST_DECL(whTest_Crypto_Aes);
WH_TEST_DECL(whTest_CryptoAesKeyUsagePolicies);
WH_TEST_DECL(whTest_Crypto_Cmac);
WH_TEST_DECL(whTest_Crypto_Curve25519);
WH_TEST_DECL(whTest_Crypto_Ecc);
WH_TEST_DECL(whTest_Crypto_Ed25519);
WH_TEST_DECL(whTest_Crypto_Kdf);
WH_TEST_DECL(whTest_Crypto_KeyPolicy);
WH_TEST_DECL(whTest_Crypto_MlDsa);
WH_TEST_DECL(whTest_Crypto_Rng);
WH_TEST_DECL(whTest_Crypto_Rsa);
WH_TEST_DECL(whTest_Crypto_Sha);
WH_TEST_DECL(whTest_CryptoEcc256);
WH_TEST_DECL(whTest_CryptoEd25519BufferTooSmall);
WH_TEST_DECL(whTest_CryptoMlDsaBufferTooSmall);
WH_TEST_DECL(whTest_CryptoRsaBufferTooSmall);
WH_TEST_DECL(whTest_CryptoSha256);
WH_TEST_DECL(whTest_She);
WH_TEST_DECL(whTest_SheMasterEcuKeyFallback);
WH_TEST_DECL(whTest_SheReqSizeChecking);
WH_TEST_DECL(whTest_Echo);
WH_TEST_DECL(whTest_NvmDma);
WH_TEST_DECL(whTest_NvmOps);
WH_TEST_DECL(whTest_ServerInfo);
WH_TEST_DECL(whTest_WolfCryptTest);
WH_TEST_DECL(whTest_AuthBadArgs);
WH_TEST_DECL(whTest_AuthLogin);
WH_TEST_DECL(whTest_AuthLogout);
WH_TEST_DECL(whTest_AuthAddUser);
WH_TEST_DECL(whTest_AuthDeleteUser);
WH_TEST_DECL(whTest_AuthSetPermissions);
WH_TEST_DECL(whTest_AuthSetCredentials);
WH_TEST_DECL(whTest_AuthRequestAuthorization);

const whTestCase whTestsMisc[] = {
    { "whTest_ClientDevId",      whTest_ClientDevId },
    { "whTest_Comm",             whTest_Comm },
    { "whTest_Dma",              whTest_Dma },
    { "whTest_KeystoreReqSize",  whTest_KeystoreReqSize },
    { "whTest_MultiClient",      whTest_MultiClient },
};
const size_t whTestsMiscCount = ARRAY_SIZE(whTestsMisc);

const whTestCase whTestsServer[] = {
    { "whTest_CertVerify", whTest_CertVerify},
    { "whTest_NvmOptional", whTest_NvmOptional},
    { "whTest_SheMasterEcuKeyFallback", whTest_SheMasterEcuKeyFallback },
    { "whTest_SheReqSizeChecking", whTest_SheReqSizeChecking },
};
const size_t whTestsServerCount = ARRAY_SIZE(whTestsServer);

const whTestCase whTestsClient[] = {
    { "whTest_ClientCerts", whTest_ClientCerts },
    { "whTest_Counter", whTest_Counter },
    { "whTest_Crypto_Aes", whTest_Crypto_Aes },
    { "whTest_CryptoAesKeyUsagePolicies", whTest_CryptoAesKeyUsagePolicies },
    { "whTest_Crypto_Cmac", whTest_Crypto_Cmac },
    { "whTest_Crypto_Curve25519", whTest_Crypto_Curve25519 },
    { "whTest_Crypto_Ecc", whTest_Crypto_Ecc },
    { "whTest_Crypto_Ed25519", whTest_Crypto_Ed25519 },
    { "whTest_Crypto_Kdf", whTest_Crypto_Kdf },
    { "whTest_Crypto_KeyPolicy", whTest_Crypto_KeyPolicy },
    { "whTest_Crypto_MlDsa", whTest_Crypto_MlDsa },
    { "whTest_Crypto_Rng", whTest_Crypto_Rng },
    { "whTest_Crypto_Rsa", whTest_Crypto_Rsa },
    { "whTest_Crypto_Sha", whTest_Crypto_Sha },
    { "whTest_Crypto_Aes", whTest_Crypto_Aes },
    { "whTest_CryptoEcc256", whTest_CryptoEcc256 },
    { "whTest_CryptoEd25519BufferTooSmall",
         whTest_CryptoEd25519BufferTooSmall },
    { "whTest_CryptoMlDsaBufferTooSmall", whTest_CryptoMlDsaBufferTooSmall },
    { "whTest_CryptoRsaBufferTooSmall", whTest_CryptoRsaBufferTooSmall },
    { "whTest_CryptoSha256", whTest_CryptoSha256 },
    { "whTest_She", whTest_She },
    { "whTest_Echo", whTest_Echo },
    { "whTest_NvmDma", whTest_NvmDma },
    { "whTest_NvmOps", whTest_NvmOps },
    { "whTest_ServerInfo", whTest_ServerInfo },
    { "whTest_WolfCryptTest", whTest_WolfCryptTest },
    { "whTest_AuthBadArgs", whTest_AuthBadArgs },
    { "whTest_AuthLogin", whTest_AuthLogin },
    { "whTest_AuthLogout", whTest_AuthLogout },
    { "whTest_AuthAddUser", whTest_AuthAddUser },
    { "whTest_AuthDeleteUser", whTest_AuthDeleteUser },
    { "whTest_AuthSetPermissions", whTest_AuthSetPermissions },
    { "whTest_AuthSetCredentials", whTest_AuthSetCredentials },
    { "whTest_AuthRequestAuthorization", whTest_AuthRequestAuthorization },
};
const size_t whTestsClientCount = ARRAY_SIZE(whTestsClient);
