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
 */

#include "wh_test_list.h"

/* Test declarations and weak skip implementations. */
WH_TEST_DECL(whTest_Dma);
WH_TEST_DECL(whTest_KeyWrapRespSize);
WH_TEST_DECL(whTest_CertVerify);
WH_TEST_DECL(whTest_ClientCerts);
WH_TEST_DECL(whTest_CryptoAes);
WH_TEST_DECL(whTest_CryptoEcc256);
WH_TEST_DECL(whTest_CryptoEd25519BufferTooSmall);
WH_TEST_DECL(whTest_CryptoMlDsaBufferTooSmall);
WH_TEST_DECL(whTest_CryptoRsaBufferTooSmall);
WH_TEST_DECL(whTest_CryptoSha256);
WH_TEST_DECL(whTest_Echo);
WH_TEST_DECL(whTest_ServerInfo);
WH_TEST_DECL(whTest_WolfCryptTest);

const whTestCase whTestsMisc[] = {
    { "whTest_Dma", whTest_Dma },
    { "whTest_KeyWrapRespSize", whTest_KeyWrapRespSize },
};
const size_t whTestsMiscCount = sizeof(whTestsMisc) / sizeof(whTestsMisc[0]);

const whTestCase whTestsServer[] = {
    { "whTest_CertVerify", whTest_CertVerify },
};
const size_t whTestsServerCount = sizeof(whTestsServer) / sizeof(whTestsServer[0]);

const whTestCase whTestsClient[] = {
    { "whTest_ClientCerts", whTest_ClientCerts },
    { "whTest_CryptoAes", whTest_CryptoAes },
    { "whTest_CryptoEcc256", whTest_CryptoEcc256 },
    { "whTest_CryptoEd25519BufferTooSmall",
      whTest_CryptoEd25519BufferTooSmall },
    { "whTest_CryptoMlDsaBufferTooSmall", whTest_CryptoMlDsaBufferTooSmall },
    { "whTest_CryptoRsaBufferTooSmall", whTest_CryptoRsaBufferTooSmall },
    { "whTest_CryptoSha256", whTest_CryptoSha256 },
    { "whTest_Echo", whTest_Echo },
    { "whTest_ServerInfo", whTest_ServerInfo },
    { "whTest_WolfCryptTest", whTest_WolfCryptTest },
};
const size_t whTestsClientCount = sizeof(whTestsClient) / sizeof(whTestsClient[0]);
