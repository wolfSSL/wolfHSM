/*
 * Copyright (C) 2024 wolfSSL Inc.
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

#include <stdio.h>
#include <string.h>

#include "wh_test_common.h"
#include "wh_test_client_crypto.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_server.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"

static int whTest_ClientCryptoRsa(whClientContext* client)
{
    int ret;
    RsaKey key;
    WC_RNG rng;
    byte plaintext[] = "Test RSA encryption";
    byte ciphertext[256];
    byte decrypted[256];
    word32 outLen;
    whKeyId keyId = WH_KEYID_ERASED;

    printf("Testing RSA operations...\n");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Test invalid parameters */
    ret = wc_InitRsaKey_ex(NULL, NULL, INVALID_DEVID);
    WH_TEST_ASSERT_RETURN(ret != 0);

    ret = wc_InitRsaKey_ex(&key, NULL, WH_DEV_ID_HSM);
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Test key generation with invalid parameters */
    ret = wc_MakeRsaKey(&key, 1024, WC_RSA_EXPONENT, NULL);
    WH_TEST_ASSERT_RETURN(ret != 0);

    /* Test valid key generation */
    ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Test encryption/decryption with invalid parameters */
    outLen = sizeof(ciphertext);
    ret = wc_RsaPublicEncrypt(NULL, sizeof(plaintext), ciphertext, outLen, &key, &rng);
    WH_TEST_ASSERT_RETURN(ret != 0);

    ret = wc_RsaPublicEncrypt(plaintext, sizeof(plaintext), NULL, outLen, &key, &rng);
    WH_TEST_ASSERT_RETURN(ret != 0);

    /* Test valid encryption/decryption */
    outLen = sizeof(ciphertext);
    ret = wc_RsaPublicEncrypt(plaintext, sizeof(plaintext), ciphertext, outLen, &key, &rng);
    WH_TEST_ASSERT_RETURN(ret >= 0);
    if (ret > 0) {
        word32 encLen = (word32)ret;
        outLen = sizeof(decrypted);
        ret = wc_RsaPrivateDecrypt(ciphertext, encLen, decrypted, outLen, &key);
        WH_TEST_ASSERT_RETURN(ret >= 0);
    }
    WH_TEST_ASSERT_RETURN(memcmp(plaintext, decrypted, sizeof(plaintext)) == 0);

    /* Test key cache operations */
    ret = wh_Client_RsaMakeCacheKey(client, 2048, WC_RSA_EXPONENT, &keyId, 
                                   WH_NVM_FLAGS_NONE, 0, NULL);
    WH_TEST_ASSERT_RETURN(ret == 0);

    ret = wh_Client_RsaSetKeyId(&key, keyId);
    WH_TEST_ASSERT_RETURN(ret == 0);

    ret = wh_Client_KeyEvict(client, keyId);
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Cleanup */
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);

    printf("RSA tests passed\n");
    return 0;
}

static int whTest_ClientCryptoAes(whClientContext* client)
{
    int ret;
    Aes aes;
    WC_RNG rng;
    byte key[32];
    byte iv[16];
    byte plaintext[] = "Test AES encryption";
    byte ciphertext[32];
    byte decrypted[32];

    printf("Testing AES operations...\n");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Generate random key and IV */
    ret = wc_RNG_GenerateBlock(&rng, key, sizeof(key));
    WH_TEST_ASSERT_RETURN(ret == 0);

    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Test invalid parameters */
    ret = wc_AesInit(NULL, NULL, INVALID_DEVID);
    WH_TEST_ASSERT_RETURN(ret != 0);

    /* Test valid initialization */
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Test key setting */
    ret = wc_AesSetKey(&aes, key, sizeof(key), iv, AES_ENCRYPTION);
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Test encryption */
    ret = wc_AesCbcEncrypt(&aes, ciphertext, plaintext, sizeof(plaintext));
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Test decryption */
    ret = wc_AesSetKey(&aes, key, sizeof(key), iv, AES_DECRYPTION);
    WH_TEST_ASSERT_RETURN(ret == 0);

    ret = wc_AesCbcDecrypt(&aes, decrypted, ciphertext, sizeof(plaintext));
    WH_TEST_ASSERT_RETURN(ret == 0);

    WH_TEST_ASSERT_RETURN(memcmp(plaintext, decrypted, sizeof(plaintext)) == 0);

    /* Cleanup */
    wc_AesFree(&aes);
    wc_FreeRng(&rng);

    printf("AES tests passed\n");
    return 0;
}

int whTest_ClientCrypto(void)
{
    int ret;
    whClientContext client = {0};
    whServerContext server = {0};
    static uint8_t req_buffer[4096];
    static uint8_t resp_buffer[4096];
    static whTransportMemConfig transportCfg = {
        .req = req_buffer,
        .req_size = sizeof(req_buffer),
        .resp = resp_buffer,
        .resp_size = sizeof(resp_buffer),
    };
    static const whTransportClientCb transportClientCb = WH_TRANSPORT_MEM_CLIENT_CB;
    static const whTransportServerCb transportServerCb = WH_TRANSPORT_MEM_SERVER_CB;
    static whTransportMemClientContext transportClientCtx = {0};
    static whTransportMemServerContext transportServerCtx = {0};
    whClientConfig clientCfg = {0};
    whServerConfig serverCfg = {0};
    whServerCryptoContext cryptoCtx = {
        .devId = WH_DEV_ID_HSM,
    };
    whCommClientConfig commClientCfg = {
        .transport_cb = &transportClientCb,
        .transport_context = &transportClientCtx,
        .transport_config = &transportCfg,
        .client_id = 1,
    };
    whCommServerConfig commServerCfg = {
        .transport_cb = &transportServerCb,
        .transport_context = &transportServerCtx,
        .transport_config = &transportCfg,
        .server_id = 1,
    };
    clientCfg.comm = &commClientCfg;
    serverCfg.comm_config = &commServerCfg;
    serverCfg.crypto = &cryptoCtx;

    printf("Testing client crypto...\n");

    /* Initialize server crypto */
    ret = wc_InitRng(cryptoCtx.rng);
    if (ret != 0) {
        WH_ERROR_PRINT("Server RNG init failed: %d\n", ret);
        return ret;
    }

    /* Initialize server */
    ret = wh_Server_Init(&server, &serverCfg);
    if (ret != 0) {
        WH_ERROR_PRINT("Server init failed: %d\n", ret);
        wc_FreeRng(cryptoCtx.rng);
        return ret;
    }

    /* Initialize client */
    ret = wh_Client_Init(&client, &clientCfg);
    if (ret != 0) {
        WH_ERROR_PRINT("Client init failed: %d\n", ret);
        return ret;
    }

    /* Run crypto tests */
    ret = whTest_ClientCryptoRsa(&client);
    if (ret != 0) {
        WH_ERROR_PRINT("RSA tests failed: %d\n", ret);
        goto cleanup;
    }

    ret = whTest_ClientCryptoAes(&client);
    if (ret != 0) {
        WH_ERROR_PRINT("AES tests failed: %d\n", ret);
        goto cleanup;
    }

    printf("All crypto tests passed\n");

cleanup:
    wh_Client_Cleanup(&client);
    wh_Server_Cleanup(&server);
    wc_FreeRng(cryptoCtx.rng);
    return ret;
}
