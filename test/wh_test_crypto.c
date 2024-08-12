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
/*
 * test/wh_test.c
 *
 */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"

#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <unistd.h> /* For sleep */
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

enum {
        REQ_SIZE = 32,
        RESP_SIZE = 64,
        BUFFER_SIZE = 4096,
    };


#define PLAINTEXT "mytextisbigplain"

#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
/* Flag causing the server loop to sleep(1) */
int serverDelay = 0;
#endif

#if defined(WOLFHSM_CFG_TEST_POSIX)
/* pointer to expose server context cancel sequence to the client cancel
 * callback */
static uint16_t* cancelSeqP;

/* Test client cancel callback that directly sets the sequence to cancel in the
 * server context */
static int _cancelCb(uint16_t seq)
{
    *cancelSeqP = seq;
    return 0;
}
#endif

int whTest_CryptoClientConfig(whClientConfig* config)
{
    int i;
    whClientContext client[1] = {0};
    int ret = 0;
    int res = 0;
    /* wolfcrypt */
    WC_RNG rng[1];
    Aes aes[1];
    RsaKey rsa[1];
    ecc_key eccPrivate[1];
    ecc_key eccPublic[1];
    curve25519_key curve25519PrivateKey[1];
    curve25519_key curve25519PublicKey[1];
    Cmac cmac[1];
    uint32_t outLen;
    uint16_t keyId;
    uint8_t key[16];
    uint8_t keyEnd[16];
    uint8_t labelStart[WH_NVM_LABEL_LEN];
    uint8_t labelEnd[WH_NVM_LABEL_LEN];
    uint8_t iv[AES_IV_SIZE];
    char plainText[16];
    char cipherText[256];
    char finalText[256];
    char cmacFodder[1000];
    uint8_t authIn[16];
    uint8_t authTag[16];
    uint8_t sharedOne[CURVE25519_KEYSIZE];
    uint8_t sharedTwo[CURVE25519_KEYSIZE];
    uint8_t knownCmacKey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t knownCmacMessage[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f,
        0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a,
        0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e,
        0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1,
        0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    uint8_t knownCmacTag[] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};

#ifndef NO_SHA256
    wc_Sha256 sha256[1];
    uint8_t   sha256Out[WC_SHA256_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char sha256InOneBlock[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t sha256ExpectedOutOneBlock[WC_SHA256_DIGEST_SIZE] = {
        0xff, 0xe0, 0x54, 0xfe, 0x7a, 0xe0, 0xcb, 0x6d, 0xc6, 0x5c, 0x3a,
        0xf9, 0xb6, 0x1d, 0x52, 0x09, 0xf4, 0x39, 0x85, 0x1d, 0xb4, 0x3d,
        0x0b, 0xa5, 0x99, 0x73, 0x37, 0xdf, 0x15, 0x46, 0x68, 0xeb};
    /* Vector long enough to span a SHA256 block */
    const char sha256InMultiBlock[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t sha256ExpectedOutMultiBlock[WC_SHA256_DIGEST_SIZE] = {
        0x7b, 0x54, 0x45, 0x86, 0xb3, 0x51, 0x43, 0x4e, 0xf6, 0x83, 0xdb,
        0x78, 0x1d, 0x94, 0xd6, 0xb0, 0x36, 0x9b, 0x36, 0x56, 0x93, 0x0e,
        0xf4, 0x47, 0x9b, 0xae, 0xff, 0xfa, 0x1f, 0x36, 0x38, 0x64};
#endif /* !NO_SHA256 */


    XMEMCPY(plainText, PLAINTEXT, sizeof(plainText));

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInit(client, NULL, NULL));

#ifdef WOLFHSM_CFG_TEST_VERBOSE
    {
        int32_t  server_rc       = 0;
        whNvmId  avail_objects   = 0;
        whNvmId  reclaim_objects = 0;
        uint32_t avail_size      = 0;
        uint32_t reclaim_size    = 0;

        WH_TEST_RETURN_ON_FAIL(
            ret = wh_Client_NvmGetAvailable(client, &server_rc, &avail_size,
                                            &avail_objects, &reclaim_size,
                                            &reclaim_objects));

        printf("PRE-CRYPTO TEST: NvmGetAvailable:%d, server_rc:%d avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects,
               (int)reclaim_size, (int)reclaim_objects);
    }
#endif /* WOLFHSM_CFG_TEST_VERBOSE */


    memset(labelStart, 0xff, sizeof(labelStart));

    /* test rng */
    if ((ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RNG_GenerateBlock(rng, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit;
    }
    if((ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv))) != 0) {
        printf("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit;
    }
    if((ret = wc_RNG_GenerateBlock(rng, authIn, sizeof(authIn))) != 0) {
        printf("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit;
    }
    printf("RNG SUCCESS\n");
    /* test cache/export */
    keyId = WH_KEYID_ERASED;
    if ((ret = wh_Client_KeyCache(client, 0, labelStart, sizeof(labelStart), key, sizeof(key), &keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    outLen = sizeof(keyEnd);
    if ((ret = wh_Client_KeyExport(client, keyId, labelEnd, sizeof(labelEnd), keyEnd, &outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        goto exit;
    }
    if (ret == 0 && XMEMCMP(key, keyEnd, outLen) == 0 && XMEMCMP(labelStart, labelEnd, sizeof(labelStart)) == 0)
        printf("KEY CACHE/EXPORT SUCCESS\n");
    else {
        WH_ERROR_PRINT("KEY CACHE/EXPORT FAILED TO MATCH\n");
        goto exit;
    }

#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
    /* WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS protects the client test code that expects to
     * interop with the custom server (also defined in this file), so that this
     * test can be run against a standard server app
     *
     * TODO: This is a temporary bodge until we properly split tests into single
     * client and multi client */

    /* test cache with duplicate keyId for a different user */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommClose(client));
    client->comm->client_id = 2;
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInit(client, NULL, NULL));
    XMEMSET(cipherText, 0xff, sizeof(cipherText));
    /* first check that evicting the other clients key fails */
    if ((ret = wh_Client_KeyEvict(client, keyId)) != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
        goto exit;
    }
    keyId = WH_KEYID_ERASED;
    if ((ret = wh_Client_KeyCache(client, 0, labelStart, sizeof(labelStart), (uint8_t*)cipherText, sizeof(key), &keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    outLen = sizeof(keyEnd);
    if ((ret = wh_Client_KeyExport(client, keyId, labelEnd, sizeof(labelEnd), keyEnd, &outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        goto exit;
    }
    if (ret != 0 || XMEMCMP(cipherText, keyEnd, outLen) != 0 || XMEMCMP(labelStart, labelEnd, sizeof(labelStart)) != 0) {
        WH_ERROR_PRINT("KEY CACHE/EXPORT FAILED TO MATCH\n");
        goto exit;
    }
    /* evict for this client */
    if ((ret = wh_Client_KeyEvict(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
        goto exit;
    }
    /* switch back and verify original key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommClose(client));
    client->comm->client_id = 1;
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInit(client, NULL, NULL));
    outLen = sizeof(keyEnd);
    if ((ret = wh_Client_KeyExport(client, keyId, labelEnd, sizeof(labelEnd), keyEnd, &outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        goto exit;
    }
    if (ret == 0 && XMEMCMP(key, keyEnd, outLen) == 0 && XMEMCMP(labelStart, labelEnd, sizeof(labelStart)) == 0)
        printf("KEY USER CACHE MUTUAL EXCLUSION SUCCESS\n");
    else {
        WH_ERROR_PRINT("KEY CACHE/EXPORT FAILED TO MATCH\n");
        goto exit;
    }
#endif /* !WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS */

    /* evict for original client */
    if ((ret = wh_Client_KeyEvict(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
        goto exit;
    }
    outLen = sizeof(keyEnd);
    if ((ret = wh_Client_KeyExport(client, keyId, labelEnd, sizeof(labelEnd), keyEnd, &outLen)) != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        goto exit;
    }
    /* test commit */
    keyId = WH_KEYID_ERASED;
    if ((ret = wh_Client_KeyCache(client, 0, labelStart, sizeof(labelStart), key, sizeof(key), &keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyCommit(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyEvict(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
        goto exit;
    }
    outLen = sizeof(keyEnd);
    if ((ret = wh_Client_KeyExport(client, keyId, labelEnd, sizeof(labelEnd), keyEnd, &outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        goto exit;
    }
    if (XMEMCMP(key, keyEnd, outLen) != 0 || XMEMCMP(labelStart, labelEnd, sizeof(labelStart)) != 0) {
        WH_ERROR_PRINT("KEY COMMIT/EXPORT FAILED TO MATCH\n");
        ret = -1;
        goto exit;
    }
    /* verify commit isn't using new nvm slots */
    for (i = 0; i < 64; i++) {
        if ((ret = wh_Client_KeyCommit(client, keyId)) != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
            goto exit;
        }
    }
    printf("KEY COMMIT/EXPORT SUCCESS\n");
    /* test erase */
    if ((ret = wh_Client_KeyErase(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyErase %d\n", ret);
        goto exit;
    }
    outLen = sizeof(keyEnd);
    if ((ret = wh_Client_KeyExport(client, keyId, labelEnd, sizeof(labelEnd), keyEnd, &outLen)) != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        goto exit;
    }
    printf("KEY ERASE SUCCESS\n");
    /* test aes CBC with client side key */
    if((ret = wc_AesInit(aes, NULL, WH_DEV_ID)) != 0) {
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesSetKey(aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION)) != 0) {
        printf("Failed to wc_AesSetKey %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesCbcEncrypt(aes, (byte*)cipherText, (byte*)plainText, sizeof(plainText))) != 0) {
        printf("Failed to wc_AesCbcEncrypt %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesSetKey(aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION)) != 0) {
        printf("Failed to wc_AesSetKey %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesCbcDecrypt(aes, (byte*)finalText, (byte*)cipherText, sizeof(plainText))) != 0) {
        printf("Failed to wc_AesCbcDecrypt %d\n", ret);
        goto exit;
    }
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        WH_ERROR_PRINT("AES CBC FAILED TO MATCH\n");
        ret = -1;
        goto exit;
    }
    /* test aes CBC with HSM side key */
    if((ret = wc_AesInit(aes, NULL, WH_DEV_ID)) != 0) {
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }
    keyId = WH_KEYID_ERASED;
    if ((ret = wh_Client_KeyCache(client, 0, labelStart, sizeof(labelStart), key, sizeof(key), &keyId)) != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    wh_Client_SetKeyIdAes(aes, keyId);
    if ((ret = wc_AesSetIV(aes, iv)) != 0) {
        printf("Failed to wc_AesSetIV %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesCbcEncrypt(aes, (byte*)cipherText, (byte*)plainText, sizeof(plainText))) != 0) {
        printf("Failed to wc_AesCbcEncrypt %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesSetKey(aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION)) != 0) {
        printf("Failed to wc_AesSetKey %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesCbcDecrypt(aes, (byte*)finalText, (byte*)cipherText, sizeof(plainText))) != 0) {
        printf("Failed to wc_AesCbcDecrypt %d\n", ret);
        goto exit;
    }
    if (memcmp(plainText, finalText, sizeof(plainText)) == 0)
        printf("AES CBC SUCCESS\n");
    else {
        WH_ERROR_PRINT("AES CBC FAILED TO MATCH\n");
        ret = -1;
        goto exit;
    }
    if((ret = wh_Client_KeyEvict(client, keyId)) != 0) {
        printf("Failed to wh_Client_KeyEvict %d\n", ret);
        goto exit;
    }
    /* test aes GCM with client side key */
    if((ret = wc_AesInit(aes, NULL, WH_DEV_ID)) != 0) {
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesSetKey(aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION)) != 0) {
        printf("Failed to wc_AesSetKey %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesGcmEncrypt(aes, (byte*)cipherText, (byte*)plainText, sizeof(plainText), iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn))) != 0) {
        printf("Failed to wc_AesGcmEncrypt %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesSetKey(aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION)) != 0) {
        printf("Failed to wc_AesSetKey %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesGcmDecrypt(aes, (byte*)finalText, (byte*)cipherText, sizeof(plainText), iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn))) != 0) {
        printf("Failed to wc_AesGcmDecrypt %d\n", ret);
        goto exit;
    }
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        WH_ERROR_PRINT("AES GCM FAILED TO MATCH\n");
        ret = -1;
        goto exit;
    }
    /* test aes GCM with HSM side key */
    if((ret = wc_AesInit(aes, NULL, WH_DEV_ID)) != 0) {
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }
    keyId = WH_KEYID_ERASED;
    if ((ret = wh_Client_KeyCache(client, 0, labelStart, sizeof(labelStart), key, sizeof(key), &keyId)) != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    wh_Client_SetKeyIdAes(aes, keyId);
    if ((ret = wc_AesSetIV(aes, iv)) != 0) {
        printf("Failed to wc_AesSetIV %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesGcmEncrypt(aes, (byte*)cipherText, (byte*)plainText, sizeof(plainText), iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn))) != 0) {
        printf("Failed to wc_AesGcmEncrypt %d\n", ret);
        goto exit;
    }
    if ((ret = wc_AesGcmDecrypt(aes, (byte*)finalText, (byte*)cipherText, sizeof(plainText), iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn))) != 0) {
        printf("Failed to wc_AesGcmDecrypt %d\n", ret);
        goto exit;
    }
    if (memcmp(plainText, finalText, sizeof(plainText)) == 0)
        printf("AES GCM SUCCESS\n");
    else {
        WH_ERROR_PRINT("AES GCM FAILED TO MATCH\n");
        ret = -1;
        goto exit;
    }
    if((ret = wh_Client_KeyEvict(client, keyId)) != 0) {
        printf("Failed to wh_Client_KeyEvict %d\n", ret);
        goto exit;
    }
    /* test rsa */
    /* Using ephemral key */
    printf("RSA testing using wolfCrypt with ephemeral keys\n");
    if((ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID)) != 0) {
        printf("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }
    if((ret = wc_MakeRsaKey(rsa, 2048, 65537, rng)) != 0) {
        printf("Failed to wc_MakeRsaKey %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText), (byte*)cipherText,
        sizeof(cipherText), rsa, rng)) < 0) {
        printf("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret, (byte*)finalText,
        sizeof(finalText), rsa)) < 0) {
        printf("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }
    if((ret = wc_FreeRsaKey(rsa)) != 0) {
        printf("Failed to wc_FreeRsaKey %d\n", ret);
        goto exit;
    }

    /* Using client export key */
    printf("RSA testing using whClient ephemeral keys\n");
    if((ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID)) != 0) {
        printf("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }
    if((ret = wh_Client_MakeExportRsaKey(client, 2048, 65537, rsa)) != 0) {
        printf("Failed to wh_Client_MakeExportRsaKey %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText), (byte*)cipherText,
        sizeof(cipherText), rsa, rng)) < 0) {
        printf("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret, (byte*)finalText,
        sizeof(finalText), rsa)) < 0) {
        printf("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }
    if((ret = wc_FreeRsaKey(rsa)) != 0) {
        printf("Failed to wc_FreeRsaKey %d\n", ret);
        goto exit;
    }

    /* Using keyCache key */
    /* Using ephemral key */
    keyId = WH_KEYID_ERASED;
    printf("RSA testing using whServer cached keys\n");
    if((ret = wh_Client_MakeCacheRsaKey(client, 2048, 65537,
            WH_NVM_FLAGS_NONE, 0, NULL, &keyId)) != 0) {
        printf("Failed to wh_Client_MakeCacheRsaKey %d\n", ret);
        goto exit;
    }

    if((ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID)) != 0) {
        printf("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }
    if((ret = wh_Client_SetKeyIdRsa(rsa, keyId)) != 0) {
        printf("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
        goto exit;
    }

    if ((ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText), (byte*)cipherText,
        sizeof(cipherText), rsa, rng)) < 0) {
        printf("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret, (byte*)finalText,
        sizeof(finalText), rsa)) < 0) {
        printf("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }

    if((ret = wh_Client_GetKeyIdRsa(rsa, &keyId)) != 0) {
        printf("Failed to wc_GetKeyIdRsa %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyEvict(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
        goto exit;
    }
    if((ret = wc_FreeRsaKey(rsa)) != 0) {
        printf("Failed to wc_FreeRsaKey %d\n", ret);
        goto exit;
    }
    printf("RSA KEYGEN SUCCESS\n");
    if (memcmp(plainText, finalText, sizeof(plainText)) == 0)
        printf("RSA SUCCESS\n");
    else {
        WH_ERROR_PRINT("RSA FAILED TO MATCH\n");
        ret = -1;
        goto exit;
    }
    /* test ecc */
    if((ret = wc_ecc_init_ex(eccPrivate, NULL, WH_DEV_ID)) != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    if((ret = wc_ecc_init_ex(eccPublic, NULL, WH_DEV_ID)) != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    if((ret = wc_ecc_make_key(rng, 32, eccPrivate)) != 0) {
        printf("Failed to wc_ecc_make_key %d\n", ret);
        goto exit;
    }
    if((ret = wc_ecc_make_key(rng, 32, eccPublic)) != 0) {
        printf("Failed to wc_ecc_make_key %d\n", ret);
        goto exit;
    }
    outLen = 32;
    if((ret = wc_ecc_shared_secret(eccPrivate, eccPublic, (byte*)cipherText, (word32*)&outLen)) != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }
    if((ret = wc_ecc_shared_secret(eccPublic, eccPrivate, (byte*)finalText, (word32*)&outLen)) != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }
    if (memcmp(cipherText, finalText, outLen) == 0)
        printf("ECDH SUCCESS\n");
    else {
        WH_ERROR_PRINT("ECDH FAILED TO MATCH\n");
        ret = -1;
        goto exit;
    }
    outLen = sizeof(finalText);
    if((ret = wc_ecc_sign_hash((void*)cipherText, sizeof(cipherText), (void*)finalText, (word32*)&outLen, rng, eccPrivate)) != 0) {
        printf("Failed to wc_ecc_sign_hash %d\n", ret);
        goto exit;
    }
    if((ret = wc_ecc_verify_hash((void*)finalText, outLen, (void*)cipherText, sizeof(cipherText), &res, eccPrivate)) != 0) {
        printf("Failed to wc_ecc_verify_hash %d\n", ret);
        goto exit;
    }
    if (res == 1)
        printf("ECC SIGN/VERIFY SUCCESS\n");
    else {
        WH_ERROR_PRINT("ECC SIGN/VERIFY FAIL\n");
        ret = -1;
        goto exit;
    }
    /* test curve25519 */
    if ((ret = wc_curve25519_init_ex(curve25519PrivateKey, NULL, WH_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    if ((ret = wc_curve25519_init_ex(curve25519PublicKey, NULL, WH_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    if ((ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PrivateKey)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }
    if ((ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PublicKey)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }
    outLen = sizeof(sharedOne);
    if ((ret = wc_curve25519_shared_secret(curve25519PrivateKey, curve25519PublicKey, sharedOne, (word32*)&outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }
    if ((ret = wc_curve25519_shared_secret(curve25519PublicKey, curve25519PrivateKey, sharedTwo, (word32*)&outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }
    if (XMEMCMP(sharedOne, sharedTwo, outLen) != 0) {
        WH_ERROR_PRINT("CURVE25519 shared secrets don't match\n");
        ret = -1;
        goto exit;
    }
    printf("CURVE25519 SUCCESS\n");
    /* test cmac */
    if((ret = wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey), WC_CMAC_AES, NULL, NULL, WH_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }
    if((ret = wc_CmacUpdate(cmac, (byte*)knownCmacMessage, sizeof(knownCmacMessage))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }
    outLen = sizeof(knownCmacTag);
    if((ret = wc_CmacFinal(cmac, (byte*)cipherText, (word32*)&outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }
    if (memcmp(knownCmacTag, cipherText, sizeof(knownCmacTag)) != 0) {
        WH_ERROR_PRINT("CMAC FAILED KNOWN ANSWER TEST\n");
        ret = -1;
        goto exit;
    }
    if((ret = wc_AesCmacVerify_ex(cmac, (byte*)knownCmacTag, sizeof(knownCmacTag), (byte*)knownCmacMessage, sizeof(knownCmacMessage), knownCmacKey, sizeof(knownCmacKey), NULL, WH_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_AesCmacVerify_ex %d\n", ret);
        goto exit;
    }
    /* test oneshot with pre-cached key */
    keyId = WH_KEYID_ERASED;
    if ((ret = wh_Client_KeyCache(client, 0, labelStart, sizeof(labelStart), knownCmacKey, sizeof(knownCmacKey), &keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    outLen = sizeof(knownCmacTag);
    if((ret = wh_Client_AesCmacGenerate(cmac, (byte*)cipherText, (word32*)&outLen, (byte*)knownCmacMessage, sizeof(knownCmacMessage), keyId, NULL)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesCmacGenerate %d\n", ret);
        goto exit;
    }
    if (memcmp(knownCmacTag, cipherText, sizeof(knownCmacTag)) != 0) {
        WH_ERROR_PRINT("CMAC FAILED KNOWN ANSWER TEST\n");
        ret = -1;
        goto exit;
    }
    /* verify the key was evicted after oneshot */
    outLen = sizeof(keyEnd);
    if ((ret = wh_Client_KeyExport(client, keyId, labelEnd, sizeof(labelEnd), keyEnd, &outLen)) != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        goto exit;
    }
    /* test oneshot verify with commited key */
    keyId = WH_KEYID_ERASED;
    if ((ret = wh_Client_KeyCache(client, 0, labelStart, sizeof(labelStart), knownCmacKey, sizeof(knownCmacKey), &keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyCommit(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
        goto exit;
    }
    if((ret = wh_Client_AesCmacVerify(cmac, (byte*)cipherText, outLen, (byte*)knownCmacMessage, sizeof(knownCmacMessage), keyId, NULL)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesCmacVerify %d\n", ret);
        goto exit;
    }
    /* verify the key still exists in NVM */
    outLen = sizeof(keyEnd);
    if ((ret = wh_Client_KeyExport(client, keyId, labelEnd, sizeof(labelEnd), keyEnd, &outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        goto exit;
    }
    /* test finished, erase key */
    if ((ret = wh_Client_KeyErase(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyErase %d\n", ret);
        goto exit;
    }

    /* test CMAC cancellation */
    if((ret = wh_Client_EnableCancel(client)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_EnableCancel %d\n", ret);
        goto exit;
    }
    if((ret = wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey), WC_CMAC_AES, NULL, NULL, WH_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }
    if((ret = wh_Client_CmacCancelableResponse(client, cmac, NULL, 0)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_CmacCancelableResponse %d\n", ret);
        goto exit;
    }
#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
    /* delay the server so scheduling doesn't interfere with the timing */
    serverDelay = 1;

    /* TODO: use hsm pause/resume functionality on real hardware */
#endif
    if((ret = wc_CmacUpdate(cmac, (byte*)cmacFodder, sizeof(knownCmacMessage))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }
    if((ret = wh_Client_CancelRequest(client)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_CancelRequest %d\n", ret);
        goto exit;
    }
#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
    serverDelay = 0;
#endif
    do {
        ret = wh_Client_CancelResponse(client);
    } while (ret == WH_ERROR_NOTREADY);
    if(ret != 0
#if defined(WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS)
        && ret != WH_ERROR_CANCEL_LATE
#endif
    ) {
        WH_ERROR_PRINT("Failed to wh_Client_CancelResponse %d\n", ret);
        goto exit;
    }
    /* test cancelable request and response work for standard CMAC request with no cancellation */
    if((ret = wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey), WC_CMAC_AES, NULL, NULL, WH_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }
    if((ret = wh_Client_CmacCancelableResponse(client, cmac, NULL, 0)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_CmacCancelableResponse %d\n", ret);
        goto exit;
    }
    if((ret = wc_CmacUpdate(cmac, (byte*)knownCmacMessage, sizeof(knownCmacMessage))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }
    if((ret = wh_Client_CmacCancelableResponse(client, cmac, NULL, 0)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_CmacCancelableResponse %d\n", ret);
        goto exit;
    }
    outLen = sizeof(knownCmacTag);
    if((ret = wc_CmacFinal(cmac, (byte*)cipherText, (word32*)&outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }
    if((ret = wh_Client_CmacCancelableResponse(client, cmac, (uint8_t*)cipherText, &outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_CmacCancelableResponse %d\n", ret);
        goto exit;
    }
    if (memcmp(knownCmacTag, cipherText, sizeof(knownCmacTag)) != 0) {
        WH_ERROR_PRINT("CMAC FAILED KNOWN ANSWER TEST\n");
        ret = -1;
        goto exit;
    }
    if((ret = wh_Client_DisableCancel(client)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_EnableCancel %d\n", ret);
        goto exit;
    }
    printf("CMAC SUCCESS\n");


#ifndef NO_SHA256
    /* Initialize SHA256 structure */
    if ((ret = wc_InitSha256_ex(sha256, NULL, WH_DEV_ID) != 0)) {
        WH_ERROR_PRINT("Failed to wc_InitSha256 %d\n", ret);
        goto exit;
    }

    /* Test SHA256 on a single block worth of data. Should trigger a server
     * transaction */
    if ((ret = wc_Sha256Update(sha256, (const byte*)sha256InOneBlock,
                               WC_SHA256_BLOCK_SIZE) != 0)) {
        WH_ERROR_PRINT("Failed to wc_Sha256Update %d\n", ret);
        goto exit;
    }

    /* Finalize should trigger a server transaction with an empty buffer */
    if ((ret = wc_Sha256Final(sha256, sha256Out) != 0)) {
        WH_ERROR_PRINT("Failed to wc_Sha256Final %d\n", ret);
        goto exit;
    }

    /* Compare the computed hash with the expected output */
    if (memcmp(sha256Out, sha256ExpectedOutOneBlock, WC_SHA256_DIGEST_SIZE) !=
        0) {
        WH_ERROR_PRINT("SHA256 hash does not match the expected output.\n");
        goto exit;
    }

    memset(sha256Out, 0, WC_SHA256_DIGEST_SIZE);

    /* Reset state for multi block test */
    wc_Sha256Free(sha256);
    if ((ret = wc_InitSha256_ex(sha256, NULL, WH_DEV_ID) != 0)) {
        WH_ERROR_PRINT("Failed to wc_InitSha256 %d\n", ret);
        goto exit;
    }

    /* Update with a non-block aligned length. Will not trigger server
     * transaction */
    if ((ret = wc_Sha256Update(sha256, (const byte*)sha256InMultiBlock, 1) !=
               0)) {
        WH_ERROR_PRINT("Failed to wc_Sha256Update %d\n", ret);
        goto exit;
    }
    /* Update with a full block, will trigger block to be sent to server and one
     * additional byte to be buffered */
    if ((ret = wc_Sha256Update(sha256, (const byte*)sha256InMultiBlock + 1,
                               WC_SHA256_BLOCK_SIZE) != 0)) {
        WH_ERROR_PRINT("Failed to wc_Sha256Update %d\n", ret);
        goto exit;
    }
    /* Update with the remaining data, should not trigger server transaction */
    if ((ret =
             wc_Sha256Update(
                 sha256,
                 (const byte*)sha256InMultiBlock + 1 + WC_SHA256_BLOCK_SIZE,
                 strlen(sha256InMultiBlock) - 1 - WC_SHA256_BLOCK_SIZE) != 0)) {
        WH_ERROR_PRINT("Failed to wc_Sha256Update %d\n", ret);
        goto exit;
    }

    /* Finalize should trigger a server transaction on the remaining partial
     * buffer */
    if ((ret = wc_Sha256Final(sha256, sha256Out) != 0)) {
        WH_ERROR_PRINT("Failed to wc_Sha256Final %d\n", ret);
        goto exit;
    }

    /* Compare the computed hash with the expected output */
    if (memcmp(sha256Out, sha256ExpectedOutMultiBlock, WC_SHA256_DIGEST_SIZE) !=
        0) {
        WH_ERROR_PRINT("SHA256 hash does not match the expected output.\n");
        goto exit;
    }

    /* Cleanup */
    wc_Sha256Free(sha256);

    printf("SHA256 SUCCESS\n");

#endif /* !NO_SHA256 */


#ifdef WOLFHSM_CFG_TEST_VERBOSE
    {
        int32_t  server_rc       = 0;
        whNvmId  avail_objects   = 0;
        whNvmId  reclaim_objects = 0;
        uint32_t avail_size      = 0;
        uint32_t reclaim_size    = 0;

        WH_TEST_RETURN_ON_FAIL(
            ret = wh_Client_NvmGetAvailable(client, &server_rc, &avail_size,
                                            &avail_objects, &reclaim_size,
                                            &reclaim_objects));

        printf("POST-CRYPTO TEST: NvmGetAvailable:%d, server_rc:%d avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects,
               (int)reclaim_size, (int)reclaim_objects);
    }
#endif /* WOLFHSM_CFG_TEST_VERBOSE */
    ret = 0;
exit:
    wc_curve25519_free(curve25519PrivateKey);
    wc_curve25519_free(curve25519PublicKey);
    wc_FreeRng(rng);

    /* Tell server to close */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommClose(client));

    if (ret == 0) {
        WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));
    }
    else {
        wh_Client_Cleanup(client);
    }

    return ret;
}

int whTest_CryptoServerConfig(whServerConfig* config)
{
    whServerContext server[1] = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int ret = 0;
#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
    int userChange = 0;
#endif

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

#if defined(WOLFHSM_CFG_TEST_POSIX)
    /* expose server ctx to client cancel callback */
    cancelSeqP = &server->cancelSeq;
#endif

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, config));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));
    server->comm->client_id = 1;

    while(am_connected == WH_COMM_CONNECTED) {
#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
        while (serverDelay == 1) {
#ifdef WOLFHSM_CFG_TEST_POSIX
            sleep(1);
#endif
        }
#endif
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) &&
                (ret != WH_ERROR_OK)) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            break;
        }
        wh_Server_GetConnected(server, &am_connected);

#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
        /* keep alive for 2 user changes */
        if (am_connected != WH_COMM_CONNECTED && userChange < 2) {
            if (userChange == 0)
                server->comm->client_id = 2;
            else if (userChange == 1)
                server->comm->client_id = 1;
            userChange++;
            am_connected = WH_COMM_CONNECTED;
            WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));
        }
#endif /* !WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS */
    }

    if ((ret == 0) || (ret == WH_ERROR_NOTREADY)) {
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    } else {
        ret = wh_Server_Cleanup(server);
    }

    return ret;
}

#if defined(WOLFHSM_CFG_TEST_POSIX)
static void* _whClientTask(void *cf)
{
    WH_TEST_ASSERT(0 == whTest_CryptoClientConfig(cf));
    return NULL;
}

static void* _whServerTask(void* cf)
{
    WH_TEST_ASSERT(0 == whTest_CryptoServerConfig(cf));
    return NULL;
}


static void _whClientServerThreadTest(whClientConfig* c_conf,
                                whServerConfig* s_conf)
{
    pthread_t cthread = {0};
    pthread_t sthread = {0};

    void* retval;
    int rc = 0;

    rc = pthread_create(&sthread, NULL, _whServerTask, s_conf);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whClientTask, c_conf);
        if (rc == 0) {
            /* All good. Block on joining */
            pthread_join(cthread, &retval);
            pthread_join(sthread, &retval);
        } else {
            /* Cancel the server thread */
            pthread_cancel(sthread);
            pthread_join(sthread, &retval);

        }
    }
}

static int wh_ClientServer_MemThreadTest(void)
{
    uint8_t req[BUFFER_SIZE] = {0};
    uint8_t resp[BUFFER_SIZE] = {0};

    whTransportMemConfig tmcf[1] = {{
        .req        = (whTransportMemCsr*)req,
        .req_size   = sizeof(req),
        .resp       = (whTransportMemCsr*)resp,
        .resp_size  = sizeof(resp),
    }};
    /* Client configuration/contexts */
    whTransportClientCb         tccb[1]   = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]   = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = 1,
    }};
    whClientConfig c_conf[1] = {{
       .comm = cc_conf,
       .cancelCb = _cancelCb,
    }};
    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]   = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]   = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1] = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = 1024 * 1024, /* 1MB  Flash */
        .sectorSize = 128 * 1024,  /* 128KB  Sector Size */
        .pageSize   = 8,           /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
    }};
    const whFlashCb  fcb[1]          = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig nf_conf[1] = {{
        .cb      = fcb,
        .context = fc,
        .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1] = {0};
    whNvmCb nfcb[1] = {WH_NVM_FLASH_CB};

    whNvmConfig n_conf[1] = {{
            .cb = nfcb,
            .context = nfc,
            .config = nf_conf,
    }};
    whNvmContext nvm[1] = {{0}};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {{
            .devId = INVALID_DEVID,
    }};

    whServerConfig                  s_conf[1] = {{
       .comm_config = cs_conf,
       .nvm = nvm,
       .crypto = crypto,
       .devId = INVALID_DEVID,
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));

    _whClientServerThreadTest(c_conf, s_conf);

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_POSIX */

int whTest_Crypto(void)
{
#if defined(WOLFHSM_CFG_TEST_POSIX)
    printf("Testing crypto: (pthread) mem...\n");
    WH_TEST_RETURN_ON_FAIL(wh_ClientServer_MemThreadTest());
#endif
    return 0;
}

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
