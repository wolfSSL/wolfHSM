/*
 * Copyright (C) 2025 wolfSSL Inc.
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
#include "wh_bench_mod.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_BENCH_ENABLE)
#include "wolfssl/wolfcrypt/aes.h"

#if defined(WOLFHSM_CFG_DMA) && defined(WOLFHSM_CFG_TEST_POSIX)
#include "port/posix/posix_transport_shm.h"
#endif /* WOLFHSM_CFG_DMA && WOLFHSM_CFG_TEST_POSIX */

#if !defined(NO_AES)

/* 128-bit key */
static const byte key128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

/* 256-bit key */
static const byte key256[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

enum { DECRYPT = 0, ENCRYPT = 1 };

#if defined(WOLFSSL_AES_COUNTER)
static int _benchAesCtr(whClientContext* client, whBenchOpContext* ctx, int id,
                        const uint8_t* key, size_t keyLen, int encrypt)
{
    int     ret       = 0;
    int     needEvict = 0;
    whKeyId keyId     = WH_KEYID_ERASED;
    Aes     aes[1];
    char    keyLabel[] = "key label";
    /* Input size is largest multiple of AES block size that fits in buffer */
    const size_t inLen =
        (WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE / WC_AES_BLOCK_SIZE) *
        WC_AES_BLOCK_SIZE;
    int i;

#if defined(WOLFHSM_CFG_BENCH_INIT_DATA_BUFFERS)
    /* Initialize the input buffer with something non-zero */
    memset(WH_BENCH_DATA_IN_BUFFER, 0xAA, inLen);
    memset(WH_BENCH_DATA_OUT_BUFFER, 0xAA, inLen);
#endif

    /* Initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_AesInit %d\n", ret);
        return ret;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, sizeof(keyLabel),
                             (uint8_t*)key, keyLen, &keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    ret = wh_Bench_SetDataSize(ctx, id, inLen);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Bench_SetDataSize %d\n", ret);
        goto exit;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        int benchStartRet;
        int benchStopRet;

        if (encrypt) {
            benchStartRet = wh_Bench_StartOp(ctx, id);
            ret           = wc_AesCtrEncrypt(aes, WH_BENCH_DATA_OUT_BUFFER,
                                             WH_BENCH_DATA_IN_BUFFER, inLen);
            benchStopRet  = wh_Bench_StopOp(ctx, id);
        }
        else {
            benchStartRet = wh_Bench_StartOp(ctx, id);
            ret           = wc_AesCtrEncrypt(aes, WH_BENCH_DATA_OUT_BUFFER,
                                             WH_BENCH_DATA_IN_BUFFER, inLen);
            benchStopRet  = wh_Bench_StopOp(ctx, id);
        }

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            goto exit;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_AesCtrc%s %d\n",
                            encrypt ? "Encrypt" : "Decrypt", ret);
            goto exit;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            goto exit;
        }
    }

exit:
    wc_AesFree(aes);

    if (needEvict) {
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    return ret;
}

int wh_Bench_Mod_Aes128CTREncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesCtr(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                        ENCRYPT);
}

int wh_Bench_Mod_Aes128CTRDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesCtr(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                        DECRYPT);
}

int wh_Bench_Mod_Aes256CTREncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesCtr(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                        ENCRYPT);
}

int wh_Bench_Mod_Aes256CTRDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesCtr(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                        DECRYPT);
}

#endif /* WOLFSSL_AES_COUNTER */
#if defined(HAVE_AES_ECB)
static int _benchAesEcb(whClientContext* client, whBenchOpContext* ctx, int id,
                        const uint8_t* key, size_t keyLen, int encrypt)
{
    int     ret       = 0;
    int     needEvict = 0;
    whKeyId keyId     = WH_KEYID_ERASED;
    Aes     aes[1];
    char    keyLabel[] = "key label";
    /* Input size is largest multiple of AES block size that fits in buffer */
    const size_t inLen =
        (WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE / WC_AES_BLOCK_SIZE) *
        WC_AES_BLOCK_SIZE;
    int i;

#if defined(WOLFHSM_CFG_BENCH_INIT_DATA_BUFFERS)
    /* Initialize the input buffer with something non-zero */
    memset(WH_BENCH_DATA_IN_BUFFER, 0xAA, inLen);
    memset(WH_BENCH_DATA_OUT_BUFFER, 0xAA, inLen);
#endif

    /* Initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_AesInit %d\n", ret);
        return ret;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, sizeof(keyLabel),
                             (uint8_t*)key, keyLen, &keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    ret = wh_Bench_SetDataSize(ctx, id, inLen);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Bench_SetDataSize %d\n", ret);
        goto exit;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        int benchStartRet;
        int benchStopRet;

        if (encrypt) {
            benchStartRet = wh_Bench_StartOp(ctx, id);
            ret           = wc_AesEcbEncrypt(aes, WH_BENCH_DATA_OUT_BUFFER,
                                             WH_BENCH_DATA_IN_BUFFER, inLen);
            benchStopRet  = wh_Bench_StopOp(ctx, id);
        }
        else {
            benchStartRet = wh_Bench_StartOp(ctx, id);
            ret           = wc_AesEcbDecrypt(aes, WH_BENCH_DATA_OUT_BUFFER,
                                             WH_BENCH_DATA_IN_BUFFER, inLen);
            benchStopRet  = wh_Bench_StopOp(ctx, id);
        }

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            goto exit;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_AesEcb%s %d\n",
                            encrypt ? "Encrypt" : "Decrypt", ret);
            goto exit;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            goto exit;
        }
    }

exit:
    wc_AesFree(aes);

    if (needEvict) {
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    return ret;
}

int wh_Bench_Mod_Aes128ECBEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesEcb(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                        ENCRYPT);
}

int wh_Bench_Mod_Aes128ECBDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesEcb(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                        DECRYPT);
}

int wh_Bench_Mod_Aes256ECBEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesEcb(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                        ENCRYPT);
}

int wh_Bench_Mod_Aes256ECBDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesEcb(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                        DECRYPT);
}
#endif /* HAVE_AES_ECB */

#if defined(HAVE_AES_CBC)
static int _benchAesCbc(whClientContext* client, whBenchOpContext* ctx, int id,
                        const uint8_t* key, size_t keyLen, int encrypt)
{
    int     ret       = 0;
    int     needEvict = 0;
    whKeyId keyId     = WH_KEYID_ERASED;
    Aes     aes[1];
    char    keyLabel[] = "key label";
    /* Input size is largest multiple of AES block size that fits in buffer */
    const size_t inLen =
        (WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE / WC_AES_BLOCK_SIZE) *
        WC_AES_BLOCK_SIZE;
    int i;

#if defined(WOLFHSM_CFG_BENCH_INIT_DATA_BUFFERS)
    /* Initialize the input buffer with something non-zero */
    memset(WH_BENCH_DATA_IN_BUFFER, 0xAA, inLen);
    memset(WH_BENCH_DATA_OUT_BUFFER, 0xAA, inLen);
#endif

    /* Initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_AesInit %d\n", ret);
        return ret;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, sizeof(keyLabel),
                             (uint8_t*)key, keyLen, &keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    ret = wh_Bench_SetDataSize(ctx, id, inLen);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Bench_SetDataSize %d\n", ret);
        goto exit;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        int benchStartRet;
        int benchStopRet;

        if (encrypt) {
            benchStartRet = wh_Bench_StartOp(ctx, id);
            ret           = wc_AesCbcEncrypt(aes, WH_BENCH_DATA_OUT_BUFFER,
                                             WH_BENCH_DATA_IN_BUFFER, inLen);
            benchStopRet  = wh_Bench_StopOp(ctx, id);
        }
        else {
            benchStartRet = wh_Bench_StartOp(ctx, id);
            ret           = wc_AesCbcDecrypt(aes, WH_BENCH_DATA_OUT_BUFFER,
                                             WH_BENCH_DATA_IN_BUFFER, inLen);
            benchStopRet  = wh_Bench_StopOp(ctx, id);
        }

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            goto exit;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_AesCbc%s %d\n",
                            encrypt ? "Encrypt" : "Decrypt", ret);
            goto exit;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            goto exit;
        }
    }

exit:
    wc_AesFree(aes);

    if (needEvict) {
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    return ret;
}


int wh_Bench_Mod_Aes128CBCEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesCbc(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                        ENCRYPT);
}

int wh_Bench_Mod_Aes128CBCDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesCbc(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                        DECRYPT);
}

int wh_Bench_Mod_Aes256CBCEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesCbc(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                        ENCRYPT);
}

int wh_Bench_Mod_Aes256CBCDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesCbc(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                        DECRYPT);
}
#endif /* HAVE_AES_CBC */

#if defined(HAVE_AESGCM)
#ifdef WOLFHSM_CFG_DMA
static int _benchAesGcmDma(whClientContext* client, whBenchOpContext* ctx,
                           int id, const uint8_t* key, size_t keyLen,
                           int encrypt)
{
    int            ret       = 0;
    int            needEvict = 0;
    whKeyId        keyId     = WH_KEYID_ERASED;
    Aes            aes[1];
    char           keyLabel[]                  = "key label";
    byte           iv[WC_AES_BLOCK_SIZE]       = {0, 1, 2,  3,  4,  5,  6,  7,
                                                  8, 9, 10, 11, 12, 13, 14, 15};
    byte           authData[WC_AES_BLOCK_SIZE] = {0, 1, 2,  3,  4,  5,  6,  7,
                                                  8, 9, 10, 11, 12, 13, 14, 15};
    byte           authTag[WC_AES_BLOCK_SIZE]  = {0, 1, 2,  3,  4,  5,  6,  7,
                                                  8, 9, 10, 11, 12, 13, 14, 15};
    const size_t   inLen = WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE / 2;
    int            i;
    const uint8_t* in  = NULL;
    uint8_t*       out = NULL;

#if defined(WOLFHSM_CFG_TEST_POSIX)
    /* Allocate buffers using XMALLOC with heap hints for DMA */
    if (ctx->transportType == WH_BENCH_TRANSPORT_POSIX_DMA) {
        void* heap =
            posixTransportShm_GetDmaHeap(client->comm->transport_context);
        in = XMALLOC(inLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (in == NULL) {
            WH_BENCH_PRINTF("Failed to allocate memory for DMA input\n");
            return WH_ERROR_NOSPACE;
        }

        out = XMALLOC(inLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (out == NULL) {
            WH_BENCH_PRINTF("Failed to allocate memory for DMA output\n");
            XFREE((uint8_t*)in, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return WH_ERROR_NOSPACE;
        }
    }
    else
#endif /* WOLFHSM_CFG_TEST_POSIX */
    {
        in  = WH_BENCH_DMA_BUFFER;
        out = (uint8_t*)in + inLen;
    }

#if defined(WOLFHSM_CFG_BENCH_INIT_DATA_BUFFERS)
    /* Initialize the buffers with something non-zero */
    memset((uint8_t*)in, 0xAA, inLen);
    memset(out, 0xAA, inLen);
#endif

    /* initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_AesInit %d\n", ret);
        return ret;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, sizeof(keyLabel),
                             (uint8_t*)key, keyLen, &keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* set the iv */
    ret = wc_AesSetIV(aes, iv);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_AesSetIV %d\n", ret);
        goto exit;
    }

    ret = wh_Bench_SetDataSize(ctx, id, inLen);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Bench_SetDataSize %d\n", ret);
        goto exit;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        int benchStartRet;
        int benchStopRet;

        if (encrypt == ENCRYPT) {
            benchStartRet = wh_Bench_StartOp(ctx, id);

            ret = wh_Client_AesGcmDma(client, aes, ENCRYPT, in, inLen, iv,
                                      sizeof(iv), authData, sizeof(authData),
                                      NULL, authTag, sizeof(authTag), out);

            benchStopRet = wh_Bench_StopOp(ctx, id);
        }
        else {
            benchStartRet = wh_Bench_StartOp(ctx, id);

            ret = wh_Client_AesGcmDma(client, aes, DECRYPT, in, inLen, iv,
                                      sizeof(iv), authData, sizeof(authData),
                                      authTag, NULL, sizeof(authTag), out);

            benchStopRet = wh_Bench_StopOp(ctx, id);

            /* Squash auth error since we are using dummy data */
            if (ret == AES_GCM_AUTH_E) {
                ret = 0;
            }
        }

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            goto exit;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_AesGcmDma %d\n", ret);
            goto exit;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            goto exit;
        }
    }

exit:
    wc_AesFree(aes);

    if (needEvict) {
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to evict key from cache: %d\n", evictRet);
            ret = evictRet;
        }
    }

#if defined(WOLFHSM_CFG_TEST_POSIX)
    if (ctx->transportType == WH_BENCH_TRANSPORT_POSIX_DMA) {
        /* if static memory was used with DMA then use XFREE */
        void* heap =
            posixTransportShm_GetDmaHeap(client->comm->transport_context);
        XFREE((uint8_t*)in, heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(out, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif /* WOLFHSM_CFG_TEST_POSIX */

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

static int _benchAesGcm(whClientContext* client, whBenchOpContext* ctx, int id,
                        const uint8_t* key, size_t keyLen, int encrypt)
{
    int     ret       = 0;
    int     needEvict = 0;
    whKeyId keyId     = WH_KEYID_ERASED;
    Aes     aes[1];
    char    keyLabel[]                  = "key label";
    byte    iv[WC_AES_BLOCK_SIZE]       = {0, 1, 2,  3,  4,  5,  6,  7,
                                           8, 9, 10, 11, 12, 13, 14, 15};
    byte    authData[WC_AES_BLOCK_SIZE] = {0, 1, 2,  3,  4,  5,  6,  7,
                                           8, 9, 10, 11, 12, 13, 14, 15};
    byte    authTag[WC_AES_BLOCK_SIZE]  = {0, 1, 2,  3,  4,  5,  6,  7,
                                           8, 9, 10, 11, 12, 13, 14, 15};
    /* Input size is largest multiple of AES block size that fits in buffer */
    const size_t inLen =
        (WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE / WC_AES_BLOCK_SIZE) *
        WC_AES_BLOCK_SIZE;
    int i;

#if defined(WOLFHSM_CFG_BENCH_INIT_DATA_BUFFERS)
    /* Initialize the input buffer with something non-zero */
    memset(WH_BENCH_DATA_IN_BUFFER, 0xAA, inLen);
    memset(WH_BENCH_DATA_OUT_BUFFER, 0xAA, inLen);
#endif

    /* initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_AesInit %d\n", ret);
        return ret;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, sizeof(keyLabel),
                             (uint8_t*)key, keyLen, &keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* set the iv */
    ret = wc_AesSetIV(aes, iv);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_AesSetIV %d\n", ret);
        goto exit;
    }

    ret = wh_Bench_SetDataSize(ctx, id, inLen);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Bench_SetDataSize %d\n", ret);
        goto exit;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        int benchStartRet;
        int benchStopRet;

        if (encrypt) {
            benchStartRet = wh_Bench_StartOp(ctx, id);

            ret = wc_AesGcmEncrypt(aes, WH_BENCH_DATA_OUT_BUFFER,
                                   WH_BENCH_DATA_IN_BUFFER, inLen, iv,
                                   sizeof(iv), authTag, sizeof(authTag),
                                   authData, sizeof(authData));

            benchStopRet = wh_Bench_StopOp(ctx, id);
        }
        else {
            benchStartRet = wh_Bench_StartOp(ctx, id);

            ret = wc_AesGcmDecrypt(aes, WH_BENCH_DATA_OUT_BUFFER,
                                   WH_BENCH_DATA_IN_BUFFER, inLen, iv,
                                   sizeof(iv), authTag, sizeof(authTag),
                                   authData, sizeof(authData));

            benchStopRet = wh_Bench_StopOp(ctx, id);

            /* Squash auth error since we are using dummy data */
            if (ret == AES_GCM_AUTH_E) {
                ret = 0;
            }
        }

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            goto exit;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_AesGcm%s %d\n",
                            encrypt ? "Encrypt" : "Decrypt", ret);
            goto exit;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            goto exit;
        }
    }

exit:
    wc_AesFree(aes);

    if (needEvict) {
        /* evict the key from the cache */
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    return ret;
}


int wh_Bench_Mod_Aes128GCMEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesGcm(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                        ENCRYPT);
}

int wh_Bench_Mod_Aes128GCMDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesGcm(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                        DECRYPT);
}

int wh_Bench_Mod_Aes256GCMEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesGcm(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                        ENCRYPT);
}

int wh_Bench_Mod_Aes256GCMDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)params;
    return _benchAesGcm(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                        DECRYPT);
}

int wh_Bench_Mod_Aes128GCMEncryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchAesGcmDma(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                           ENCRYPT);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_Aes128GCMDecryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchAesGcmDma(client, ctx, id, (uint8_t*)key128, sizeof(key128),
                           DECRYPT);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_Aes256GCMEncryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchAesGcmDma(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                           ENCRYPT);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_Aes256GCMDecryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchAesGcmDma(client, ctx, id, (uint8_t*)key256, sizeof(key256),
                           DECRYPT);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}
#endif /* HAVE_AESGCM */

#endif /* !defined(NO_AES) */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_BENCH_ENABLE */
