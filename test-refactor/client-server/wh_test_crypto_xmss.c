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
 * test-refactor/client-server/wh_test_crypto_xmss.c
 *
 * XMSS (stateful hash-based) tests routed through the server over DMA:
 *   _whTest_CryptoXmssCryptoCb - generate / durability / sign / verify, public
 *                                key export and import, and enforcement of the
 *                                no-private-export / no-private-import policy
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#if defined(WOLFSSL_HAVE_XMSS)
#include "wolfssl/wolfcrypt/wc_xmss.h"
#endif

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFHSM_CFG_DMA) && \
    defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)

/* "XMSS-SHA2_10_256" is the smallest standardized XMSS parameter set
 * (height 10, 1024 signatures). pubLen=68, sigLen=2500. */
#define WH_TEST_XMSS_PARAM_STR "XMSS-SHA2_10_256"
static byte whTest_XmssSigBuf[2500];

static int _whTest_CryptoXmssCryptoCb(whClientContext* ctx, int devId,
                                      WC_RNG* rng)
{
    int        ret           = 0;
    XmssKey    key[1];
    int        keyInited     = 0;
    word32     sigLen        = 0;
    word32     sigCap        = 0;
    const byte msg[]         = "wolfHSM XMSS cryptocb test";
    word32     msgSz         = (word32)sizeof(msg) - 1;

    (void)rng;

    memset(whTest_XmssSigBuf, 0, sizeof(whTest_XmssSigBuf));

    ret = wc_XmssKey_Init(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wc_XmssKey_Init devId=0x%X ret=%d\n", devId, ret);
        return ret;
    }
    keyInited = 1;

    if (ret == 0) {
        ret = wc_XmssKey_SetParamStr(key, WH_TEST_XMSS_PARAM_STR);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed XMSS SetParamStr=\"%s\" ret=%d\n",
                           WH_TEST_XMSS_PARAM_STR, ret);
        }
    }

    if (ret == 0) {
        ret = wc_XmssKey_GetSigLen(key, &sigCap);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed XMSS GetSigLen ret=%d\n", ret);
        }
        else if (sigCap > sizeof(whTest_XmssSigBuf)) {
            WH_ERROR_PRINT("XMSS sig buffer too small: need=%u have=%u\n",
                           (unsigned)sigCap,
                           (unsigned)sizeof(whTest_XmssSigBuf));
            ret = BUFFER_E;
        }
    }

    /* MakeKey via cryptocb: the server commits the key to NVM before
     * returning the public key over DMA. */
    if (ret == 0) {
        ret = wc_XmssKey_MakeKey(key, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed XMSS MakeKey ret=%d\n", ret);
        }
    }

    /* wc_XmssKey_SigsLeft returns a boolean: nonzero = signatures available,
     * 0 = exhausted. */
    if (ret == 0) {
        if (wc_XmssKey_SigsLeft(key) == 0) {
            WH_ERROR_PRINT("XMSS reported exhausted on fresh key\n");
            ret = -1;
        }
    }

    /* Durability: keygen must commit the key to NVM before returning the pub.
     * Evict the volatile cache copy (as a power loss before the first sign
     * would) and confirm the key is still resident in NVM. */
    if (ret == 0) {
        whKeyId durId = WH_KEYID_ERASED;
        if ((wh_Client_XmssGetKeyId(key, &durId) == 0) &&
            !WH_KEYID_ISERASED(durId)) {
            ret = wh_Client_KeyEvict(ctx, durId);
            if (ret != 0) {
                WH_ERROR_PRINT("XMSS durability evict failed: ret=%d\n", ret);
            }
            else {
                /* SigsLeft reloads the key from NVM; a negative return means
                 * keygen failed to commit it. A fresh key reports 1. */
                ret = wh_Client_XmssSigsLeftDma(ctx, key);
                if (ret < 0) {
                    WH_ERROR_PRINT("XMSS key not durable after keygen: "
                                   "ret=%d\n", ret);
                }
                else {
                    ret = 0;
                }
            }
        }
    }

    /* EPHEMERAL is invalid for a stateful private keygen and must be rejected
     * locally with WH_ERROR_BADARGS. */
    if (ret == 0) {
        int badRet = wh_Client_XmssMakeKeyDma(ctx, key, NULL,
                                              WH_NVM_FLAGS_EPHEMERAL, 0, NULL);
        if (badRet != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("XMSS ephemeral keygen not rejected: ret=%d "
                           "(expected WH_ERROR_BADARGS)\n", badRet);
            ret = WH_ERROR_ABORTED;
        }
    }

    if (ret == 0) {
        sigLen = sigCap;
        ret = wc_XmssKey_Sign(key, whTest_XmssSigBuf, &sigLen, msg, (int)msgSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed XMSS Sign ret=%d\n", ret);
        }
        else if (sigLen != sigCap) {
            WH_ERROR_PRINT("XMSS Sign produced unexpected length=%u expected=%u\n",
                           (unsigned)sigLen, (unsigned)sigCap);
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = wc_XmssKey_Verify(key, whTest_XmssSigBuf, sigLen, msg, (int)msgSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed XMSS Verify ret=%d\n", ret);
        }
    }

    if (ret == 0) {
        whTest_XmssSigBuf[0] ^= 0xFF;
        ret = wc_XmssKey_Verify(key, whTest_XmssSigBuf, sigLen, msg, (int)msgSz);
        whTest_XmssSigBuf[0] ^= 0xFF;
        if (ret == 0) {
            WH_ERROR_PRINT("XMSS Verify unexpectedly accepted tampered sig\n");
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    if (ret == 0) {
        const byte wrongMsg[] = "wolfHSM XMSS cryptocb wrong";
        ret = wc_XmssKey_Verify(key, whTest_XmssSigBuf, sigLen, wrongMsg,
                                (int)(sizeof(wrongMsg) - 1));
        if (ret == 0) {
            WH_ERROR_PRINT("XMSS Verify unexpectedly accepted wrong message\n");
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    /* H=10 means 1024 sigs total; after one sign, the key is still not
     * exhausted. */
    if (ret == 0) {
        if (wc_XmssKey_SigsLeft(key) == 0) {
            WH_ERROR_PRINT("XMSS reported exhausted after one sign\n");
            ret = -1;
        }
    }

    /* Verify the public key matches when read back */
    if (ret == 0) {
        whKeyId  pubId     = WH_KEYID_ERASED;
        word32   pubLen    = 0;
        uint8_t  pubBuf[128];
        uint16_t pubBufLen = (uint16_t)sizeof(pubBuf);
        if ((wh_Client_XmssGetKeyId(key, &pubId) == 0) &&
            !WH_KEYID_ISERASED(pubId) &&
            (wc_XmssKey_GetPubLen(key, &pubLen) == 0) &&
            (pubLen <= sizeof(pubBuf))) {
            int pubRet = wh_Client_KeyExportPublic(ctx, pubId, WH_KEY_ALGO_XMSS,
                                                   NULL, 0, pubBuf, &pubBufLen);
            if (pubRet != WH_ERROR_OK) {
                WH_ERROR_PRINT("XMSS export pub failed: ret=%d\n", pubRet);
                ret = pubRet;
            }
            else if (((word32)pubBufLen != pubLen) ||
                     (memcmp(pubBuf, key->pk, pubLen) != 0)) {
                WH_ERROR_PRINT("XMSS export pub mismatch len=%u expected=%u\n",
                               (unsigned)pubBufLen, (unsigned)pubLen);
                ret = WH_ERROR_ABORTED;
            }
        }
    }

    /* Public-key import: provision a verify-only copy of this key's public
     * half under a new keyId, verify the signature made above against it, and
     * confirm signing with it is refused (no private state). */
    if (ret == 0) {
        XmssKey pubKey[1];
        int     pubInited = 0;
        word32  pubLen    = 0;
        uint8_t pubRaw[128];
        whKeyId pubKeyId  = WH_KEYID_ERASED;
        int     vres      = 0;

        ret = wc_XmssKey_GetPubLen(key, &pubLen);
        if ((ret == 0) && (pubLen > sizeof(pubRaw))) {
            ret = BUFFER_E;
        }
        if (ret == 0) {
            ret = wc_XmssKey_ExportPubRaw(key, pubRaw, &pubLen);
        }
        if (ret == 0) {
            ret = wc_XmssKey_Init(pubKey, NULL, devId);
        }
        if (ret == 0) {
            pubInited = 1;
            ret = wc_XmssKey_SetParamStr(pubKey, WH_TEST_XMSS_PARAM_STR);
        }
        if (ret == 0) {
            ret = wc_XmssKey_ImportPubRaw(pubKey, pubRaw, pubLen);
        }
        /* EPHEMERAL keeps it cache-only for an easy cleanup; production would
         * pin with WH_NVM_FLAGS_NONMODIFIABLE and commit. */
        if (ret == 0) {
            ret = wh_Client_XmssImportPubKey(ctx, pubKey, &pubKeyId,
                                             WH_NVM_FLAGS_EPHEMERAL, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("XMSS import pub failed: ret=%d\n", ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_XmssVerifyDma(ctx, whTest_XmssSigBuf, sigLen, msg,
                                          msgSz, &vres, pubKey);
            if ((ret == 0) && (vres != 1)) {
                WH_ERROR_PRINT("XMSS verify with imported pub failed\n");
                ret = WH_ERROR_ABORTED;
            }
        }
        if (ret == 0) {
            word32 tmpSigLen = (word32)sizeof(whTest_XmssSigBuf);
            int    signRet =
                wh_Client_XmssSignDma(ctx, msg, msgSz, whTest_XmssSigBuf,
                                      &tmpSigLen, pubKey);
            if (signRet == 0) {
                WH_ERROR_PRINT("XMSS sign with verify-only key unexpectedly "
                               "succeeded\n");
                ret = WH_ERROR_ABORTED;
            }
        }
        if (!WH_KEYID_ISERASED(pubKeyId)) {
            (void)wh_Client_KeyEvict(ctx, pubKeyId);
        }
        if (pubInited) {
            wc_XmssKey_Free(pubKey);
        }
    }

    /* The generic export API must refuse to return the private key state.
     * Keygen forces WH_NVM_FLAGS_NONEXPORTABLE, so export of the resident
     * key is denied with WH_ERROR_ACCESS. */
    if (ret == 0) {
        whKeyId  exportId = WH_KEYID_ERASED;
        uint8_t  expBuf[256];
        uint16_t expLen   = (uint16_t)sizeof(expBuf);
        if ((wh_Client_XmssGetKeyId(key, &exportId) == 0) &&
            !WH_KEYID_ISERASED(exportId)) {
            int expRet =
                wh_Client_KeyExport(ctx, exportId, NULL, 0, expBuf, &expLen);
            if (expRet != WH_ERROR_ACCESS) {
                WH_ERROR_PRINT("XMSS export not blocked: ret=%d "
                               "(expected WH_ERROR_ACCESS)\n", expRet);
                ret = (expRet == 0) ? WH_ERROR_ABORTED : expRet;
            }
        }
    }

    /* Attempt to import an XMSS key which must be rejected */
    if (ret == 0) {
        uint8_t  fakeBlob[64];
        uint32_t xmssMagic = 0x584D5301u; /* 'XMS\1', see wh_crypto.c */
        whKeyId  impId     = WH_KEYID_ERASED;
        int      impRet;
        memset(fakeBlob, 0, sizeof(fakeBlob));
        memcpy(fakeBlob, &xmssMagic, sizeof(xmssMagic));
        fakeBlob[6] = 1; /* privLen field nonzero: a private-bearing blob */
        impRet = wh_Client_KeyCache(ctx, 0, NULL, 0, fakeBlob,
                                    (uint16_t)sizeof(fakeBlob), &impId);
        if (impRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("XMSS blob import not blocked: ret=%d "
                           "(expected WH_ERROR_ACCESS)\n", impRet);
            if ((impRet == 0) && !WH_KEYID_ISERASED(impId)) {
                (void)wh_Client_KeyEvict(ctx, impId);
            }
            ret = (impRet == 0) ? WH_ERROR_ABORTED : impRet;
        }
    }

    /* Also ensure direct NVM import is blocked */
    if (ret == 0) {
        uint8_t  fakeBlob[64];
        uint32_t xmssMagic = 0x584D5301u; /* 'XMS\1', see wh_crypto.c */
        int32_t  addRc    = 0;
        int      addRet;
        whNvmId  addId    = 0x1042; /* An arbitrary ID in the NVM range */
        memset(fakeBlob, 0, sizeof(fakeBlob));
        memcpy(fakeBlob, &xmssMagic, sizeof(xmssMagic));
        fakeBlob[6] = 1; /* privLen field nonzero: a private-bearing blob */
        addRet = wh_Client_NvmAddObject(ctx, addId, WH_NVM_ACCESS_ANY,
                                        WH_NVM_FLAGS_NONE, 0, NULL,
                                        (whNvmSize)sizeof(fakeBlob), fakeBlob,
                                        &addRc);
        if ((addRet != WH_ERROR_OK) || (addRc != WH_ERROR_ACCESS)) {
            WH_ERROR_PRINT("XMSS blob NVM import not blocked: ret=%d rc=%d "
                           "(expected rc WH_ERROR_ACCESS)\n", addRet,
                           (int)addRc);
            ret = (addRc != 0) ? addRc : WH_ERROR_ABORTED;
        }
    }

    if (keyInited) {
        whKeyId evictId = WH_KEYID_ERASED;
        if ((wh_Client_XmssGetKeyId(key, &evictId) == 0) &&
            !WH_KEYID_ISERASED(evictId)) {
            int evictRet = wh_Client_KeyEvict(ctx, evictId);
            if ((evictRet != 0) && (ret == 0)) {
                WH_ERROR_PRINT("Failed XMSS evict keyId=0x%X ret=%d\n",
                               (unsigned)evictId, evictRet);
                ret = evictRet;
            }
        }
        wc_XmssKey_Free(key);
    }

    if (ret == 0) {
        WH_TEST_PRINT("XMSS CryptoCb DEVID=0x%X SUCCESS\n", devId);
    }

    return ret;
}

int whTest_Crypto_Xmss(whClientContext* ctx)
{
    int    ret       = 0;
    int    rngInited = 0;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    rngInited = 1;

    /* XMSS dispatches through the DMA-only cryptocb. */
    (void)wh_Client_SetDmaMode(ctx, 1);
    ret = _whTest_CryptoXmssCryptoCb(ctx, WH_DEV_ID_DMA, rng);
    (void)wh_Client_SetDmaMode(ctx, 0);

    if (rngInited) {
        (void)wc_FreeRng(rng);
    }

    return ret;
}

#endif /* WOLFHSM_CFG_DMA && WOLFSSL_HAVE_XMSS && !WOLFSSL_XMSS_VERIFY_ONLY */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
