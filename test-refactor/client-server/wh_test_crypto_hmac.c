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
 * test-refactor/client-server/wh_test_crypto_hmac.c
 *
 * One-shot HMAC through wolfCrypt and through the wh_Client_HmacGenerate
 * client API, with and without DMA, checked against RFC 4231 vectors and
 * software HMAC. Also checks that streaming is left to wolfCrypt and that the
 * server checks the sizes in a request.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/hmac.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifndef NO_HMAC

static const int whTest_HmacTypes[] = {
#ifndef NO_SHA
    WC_SHA,
#endif
#ifdef WOLFSSL_SHA224
    WC_SHA224,
#endif
#ifndef NO_SHA256
    WC_SHA256,
#endif
#ifdef WOLFSSL_SHA384
    WC_SHA384,
#endif
#ifdef WOLFSSL_SHA512
    WC_SHA512,
#endif
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
    WC_SHA3_224,
#endif
#ifndef WOLFSSL_NOSHA3_256
    WC_SHA3_256,
#endif
#ifndef WOLFSSL_NOSHA3_384
    WC_SHA3_384,
#endif
#ifndef WOLFSSL_NOSHA3_512
    WC_SHA3_512,
#endif
#endif /* WOLFSSL_SHA3 */
};
#define WH_TEST_HMAC_TYPE_CNT \
    (sizeof(whTest_HmacTypes) / sizeof(whTest_HmacTypes[0]))

/* RFC 4231 test case 2 */
static const uint8_t whTest_HmacKey[] = "Jefe";
static const uint8_t whTest_HmacMsg[] = "what do ya want for nothing?";
#define WH_TEST_HMAC_KEY_SZ ((uint32_t)sizeof(whTest_HmacKey) - 1u)
#define WH_TEST_HMAC_MSG_SZ ((uint32_t)sizeof(whTest_HmacMsg) - 1u)
#ifndef NO_SHA256
static const uint8_t whTest_HmacTag256[WC_SHA256_DIGEST_SIZE] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
    0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
    0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};

/* RFC 4231 test case 6. The key is 131 bytes of 0xaa, which is larger than the
 * hash block. */
#define WH_TEST_HMAC_LONG_KEY_SZ 131
static const uint8_t whTest_HmacLongKeyMsg[] =
    "Test Using Larger Than Block-Size Key - Hash Key First";
static const uint8_t whTest_HmacLongKeyTag256[WC_SHA256_DIGEST_SIZE] = {
    0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26,
    0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28,
    0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54};
#endif /* !NO_SHA256 */

/* Large static input buffer, so only built for the POSIX test harness */
#ifdef WOLFHSM_CFG_TEST_POSIX
/* One byte more than a non-DMA request can hold */
static uint8_t
    whTest_HmacBigBuf[WH_MESSAGE_CRYPTO_HMAC_MAX_INLINE_GENERATE_SZ + 1u];
#endif

static void _whTest_HmacFillBuf(uint8_t* buf, uint32_t sz)
{
    uint32_t i;
    for (i = 0; i < sz; i++) {
        buf[i] = (uint8_t)((i * 7u + 3u) & 0xff);
    }
}

/* Software HMAC with no devId, used as the reference */
static int _whTest_HmacReference(int type, const uint8_t* key, uint32_t keyLen,
                                 const uint8_t* in, uint32_t inLen,
                                 uint8_t* out, word32* outSz)
{
    return wc_HmacGenerate(type, out, outSz, in, inLen, key, keyLen);
}

/* One-shot generate and verify through wolfCrypt on devId, checked against
 * software HMAC */
static int _whTest_HmacOneshotMatch(int devId, int type, const uint8_t* key,
                                    uint32_t keyLen, const uint8_t* in,
                                    uint32_t inLen)
{
    int     ret;
    Hmac    hmac[1];
    uint8_t tag[WC_MAX_DIGEST_SIZE];
    uint8_t ref[WC_MAX_DIGEST_SIZE];
    word32  tagSz = sizeof(tag);
    word32  refSz = sizeof(ref);

    ret = wc_HmacGenerate_ex(hmac, type, tag, &tagSz, in, inLen, key, keyLen,
                             NULL, devId);
    if (ret == 0) {
        ret = _whTest_HmacReference(type, key, keyLen, in, inLen, ref, &refSz);
    }
    if (ret == 0 && (tagSz != refSz || memcmp(tag, ref, refSz) != 0)) {
        WH_ERROR_PRINT("HMAC: generate mismatch type=%d\n", type);
        ret = -1;
    }
    if (ret == 0) {
        ret = wc_HmacVerify_ex(hmac, type, ref, refSz, in, inLen, key, keyLen,
                               NULL, devId);
    }
    if (ret == 0) {
        ref[0] ^= 0x01;
        if (wc_HmacVerify_ex(hmac, type, ref, refSz, in, inLen, key, keyLen,
                             NULL, devId) != MAC_CMP_FAILED_E) {
            WH_ERROR_PRINT("HMAC: bad tag accepted type=%d\n", type);
            ret = -1;
        }
    }
    return ret;
}

/* HMAC through wolfCrypt and the crypto callback. The HSM does only one-shot
 * HMAC, which is wc_HmacGenerate_ex() and wc_HmacVerify_ex(). wolfCrypt
 * computes a streaming HMAC on the client. */
static int _whTest_CryptoHmacWolfCrypt(whClientContext* ctx, int devId)
{
    int            ret = 0;
    Hmac           hmac[1];
    uint8_t        tag[WC_MAX_DIGEST_SIZE];
    whKeyId        keyId                     = WH_KEYID_ERASED;
    uint8_t        labelIn[WH_NVM_LABEL_LEN] = "HMAC Key Label";
    const uint8_t* key                       = whTest_HmacKey;
    const uint8_t* msg                       = whTest_HmacMsg;
    size_t         i;

    /* Only used with SHA-256 */
    (void)ctx;
    (void)hmac;
    (void)tag;
    (void)labelIn;

    /* One-shot generate and verify for each hash type, with a message and with
     * an empty message */
    for (i = 0; ret == 0 && i < WH_TEST_HMAC_TYPE_CNT; i++) {
        ret = _whTest_HmacOneshotMatch(devId, whTest_HmacTypes[i], key,
                                       WH_TEST_HMAC_KEY_SZ, msg,
                                       WH_TEST_HMAC_MSG_SZ);
        if (ret == 0) {
            ret = _whTest_HmacOneshotMatch(devId, whTest_HmacTypes[i], key,
                                           WH_TEST_HMAC_KEY_SZ, NULL, 0);
        }
        if (ret != 0) {
            WH_ERROR_PRINT("HMAC: one-shot failed type=%d ret=%d\n",
                           whTest_HmacTypes[i], ret);
        }
    }

#ifndef NO_SHA256
    /* Known answer. A one-shot MAC must use only one server request. */
    if (ret == 0) {
        word32   tagSz = sizeof(tag);
        uint16_t seq   = ctx->comm->seq;

        ret = wc_HmacGenerate_ex(hmac, WC_SHA256, tag, &tagSz, msg,
                                 WH_TEST_HMAC_MSG_SZ, key, WH_TEST_HMAC_KEY_SZ,
                                 NULL, devId);
        if (ret == 0 && (tagSz != sizeof(whTest_HmacTag256) ||
                         memcmp(tag, whTest_HmacTag256, tagSz) != 0)) {
            WH_ERROR_PRINT("HMAC: known answer mismatch\n");
            ret = -1;
        }
        if (ret == 0 && (uint16_t)(ctx->comm->seq - seq) != 1) {
            WH_ERROR_PRINT("HMAC: one-shot took %u requests (want 1)\n",
                           (unsigned)(uint16_t)(ctx->comm->seq - seq));
            ret = -1;
        }
    }

    /* A key larger than the hash block */
    if (ret == 0) {
        uint8_t longKey[WH_TEST_HMAC_LONG_KEY_SZ];
        word32  tagSz = sizeof(tag);

        memset(longKey, 0xaa, sizeof(longKey));
        ret = wc_HmacGenerate_ex(hmac, WC_SHA256, tag, &tagSz,
                                 whTest_HmacLongKeyMsg,
                                 sizeof(whTest_HmacLongKeyMsg) - 1, longKey,
                                 sizeof(longKey), NULL, devId);
        if (ret == 0 && memcmp(tag, whTest_HmacLongKeyTag256, tagSz) != 0) {
            WH_ERROR_PRINT("HMAC: long key mismatch\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                 sizeof(labelIn), (uint8_t*)key,
                                 WH_TEST_HMAC_KEY_SZ, &keyId);
    }

    /* A key stored in the HSM, with the one-shot functions. The key ID is
     * bound to the struct and no key bytes are given. Each MAC must use only
     * one server request. */
    if (ret == 0) {
        uint8_t  ref[WC_MAX_DIGEST_SIZE];
        word32   refSz = sizeof(ref);
        word32   tagSz = sizeof(tag);
        uint16_t seq   = 0;

        ret = wc_HmacInit(hmac, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_HmacSetKeyId(hmac, keyId);
        }
        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            seq = ctx->comm->seq;
            ret = wc_HmacGenerate_ex(hmac, WC_SHA256, tag, &tagSz, msg,
                                     WH_TEST_HMAC_MSG_SZ, NULL, 0, NULL, devId);
        }
        if (ret == 0 && (tagSz != sizeof(whTest_HmacTag256) ||
                         memcmp(tag, whTest_HmacTag256, tagSz) != 0)) {
            WH_ERROR_PRINT("HMAC: HSM key one-shot mismatch\n");
            ret = -1;
        }
        if (ret == 0 && (uint16_t)(ctx->comm->seq - seq) != 1) {
            WH_ERROR_PRINT("HMAC: HSM key one-shot took %u requests (want 1)\n",
                           (unsigned)(uint16_t)(ctx->comm->seq - seq));
            ret = -1;
        }
        if (ret == 0) {
            ret = wc_HmacVerify_ex(hmac, WC_SHA256, whTest_HmacTag256,
                                   sizeof(whTest_HmacTag256), msg,
                                   WH_TEST_HMAC_MSG_SZ, NULL, 0, NULL, devId);
        }
        if (ret == 0) {
            /* The MAC of the whole message does not match a shorter one */
            int rc = wc_HmacVerify_ex(hmac, WC_SHA256, whTest_HmacTag256,
                                      sizeof(whTest_HmacTag256), msg, 10, NULL,
                                      0, NULL, devId);
            if (rc != MAC_CMP_FAILED_E) {
                WH_ERROR_PRINT("HMAC: HSM key verify returned %d\n", rc);
                ret = -1;
            }
        }
        /* An empty message */
        if (ret == 0) {
            ret = _whTest_HmacReference(WC_SHA256, key, WH_TEST_HMAC_KEY_SZ,
                                        NULL, 0, ref, &refSz);
        }
        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            tagSz = sizeof(tag);
            seq   = ctx->comm->seq;
            ret   = wc_HmacGenerate_ex(hmac, WC_SHA256, tag, &tagSz, NULL, 0,
                                       NULL, 0, NULL, devId);
        }
        if (ret == 0 && (tagSz != refSz || memcmp(tag, ref, refSz) != 0)) {
            WH_ERROR_PRINT("HMAC: HSM key one-shot empty message mismatch\n");
            ret = -1;
        }
        if (ret == 0 && (uint16_t)(ctx->comm->seq - seq) != 1) {
            WH_ERROR_PRINT("HMAC: HSM key one-shot took %u requests (want 1)\n",
                           (unsigned)(uint16_t)(ctx->comm->seq - seq));
            ret = -1;
        }
        wc_HmacFree(hmac);
    }

    /* Streaming is not sent to the HSM. With a key stored in the HSM there are
     * no key bytes on the client, so the update and the final must fail. */
    if (ret == 0) {
        whKeyId gotId = WH_KEYID_ERASED;

        ret = wc_HmacInit(hmac, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_HmacSetKeyId(hmac, keyId);
        }
        if (ret == 0) {
            ret = wh_Client_HmacGetKeyId(hmac, &gotId);
        }
        if (ret == 0 && gotId != keyId) {
            WH_ERROR_PRINT("HMAC: key ID not read back\n");
            ret = -1;
        }
        if (ret == 0) {
            ret = wc_HmacSetKey(hmac, WC_SHA256, NULL, 0);
        }
        if (ret == 0) {
            int rc = wc_HmacUpdate(hmac, msg, WH_TEST_HMAC_MSG_SZ);
            if (rc != MISSING_KEY) {
                WH_ERROR_PRINT("HMAC: HSM key update returned %d\n", rc);
                ret = -1;
            }
        }
        if (ret == 0) {
            int rc = wc_HmacFinal(hmac, tag);
            if (rc != MISSING_KEY) {
                WH_ERROR_PRINT("HMAC: HSM key final returned %d\n", rc);
                ret = -1;
            }
        }
        /* The key ID is kept when the struct is keyed again */
        if (ret == 0) {
            ret = wc_HmacSetKey(hmac, WC_SHA256, NULL, 0);
        }
        if (ret == 0) {
            gotId = WH_KEYID_ERASED;
            ret   = wh_Client_HmacGetKeyId(hmac, &gotId);
            if (ret == 0 && gotId != keyId) {
                WH_ERROR_PRINT("HMAC: key ID lost on re-key\n");
                ret = -1;
            }
        }
        wc_HmacFree(hmac);
    }

    /* wc_HmacInit_Id() also binds a key ID */
    if (ret == 0) {
        word32 tagSz = sizeof(tag);

        ret = wc_HmacInit_Id(hmac, (unsigned char*)&keyId, (int)sizeof(keyId),
                             NULL, devId);
        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            ret = wc_HmacGenerate_ex(hmac, WC_SHA256, tag, &tagSz, msg,
                                     WH_TEST_HMAC_MSG_SZ, NULL, 0, NULL, devId);
        }
        if (ret == 0 &&
            memcmp(tag, whTest_HmacTag256, sizeof(whTest_HmacTag256)) != 0) {
            WH_ERROR_PRINT("HMAC: wc_HmacInit_Id key mismatch\n");
            ret = -1;
        }
        wc_HmacFree(hmac);
    }

    /* Key bytes given to a one-shot are used. The struct is only storage then,
     * so a key ID in it is not read. */
    if (ret == 0) {
        const uint8_t otherKey[] = "not the HSM key";
        uint8_t       ref[WC_MAX_DIGEST_SIZE];
        word32        refSz = sizeof(ref);
        word32        tagSz = sizeof(tag);

        ret = _whTest_HmacReference(WC_SHA256, otherKey,
                                    (uint32_t)sizeof(otherKey) - 1, msg,
                                    WH_TEST_HMAC_MSG_SZ, ref, &refSz);
        if (ret == 0) {
            ret = wc_HmacInit(hmac, NULL, devId);
        }
        if (ret == 0) {
            ret = wh_Client_HmacSetKeyId(hmac, keyId);
        }
        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            ret = wc_HmacGenerate_ex(hmac, WC_SHA256, tag, &tagSz, msg,
                                     WH_TEST_HMAC_MSG_SZ, otherKey,
                                     (word32)sizeof(otherKey) - 1, NULL, devId);
        }
        if (ret == 0 && (tagSz != refSz || memcmp(tag, ref, refSz) != 0)) {
            WH_ERROR_PRINT("HMAC: key bytes not used over a key ID\n");
            ret = -1;
        }
        wc_HmacFree(hmac);
    }

    /* A key ID that is not in the HSM must fail and must not fall back to
     * software */
    if (ret == 0) {
        ret = wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        ret = wc_HmacInit(hmac, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_HmacSetKeyId(hmac, keyId);
        }
        if (ret == 0) {
            word32 tagSz = sizeof(tag);
            int    rc =
                wc_HmacGenerate_ex(hmac, WC_SHA256, tag, &tagSz, msg,
                                   WH_TEST_HMAC_MSG_SZ, NULL, 0, NULL, devId);
            if (rc != WH_ERROR_NOTFOUND) {
                WH_ERROR_PRINT("HMAC: missing key one-shot returned %d\n", rc);
                ret = -1;
            }
        }
        wc_HmacFree(hmac);
    }
    keyId = WH_KEYID_ERASED;

    /* With key bytes wolfCrypt computes a streaming MAC on the client. The
     * struct then makes a second MAC with the same key. */
    if (ret == 0) {
        uint8_t ref[WC_MAX_DIGEST_SIZE];
        word32  refSz = sizeof(ref);

        ret = wc_HmacInit(hmac, NULL, devId);
        if (ret == 0) {
            ret = wc_HmacSetKey(hmac, WC_SHA256, key, WH_TEST_HMAC_KEY_SZ);
        }
        if (ret == 0) {
            ret = wc_HmacUpdate(hmac, msg, 10);
        }
        if (ret == 0) {
            ret = wc_HmacUpdate(hmac, msg + 10, WH_TEST_HMAC_MSG_SZ - 10);
        }
        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            ret = wc_HmacFinal(hmac, tag);
        }
        if (ret == 0 &&
            memcmp(tag, whTest_HmacTag256, sizeof(whTest_HmacTag256)) != 0) {
            WH_ERROR_PRINT("HMAC: streaming mismatch\n");
            ret = -1;
        }
        /* The second MAC is over the first 10 bytes of the message */
        if (ret == 0) {
            ret = wc_HmacUpdate(hmac, msg, 10);
        }
        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            ret = wc_HmacFinal(hmac, tag);
        }
        if (ret == 0) {
            ret = _whTest_HmacReference(WC_SHA256, key, WH_TEST_HMAC_KEY_SZ,
                                        msg, 10, ref, &refSz);
        }
        if (ret == 0 && memcmp(tag, ref, refSz) != 0) {
            WH_ERROR_PRINT("HMAC: streaming reuse mismatch\n");
            ret = -1;
        }
        wc_HmacFree(hmac);
    }

    /* A copy made after the update must give the same MAC */
    if (ret == 0) {
        Hmac    copy[1];
        uint8_t copyTag[WC_MAX_DIGEST_SIZE] = {0};

        ret = wc_HmacInit(hmac, NULL, devId);
        if (ret == 0) {
            ret = wc_HmacSetKey(hmac, WC_SHA256, key, WH_TEST_HMAC_KEY_SZ);
        }
        if (ret == 0) {
            ret = wc_HmacUpdate(hmac, msg, WH_TEST_HMAC_MSG_SZ);
        }
        if (ret == 0) {
            ret = wc_HmacCopy(hmac, copy);
            if (ret == 0) {
                ret = wc_HmacFinal(copy, copyTag);
                wc_HmacFree(copy);
            }
        }
        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            ret = wc_HmacFinal(hmac, tag);
        }
        if (ret == 0 &&
            (memcmp(tag, whTest_HmacTag256, sizeof(whTest_HmacTag256)) != 0 ||
             memcmp(copyTag, whTest_HmacTag256, sizeof(whTest_HmacTag256)) !=
                 0)) {
            WH_ERROR_PRINT("HMAC: copy mismatch\n");
            ret = -1;
        }
        wc_HmacFree(hmac);
    }

    /* A free after an update with no final must leave no request pending */
    if (ret == 0) {
        ret = wc_HmacInit(hmac, NULL, devId);
        if (ret == 0) {
            ret = wc_HmacSetKey(hmac, WC_SHA256, key, WH_TEST_HMAC_KEY_SZ);
        }
        if (ret == 0) {
            ret = wc_HmacUpdate(hmac, msg, WH_TEST_HMAC_MSG_SZ);
        }
        wc_HmacFree(hmac);
        if (ret == 0 && wh_Client_IsRequestPending(ctx) != 0) {
            WH_ERROR_PRINT("HMAC: request left pending\n");
            ret = -1;
        }
        if (ret == 0) {
            ret = _whTest_HmacOneshotMatch(devId, WC_SHA256, key,
                                           WH_TEST_HMAC_KEY_SZ, msg,
                                           WH_TEST_HMAC_MSG_SZ);
        }
    }

    /* A NULL key with no key ID bound to the struct. There is no key to use,
     * so the call must fail as it does in wolfCrypt and send no request. */
    if (ret == 0) {
        word32   tagSz = sizeof(tag);
        uint16_t seq   = ctx->comm->seq;

        ret = wc_HmacInit(hmac, NULL, devId);
        if (ret == 0) {
            int rc =
                wc_HmacGenerate_ex(hmac, WC_SHA256, tag, &tagSz, msg,
                                   WH_TEST_HMAC_MSG_SZ, NULL, 0, NULL, devId);
            if (rc != MISSING_KEY) {
                WH_ERROR_PRINT("HMAC: no key generate returned %d\n", rc);
                ret = -1;
            }
        }
        if (ret == 0) {
            int rc = wc_HmacVerify_ex(
                hmac, WC_SHA256, whTest_HmacTag256, sizeof(whTest_HmacTag256),
                msg, WH_TEST_HMAC_MSG_SZ, NULL, 0, NULL, devId);
            if (rc != MISSING_KEY) {
                WH_ERROR_PRINT("HMAC: no key verify returned %d\n", rc);
                ret = -1;
            }
        }
        if (ret == 0 && ctx->comm->seq != seq) {
            WH_ERROR_PRINT("HMAC: no key sent a request\n");
            ret = -1;
        }
        wc_HmacFree(hmac);
    }

    /* An empty key is a key pointer with a size of 0. The HSM does not take
     * it, so wolfCrypt computes the MAC on the client. */
    if (ret == 0) {
        ret = _whTest_HmacOneshotMatch(devId, WC_SHA256, key, 0, msg,
                                       WH_TEST_HMAC_MSG_SZ);
        if (ret != 0) {
            WH_ERROR_PRINT("HMAC: empty key failed ret=%d\n", ret);
        }
    }

#ifdef WOLFHSM_CFG_TEST_POSIX
    /* A message too large for one request works with DMA, which passes it by
     * address. It fails without DMA. */
    if (ret == 0) {
        int dmaMode = 0;

        _whTest_HmacFillBuf(whTest_HmacBigBuf, sizeof(whTest_HmacBigBuf));
        ret = wh_Client_GetDmaMode(ctx, &dmaMode);
        if (ret == 0 && dmaMode != 0) {
            ret = _whTest_HmacOneshotMatch(
                devId, WC_SHA256, key, WH_TEST_HMAC_KEY_SZ, whTest_HmacBigBuf,
                sizeof(whTest_HmacBigBuf));
        }
        else if (ret == 0) {
            word32 tagSz = sizeof(tag);
            int    rc =
                wc_HmacGenerate_ex(hmac, WC_SHA256, tag, &tagSz,
                                   whTest_HmacBigBuf, sizeof(whTest_HmacBigBuf),
                                   key, WH_TEST_HMAC_KEY_SZ, NULL, devId);
            if (rc != BAD_FUNC_ARG) {
                WH_ERROR_PRINT("HMAC: oversize message returned %d\n", rc);
                ret = -1;
            }
        }
    }
#endif /* WOLFHSM_CFG_TEST_POSIX */
#endif /* !NO_SHA256 */

    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        WH_TEST_PRINT("HMAC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifndef NO_SHA256
/* Send the request that is in the client comm buffer and get the server return
 * code */
static int _whTest_HmacSendRaw(whClientContext* ctx, uint16_t group,
                               uint16_t reqSz, int* outRc)
{
    int      ret;
    uint8_t* data      = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    uint16_t respGroup = 0;
    uint16_t action    = 0;
    uint16_t size      = 0;

    ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_HMAC, reqSz, data);
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &respGroup, &action, &size,
                                         WOLFHSM_CFG_COMM_DATA_LEN, data);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        if (size < sizeof(whMessageCrypto_GenericResponseHeader)) {
            ret = WH_ERROR_ABORTED;
        }
        else {
            *outRc = ((whMessageCrypto_GenericResponseHeader*)data)->rc;
        }
    }
    return ret;
}

/* Put a correct HMAC request in the client comm buffer and return its size */
static uint16_t _whTest_HmacBuildRaw(whClientContext* ctx)
{
    uint8_t* data = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    whMessageCrypto_GenericRequestHeader* hdr =
        (whMessageCrypto_GenericRequestHeader*)data;
    whMessageCrypto_HmacRequest* req = (whMessageCrypto_HmacRequest*)(hdr + 1);
    uint8_t*                     payload = (uint8_t*)(req + 1);

    memset(data, 0, sizeof(*hdr) + sizeof(*req));
    hdr->algoType = WC_ALGO_TYPE_HMAC;
    hdr->affinity = ctx->cryptoAffinity;
    req->hashType = WC_SHA256;
    req->inSz     = WH_TEST_HMAC_MSG_SZ;
    req->keySz    = WH_TEST_HMAC_KEY_SZ;
    memcpy(payload, whTest_HmacMsg, WH_TEST_HMAC_MSG_SZ);
    memcpy(payload + WH_TEST_HMAC_MSG_SZ, whTest_HmacKey, WH_TEST_HMAC_KEY_SZ);

    return (uint16_t)(sizeof(*hdr) + sizeof(*req) + WH_TEST_HMAC_MSG_SZ +
                      WH_TEST_HMAC_KEY_SZ);
}

/* The server must refuse a request whose sizes do not agree with the bytes
 * sent */
static int _whTest_CryptoHmacBadRequest(whClientContext* ctx)
{
    int      ret;
    int      rc   = 0;
    uint8_t* data = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    whMessageCrypto_HmacRequest* req =
        (whMessageCrypto_HmacRequest*)(data +
                                       sizeof(
                                           whMessageCrypto_GenericRequestHeader));
    uint16_t reqSz;

    /* A correct request must pass, so the requests below fail only because of
     * their sizes */
    reqSz = _whTest_HmacBuildRaw(ctx);
    ret   = _whTest_HmacSendRaw(ctx, WH_MESSAGE_GROUP_CRYPTO, reqSz, &rc);
    if (ret == 0 && rc != 0) {
        WH_ERROR_PRINT("HMAC request: well-formed request returned %d\n", rc);
        ret = -1;
    }

    /* The last key byte is not sent */
    if (ret == 0) {
        reqSz = _whTest_HmacBuildRaw(ctx);
        ret   = _whTest_HmacSendRaw(ctx, WH_MESSAGE_GROUP_CRYPTO,
                                    (uint16_t)(reqSz - 1), &rc);
        if (ret == 0 && rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC request: short key returned %d\n", rc);
            ret = -1;
        }
    }

    /* The message size is larger than all the bytes sent */
    if (ret == 0) {
        reqSz     = _whTest_HmacBuildRaw(ctx);
        req->inSz = WH_TEST_HMAC_MSG_SZ + WH_TEST_HMAC_KEY_SZ + 1u;
        ret = _whTest_HmacSendRaw(ctx, WH_MESSAGE_GROUP_CRYPTO, reqSz, &rc);
        if (ret == 0 && rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC request: oversize message returned %d\n", rc);
            ret = -1;
        }
    }

    /* The request ends inside the request struct */
    if (ret == 0) {
        (void)_whTest_HmacBuildRaw(ctx);
        reqSz = (uint16_t)(sizeof(whMessageCrypto_GenericRequestHeader) +
                           sizeof(whMessageCrypto_HmacRequest) - 1u);
        ret   = _whTest_HmacSendRaw(ctx, WH_MESSAGE_GROUP_CRYPTO, reqSz, &rc);
        if (ret == 0 && rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC request: short header returned %d\n", rc);
            ret = -1;
        }
    }

#ifdef WOLFHSM_CFG_DMA
    /* The server must refuse both DMA requests before it uses the message
     * address, so no address is set */
    if (ret == 0) {
        whMessageCrypto_GenericRequestHeader* hdr =
            (whMessageCrypto_GenericRequestHeader*)data;
        whMessageCrypto_HmacDmaRequest* dmaReq =
            (whMessageCrypto_HmacDmaRequest*)(hdr + 1);

        reqSz =
            (uint16_t)(sizeof(*hdr) + sizeof(*dmaReq) + WH_TEST_HMAC_KEY_SZ);

        /* The key size is larger than the key bytes sent */
        memset(data, 0, sizeof(*hdr) + sizeof(*dmaReq));
        hdr->algoType    = WC_ALGO_TYPE_HMAC;
        hdr->affinity    = ctx->cryptoAffinity;
        dmaReq->hashType = WC_SHA256;
        dmaReq->keySz    = WH_TEST_HMAC_KEY_SZ + 1u;
        memcpy(dmaReq + 1, whTest_HmacKey, WH_TEST_HMAC_KEY_SZ);
        ret = _whTest_HmacSendRaw(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, reqSz, &rc);
        if (ret == 0 && rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC DMA request: short key returned %d\n", rc);
            ret = -1;
        }

        /* The message size does not fit in 32 bits */
        if (ret == 0) {
            memset(data, 0, sizeof(*hdr) + sizeof(*dmaReq));
            hdr->algoType    = WC_ALGO_TYPE_HMAC;
            hdr->affinity    = ctx->cryptoAffinity;
            dmaReq->hashType = WC_SHA256;
            dmaReq->keySz    = WH_TEST_HMAC_KEY_SZ;
            dmaReq->input.sz = ((uint64_t)1 << 32);
            memcpy(dmaReq + 1, whTest_HmacKey, WH_TEST_HMAC_KEY_SZ);
            ret = _whTest_HmacSendRaw(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, reqSz,
                                      &rc);
            if (ret == 0 && rc != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT(
                    "HMAC DMA request: 64-bit message size returned %d\n", rc);
                ret = -1;
            }
        }
    }
#endif /* WOLFHSM_CFG_DMA */

    if (ret == 0) {
        WH_TEST_PRINT("HMAC request size checks SUCCESS\n");
    }
    return ret;
}
#endif /* !NO_SHA256 */

/* The HMAC client API without DMA, blocking and async */
static int _whTest_CryptoHmacClient(whClientContext* ctx)
{
    int            ret = 0;
    uint8_t        tag[WC_MAX_DIGEST_SIZE];
    uint8_t        ref[WC_MAX_DIGEST_SIZE];
    uint32_t       tagSz;
    word32         refSz;
    whKeyId        keyId                     = WH_KEYID_ERASED;
    uint8_t        labelIn[WH_NVM_LABEL_LEN] = "HMAC Client Label";
    const uint8_t* key                       = whTest_HmacKey;
    const uint8_t* msg                       = whTest_HmacMsg;
    size_t         i;

    /* Only used with SHA-256 */
    (void)labelIn;

    /* Blocking generate with key bytes for each hash type */
    for (i = 0; ret == 0 && i < WH_TEST_HMAC_TYPE_CNT; i++) {
        int type = whTest_HmacTypes[i];

        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret   = wh_Client_HmacGenerate(ctx, type, WH_KEYID_ERASED, key,
                                       WH_TEST_HMAC_KEY_SZ, msg,
                                       WH_TEST_HMAC_MSG_SZ, tag, &tagSz);
        if (ret == 0) {
            refSz = sizeof(ref);
            ret   = _whTest_HmacReference(type, key, WH_TEST_HMAC_KEY_SZ, msg,
                                          WH_TEST_HMAC_MSG_SZ, ref, &refSz);
        }
        /* The MAC length returned is the digest size */
        if (ret == 0 && (tagSz != refSz || memcmp(tag, ref, refSz) != 0)) {
            WH_ERROR_PRINT("HMAC client: mismatch type=%d\n", type);
            ret = -1;
        }
        if (ret != 0) {
            WH_ERROR_PRINT("HMAC client: generate failed type=%d ret=%d\n",
                           type, ret);
        }
    }

#ifndef NO_SHA256
    /* Async request and response with a key stored in the HSM */
    if (ret == 0) {
        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                 sizeof(labelIn), (uint8_t*)key,
                                 WH_TEST_HMAC_KEY_SZ, &keyId);
    }
    if (ret == 0) {
        ret = wh_Client_HmacGenerateRequest(ctx, WC_SHA256, keyId, NULL, 0, msg,
                                            WH_TEST_HMAC_MSG_SZ);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_HmacGenerateResponse(ctx, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && (tagSz != sizeof(whTest_HmacTag256) ||
                     memcmp(tag, whTest_HmacTag256, tagSz) != 0)) {
        WH_ERROR_PRINT("HMAC client: async HSM key mismatch\n");
        ret = -1;
    }

    /* An empty message, with key bytes and with the stored key */
    if (ret == 0) {
        refSz = sizeof(ref);
        ret   = _whTest_HmacReference(WC_SHA256, key, WH_TEST_HMAC_KEY_SZ, NULL,
                                      0, ref, &refSz);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret   = wh_Client_HmacGenerate(ctx, WC_SHA256, WH_KEYID_ERASED, key,
                                       WH_TEST_HMAC_KEY_SZ, NULL, 0, tag, &tagSz);
        if (ret == 0 && memcmp(tag, ref, refSz) != 0) {
            WH_ERROR_PRINT("HMAC client: empty message mismatch\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret   = wh_Client_HmacGenerate(ctx, WC_SHA256, keyId, NULL, 0, NULL, 0,
                                       tag, &tagSz);
        if (ret == 0 && memcmp(tag, ref, refSz) != 0) {
            WH_ERROR_PRINT("HMAC client: empty message HSM key mismatch\n");
            ret = -1;
        }
    }

    /* A buffer that is too small gets the necessary size, and no request stays
     * pending */
    if (ret == 0) {
        int rc;

        tagSz = WC_SHA256_DIGEST_SIZE - 1;
        rc    = wh_Client_HmacGenerate(ctx, WC_SHA256, keyId, NULL, 0, msg,
                                       WH_TEST_HMAC_MSG_SZ, tag, &tagSz);
        if (rc != WH_ERROR_BUFFER_SIZE || tagSz != WC_SHA256_DIGEST_SIZE) {
            WH_ERROR_PRINT("HMAC client: small buffer returned %d size %u\n",
                           rc, (unsigned)tagSz);
            ret = -1;
        }
        else if (wh_Client_IsRequestPending(ctx) != 0) {
            WH_ERROR_PRINT("HMAC client: request left pending\n");
            ret = -1;
        }
    }

#ifdef WOLFHSM_CFG_TEST_POSIX
    /* The largest request. One more byte of message or key must not fit. */
    if (ret == 0) {
        const uint32_t maxSz = WH_MESSAGE_CRYPTO_HMAC_MAX_INLINE_GENERATE_SZ;
        uint8_t*       buf   = whTest_HmacBigBuf;

        _whTest_HmacFillBuf(buf, sizeof(whTest_HmacBigBuf));

        /* With a stored key, the message can fill the request */
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret = wh_Client_HmacGenerate(ctx, WC_SHA256, keyId, NULL, 0, buf, maxSz,
                                     tag, &tagSz);
        if (ret == 0) {
            refSz = sizeof(ref);
            ret   = _whTest_HmacReference(WC_SHA256, key, WH_TEST_HMAC_KEY_SZ,
                                          buf, maxSz, ref, &refSz);
        }
        if (ret == 0 && memcmp(tag, ref, refSz) != 0) {
            WH_ERROR_PRINT("HMAC client: max message mismatch\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_HmacGenerateRequest(
                            ctx, WC_SHA256, keyId, NULL, 0, buf, maxSz + 1u) !=
                            WH_ERROR_REQUEST_SIZE) {
            WH_ERROR_PRINT("HMAC client: oversize message not rejected\n");
            ret = -1;
        }

        /* Key bytes use part of the request, so the message must be shorter */
        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            tagSz = sizeof(tag);
            ret   = wh_Client_HmacGenerate(
                ctx, WC_SHA256, WH_KEYID_ERASED, key, WH_TEST_HMAC_KEY_SZ, buf,
                maxSz - WH_TEST_HMAC_KEY_SZ, tag, &tagSz);
        }
        if (ret == 0) {
            refSz = sizeof(ref);
            ret =
                _whTest_HmacReference(WC_SHA256, key, WH_TEST_HMAC_KEY_SZ, buf,
                                      maxSz - WH_TEST_HMAC_KEY_SZ, ref, &refSz);
        }
        if (ret == 0 && memcmp(tag, ref, refSz) != 0) {
            WH_ERROR_PRINT("HMAC client: max message with key mismatch\n");
            ret = -1;
        }
        if (ret == 0 &&
            wh_Client_HmacGenerateRequest(
                ctx, WC_SHA256, WH_KEYID_ERASED, key, WH_TEST_HMAC_KEY_SZ, buf,
                maxSz - WH_TEST_HMAC_KEY_SZ + 1u) != WH_ERROR_REQUEST_SIZE) {
            WH_ERROR_PRINT("HMAC client: oversize message with key not "
                           "rejected\n");
            ret = -1;
        }
    }
#endif /* WOLFHSM_CFG_TEST_POSIX */

    /* A stored key that was evicted */
    if (ret == 0) {
        ret = wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        int rc;

        tagSz = sizeof(tag);
        rc    = wh_Client_HmacGenerate(ctx, WC_SHA256, keyId, NULL, 0, msg,
                                       WH_TEST_HMAC_MSG_SZ, tag, &tagSz);
        if (rc != WH_ERROR_NOTFOUND) {
            WH_ERROR_PRINT("HMAC client: missing key returned %d\n", rc);
            ret = -1;
        }
    }
    keyId = WH_KEYID_ERASED;

    /* The largest key that the server reads by ID works, and a larger one is
     * refused. The same key given as bytes has no such limit. */
    if (ret == 0) {
        uint8_t bigKey[WOLFHSM_CFG_SERVER_HMAC_MAX_KEY_SIZE + 1];
        int     rc;

        _whTest_HmacFillBuf(bigKey, sizeof(bigKey));

        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                 sizeof(labelIn), bigKey, sizeof(bigKey) - 1,
                                 &keyId);
        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            tagSz = sizeof(tag);
            ret   = wh_Client_HmacGenerate(ctx, WC_SHA256, keyId, NULL, 0, msg,
                                           WH_TEST_HMAC_MSG_SZ, tag, &tagSz);
        }
        if (ret == 0) {
            refSz = sizeof(ref);
            ret   = _whTest_HmacReference(WC_SHA256, bigKey, sizeof(bigKey) - 1,
                                          msg, WH_TEST_HMAC_MSG_SZ, ref, &refSz);
        }
        if (ret == 0 && memcmp(tag, ref, refSz) != 0) {
            WH_ERROR_PRINT("HMAC client: max stored key mismatch\n");
            ret = -1;
        }
        if (keyId != WH_KEYID_ERASED) {
            (void)wh_Client_KeyEvict(ctx, keyId);
            keyId = WH_KEYID_ERASED;
        }

        if (ret == 0) {
            ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                     sizeof(labelIn), bigKey, sizeof(bigKey),
                                     &keyId);
        }
        if (ret == 0) {
            tagSz = sizeof(tag);
            rc    = wh_Client_HmacGenerate(ctx, WC_SHA256, keyId, NULL, 0, msg,
                                           WH_TEST_HMAC_MSG_SZ, tag, &tagSz);
            if (rc != WH_ERROR_NOSPACE) {
                WH_ERROR_PRINT("HMAC client: oversize stored key returned "
                               "%d\n",
                               rc);
                ret = -1;
            }
        }
        if (keyId != WH_KEYID_ERASED) {
            (void)wh_Client_KeyEvict(ctx, keyId);
            keyId = WH_KEYID_ERASED;
        }

        if (ret == 0) {
            memset(tag, 0, sizeof(tag));
            tagSz = sizeof(tag);
            ret   = wh_Client_HmacGenerate(ctx, WC_SHA256, WH_KEYID_ERASED,
                                           bigKey, sizeof(bigKey), msg,
                                           WH_TEST_HMAC_MSG_SZ, tag, &tagSz);
        }
        if (ret == 0) {
            refSz = sizeof(ref);
            ret = _whTest_HmacReference(WC_SHA256, bigKey, sizeof(bigKey), msg,
                                        WH_TEST_HMAC_MSG_SZ, ref, &refSz);
        }
        if (ret == 0 && memcmp(tag, ref, refSz) != 0) {
            WH_ERROR_PRINT("HMAC client: large key bytes mismatch\n");
            ret = -1;
        }
    }

    /* Bad arguments. No request must be sent for them. */
    if (ret == 0) {
        const whKeyId someId = 1;
        uint16_t      seq    = ctx->comm->seq;

        tagSz = sizeof(tag);
        if (wh_Client_HmacGenerate(
                NULL, WC_SHA256, WH_KEYID_ERASED, key, WH_TEST_HMAC_KEY_SZ, msg,
                WH_TEST_HMAC_MSG_SZ, tag, &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC client: NULL ctx not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_HmacGenerate(ctx, WC_SHA256, WH_KEYID_ERASED,
                                               key, WH_TEST_HMAC_KEY_SZ, NULL,
                                               WH_TEST_HMAC_MSG_SZ, tag,
                                               &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC client: NULL message not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_HmacGenerate(ctx, WC_SHA256, WH_KEYID_ERASED,
                                               NULL, WH_TEST_HMAC_KEY_SZ, msg,
                                               WH_TEST_HMAC_MSG_SZ, tag,
                                               &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC client: NULL key not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 &&
            wh_Client_HmacGenerate(ctx, WC_SHA256, WH_KEYID_ERASED, NULL, 0,
                                   msg, WH_TEST_HMAC_MSG_SZ, tag,
                                   &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC client: no key not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_HmacGenerate(ctx, WC_SHA256, someId, key,
                                               WH_TEST_HMAC_KEY_SZ, msg,
                                               WH_TEST_HMAC_MSG_SZ, tag,
                                               &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC client: key and key ID not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_HmacGenerate(ctx, WC_SHA256, WH_KEYID_ERASED,
                                               key, WH_TEST_HMAC_KEY_SZ, msg,
                                               WH_TEST_HMAC_MSG_SZ, NULL,
                                               &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC client: NULL output not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_HmacGenerate(ctx, WC_SHA256, WH_KEYID_ERASED,
                                               key, WH_TEST_HMAC_KEY_SZ, msg,
                                               WH_TEST_HMAC_MSG_SZ, tag,
                                               NULL) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC client: NULL output size not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_HmacGenerateResponse(ctx, NULL, &tagSz) !=
                            WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC client: NULL response output not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 && ctx->comm->seq != seq) {
            WH_ERROR_PRINT("HMAC client: bad arguments sent a request\n");
            ret = -1;
        }
    }
#endif /* !NO_SHA256 */

    /* A hash type that the server does not know */
    if (ret == 0) {
        int rc;

        tagSz = sizeof(tag);
        rc    = wh_Client_HmacGenerate(ctx, WC_HASH_TYPE_NONE, WH_KEYID_ERASED,
                                       key, WH_TEST_HMAC_KEY_SZ, msg,
                                       WH_TEST_HMAC_MSG_SZ, tag, &tagSz);
        if (rc != BAD_FUNC_ARG) {
            WH_ERROR_PRINT("HMAC client: bad hash type returned %d\n", rc);
            ret = -1;
        }
    }

    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        WH_TEST_PRINT("HMAC Client Non-DMA API SUCCESS\n");
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* The HMAC client API with DMA, blocking and async */
static int _whTest_CryptoHmacDmaClient(whClientContext* ctx)
{
    int            ret = 0;
    uint8_t        tag[WC_MAX_DIGEST_SIZE];
    uint8_t        ref[WC_MAX_DIGEST_SIZE];
    uint32_t       tagSz;
    word32         refSz;
    whKeyId        keyId                     = WH_KEYID_ERASED;
    uint8_t        labelIn[WH_NVM_LABEL_LEN] = "HMAC DMA Label";
    const uint8_t* key                       = whTest_HmacKey;
    const uint8_t* msg                       = whTest_HmacMsg;
    size_t         i;

    /* Only used with SHA-256 */
    (void)labelIn;

    /* Blocking generate with key bytes for each hash type */
    for (i = 0; ret == 0 && i < WH_TEST_HMAC_TYPE_CNT; i++) {
        int type = whTest_HmacTypes[i];

        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret   = wh_Client_HmacGenerateDma(ctx, type, WH_KEYID_ERASED, key,
                                          WH_TEST_HMAC_KEY_SZ, msg,
                                          WH_TEST_HMAC_MSG_SZ, tag, &tagSz);
        if (ret == 0) {
            refSz = sizeof(ref);
            ret   = _whTest_HmacReference(type, key, WH_TEST_HMAC_KEY_SZ, msg,
                                          WH_TEST_HMAC_MSG_SZ, ref, &refSz);
        }
        if (ret == 0 && (tagSz != refSz || memcmp(tag, ref, refSz) != 0)) {
            WH_ERROR_PRINT("HMAC DMA: mismatch type=%d\n", type);
            ret = -1;
        }
        if (ret != 0) {
            WH_ERROR_PRINT("HMAC DMA: generate failed type=%d ret=%d\n", type,
                           ret);
        }
    }

#ifndef NO_SHA256
    /* Async request and response with a key stored in the HSM. A second request
     * while the first is in flight must be refused. */
    if (ret == 0) {
        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                 sizeof(labelIn), (uint8_t*)key,
                                 WH_TEST_HMAC_KEY_SZ, &keyId);
    }
    if (ret == 0) {
        ret = wh_Client_HmacGenerateDmaRequest(ctx, WC_SHA256, keyId, NULL, 0,
                                               msg, WH_TEST_HMAC_MSG_SZ);
    }
    if (ret == 0) {
        int rc = wh_Client_HmacGenerateDmaRequest(ctx, WC_SHA256, keyId, NULL,
                                                  0, msg, WH_TEST_HMAC_MSG_SZ);
        if (rc != WH_ERROR_REQUEST_PENDING) {
            WH_ERROR_PRINT("HMAC DMA: second request returned %d\n", rc);
            ret = -1;
        }
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            rc = wh_Client_HmacGenerateDmaResponse(ctx, tag, &tagSz);
        } while (rc == WH_ERROR_NOTREADY);
        if (ret == 0) {
            ret = rc;
        }
    }
    if (ret == 0 && (tagSz != sizeof(whTest_HmacTag256) ||
                     memcmp(tag, whTest_HmacTag256, tagSz) != 0)) {
        WH_ERROR_PRINT("HMAC DMA: async HSM key mismatch\n");
        ret = -1;
    }

    /* An empty message */
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret = wh_Client_HmacGenerateDma(ctx, WC_SHA256, keyId, NULL, 0, NULL, 0,
                                        tag, &tagSz);
    }
    if (ret == 0) {
        refSz = sizeof(ref);
        ret   = _whTest_HmacReference(WC_SHA256, key, WH_TEST_HMAC_KEY_SZ, NULL,
                                      0, ref, &refSz);
    }
    if (ret == 0 && memcmp(tag, ref, refSz) != 0) {
        WH_ERROR_PRINT("HMAC DMA: empty message mismatch\n");
        ret = -1;
    }

#ifdef WOLFHSM_CFG_TEST_POSIX
    /* A message too large for a non-DMA request */
    if (ret == 0) {
        _whTest_HmacFillBuf(whTest_HmacBigBuf, sizeof(whTest_HmacBigBuf));
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret   = wh_Client_HmacGenerateDma(ctx, WC_SHA256, keyId, NULL, 0,
                                          whTest_HmacBigBuf,
                                          sizeof(whTest_HmacBigBuf), tag, &tagSz);
    }
    if (ret == 0) {
        refSz = sizeof(ref);
        ret   = _whTest_HmacReference(WC_SHA256, key, WH_TEST_HMAC_KEY_SZ,
                                      whTest_HmacBigBuf,
                                      sizeof(whTest_HmacBigBuf), ref, &refSz);
    }
    if (ret == 0 && memcmp(tag, ref, refSz) != 0) {
        WH_ERROR_PRINT("HMAC DMA: large message mismatch\n");
        ret = -1;
    }
#endif /* WOLFHSM_CFG_TEST_POSIX */

    /* A buffer that is too small */
    if (ret == 0) {
        int rc;

        tagSz = WC_SHA256_DIGEST_SIZE - 1;
        rc    = wh_Client_HmacGenerateDma(ctx, WC_SHA256, keyId, NULL, 0, msg,
                                          WH_TEST_HMAC_MSG_SZ, tag, &tagSz);
        if (rc != WH_ERROR_BUFFER_SIZE || tagSz != WC_SHA256_DIGEST_SIZE) {
            WH_ERROR_PRINT("HMAC DMA: small buffer returned %d size %u\n", rc,
                           (unsigned)tagSz);
            ret = -1;
        }
    }

    /* Bad arguments. No request must be sent for them. */
    if (ret == 0) {
        uint16_t seq = ctx->comm->seq;

        tagSz = sizeof(tag);
        if (wh_Client_HmacGenerateDma(
                NULL, WC_SHA256, WH_KEYID_ERASED, key, WH_TEST_HMAC_KEY_SZ, msg,
                WH_TEST_HMAC_MSG_SZ, tag, &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC DMA: NULL ctx not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 &&
            wh_Client_HmacGenerateDma(
                ctx, WC_SHA256, WH_KEYID_ERASED, key, WH_TEST_HMAC_KEY_SZ, NULL,
                WH_TEST_HMAC_MSG_SZ, tag, &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC DMA: NULL message not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 &&
            wh_Client_HmacGenerateDma(ctx, WC_SHA256, WH_KEYID_ERASED, NULL, 0,
                                      msg, WH_TEST_HMAC_MSG_SZ, tag,
                                      &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC DMA: no key not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_HmacGenerateDma(ctx, WC_SHA256, keyId, key,
                                                  WH_TEST_HMAC_KEY_SZ, msg,
                                                  WH_TEST_HMAC_MSG_SZ, tag,
                                                  &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC DMA: key and key ID not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 &&
            wh_Client_HmacGenerateDma(
                ctx, WC_SHA256, WH_KEYID_ERASED, key, WH_TEST_HMAC_KEY_SZ, msg,
                WH_TEST_HMAC_MSG_SZ, NULL, &tagSz) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("HMAC DMA: NULL output not BADARGS\n");
            ret = -1;
        }
        if (ret == 0 && ctx->comm->seq != seq) {
            WH_ERROR_PRINT("HMAC DMA: bad arguments sent a request\n");
            ret = -1;
        }
    }
#endif /* !NO_SHA256 */

    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        WH_TEST_PRINT("HMAC Client DMA API SUCCESS\n");
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

int whTest_Crypto_Hmac(whClientContext* ctx)
{
    int i;

    /* HMAC through wolfCrypt uses the cryptocb, so run it in each dispatch
     * mode */
    for (i = 0; i < WH_TEST_DMA_MODE_CNT; i++) {
        (void)wh_Client_SetDmaMode(ctx, i);
        WH_TEST_RETURN_ON_FAIL(
            _whTest_CryptoHmacWolfCrypt(ctx, WH_CLIENT_DEVID(ctx)));
    }
    (void)wh_Client_SetDmaMode(ctx, 0);

    /* The client API tests call the DMA and non-DMA functions directly */
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoHmacClient(ctx));
#ifndef NO_SHA256
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoHmacBadRequest(ctx));
#endif
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoHmacDmaClient(ctx));
#endif
    return 0;
}
#endif /* !NO_HMAC */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
