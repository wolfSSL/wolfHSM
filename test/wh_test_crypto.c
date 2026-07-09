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

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include <stdint.h>
#include <string.h> /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#if defined(WOLFSSL_HAVE_LMS)
#include "wolfssl/wolfcrypt/wc_lms.h"
#endif
#if defined(WOLFSSL_HAVE_XMSS)
#include "wolfssl/wolfcrypt/wc_xmss.h"
#endif
#include "wolfssl/wolfcrypt/wc_mlkem.h"

#include "wolfhsm/wh_error.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#endif

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_crypto.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_crypto.h"
/* Pull in client keywrap tests to run against server */
#include "wh_test_keywrap.h"
#endif

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"
#endif

#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_crypto.h"

#include "wh_test_common.h"
#include "wh_test_dma.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <unistd.h> /* For sleep */
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */
#define FLASH_SECTOR_SIZE (128 * 1024) /* 128KB */
#define FLASH_PAGE_SIZE (8) /* 8B */

#ifndef TEST_ADMIN_USERNAME
#define TEST_ADMIN_USERNAME "admin"
#endif
#ifndef TEST_ADMIN_PIN
#define TEST_ADMIN_PIN "1234"
#endif

#define ALT_CLIENT_ID (2)

enum {
    /* Total size needs to fit:
     * - Transport CSR (whTransportMemCsr)
     * - Comm header (whCommHeader)
     * - Max data size (WOLFHSM_CFG_COMM_DATA_LEN)
     */
    BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                  WOLFHSM_CFG_COMM_DATA_LEN,
};


#define PLAINTEXT "mytextisbigplain"

#ifdef WOLFHSM_CFG_IS_TEST_SERVER
/* Flag causing the server loop to sleep(1) */
int serverDelay = 0;
#endif /* WOLFHSM_CFG_IS_TEST_SERVER */

#if defined(WOLFHSM_CFG_DEBUG_VERBOSE) && defined(WOLFHSM_CFG_ENABLE_CLIENT)
static int whTest_ShowNvmAvailable(whClientContext* ctx)
{
    int ret = 0;
    int32_t  server_rc       = 0;
    whNvmId  avail_objects   = 0;
    whNvmId  reclaim_objects = 0;
    uint32_t avail_size      = 0;
    uint32_t reclaim_size    = 0;

    ret = wh_Client_NvmGetAvailable(ctx, &server_rc, &avail_size,
                                        &avail_objects, &reclaim_size,
                                        &reclaim_objects);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to get available NVM status\n");
    } else {
        WH_TEST_DEBUG_PRINT("CRYPTO TEST NVM STATUS: NvmGetAvailable:%d, server_rc:%d "
                "avail_size:%d avail_objects:%d, reclaim_size:%d "
                "reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects,
               (int)reclaim_size, (int)reclaim_objects);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DEBUG_VERBOSE && WOLFHSM_CFG_ENABLE_CLIENT */

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
static int whTest_CryptoRng(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx; /* Unused */

#define WH_TEST_RNG_LIL 7
#define WH_TEST_RNG_MED 1024
#define WH_TEST_RNG_BIG (WOLFHSM_CFG_COMM_DATA_LEN * 2)
    int ret;
    uint8_t lil[WH_TEST_RNG_LIL];
    uint8_t med[WH_TEST_RNG_MED];
    uint8_t big[WH_TEST_RNG_BIG];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
    } else {
        int freeRet;
        ret = wc_RNG_GenerateBlock(rng, lil, sizeof(lil));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        } else {
            ret = wc_RNG_GenerateBlock(rng, med, sizeof(med));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
            } else {
                ret = wc_RNG_GenerateBlock(rng, big, sizeof(big));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
                }
                else if (memcmp(lil, med, sizeof(lil)) == 0) {
                    /* The prefixes of two successive independent RNG calls
                     * must not match. A collision here indicates a stuck RNG */
                    WH_ERROR_PRINT("RNG: successive calls produced identical "
                                   "prefix\n");
                    ret = -1;
                }
            }
        }
        /* Always free the RNG if InitRng succeeded, regardless of which (if
         * any) GenerateBlock call failed. */
        freeRet = wc_FreeRng(rng);
        if (freeRet != 0) {
            WH_ERROR_PRINT("Failed to wc_FreeRng %d\n", freeRet);
            if (ret == 0) {
                ret = freeRet;
            }
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("RNG DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Returns 0 if buf appears to contain non-trivial data (not all zero), -1 on
 * the all-zero case which would suggest the response was never written. */
static int whTest_RngBufNonZero(const uint8_t* buf, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return -1;
}

/* Direct exercise of the new async non-DMA RNG primitives. */
static int whTest_CryptoRngAsync(whClientContext* ctx)
{
    int      ret = WH_ERROR_OK;
    uint8_t  small[64];
    uint8_t  big[WOLFHSM_CFG_COMM_DATA_LEN * 2];
    uint32_t got;

    /* Case A: small Request -> poll Response */
    if (ret == 0) {
        memset(small, 0, sizeof(small));
        ret = wh_Client_RngGenerateRequest(ctx, sizeof(small));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG: Request(small) failed %d\n", ret);
        }
    }
    if (ret == 0) {
        got = sizeof(small);
        do {
            ret = wh_Client_RngGenerateResponse(ctx, small, &got);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG: Response(small) failed %d\n", ret);
        }
        else if (got != sizeof(small)) {
            WH_ERROR_PRINT("Async RNG: short read got=%u want=%u\n",
                           (unsigned)got, (unsigned)sizeof(small));
            ret = -1;
        }
        else if (whTest_RngBufNonZero(small, sizeof(small)) != 0) {
            WH_ERROR_PRINT("Async RNG: small buffer all zeros\n");
            ret = -1;
        }
    }

    /* Case B: max-inline-size Request -> Response in a single round trip */
    if (ret == 0) {
        uint32_t cap = (uint32_t)WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ;
        memset(big, 0, cap);
        ret = wh_Client_RngGenerateRequest(ctx, cap);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG: Request(max) failed %d\n", ret);
        }
        if (ret == 0) {
            got = cap;
            do {
                ret = wh_Client_RngGenerateResponse(ctx, big, &got);
            } while (ret == WH_ERROR_NOTREADY);
            if (ret == 0 && got != cap) {
                WH_ERROR_PRINT("Async RNG: max read short got=%u want=%u\n",
                               (unsigned)got, (unsigned)cap);
                ret = -1;
            }
            else if (ret == 0 && whTest_RngBufNonZero(big, cap) != 0) {
                WH_ERROR_PRINT("Async RNG: max buffer all zeros\n");
                ret = -1;
            }
        }
    }

    /* Case C: caller-driven chunking to fill a buffer larger than the per-call
     * inline capacity. */
    if (ret == 0) {
        uint32_t cap      = (uint32_t)WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ;
        uint32_t total    = (uint32_t)sizeof(big);
        uint32_t consumed = 0;

        memset(big, 0, total);
        while (ret == 0 && consumed < total) {
            uint32_t want = total - consumed;
            if (want > cap) {
                want = cap;
            }
            ret = wh_Client_RngGenerateRequest(ctx, want);
            if (ret == 0) {
                got = want;
                do {
                    ret = wh_Client_RngGenerateResponse(ctx, big + consumed,
                                                        &got);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (got == 0 || got > want) {
                    WH_ERROR_PRINT(
                        "Async RNG: bad chunk reply got=%u want=%u\n",
                        (unsigned)got, (unsigned)want);
                    ret = -1;
                }
                else {
                    consumed += got;
                }
            }
        }
        if (ret == 0 && whTest_RngBufNonZero(big, total) != 0) {
            WH_ERROR_PRINT("Async RNG: chunked buffer all zeros\n");
            ret = -1;
        }
    }

    /* Case D: oversize request must be rejected without sending. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateRequest(
            ctx, (uint32_t)WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ + 1u);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG: oversize Request returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }

    /* Case E: zero-size request must be rejected. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateRequest(ctx, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG: zero-size Request returned %d (want BADARGS)\n",
                rc);
            ret = -1;
        }
    }

    /* Case F: NULL ctx rejection on both halves. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateRequest(NULL, 16);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG: NULL ctx Request returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        got    = 16;
        int rc = wh_Client_RngGenerateResponse(NULL, small, &got);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG: NULL ctx Response returned %d (want BADARGS)\n",
                rc);
            ret = -1;
        }
    }

    /* Case G: NULL inout_size rejection. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateResponse(ctx, small, NULL);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async RNG: NULL inout_size Response returned %d "
                           "(want BADARGS)\n",
                           rc);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("RNG ASYNC SUCCESS\n");
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA RNG primitives. */
static int whTest_CryptoRngDmaAsync(whClientContext* ctx)
{
    int ret = WH_ERROR_OK;
    /* DMA bypasses the comm buffer so we can request more than COMM_DATA_LEN
     * in a single round trip. */
    uint8_t big[WOLFHSM_CFG_COMM_DATA_LEN * 2];

    /* Case A: basic DMA Request -> Response */
    if (ret == 0) {
        memset(big, 0, sizeof(big));
        ret = wh_Client_RngGenerateDmaRequest(ctx, big, sizeof(big));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG DMA: Request failed %d\n", ret);
        }
    }
    if (ret == 0) {
        do {
            ret = wh_Client_RngGenerateDmaResponse(ctx);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG DMA: Response failed %d\n", ret);
        }
        else if (whTest_RngBufNonZero(big, sizeof(big)) != 0) {
            WH_ERROR_PRINT("Async RNG DMA: buffer all zeros\n");
            ret = -1;
        }
    }

    /* Case B: small DMA request still works (no chunking semantics). */
    if (ret == 0) {
        uint8_t small[32];
        memset(small, 0, sizeof(small));
        ret = wh_Client_RngGenerateDmaRequest(ctx, small, sizeof(small));
        if (ret == 0) {
            do {
                ret = wh_Client_RngGenerateDmaResponse(ctx);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && whTest_RngBufNonZero(small, sizeof(small)) != 0) {
            WH_ERROR_PRINT("Async RNG DMA: small buffer all zeros\n");
            ret = -1;
        }
    }

    /* Case C: input validation. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateDmaRequest(NULL, big, sizeof(big));
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG DMA: NULL ctx returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc = wh_Client_RngGenerateDmaRequest(ctx, NULL, sizeof(big));
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG DMA: NULL out returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc = wh_Client_RngGenerateDmaRequest(ctx, big, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG DMA: zero size returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc = wh_Client_RngGenerateDmaResponse(NULL);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG DMA: Response NULL ctx returned %d (want BADARGS)\n",
                rc);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("RNG DMA ASYNC SUCCESS\n");
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#ifndef NO_RSA
static int whTest_CryptoRsa(whClientContext* ctx, int devId, WC_RNG* rng)
{
#define RSA_KEY_BITS 2048
#define RSA_KEY_BYTES (RSA_KEY_BITS/8)
#define RSA_EXPONENT WC_RSA_EXPONENT

    int ret = WH_ERROR_OK;
    RsaKey rsa[1];
    char plainText[sizeof(PLAINTEXT)] = PLAINTEXT;
    char cipherText[RSA_KEY_BYTES];
    char finalText[RSA_KEY_BYTES];
    whKeyId keyId = WH_KEYID_ERASED;

    /* Using ephemeral key */
    memset(cipherText, 0, sizeof(cipherText));
    memset(finalText, 0, sizeof(finalText));
    ret = wc_InitRsaKey_ex(rsa, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
    } else {
        ret = wc_MakeRsaKey(rsa, RSA_KEY_BITS, RSA_EXPONENT, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_MakeRsaKey %d\n", ret);
        } else {
            ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText),
                    (byte*)cipherText, sizeof(cipherText), rsa, rng);
            if (ret < 0) {
                WH_ERROR_PRINT("Failed to wc_RsaPublicEncrypt %d\n", ret);
            } else {
                ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret,
                        (byte*)finalText, sizeof(finalText), rsa);
                if (ret < 0) {
                    WH_ERROR_PRINT("Failed to wc_RsaPrivateDecrypt %d\n", ret);
                } else {
                    ret = 0;
                    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
                        WH_ERROR_PRINT("Failed to match\n");
                        ret = -1;
                    }
                }
            }
        }
        (void)wc_FreeRsaKey(rsa);
    }

    if (ret == 0) {
        /* Using client export key */
        memset(cipherText, 0, sizeof(cipherText));
        memset(finalText, 0, sizeof(finalText));
        ret = wc_InitRsaKey_ex(rsa, NULL, WH_CLIENT_DEVID(ctx));
        if (ret!= 0) {
            WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
        } else {
            ret = wh_Client_RsaMakeExportKey(ctx, RSA_KEY_BITS, RSA_EXPONENT,
                    rsa);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to make exported key %d\n", ret);
            } else {
                ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText),
                        (byte*)cipherText, sizeof(cipherText), rsa, rng);
                if (ret < 0) {
                    WH_ERROR_PRINT("Failed to encrypt %d\n", ret);
                } else {
                    ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret,
                            (byte*)finalText, sizeof(finalText), rsa);
                    if (ret < 0) {
                        WH_ERROR_PRINT("Failed to decrypt %d\n", ret);
                    } else {
                        ret = 0;
                        if (memcmp(plainText, finalText, sizeof(plainText)) !=
                            0) {
                            WH_ERROR_PRINT("Failed to match\n");
                            ret = -1;
                        }
                    }
                }
            }
            (void)wc_FreeRsaKey(rsa);
        }
    }

    if (ret == 0) {
        /* Using keyCache key */
        memset(cipherText, 0, sizeof(cipherText));
        memset(finalText, 0, sizeof(finalText));
        ret = wh_Client_RsaMakeCacheKey(
            ctx, RSA_KEY_BITS, RSA_EXPONENT, &keyId,
            WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, 0, NULL);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
        } else {
            ret = wc_InitRsaKey_ex(rsa, NULL, WH_CLIENT_DEVID(ctx));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
            } else {
                ret = wh_Client_RsaSetKeyId(rsa, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
                } else {
                    ret = wh_Client_RsaGetKeyId(rsa, &keyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_GetKeyIdRsa %d\n", ret);
                    } else {
                        ret = wc_RsaPublicEncrypt(
                                (byte*)plainText, sizeof(plainText),
                                (byte*)cipherText, sizeof(cipherText), rsa,
                                rng);
                        if (ret < 0) {
                            WH_ERROR_PRINT("Failed to encrypt %d\n", ret);
                        } else {
                            ret = wc_RsaPrivateDecrypt(
                                    (byte*)cipherText, ret,
                                    (byte*)finalText, sizeof(finalText), rsa);
                            if (ret < 0) {
                                WH_ERROR_PRINT("Failed to decrypt %d\n", ret);
                            } else {
                                ret = 0;
                                if (memcmp(plainText, finalText,
                                           sizeof(plainText)) != 0) {
                                    WH_ERROR_PRINT("Failed to match\n");
                                    ret = -1;
                                }
                            }
                        }
                    }
                }
                (void)wc_FreeRsaKey(rsa);
            }
        }
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Export-public-only test on a NONEXPORTABLE cached key */
    if (ret == 0) {
        RsaKey   rsaFull[1];
        RsaKey   rsaPub[1];
        /* Large enough to hold a real RSA key DER so the access-control
         * assertion below doesn't get masked by a buffer-too-small
         * (WH_ERROR_ABORTED) failure if the policy/read order ever changes. */
        char     exportBuf[2048];
        uint16_t exportLen;
        whKeyId  pubOnlyId = WH_KEYID_ERASED;

        memset(cipherText, 0, sizeof(cipherText));
        memset(finalText, 0, sizeof(finalText));

        ret = wh_Client_RsaMakeCacheKey(
            ctx, RSA_KEY_BITS, RSA_EXPONENT, &pubOnlyId,
            WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT |
                WH_NVM_FLAGS_NONEXPORTABLE,
            0, NULL);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to make NONEXPORTABLE cached key %d\n", ret);
        }

        /* Full export must be denied */
        if (ret == 0) {
            exportLen = sizeof(exportBuf);
            int denyRet = wh_Client_KeyExport(ctx, pubOnlyId, NULL, 0,
                                              (uint8_t*)exportBuf, &exportLen);
            if (denyRet != WH_ERROR_ACCESS) {
                WH_ERROR_PRINT(
                    "NONEXPORTABLE key was not denied on full export: %d\n",
                    denyRet);
                ret = -1;
            }
        }

        /* Public export must succeed and yield a usable public key */
        if (ret == 0) {
            ret = wc_InitRsaKey_ex(rsaPub, NULL, INVALID_DEVID);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to init rsaPub %d\n", ret);
            }
            else {
                ret = wh_Client_RsaExportPublicKey(ctx, pubOnlyId, rsaPub, 0,
                                                   NULL);
                if (ret != 0) {
                    WH_ERROR_PRINT("wh_Client_RsaExportPublicKey failed %d\n",
                                   ret);
                }
                else if (rsaPub->type != RSA_PUBLIC) {
                    WH_ERROR_PRINT(
                        "Exported RSA key is not public-only (type=%d)\n",
                        rsaPub->type);
                    ret = -1;
                }
                else {
                    /* Encrypt with the client-side public-only key, then
                     * decrypt on the HSM using the cached private key. */
                    int encLen = wc_RsaPublicEncrypt(
                        (byte*)plainText, sizeof(plainText),
                        (byte*)cipherText, sizeof(cipherText), rsaPub, rng);
                    if (encLen < 0) {
                        WH_ERROR_PRINT(
                            "PublicEncrypt with exported pub failed %d\n",
                            encLen);
                        ret = encLen;
                    }
                    else {
                        ret = wc_InitRsaKey_ex(rsaFull, NULL,
                                               WH_CLIENT_DEVID(ctx));
                        if (ret == 0) {
                            ret = wh_Client_RsaSetKeyId(rsaFull, pubOnlyId);
                        }
                        if (ret == 0) {
                            int decLen = wc_RsaPrivateDecrypt(
                                (byte*)cipherText, encLen, (byte*)finalText,
                                sizeof(finalText), rsaFull);
                            if (decLen < 0) {
                                WH_ERROR_PRINT(
                                    "HSM PrivateDecrypt failed %d\n", decLen);
                                ret = decLen;
                            }
                            else if (memcmp(plainText, finalText,
                                            sizeof(plainText)) != 0) {
                                WH_ERROR_PRINT(
                                    "Round-trip plaintext mismatch\n");
                                ret = -1;
                            }
                            else {
                                ret = 0;
                            }
                        }
                        (void)wc_FreeRsaKey(rsaFull);
                    }
                }
                (void)wc_FreeRsaKey(rsaPub);
            }
        }

        /* Wrong algo selector must be rejected */
        if (ret == 0) {
            byte     dummy[8];
            uint16_t dummySz = sizeof(dummy);
            int      negRet  = wh_Client_KeyExportPublic(
                ctx, pubOnlyId, WH_KEY_ALGO_ECC, NULL, 0, dummy, &dummySz);
            if (negRet == 0) {
                WH_ERROR_PRINT(
                    "ExportPublic succeeded with wrong algo selector\n");
                ret = -1;
            }
        }

        /* Unknown keyId must be rejected with NOTFOUND */
        if (ret == 0) {
            byte     dummy[8];
            uint16_t dummySz = sizeof(dummy);
            /* Pick a client-side keyId that is unlikely to exist.
             * 0xBADE is well clear of auto-assigned IDs starting near 1. */
            whKeyId  missing = (whKeyId)0xBADE;
            int      negRet  = wh_Client_KeyExportPublic(
                ctx, missing, WH_KEY_ALGO_RSA, NULL, 0, dummy, &dummySz);
            if (negRet != WH_ERROR_NOTFOUND) {
                WH_ERROR_PRINT(
                    "ExportPublic on missing keyId returned %d, "
                    "expected WH_ERROR_NOTFOUND\n",
                    negRet);
                ret = -1;
            }
        }

        if (!WH_KEYID_ISERASED(pubOnlyId)) {
            (void)wh_Client_KeyEvict(ctx, pubOnlyId);
        }

        if (ret == 0) {
            WH_TEST_PRINT("RSA EXPORT-PUBLIC SUCCESS\n");
        }
    }

    /* Cache-and-export-public: a single keygen call returns the public key */
    if (ret == 0) {
        RsaKey   genPub[1];
        RsaKey   refPub[1];
        whKeyId  cacheId  = WH_KEYID_ERASED;
        byte     genDer[2048];
        byte     refDer[2048];
        int      genDerSz = 0;
        int      refDerSz = 0;
        int      genInit  = 0;
        int      refInit  = 0;

        memset(cipherText, 0, sizeof(cipherText));
        memset(finalText, 0, sizeof(finalText));

        ret = wc_InitRsaKey_ex(genPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            genInit = 1;
            ret     = wh_Client_RsaMakeCacheKeyAndExportPublic(
                ctx, RSA_KEY_BITS, RSA_EXPONENT, &cacheId,
                WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, 0,
                NULL, genPub);
            if (ret != 0) {
                WH_ERROR_PRINT("RsaMakeCacheKeyAndExportPublic failed %d\n",
                               ret);
            }
        }

        /* Cross-check the keygen-returned public key against a separate
         * ExportPublicKey call on the same cached keyId. */
        if (ret == 0) {
            ret = wc_InitRsaKey_ex(refPub, NULL, INVALID_DEVID);
            if (ret == 0) {
                refInit = 1;
                ret     = wh_Client_RsaExportPublicKey(ctx, cacheId, refPub, 0,
                                                       NULL);
                if (ret != 0) {
                    WH_ERROR_PRINT("RsaExportPublicKey failed %d\n", ret);
                }
            }
        }
        if (ret == 0) {
            genDerSz = wc_RsaKeyToPublicDer(genPub, genDer, sizeof(genDer));
            refDerSz = wc_RsaKeyToPublicDer(refPub, refDer, sizeof(refDer));
            if ((genDerSz <= 0) || (genDerSz != refDerSz) ||
                (memcmp(genDer, refDer, (size_t)genDerSz) != 0)) {
                WH_ERROR_PRINT("keygen pubkey mismatch vs ExportPublicKey\n");
                ret = -1;
            }
        }

        /* Prove the returned public key is usable: encrypt locally with the
         * exported public key (refPub) the client holds, then decrypt on the
         * HSM using genPub directly as the private-key handle (no separate key
         * object). */
        if (ret == 0) {
            int encLen = wc_RsaPublicEncrypt(
                (byte*)plainText, sizeof(plainText), (byte*)cipherText,
                sizeof(cipherText), refPub, rng);
            if (encLen < 0) {
                WH_ERROR_PRINT("PublicEncrypt with keygen pub failed %d\n",
                               encLen);
                ret = encLen;
            }
            else {
                int decLen = wc_RsaPrivateDecrypt(
                    (byte*)cipherText, encLen, (byte*)finalText,
                    sizeof(finalText), genPub);
                if (decLen < 0) {
                    WH_ERROR_PRINT("HSM PrivateDecrypt failed %d\n", decLen);
                    ret = decLen;
                }
                else if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
                    WH_ERROR_PRINT("keygen-pub round-trip mismatch\n");
                    ret = -1;
                }
            }
        }

        if (genInit != 0) {
            (void)wc_FreeRsaKey(genPub);
        }
        if (refInit != 0) {
            (void)wc_FreeRsaKey(refPub);
        }
        if (!WH_KEYID_ISERASED(cacheId)) {
            (void)wh_Client_KeyEvict(ctx, cacheId);
        }

        if (ret == 0) {
            WH_TEST_PRINT("RSA CACHE-AND-EXPORT-PUBLIC SUCCESS\n");
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("RSA SUCCESS\n");
    }
    return ret;
}

static int whTest_CryptoRsaAsync(whClientContext* ctx, WC_RNG* rng)
{
    int     ret = WH_ERROR_OK;
    RsaKey  rsa[1];
    int     rsaInit                      = 0;
    whKeyId keyId                        = WH_KEYID_ERASED;
    int     keyCached                    = 0;
    char    plainText[sizeof(PLAINTEXT)] = PLAINTEXT;
    /* Leading zeros ensure msg < N, so the raw RSA primitives
     * (sign/verify without padding) round-trip exactly. */
    uint8_t  msgBuf[RSA_KEY_BYTES];
    uint8_t  cipherText[RSA_KEY_BYTES];
    uint8_t  finalText[RSA_KEY_BYTES];
    uint16_t cipherLen;
    uint16_t finalLen;
    int      reportedSize = 0;

    memset(msgBuf, 0, sizeof(msgBuf));
    memcpy(msgBuf + sizeof(msgBuf) - sizeof(plainText), plainText,
           sizeof(plainText));

    WH_TEST_PRINT("Testing RSA async API...\n");

    /* 1) RsaMakeCacheKey async: generate a key into the server cache */
    ret = wh_Client_RsaMakeCacheKeyRequest(
        ctx, RSA_KEY_BITS, RSA_EXPONENT, WH_KEYID_ERASED,
        WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, 0, NULL);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("RsaMakeCacheKeyRequest failed: %d\n", ret);
    }
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_RsaMakeCacheKeyResponse(ctx, &keyId);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("RsaMakeCacheKeyResponse failed: %d\n", ret);
        }
        else if (WH_KEYID_ISERASED(keyId)) {
            WH_ERROR_PRINT("RsaMakeCacheKey returned erased keyId\n");
            ret = -1;
        }
        else {
            keyCached = 1;
        }
    }

    /* 2) RsaMakeCacheKeyRequest rejects EPHEMERAL */
    if (ret == WH_ERROR_OK) {
        int badret = wh_Client_RsaMakeCacheKeyRequest(
            ctx, RSA_KEY_BITS, RSA_EXPONENT, WH_KEYID_ERASED,
            WH_NVM_FLAGS_EPHEMERAL, 0, NULL);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RsaMakeCacheKeyRequest with EPHEMERAL returned %d "
                           "(want BADARGS)\n",
                           badret);
            ret = -1;
        }
    }

    /* 3) RsaGetSize async */
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_RsaGetSizeRequest(ctx, keyId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("RsaGetSizeRequest failed: %d\n", ret);
        }
    }
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_RsaGetSizeResponse(ctx, &reportedSize);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("RsaGetSizeResponse failed: %d\n", ret);
        }
        else if (reportedSize != RSA_KEY_BYTES) {
            WH_ERROR_PRINT("RsaGetSize returned %d, want %d\n", reportedSize,
                           RSA_KEY_BYTES);
            ret = -1;
        }
    }

    /* 4) Erased keyId must be rejected by Request halves */
    if (ret == WH_ERROR_OK) {
        int badret = wh_Client_RsaGetSizeRequest(ctx, WH_KEYID_ERASED);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RsaGetSizeRequest with erased keyId returned %d "
                           "(want BADARGS)\n",
                           badret);
            ret = -1;
        }
        badret = wh_Client_RsaFunctionRequest(
            ctx, WH_KEYID_ERASED, RSA_PUBLIC_ENCRYPT, (uint8_t*)plainText,
            sizeof(plainText), sizeof(cipherText));
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RsaFunctionRequest with erased keyId returned %d "
                           "(want BADARGS)\n",
                           badret);
            ret = -1;
        }
    }

    /* 5) NULL ctx must be rejected by Request halves */
    if (ret == WH_ERROR_OK) {
        int badret = wh_Client_RsaGetSizeRequest(NULL, keyId);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RsaGetSizeRequest with NULL ctx returned %d "
                           "(want BADARGS)\n",
                           badret);
            ret = -1;
        }
    }

    /* 5b) Response halves reject NULL args before any transport activity,
     * so these checks are safe to run with no outstanding request. */
    if (ret == WH_ERROR_OK) {
        whKeyId dummyKeyId = WH_KEYID_ERASED;
        int     dummySize  = 0;
        uint8_t dummyBuf[8];
        int     badret;

        badret = wh_Client_RsaGetSizeResponse(NULL, &dummySize);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RsaGetSizeResponse with NULL ctx returned %d "
                           "(want BADARGS)\n",
                           badret);
            ret = -1;
        }
        badret = wh_Client_RsaGetSizeResponse(ctx, NULL);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RsaGetSizeResponse with NULL out_size returned %d "
                           "(want BADARGS)\n",
                           badret);
            ret = -1;
        }
        badret = wh_Client_RsaFunctionResponse(ctx, dummyBuf, NULL);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RsaFunctionResponse with out non-NULL and "
                           "inout_out_len NULL returned %d (want BADARGS)\n",
                           badret);
            ret = -1;
        }
        badret = wh_Client_RsaMakeCacheKeyResponse(NULL, &dummyKeyId);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RsaMakeCacheKeyResponse with NULL ctx returned %d "
                           "(want BADARGS)\n",
                           badret);
            ret = -1;
        }
        badret = wh_Client_RsaMakeCacheKeyResponse(ctx, NULL);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "RsaMakeCacheKeyResponse with NULL out_key_id returned %d "
                "(want BADARGS)\n",
                badret);
            ret = -1;
        }
        badret = wh_Client_RsaMakeExportKeyResponse(ctx, NULL);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RsaMakeExportKeyResponse with NULL rsa returned %d "
                           "(want BADARGS)\n",
                           badret);
            ret = -1;
        }
    }

    /* 6) RsaFunction async: private encrypt (raw sign). */
    if (ret == WH_ERROR_OK) {
        memset(cipherText, 0, sizeof(cipherText));
        cipherLen = sizeof(cipherText);
        ret = wh_Client_RsaFunctionRequest(ctx, keyId, RSA_PRIVATE_ENCRYPT,
                                           msgBuf, sizeof(msgBuf), cipherLen);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("RsaFunctionRequest (sign) failed: %d\n", ret);
        }
    }
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_RsaFunctionResponse(ctx, cipherText, &cipherLen);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("RsaFunctionResponse (sign) failed: %d\n", ret);
        }
        else if (cipherLen != RSA_KEY_BYTES) {
            WH_ERROR_PRINT("Sign produced %u bytes, want %d\n",
                           (unsigned)cipherLen, RSA_KEY_BYTES);
            ret = -1;
        }
    }

    /* 7) Undersized output buffer must return WH_ERROR_BUFFER_SIZE with
     * the required size reported and the caller's buffer untouched. */
    if (ret == WH_ERROR_OK) {
        uint8_t  smallBuf[8];
        uint8_t  sentinel[sizeof(smallBuf)];
        uint16_t smallLen = sizeof(smallBuf);
        int      bsret;

        memset(smallBuf, 0xAA, sizeof(smallBuf));
        memset(sentinel, 0xAA, sizeof(sentinel));

        bsret = wh_Client_RsaFunctionRequest(ctx, keyId, RSA_PRIVATE_ENCRYPT,
                                             msgBuf, sizeof(msgBuf),
                                             sizeof(cipherText));
        if (bsret == WH_ERROR_OK) {
            do {
                bsret = wh_Client_RsaFunctionResponse(ctx, smallBuf, &smallLen);
            } while (bsret == WH_ERROR_NOTREADY);
        }
        if (bsret != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT("RsaFunctionResponse with small buffer returned %d "
                           "(want WH_ERROR_BUFFER_SIZE)\n",
                           bsret);
            ret = -1;
        }
        else if (smallLen != RSA_KEY_BYTES) {
            WH_ERROR_PRINT(
                "BUFFER_SIZE path did not report required size: got %u "
                "want %d\n",
                (unsigned)smallLen, RSA_KEY_BYTES);
            ret = -1;
        }
        else if (memcmp(smallBuf, sentinel, sizeof(smallBuf)) != 0) {
            WH_ERROR_PRINT(
                "BUFFER_SIZE path wrote into caller's output buffer\n");
            ret = -1;
        }
    }

    /* 8) RsaFunction async: public decrypt (raw verify) recovers msgBuf. */
    if (ret == WH_ERROR_OK) {
        memset(finalText, 0, sizeof(finalText));
        finalLen = sizeof(finalText);
        ret      = wh_Client_RsaFunctionRequest(ctx, keyId, RSA_PUBLIC_DECRYPT,
                                                cipherText, cipherLen, finalLen);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("RsaFunctionRequest (verify) failed: %d\n", ret);
        }
    }
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_RsaFunctionResponse(ctx, finalText, &finalLen);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("RsaFunctionResponse (verify) failed: %d\n", ret);
        }
        else if (finalLen != sizeof(msgBuf) ||
                 memcmp(msgBuf, finalText, sizeof(msgBuf)) != 0) {
            WH_ERROR_PRINT(
                "Sign/verify round-trip mismatch: finalLen=%u msgLen=%u\n",
                (unsigned)finalLen, (unsigned)sizeof(msgBuf));
            ret = -1;
        }
    }

    /* Evict keys now that we are done with them to free up cache space */
    if (ret == WH_ERROR_OK && keyCached) {
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("KeyEvict after sign/verify failed: %d\n", ret);
        }
        else {
            keyCached = 0;
        }
    }

    /* 9) RsaMakeExportKey async: server generates ephemeral key, returns DER.
     */
    if (ret == WH_ERROR_OK) {
        ret = wc_InitRsaKey_ex(rsa, NULL, WH_CLIENT_DEVID(ctx));
        if (ret != 0) {
            WH_ERROR_PRINT("wc_InitRsaKey_ex failed: %d\n", ret);
        }
        else {
            rsaInit = 1;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret =
            wh_Client_RsaMakeExportKeyRequest(ctx, RSA_KEY_BITS, RSA_EXPONENT);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("RsaMakeExportKeyRequest failed: %d\n", ret);
        }
    }
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_RsaMakeExportKeyResponse(ctx, rsa);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("RsaMakeExportKeyResponse failed: %d\n", ret);
        }
    }

    /* 10) Round trip the exported key for an RSA operation */
    if (ret == WH_ERROR_OK) {
        int encLen;
        int decLen;

        memset(cipherText, 0, sizeof(cipherText));
        memset(finalText, 0, sizeof(finalText));
        encLen = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText),
                                     cipherText, sizeof(cipherText), rsa, rng);
        if (encLen < 0) {
            WH_ERROR_PRINT("PublicEncrypt failed: %d\n", encLen);
            ret = encLen;
        }
        else {
            decLen = wc_RsaPrivateDecrypt(cipherText, encLen, finalText,
                                          sizeof(finalText), rsa);
            if (decLen < 0) {
                WH_ERROR_PRINT("PrivateDecrypt failed: %d\n", decLen);
                ret = decLen;
            }
            else if ((size_t)decLen != sizeof(plainText) ||
                     memcmp(plainText, finalText, sizeof(plainText)) != 0) {
                WH_ERROR_PRINT("exported-key round-trip mismatch\n");
                ret = -1;
            }
        }
    }

    if (rsaInit) {
        (void)wc_FreeRsaKey(rsa);
    }
    if (keyCached) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == WH_ERROR_OK) {
        WH_TEST_PRINT("RSA async API SUCCESS\n");
    }
    return ret;
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
static int whTest_CryptoEcc(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int ret = WH_ERROR_OK;
    ecc_key bobKey[1];
    ecc_key aliceKey[1];
#define TEST_ECC_KEYSIZE 32
#define TEST_ECC_CURVE_ID ECC_SECP256R1
    uint8_t shared_ab[TEST_ECC_KEYSIZE] = {0};
    uint8_t shared_ba[TEST_ECC_KEYSIZE] = {0};
    uint8_t hash[TEST_ECC_KEYSIZE] = {0};
    uint8_t sig[ECC_MAX_SIG_SIZE] = {0};
    whKeyId keyIdPrivate = WH_KEYID_ERASED;
    whKeyId checkKeyId = WH_KEYID_ERASED;
    whNvmFlags flags = WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |
                       WH_NVM_FLAGS_USAGE_DERIVE;
    uint8_t labelPrivate[WH_NVM_LABEL_LEN] = "ECC Private Key";

    /* Test Case 1: Using ephemeral key (normal wolfCrypt flow) */
    ret = wc_ecc_init_ex(bobKey, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_ecc_init_ex %d\n", ret);
    } else {
        ret = wc_ecc_init_ex(aliceKey, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_ecc_init_ex %d\n", ret);
        } else {
            ret = wc_ecc_make_key(rng, TEST_ECC_KEYSIZE, bobKey);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_ecc_make_key %d\n", ret);
            } else {
                ret = wc_ecc_make_key(rng, TEST_ECC_KEYSIZE, aliceKey);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_ecc_make_key %d\n", ret);
                } else {
                    word32 secLen = TEST_ECC_KEYSIZE;
                    ret           = wc_ecc_shared_secret(bobKey, aliceKey,
                                                         (byte*)shared_ab, &secLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute secret %d\n", ret);
                    } else {
                        ret = wc_ecc_shared_secret(aliceKey, bobKey,
                                                   (byte*)shared_ba, &secLen);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to compute secret %d\n",
                                    ret);
                        } else {
                            if (memcmp(shared_ab, shared_ba, secLen) == 0) {
                                WH_TEST_PRINT("ECC ephemeral ECDH SUCCESS\n");
                            }
                            else {
                                WH_ERROR_PRINT(
                                    "ECC ephemeral ECDH FAILED TO MATCH\n");
                                ret = -1;
                            }
                        }
                    }
                    if (ret == 0) {
                        /* Use the shared secret as a random hash */
                        memcpy(hash, shared_ba, sizeof(hash));
                        word32 sigLen = sizeof(sig);
                        ret = wc_ecc_sign_hash((void*)hash, sizeof(hash),
                                               (void*)sig, &sigLen, rng,
                                               bobKey);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_ecc_sign_hash %d\n",
                                           ret);
                        } else {
                            int res = 0;
                            ret     = wc_ecc_verify_hash((void*)sig, sigLen,
                                                         (void*)hash, sizeof(hash),
                                                         &res, bobKey);
                            if (ret != 0) {
                                WH_ERROR_PRINT("Failed to wc_ecc_verify_hash"
                                               " %d\n",
                                               ret);
                            }
                            else {
                                if (res == 1) {
                                    WH_TEST_PRINT(
                                        "ECC ephemeral SIGN/VERIFY SUCCESS\n");
                                }
                                else {
                                    WH_ERROR_PRINT(
                                        "ECC ephemeral SIGN/VERIFY FAIL\n");
                                    ret = -1;
                                }
                            }
                        }
                    }
                }
            }
            wc_ecc_free(aliceKey);
        }
        wc_ecc_free(bobKey);
    }

    /* Test Case 2: Using client export key */
    if (ret == 0) {
        memset(shared_ab, 0, sizeof(shared_ab));
        memset(shared_ba, 0, sizeof(shared_ba));
        memset(sig, 0, sizeof(sig));

        ret = wc_ecc_init_ex(bobKey, NULL, WH_CLIENT_DEVID(ctx));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_ecc_init_ex for export key %d\n", ret);
        }
        else {
            ret = wc_ecc_init_ex(aliceKey, NULL, WH_CLIENT_DEVID(ctx));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_ecc_init_ex for export key %d\n",
                               ret);
            }
            else {
                /* Server creates keys and exports them to client */
                ret = wh_Client_EccMakeExportKey(ctx, TEST_ECC_KEYSIZE,
                                                 TEST_ECC_CURVE_ID, bobKey);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_EccMakeExportKey %d\n",
                                   ret);
                }
                if (ret == 0) {
                    ret = wh_Client_EccMakeExportKey(
                        ctx, TEST_ECC_KEYSIZE, TEST_ECC_CURVE_ID, aliceKey);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to wh_Client_EccMakeExportKey %d\n", ret);
                    }
                }
                /* Test ECDH with exported keys */
                if (ret == 0) {
                    word32 secLen = TEST_ECC_KEYSIZE;
                    ret           = wc_ecc_shared_secret(bobKey, aliceKey,
                                                         (byte*)shared_ab, &secLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to compute export key secret %d\n", ret);
                    }
                }
                if (ret == 0) {
                    word32 secLen = TEST_ECC_KEYSIZE;
                    ret           = wc_ecc_shared_secret(aliceKey, bobKey,
                                                         (byte*)shared_ba, &secLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to compute export key secret %d\n", ret);
                    }
                }
                if (ret == 0) {
                    if (memcmp(shared_ab, shared_ba, TEST_ECC_KEYSIZE) != 0) {
                        WH_ERROR_PRINT("ECC export key ECDH FAILED TO MATCH\n");
                        ret = -1;
                    }
                    else {
                        WH_TEST_PRINT("ECC export key ECDH SUCCESS\n");
                    }
                }
                /* Test ECDSA sign/verify with exported keys */
                if (ret == 0) {
                    memcpy(hash, shared_ba, sizeof(hash));
                    word32 sigLen = sizeof(sig);
                    ret           = wc_ecc_sign_hash((void*)hash, sizeof(hash),
                                                     (void*)sig, &sigLen, rng, bobKey);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to sign with export key %d\n",
                                       ret);
                    }
                    else {
                        int res = 0;
                        ret =
                            wc_ecc_verify_hash((void*)sig, sigLen, (void*)hash,
                                               sizeof(hash), &res, bobKey);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to verify with export key %d\n", ret);
                        }
                        else if (res != 1) {
                            WH_ERROR_PRINT("ECC export key SIGN/VERIFY FAIL\n");
                            ret = -1;
                        }
                        else {
                            WH_TEST_PRINT(
                                "ECC export key SIGN/VERIFY SUCCESS\n");
                        }
                    }
                }
                wc_ecc_free(aliceKey);
            }
            wc_ecc_free(bobKey);
        }
    }

    /* Test Case 3: Using keyCache key (key stays on server)
     * Use only ONE cached key to avoid key cache space issues.
     * For ECDH, use an ephemeral peer key. */
    if (ret == 0) {
        memset(shared_ab, 0, sizeof(shared_ab));
        memset(shared_ba, 0, sizeof(shared_ba));
        memset(sig, 0, sizeof(sig));
        keyIdPrivate = WH_KEYID_ERASED;

        /* Server creates and caches one key */
        ret = wh_Client_EccMakeCacheKey(ctx, TEST_ECC_KEYSIZE,
                                        TEST_ECC_CURVE_ID, &keyIdPrivate, flags,
                                        sizeof(labelPrivate), labelPrivate);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_EccMakeCacheKey %d\n", ret);
        }
        if (ret == 0) {
            /* Init the cached key struct and associate with server key ID */
            ret = wc_ecc_init_ex(bobKey, NULL, WH_CLIENT_DEVID(ctx));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_ecc_init_ex for cache key %d\n",
                               ret);
            }
            else {
                ret = wh_Client_EccSetKeyId(bobKey, keyIdPrivate);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_EccSetKeyId %d\n", ret);
                }
                /* Verify key ID was set correctly */
                if (ret == 0) {
                    ret = wh_Client_EccGetKeyId(bobKey, &checkKeyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wh_Client_EccGetKeyId %d\n",
                                       ret);
                    }
                    else if (checkKeyId != keyIdPrivate) {
                        WH_ERROR_PRINT(
                            "ECC key ID mismatch: got %u, expected %u\n",
                            checkKeyId, keyIdPrivate);
                        ret = -1;
                    }
                }
                /* Set curve parameters (required since key data isn't exported)
                 */
                if (ret == 0) {
                    ret = wc_ecc_set_curve(bobKey, TEST_ECC_KEYSIZE,
                                           TEST_ECC_CURVE_ID);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_ecc_set_curve %d\n", ret);
                    }
                }
                /* Create ephemeral peer key for ECDH test */
                if (ret == 0) {
                    ret = wc_ecc_init_ex(aliceKey, NULL, WH_CLIENT_DEVID(ctx));
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to wc_ecc_init_ex for peer key %d\n", ret);
                    }
                    else {
                        ret = wc_ecc_make_key(rng, TEST_ECC_KEYSIZE, aliceKey);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to wc_ecc_make_key for peer %d\n", ret);
                        }
                        /* Test ECDH: cached key with ephemeral peer */
                        if (ret == 0) {
                            word32 secLen = TEST_ECC_KEYSIZE;
                            ret           = wc_ecc_shared_secret(
                                bobKey, aliceKey, (byte*)shared_ab, &secLen);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed to compute cache key secret %d\n",
                                    ret);
                            }
                        }
                        if (ret == 0) {
                            word32 secLen = TEST_ECC_KEYSIZE;
                            ret           = wc_ecc_shared_secret(
                                aliceKey, bobKey, (byte*)shared_ba, &secLen);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed to compute peer secret %d\n", ret);
                            }
                        }
                        if (ret == 0) {
                            if (memcmp(shared_ab, shared_ba,
                                       TEST_ECC_KEYSIZE) != 0) {
                                WH_ERROR_PRINT(
                                    "ECC cache key ECDH FAILED TO MATCH\n");
                                ret = -1;
                            }
                            else {
                                WH_TEST_PRINT("ECC cache key ECDH SUCCESS\n");
                            }
                        }
                        wc_ecc_free(aliceKey);
                    }
                }
                /* Test ECDSA sign/verify with cached key */
                if (ret == 0) {
                    memcpy(hash, shared_ba, sizeof(hash));
                    word32 sigLen = sizeof(sig);
                    ret           = wc_ecc_sign_hash((void*)hash, sizeof(hash),
                                                     (void*)sig, &sigLen, rng, bobKey);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to sign with cache key %d\n",
                                       ret);
                    }
                    else {
                        int res = 0;
                        ret =
                            wc_ecc_verify_hash((void*)sig, sigLen, (void*)hash,
                                               sizeof(hash), &res, bobKey);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to verify with cache key %d\n", ret);
                        }
                        else if (res != 1) {
                            WH_ERROR_PRINT("ECC cache key SIGN/VERIFY FAIL\n");
                            ret = -1;
                        }
                        else {
                            WH_TEST_PRINT(
                                "ECC cache key SIGN/VERIFY SUCCESS\n");
                        }
                    }
                }
                wc_ecc_free(bobKey);
            }
        }
        /* Evict server key regardless of test success */
        if (!WH_KEYID_ISERASED(keyIdPrivate)) {
            (void)wh_Client_KeyEvict(ctx, keyIdPrivate);
        }
    }

    /* Export-public-only test on a NONEXPORTABLE cached ECC key. Generate
     * a signature on the HSM and verify it client-side using the exported
     * public key. */
    if (ret == 0) {
        whKeyId pubOnlyId = WH_KEYID_ERASED;
        ecc_key pubKey[1];
        uint8_t sig[ECC_MAX_SIG_SIZE];
        word32  sigLen   = sizeof(sig);
        int     verify   = 0;
        /* Large enough to hold an ECC key DER so the access-control assertion
         * doesn't get masked by a buffer-too-small failure. */
        uint8_t denyBuf[256];
        uint16_t denyLen = sizeof(denyBuf);

        ret = wh_Client_EccMakeCacheKey(
            ctx, TEST_ECC_KEYSIZE, TEST_ECC_CURVE_ID, &pubOnlyId,
            WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |
                WH_NVM_FLAGS_NONEXPORTABLE,
            0, NULL);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to make NONEXPORTABLE cached ECC key %d\n", ret);
        }

        /* Full export must be denied */
        if (ret == 0) {
            int denyRet = wh_Client_KeyExport(ctx, pubOnlyId, NULL, 0,
                                              denyBuf, &denyLen);
            if (denyRet != WH_ERROR_ACCESS) {
                WH_ERROR_PRINT(
                    "NONEXPORTABLE ECC full export was not denied: %d\n",
                    denyRet);
                ret = -1;
            }
        }

        /* Sign on HSM using the cached private key */
        if (ret == 0) {
            ecc_key hsmKey[1];
            ret = wc_ecc_init_ex(hsmKey, NULL, devId);
            if (ret == 0) {
                ret = wh_Client_EccSetKeyId(hsmKey, pubOnlyId);
            }
            if (ret == 0) {
                ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng,
                                       hsmKey);
                if (ret != 0) {
                    WH_ERROR_PRINT("HSM ECC sign failed %d\n", ret);
                }
            }
            wc_ecc_free(hsmKey);
        }

        /* Export the public key, then verify client-side */
        if (ret == 0) {
            ret = wc_ecc_init_ex(pubKey, NULL, INVALID_DEVID);
            if (ret == 0) {
                ret = wh_Client_EccExportPublicKey(ctx, pubOnlyId, pubKey, 0,
                                                   NULL);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "wh_Client_EccExportPublicKey failed %d\n", ret);
                }
                else if (pubKey->type != ECC_PUBLICKEY) {
                    WH_ERROR_PRINT(
                        "Exported ECC key is not public-only (type=%d)\n",
                        pubKey->type);
                    ret = -1;
                }
                else {
                    ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash),
                                             &verify, pubKey);
                    if (ret != 0 || verify != 1) {
                        WH_ERROR_PRINT(
                            "Client-side ECC verify failed ret=%d verify=%d\n",
                            ret, verify);
                        if (ret == 0) {
                            ret = -1;
                        }
                    }
                }
                wc_ecc_free(pubKey);
            }
        }

        if (!WH_KEYID_ISERASED(pubOnlyId)) {
            (void)wh_Client_KeyEvict(ctx, pubOnlyId);
        }

        if (ret == 0) {
            WH_TEST_PRINT("ECC EXPORT-PUBLIC SUCCESS\n");
        }
    }

    /* Cache-and-export-public: a single keygen call returns the public key */
    if (ret == 0) {
        whKeyId  cacheId  = WH_KEYID_ERASED;
        ecc_key  genPub[1];
        ecc_key  refPub[1];
        byte     genDer[256];
        byte     refDer[256];
        int      genDerSz = 0;
        int      refDerSz = 0;
        int      genInit  = 0;
        int      refInit  = 0;
        uint8_t  sig[ECC_MAX_SIG_SIZE];
        word32   sigLen   = sizeof(sig);
        int      verify   = 0;
        uint8_t  label[]  = "ecc-cache-export";
        uint8_t  readLabel[WH_NVM_LABEL_LEN] = {0};

        ret = wc_ecc_init_ex(genPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            genInit = 1;
            /* Exercise label forwarding on the cache-and-export path. */
            ret     = wh_Client_EccMakeCacheKeyAndExportPublic(
                ctx, TEST_ECC_KEYSIZE, TEST_ECC_CURVE_ID, &cacheId,
                WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY,
                sizeof(label), label, genPub);
            if (ret != 0) {
                WH_ERROR_PRINT("EccMakeCacheKeyAndExportPublic failed %d\n",
                               ret);
            }
        }

        /* Cross-check the keygen-returned public key against ExportPublicKey,
         * and confirm the label was stored with the cached key. */
        if (ret == 0) {
            ret = wc_ecc_init_ex(refPub, NULL, INVALID_DEVID);
            if (ret == 0) {
                refInit = 1;
                ret     = wh_Client_EccExportPublicKey(
                    ctx, cacheId, refPub, sizeof(readLabel), readLabel);
                if (ret != 0) {
                    WH_ERROR_PRINT("wh_Client_EccExportPublicKey failed %d\n",
                                   ret);
                }
                else if (memcmp(readLabel, label, sizeof(label)) != 0) {
                    WH_ERROR_PRINT("keygen label not stored with cached key\n");
                    ret = -1;
                }
            }
        }
        if (ret == 0) {
            genDerSz = wc_EccPublicKeyToDer(genPub, genDer, sizeof(genDer), 1);
            refDerSz = wc_EccPublicKeyToDer(refPub, refDer, sizeof(refDer), 1);
            if ((genDerSz <= 0) || (genDerSz != refDerSz) ||
                (memcmp(genDer, refDer, (size_t)genDerSz) != 0)) {
                WH_ERROR_PRINT("keygen pubkey mismatch vs ExportPublicKey\n");
                ret = -1;
            }
        }

        /* Prove usability: sign on the HSM using genPub directly as the
         * private-key handle (no separate key object), then verify locally with
         * the exported public key (refPub) the client holds. */
        if (ret == 0) {
            ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng,
                                   genPub);
            if (ret != 0) {
                WH_ERROR_PRINT("HSM ECC sign failed %d\n", ret);
            }
        }
        if (ret == 0) {
            ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &verify,
                                     refPub);
            if ((ret != 0) || (verify != 1)) {
                WH_ERROR_PRINT(
                    "verify with keygen pub failed ret=%d verify=%d\n", ret,
                    verify);
                if (ret == 0) {
                    ret = -1;
                }
            }
        }

        if (genInit != 0) {
            wc_ecc_free(genPub);
        }
        if (refInit != 0) {
            wc_ecc_free(refPub);
        }
        if (!WH_KEYID_ISERASED(cacheId)) {
            (void)wh_Client_KeyEvict(ctx, cacheId);
        }

        if (ret == 0) {
            WH_TEST_PRINT("ECC CACHE-AND-EXPORT-PUBLIC SUCCESS\n");
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("ECC SUCCESS\n");
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Generic-transport DMA smoke test: cache an ECC keypair, export the
 * public half via wh_Client_KeyExportPublicDma (no per-algo wrapper),
 * deserialize, and verify a HSM-side signature. The HSM sign step uses
 * the regular (non-DMA) ECC cryptoCb because ECC sign over DMA is not in
 * scope for this test - the DMA bit being exercised is the public-key
 * export only. */
static int whTest_CryptoEccExportPublicDma(whClientContext* ctx, int devId,
                                           WC_RNG* rng)
{
    int     ret               = 0;
    whKeyId keyId             = WH_KEYID_ERASED;
    ecc_key pubKey[1]         = {0};
    /* Non-zero digest: wolfCrypt rejects all-zero hashes with ECC_BAD_ARG_E
     * unless WC_ALLOW_ECC_ZERO_HASH is defined. */
    uint8_t hash[TEST_ECC_KEYSIZE];
    uint8_t sig[ECC_MAX_SIG_SIZE]  = {0};
    word32  sigLen            = sizeof(sig);
    int     verified          = 0;
    byte    derBuf[ECC_BUFSIZE];
    uint16_t derSz            = sizeof(derBuf);
    word32   i;
    (void)devId;

    for (i = 0; i < sizeof(hash); i++) {
        hash[i] = (uint8_t)(i + 1);
    }

    ret = wh_Client_EccMakeCacheKey(
        ctx, TEST_ECC_KEYSIZE, TEST_ECC_CURVE_ID, &keyId,
        WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |
            WH_NVM_FLAGS_NONEXPORTABLE,
        0, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT(
            "Failed to make NONEXPORTABLE ECC cached key (DMA test) %d\n",
            ret);
        return ret;
    }

    /* Sign on HSM with the cached private key (non-DMA cryptoCb). */
    if (ret == 0) {
        ecc_key hsmKey[1];
        ret = wc_ecc_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
        if (ret == 0) {
            ret = wh_Client_EccSetKeyId(hsmKey, keyId);
        }
        if (ret == 0) {
            ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng,
                                   hsmKey);
        }
        wc_ecc_free(hsmKey);
    }

    /* Pull the public half out of the HSM via the generic DMA transport. */
    if (ret == 0) {
        ret = wh_Client_KeyExportPublicDma(ctx, keyId, WH_KEY_ALGO_ECC,
                                           derBuf, derSz, NULL, 0, &derSz);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "wh_Client_KeyExportPublicDma(ECC) failed %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wc_ecc_init_ex(pubKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Crypto_EccDeserializeKeyDer(derBuf, derSz, pubKey);
        }
        if (ret == 0 && pubKey->type != ECC_PUBLICKEY) {
            WH_ERROR_PRINT(
                "Exported ECC key (DMA) is not public-only (type=%d)\n",
                pubKey->type);
            ret = -1;
        }
        if (ret == 0) {
            ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash),
                                     &verified, pubKey);
            if (ret != 0 || verified != 1) {
                WH_ERROR_PRINT(
                    "Client-side ECC verify (DMA) failed ret=%d verify=%d\n",
                    ret, verified);
                if (ret == 0) {
                    ret = -1;
                }
            }
        }
        wc_ecc_free(pubKey);
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("ECC EXPORT-PUBLIC DMA SUCCESS\n");
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

static int whTest_CryptoEccCacheDuplicate(whClientContext* client)
{
    int      ret   = WH_ERROR_OK;
    whKeyId  keyId = WH_KEYID_ERASED;
    uint8_t  key1[ECC_BUFSIZE];
    uint8_t  key2[ECC_BUFSIZE];
    uint16_t key1Len = sizeof(key1);
    uint16_t key2Len = sizeof(key2);

    WH_TEST_PRINT("  Testing ECC cache duplicate returns latest key...\n");

    /* Generate first cached key and export it */
    ret = wh_Client_EccMakeCacheKey(client, 32, ECC_SECP256R1, &keyId,
                                    WH_NVM_FLAGS_NONE, 0, NULL);
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_KeyExport(client, keyId, NULL, 0, key1, &key1Len);
    }

    /* Generate a second key using the same keyId to create a duplicate slot */
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_EccMakeCacheKey(client, 32, ECC_SECP256R1, &keyId,
                                        WH_NVM_FLAGS_NONE, 0, NULL);
    }

    /* Export again; result should match the most recent key, not the first */
    if (ret == WH_ERROR_OK) {
        key2Len = sizeof(key2);
        ret     = wh_Client_KeyExport(client, keyId, NULL, 0, key2, &key2Len);
    }

    if (ret == WH_ERROR_OK) {
        if ((key1Len == key2Len) && (memcmp(key1, key2, key1Len) == 0)) {
            WH_ERROR_PRINT("    FAIL: Export returned original ECC key after "
                           "duplicate insert\n");
            ret = WH_ERROR_ABORTED;
        }
        else {
            WH_TEST_PRINT(
                "    PASS: Export returned most recent cached ECC key\n");
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        wh_Client_KeyEvict(client, keyId);
    }

    return ret;
}

#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)

/* Key sizes in bytes for each curve */
#define WH_TEST_ECC_P256_KEY_SIZE 32
#define WH_TEST_ECC_P384_KEY_SIZE 48
#define WH_TEST_ECC_P521_KEY_SIZE 66

/* Use maximum digest size for all curves to test hash truncation edge cases.
 * ECDSA implementations must properly truncate hashes larger than the curve
 * order. */
#define WH_TEST_ECC_HASH_SIZE WC_MAX_DIGEST_SIZE

static int whTest_CryptoEccCrossVerify_OneCurve(whClientContext* ctx,
                                                WC_RNG* rng, int keySize,
                                                int curveId, const char* name)
{
    ecc_key hsmKey[1]                   = {0};
    ecc_key swKey[1]                    = {0};
    uint8_t hash[WH_TEST_ECC_HASH_SIZE] = {0};
    uint8_t sig[ECC_MAX_SIG_SIZE]       = {0};
    uint8_t pubX[ECC_MAXSIZE]           = {0};
    uint8_t pubY[ECC_MAXSIZE]           = {0};
    word32  pubXLen                     = 0;
    word32  pubYLen                     = 0;
    word32  sigLen                      = 0;
    int     res                         = 0;
    whKeyId keyId                       = WH_KEYID_ERASED;
    int     hsmKeyInit                  = 0;
    int     swKeyInit                   = 0;
    int     ret                         = WH_ERROR_OK;
    int     i;

    /* Use non-repeating pattern to detect hash truncation bugs */
    for (i = 0; i < WH_TEST_ECC_HASH_SIZE; i++) {
        hash[i] = (uint8_t)i;
    }

    WH_TEST_PRINT("  Testing %s curve...\n", name);

    pubXLen = keySize;
    pubYLen = keySize;

    /* Test 1: HSM sign + Software verify */
    ret = wc_ecc_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("%s: Failed to init HSM key: %d\n", name, ret);
    }
    else {
        hsmKeyInit = 1;
    }
    if (ret == 0) {
        ret = wc_ecc_make_key(rng, keySize, hsmKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to generate HSM key: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        /* Export public key from HSM */
        ret = wc_ecc_export_public_raw(hsmKey, pubX, &pubXLen, pubY, &pubYLen);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to export HSM public key: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        /* Sign with HSM */
        sigLen = sizeof(sig);
        ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, hsmKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: HSM sign failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        /* Import public key into software key for verification */
        ret = wc_ecc_init_ex(swKey, NULL, INVALID_DEVID);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to init SW key: %d\n", name, ret);
        }
        else {
            swKeyInit = 1;
        }
    }
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(swKey, pubX, pubY, NULL, curveId);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to import public to SW: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        /* Verify with software */
        res = 0;
        ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &res, swKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: SW verify failed: %d\n", name, ret);
        }
        else if (res != 1) {
            WH_ERROR_PRINT("%s: HSM sign + SW verify: signature invalid\n",
                           name);
            ret = -1;
        }
        else {
            WH_TEST_PRINT("    HSM sign + SW verify: PASS\n");
        }
    }
    /* Cleanup Test 1 keys */
    if (swKeyInit) {
        wc_ecc_free(swKey);
        swKeyInit = 0;
    }
    if (hsmKeyInit) {
        if (wh_Client_EccGetKeyId(hsmKey, &keyId) == 0 &&
            !WH_KEYID_ISERASED(keyId)) {
            (void)wh_Client_KeyEvict(ctx, keyId);
        }
        wc_ecc_free(hsmKey);
        hsmKeyInit = 0;
    }

    /* Test 2: Software sign + HSM verify */
    if (ret == 0) {
        memset(sig, 0, sizeof(sig));
        memset(pubX, 0, sizeof(pubX));
        memset(pubY, 0, sizeof(pubY));
        pubXLen = keySize;
        pubYLen = keySize;
        keyId   = WH_KEYID_ERASED;

        ret = wc_ecc_init_ex(swKey, NULL, INVALID_DEVID);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to init SW key: %d\n", name, ret);
        }
        else {
            swKeyInit = 1;
        }
    }
    if (ret == 0) {
        ret = wc_ecc_make_key(rng, keySize, swKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to generate SW key: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        /* Export public key from software */
        ret = wc_ecc_export_public_raw(swKey, pubX, &pubXLen, pubY, &pubYLen);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to export SW public key: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        /* Sign with software */
        sigLen = sizeof(sig);
        ret    = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, swKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: SW sign failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        /* Import public key into HSM key for verification */
        ret = wc_ecc_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to init HSM key: %d\n", name, ret);
        }
        else {
            hsmKeyInit = 1;
        }
    }
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(hsmKey, pubX, pubY, NULL, curveId);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to import public to HSM: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        /* Verify with HSM */
        res = 0;
        ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &res, hsmKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: HSM verify failed: %d\n", name, ret);
        }
        else if (res != 1) {
            WH_ERROR_PRINT("%s: SW sign + HSM verify: signature invalid\n",
                           name);
            ret = -1;
        }
        else {
            WH_TEST_PRINT("    SW sign + HSM verify: PASS\n");
        }
    }
    /* Cleanup Test 2 keys */
    if (hsmKeyInit) {
        if (wh_Client_EccGetKeyId(hsmKey, &keyId) == 0 &&
            !WH_KEYID_ISERASED(keyId)) {
            (void)wh_Client_KeyEvict(ctx, keyId);
        }
        wc_ecc_free(hsmKey);
    }
    if (swKeyInit) {
        wc_ecc_free(swKey);
    }

    return ret;
}

/**
 * Test ECDSA cross-verification between HSM and software implementations.
 * This detects bugged hardware that might verify its own bad signatures.
 *
 * Tests two scenarios per curve:
 * 1. HSM sign + Software verify
 * 2. Software sign + HSM verify
 */
static int whTest_CryptoEccCrossVerify(whClientContext* ctx, WC_RNG* rng)
{
    int ret = WH_ERROR_OK;

    WH_TEST_PRINT("Testing ECDSA cross-verification (HSM<->SW)...\n");

#if !defined(NO_ECC256)
    if (ret == 0) {
        ret = whTest_CryptoEccCrossVerify_OneCurve(
            ctx, rng, WH_TEST_ECC_P256_KEY_SIZE, ECC_SECP256R1, "P-256");
    }
#endif

#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
    if (ret == 0) {
        ret = whTest_CryptoEccCrossVerify_OneCurve(
            ctx, rng, WH_TEST_ECC_P384_KEY_SIZE, ECC_SECP384R1, "P-384");
    }
#endif

#if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
    if (ret == 0) {
        ret = whTest_CryptoEccCrossVerify_OneCurve(
            ctx, rng, WH_TEST_ECC_P521_KEY_SIZE, ECC_SECP521R1, "P-521");
    }
#endif

    if (ret == 0) {
        WH_TEST_PRINT("ECDSA cross-verification SUCCESS\n");
    }

    return ret;
}

/**
 * Test the async Request/Response API for ECC sign and verify.
 *
 * For each curve:
 * 1. Generate a HSM ECC key (server-cached with an assigned keyId).
 * 2. Call wh_Client_EccSignRequest + poll wh_Client_EccSignResponse; verify
 *    the resulting signature in software.
 * 3. Import the public key as a separate cache slot; call
 *    wh_Client_EccVerifyRequest + poll wh_Client_EccVerifyResponse; assert
 *    res == 1.
 * 4. Assert that *Request() with an erased keyId returns WH_ERROR_BADARGS.
 */
static int whTest_CryptoEccSignVerifyAsync_OneCurve(whClientContext* ctx,
                                                    WC_RNG* rng, int keySize,
                                                    int         curveId,
                                                    const char* name)
{
    ecc_key  hsmKey[1]                   = {0};
    ecc_key  swKey[1]                    = {0};
    uint8_t  hash[WH_TEST_ECC_HASH_SIZE] = {0};
    uint8_t  sig[ECC_MAX_SIG_SIZE]       = {0};
    uint8_t  pubX[ECC_MAXSIZE]           = {0};
    uint8_t  pubY[ECC_MAXSIZE]           = {0};
    word32   pubXLen                     = 0;
    word32   pubYLen                     = 0;
    uint16_t sigLen                      = 0;
    int      res                         = 0;
    whKeyId  signKeyId                   = WH_KEYID_ERASED;
    whKeyId  verifyKeyId                 = WH_KEYID_ERASED;
    int      hsmKeyInit                  = 0;
    int      swKeyInit                   = 0;
    int      ret                         = WH_ERROR_OK;
    int      i;

    /* Use non-repeating pattern to detect hash truncation bugs */
    for (i = 0; i < WH_TEST_ECC_HASH_SIZE; i++) {
        hash[i] = (uint8_t)i;
    }

    WH_TEST_PRINT("  Testing async Sign/Verify %s curve...\n", name);

    pubXLen = keySize;
    pubYLen = keySize;

    ret = wc_ecc_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
    if (ret == 0) {
        hsmKeyInit = 1;
        ret        = wc_ecc_make_key(rng, keySize, hsmKey);
    }
    if (ret == 0) {
        uint8_t signLabel[] = "TestEccAsyncSign";
        signKeyId           = WH_KEYID_ERASED;
        ret                 = wh_Client_EccImportKey(ctx, hsmKey, &signKeyId,
                                                     WH_NVM_FLAGS_USAGE_SIGN, sizeof(signLabel),
                                                     signLabel);
    }

    /* Async sign */
    if (ret == 0) {
        sigLen = sizeof(sig);
        ret    = wh_Client_EccSignRequest(ctx, signKeyId, hash, sizeof(hash));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccSignRequest failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccSignResponse(ctx, sig, &sigLen);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccSignResponse failed: %d\n", name, ret);
        }
    }

    /* Precondition: erased keyId must return BADARGS from Request */
    if (ret == 0) {
        int badret =
            wh_Client_EccSignRequest(ctx, WH_KEYID_ERASED, hash, sizeof(hash));
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: EccSignRequest with erased keyId returned %d "
                           "(want BADARGS)\n",
                           name, badret);
            ret = -1;
        }
    }

    /* Export public key from HSM for verify path */
    if (ret == 0) {
        ret = wc_ecc_export_public_raw(hsmKey, pubX, &pubXLen, pubY, &pubYLen);
    }

    /* Software verify as an independent sanity check */
    if (ret == 0) {
        ret = wc_ecc_init_ex(swKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            swKeyInit = 1;
            ret = wc_ecc_import_unsigned(swKey, pubX, pubY, NULL, curveId);
        }
    }
    if (ret == 0) {
        res = 0;
        ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &res, swKey);
        if (ret == 0 && res != 1) {
            WH_ERROR_PRINT("%s: async sign produced invalid signature\n", name);
            ret = -1;
        }
    }

    /* Import the public key into a second HSM cache slot and async-verify */
    if (ret == 0) {
        ecc_key pubOnly[1] = {0};
        uint8_t label[]    = "TestEccAsyncVerify";

        ret = wc_ecc_init_ex(pubOnly, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_ecc_import_unsigned(pubOnly, pubX, pubY, NULL, curveId);
        }
        if (ret == 0) {
            verifyKeyId = WH_KEYID_ERASED;
            ret         = wh_Client_EccImportKey(ctx, pubOnly, &verifyKeyId,
                                                 WH_NVM_FLAGS_USAGE_VERIFY,
                                                 sizeof(label), label);
        }
        wc_ecc_free(pubOnly);
    }
    if (ret == 0) {
        ret = wh_Client_EccVerifyRequest(ctx, verifyKeyId, sig, sigLen, hash,
                                         sizeof(hash));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccVerifyRequest failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        res = 0;
        do {
            ret = wh_Client_EccVerifyResponse(ctx, NULL, &res);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccVerifyResponse failed: %d\n", name, ret);
        }
        else if (res != 1) {
            WH_ERROR_PRINT("%s: async verify returned res=%d (want 1)\n", name,
                           res);
            ret = -1;
        }
    }
    if (ret == 0) {
        int badret = wh_Client_EccVerifyRequest(ctx, WH_KEYID_ERASED, sig,
                                                sigLen, hash, sizeof(hash));
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: EccVerifyRequest with erased keyId returned %d "
                           "(want BADARGS)\n",
                           name, badret);
            ret = -1;
        }
    }

    /* NULL ctx must be rejected by every async half (matches RNG discipline).
     */
    if (ret == 0) {
        int rc1 = wh_Client_EccSignRequest(NULL, signKeyId, hash, sizeof(hash));
        int rc2 = wh_Client_EccSignResponse(NULL, sig, &sigLen);
        int rc3 = wh_Client_EccVerifyRequest(NULL, verifyKeyId, sig, sigLen,
                                             hash, sizeof(hash));
        int rc4 = wh_Client_EccVerifyResponse(NULL, NULL, &res);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS ||
            rc3 != WH_ERROR_BADARGS || rc4 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: NULL ctx async API rc=(%d,%d,%d,%d) want all "
                           "BADARGS\n",
                           name, rc1, rc2, rc3, rc4);
            ret = -1;
        }
    }

    /* Mismatched output-arg shape on Response must BADARGS pre-Recv. ctx has
     * no pending request here, so this also confirms the call is
     * non-mutating. */
    if (ret == 0) {
        int rc1 = wh_Client_EccSignResponse(ctx, sig, NULL);
        int rc2 = wh_Client_EccVerifyResponse(ctx, NULL, NULL);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: bad-arg Response rc=(%d,%d) want both BADARGS\n", name,
                rc1, rc2);
            ret = -1;
        }
    }

    /* Wrapper-level regression: response-side bad args must be caught before
     * SendRequest so the caller's ctx is not left stuck-pending. */
    if (ret == 0) {
        int badret = wh_Client_EccVerify(ctx, hsmKey, sig, sigLen, hash,
                                         sizeof(hash), NULL);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: EccVerify with NULL out_res returned %d "
                           "(want BADARGS)\n",
                           name, badret);
            ret = -1;
        }
    }

    /* Confirm ctx is still usable after the wrapper rejection. */
    if (ret == 0) {
        int rc;
        sigLen = sizeof(sig);
        rc     = wh_Client_EccSignRequest(ctx, signKeyId, hash, sizeof(hash));
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccSignResponse(ctx, sig, &sigLen);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: ctx stuck after wrapper BADARGS (rc=%d)\n",
                           name, rc);
            ret = -1;
        }
    }

    /* Too-small sig buffer must return WH_ERROR_BUFFER_SIZE with the required
     * size in *inout_sig_len, and must NOT write a partial signature. Mirrors
     * the matching ECDH regression test, since the implementation explicitly
     * promises to fail rather than silently truncate signature bytes. */
    if (ret == 0) {
        uint8_t  small_buf[1] = {0xAA};
        uint16_t small_len    = sizeof(small_buf);
        int      rc;
        rc = wh_Client_EccSignRequest(ctx, signKeyId, hash, sizeof(hash));
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccSignResponse(ctx, small_buf, &small_len);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT(
                "%s: too-small buffer Sign Response rc=%d (want BUFFER_SIZE)\n",
                name, rc);
            ret = -1;
        }
        else if (small_len <= 1 || small_len > ECC_MAX_SIG_SIZE) {
            WH_ERROR_PRINT("%s: too-small buffer Sign required size=%u "
                           "(want > 1 and <= ECC_MAX_SIG_SIZE)\n",
                           name, (unsigned)small_len);
            ret = -1;
        }
        else if (small_buf[0] != 0xAA) {
            WH_ERROR_PRINT(
                "%s: partial signature leaked into too-small buffer\n", name);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("    async Sign/Verify %s: PASS\n", name);
    }

    /* Cleanup: evict any cached keys, free wolfCrypt structs */
    if (!WH_KEYID_ISERASED(verifyKeyId)) {
        (void)wh_Client_KeyEvict(ctx, verifyKeyId);
    }
    if (!WH_KEYID_ISERASED(signKeyId)) {
        (void)wh_Client_KeyEvict(ctx, signKeyId);
    }
    if (swKeyInit) {
        wc_ecc_free(swKey);
    }
    if (hsmKeyInit) {
        wc_ecc_free(hsmKey);
    }
    return ret;
}

#ifdef HAVE_ECC_DHE
/**
 * Test the async Request/Response API for ECDH.
 *
 * For each curve:
 * 1. Generate two HSM ECC keys (both server-cached).
 * 2. Export public bytes from each, import each into the opposite side as a
 *    separate cache slot so we have a (private_A, public_B) and
 *    (private_B, public_A) pair for cross-verification.
 * 3. Call wh_Client_EccSharedSecretRequest + poll
 *    wh_Client_EccSharedSecretResponse with (privA, pubB) and (privB, pubA).
 * 4. Assert both shared secrets are equal.
 * 5. Assert that *Request() with an erased keyId returns WH_ERROR_BADARGS.
 */
static int whTest_CryptoEccSharedSecretAsync_OneCurve(whClientContext* ctx,
                                                      WC_RNG* rng, int keySize,
                                                      int         curveId,
                                                      const char* name)
{
    ecc_key  keyA[1]                = {0};
    ecc_key  keyB[1]                = {0};
    ecc_key  pubA[1]                = {0};
    ecc_key  pubB[1]                = {0};
    uint8_t  pubAx[ECC_MAXSIZE]     = {0};
    uint8_t  pubAy[ECC_MAXSIZE]     = {0};
    uint8_t  pubBx[ECC_MAXSIZE]     = {0};
    uint8_t  pubBy[ECC_MAXSIZE]     = {0};
    word32   pubAxLen               = 0;
    word32   pubAyLen               = 0;
    word32   pubBxLen               = 0;
    word32   pubByLen               = 0;
    uint8_t  secret_AB[ECC_MAXSIZE] = {0};
    uint8_t  secret_BA[ECC_MAXSIZE] = {0};
    uint16_t secret_AB_len          = sizeof(secret_AB);
    uint16_t secret_BA_len          = sizeof(secret_BA);
    whKeyId  privAId                = WH_KEYID_ERASED;
    whKeyId  privBId                = WH_KEYID_ERASED;
    whKeyId  pubAId                 = WH_KEYID_ERASED;
    whKeyId  pubBId                 = WH_KEYID_ERASED;
    int      keyAInit               = 0;
    int      keyBInit               = 0;
    int      pubAInit               = 0;
    int      pubBInit               = 0;
    uint8_t  labelA[]               = "TestEccDhAsyncA";
    uint8_t  labelB[]               = "TestEccDhAsyncB";
    int      ret                    = WH_ERROR_OK;

    WH_TEST_PRINT("  Testing async ECDH %s curve...\n", name);

    pubAxLen = pubAyLen = pubBxLen = pubByLen = keySize;

    /* Generate two local ECC keys, then import each to the server cache so
     * that both private keys have valid keyIds usable by the async API. */
    ret = wc_ecc_init_ex(keyA, NULL, WH_CLIENT_DEVID(ctx));
    if (ret == 0) {
        keyAInit = 1;
        ret      = wc_ecc_make_key(rng, keySize, keyA);
    }
    if (ret == 0) {
        uint8_t privLabelA[] = "TestEccDhAsyncPrivA";
        privAId              = WH_KEYID_ERASED;
        ret                  = wh_Client_EccImportKey(ctx, keyA, &privAId,
                                                      WH_NVM_FLAGS_USAGE_DERIVE,
                                                      sizeof(privLabelA), privLabelA);
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(keyB, NULL, WH_CLIENT_DEVID(ctx));
    }
    if (ret == 0) {
        keyBInit = 1;
        ret      = wc_ecc_make_key(rng, keySize, keyB);
    }
    if (ret == 0) {
        uint8_t privLabelB[] = "TestEccDhAsyncPrivB";
        privBId              = WH_KEYID_ERASED;
        ret                  = wh_Client_EccImportKey(ctx, keyB, &privBId,
                                                      WH_NVM_FLAGS_USAGE_DERIVE,
                                                      sizeof(privLabelB), privLabelB);
    }

    /* Export raw public bytes so we can import into independent cache slots */
    if (ret == 0) {
        ret =
            wc_ecc_export_public_raw(keyA, pubAx, &pubAxLen, pubAy, &pubAyLen);
    }
    if (ret == 0) {
        ret =
            wc_ecc_export_public_raw(keyB, pubBx, &pubBxLen, pubBy, &pubByLen);
    }

    /* Build public-only keys and import each as a distinct cache slot */
    if (ret == 0) {
        ret = wc_ecc_init_ex(pubA, NULL, INVALID_DEVID);
        if (ret == 0) {
            pubAInit = 1;
            ret = wc_ecc_import_unsigned(pubA, pubAx, pubAy, NULL, curveId);
        }
    }
    if (ret == 0) {
        ret = wh_Client_EccImportKey(ctx, pubA, &pubAId,
                                     WH_NVM_FLAGS_USAGE_DERIVE, sizeof(labelA),
                                     labelA);
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(pubB, NULL, INVALID_DEVID);
        if (ret == 0) {
            pubBInit = 1;
            ret = wc_ecc_import_unsigned(pubB, pubBx, pubBy, NULL, curveId);
        }
    }
    if (ret == 0) {
        ret = wh_Client_EccImportKey(ctx, pubB, &pubBId,
                                     WH_NVM_FLAGS_USAGE_DERIVE, sizeof(labelB),
                                     labelB);
    }

    /* Async ECDH: A_priv * B_pub */
    if (ret == 0) {
        ret = wh_Client_EccSharedSecretRequest(ctx, privAId, pubBId);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccSharedSecretResponse(ctx, secret_AB,
                                                    &secret_AB_len);
        } while (ret == WH_ERROR_NOTREADY);
    }

    /* Async ECDH: B_priv * A_pub */
    if (ret == 0) {
        ret = wh_Client_EccSharedSecretRequest(ctx, privBId, pubAId);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccSharedSecretResponse(ctx, secret_BA,
                                                    &secret_BA_len);
        } while (ret == WH_ERROR_NOTREADY);
    }

    if (ret == 0) {
        if (secret_AB_len != secret_BA_len ||
            memcmp(secret_AB, secret_BA, secret_AB_len) != 0) {
            WH_ERROR_PRINT("%s: async ECDH secrets differ across sides\n",
                           name);
            ret = -1;
        }
    }

    /* Too-small output buffer must return WH_ERROR_BUFFER_SIZE with the
     * required size in *inout_size, and must NOT write a partial secret. */
    if (ret == 0) {
        uint8_t  small_buf[1] = {0xAA};
        uint16_t small_len    = sizeof(small_buf);
        int      rc;
        rc = wh_Client_EccSharedSecretRequest(ctx, privAId, pubBId);
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccSharedSecretResponse(ctx, small_buf,
                                                       &small_len);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT(
                "%s: too-small buffer ECDH Response rc=%d (want BUFFER_SIZE)\n",
                name, rc);
            ret = -1;
        }
        else if (small_len != secret_AB_len) {
            WH_ERROR_PRINT("%s: too-small buffer required size=%u (want %u)\n",
                           name, (unsigned)small_len, (unsigned)secret_AB_len);
            ret = -1;
        }
        else if (small_buf[0] != 0xAA) {
            WH_ERROR_PRINT("%s: partial secret leaked into too-small buffer\n",
                           name);
            ret = -1;
        }
    }

    /* Wrapper path must surface BUFFER_SIZE the same way. */
    if (ret == 0) {
        uint8_t  small_buf[1] = {0xAA};
        uint16_t small_len    = sizeof(small_buf);
        int      rc =
            wh_Client_EccSharedSecret(ctx, keyA, pubB, small_buf, &small_len);
        if (rc != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT(
                "%s: too-small buffer ECDH wrapper rc=%d (want BUFFER_SIZE)\n",
                name, rc);
            ret = -1;
        }
        else if (small_len != secret_AB_len) {
            WH_ERROR_PRINT("%s: wrapper too-small required size=%u (want %u)\n",
                           name, (unsigned)small_len, (unsigned)secret_AB_len);
            ret = -1;
        }
        else if (small_buf[0] != 0xAA) {
            WH_ERROR_PRINT(
                "%s: wrapper leaked partial secret into too-small buffer\n",
                name);
            ret = -1;
        }
    }

    /* Precondition: erased keyId on either side must return BADARGS */
    if (ret == 0) {
        int badret =
            wh_Client_EccSharedSecretRequest(ctx, WH_KEYID_ERASED, pubBId);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: ECDH Request with erased priv keyId returned %d\n", name,
                badret);
            ret = -1;
        }
    }
    if (ret == 0) {
        int badret =
            wh_Client_EccSharedSecretRequest(ctx, privAId, WH_KEYID_ERASED);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: ECDH Request with erased pub keyId returned %d\n", name,
                badret);
            ret = -1;
        }
    }

    /* NULL ctx must be rejected by both async halves. */
    if (ret == 0) {
        int rc1 = wh_Client_EccSharedSecretRequest(NULL, privAId, pubBId);
        int rc2 =
            wh_Client_EccSharedSecretResponse(NULL, secret_AB, &secret_AB_len);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: NULL ctx async ECDH rc=(%d,%d) want BADARGS\n",
                           name, rc1, rc2);
            ret = -1;
        }
    }

    /* Response must reject (out != NULL && inout_size == NULL) pre-Recv. */
    if (ret == 0) {
        int rc = wh_Client_EccSharedSecretResponse(ctx, secret_AB, NULL);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: SharedSecretResponse(out, NULL) returned %d "
                           "(want BADARGS)\n",
                           name, rc);
            ret = -1;
        }
    }

    /* Wrapper-level regression: NULL inout_size must BADARGS pre-Send so the
     * caller's ctx is not left stuck-pending. */
    if (ret == 0) {
        int badret =
            wh_Client_EccSharedSecret(ctx, keyA, pubB, secret_AB, NULL);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: EccSharedSecret with NULL inout_size returned %d "
                "(want BADARGS)\n",
                name, badret);
            ret = -1;
        }
    }

    /* Confirm ctx is still usable after the wrapper rejection. */
    if (ret == 0) {
        int rc;
        secret_AB_len = sizeof(secret_AB);
        rc            = wh_Client_EccSharedSecretRequest(ctx, privAId, pubBId);
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccSharedSecretResponse(ctx, secret_AB,
                                                       &secret_AB_len);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: ctx stuck after ECDH wrapper BADARGS (rc=%d)\n",
                           name, rc);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("    async ECDH %s: PASS\n", name);
    }

    /* Cleanup */
    if (!WH_KEYID_ISERASED(pubBId)) {
        (void)wh_Client_KeyEvict(ctx, pubBId);
    }
    if (!WH_KEYID_ISERASED(pubAId)) {
        (void)wh_Client_KeyEvict(ctx, pubAId);
    }
    if (!WH_KEYID_ISERASED(privBId)) {
        (void)wh_Client_KeyEvict(ctx, privBId);
    }
    if (!WH_KEYID_ISERASED(privAId)) {
        (void)wh_Client_KeyEvict(ctx, privAId);
    }
    if (pubBInit) {
        wc_ecc_free(pubB);
    }
    if (pubAInit) {
        wc_ecc_free(pubA);
    }
    if (keyBInit) {
        wc_ecc_free(keyB);
    }
    if (keyAInit) {
        wc_ecc_free(keyA);
    }
    return ret;
}

/**
 * Test the cache-mode ECDH shared-secret API.
 *
 * For each curve:
 * 1. Generate two HSM ECC keys.
 * 2. Compute the shared secret in export mode and capture the secret bytes.
 * 3. Compute the same shared secret in cache mode (USAGE_DERIVE) and read it
 *    back via wh_Client_KeyExport. The cached bytes must match the export-mode
 *    secret exactly.
 * 4. Verify the BADARGS guards: EPHEMERAL flag, NULL inout id.
 * 5. Repeat the round-trip via the async CacheKeyRequest/Response pair.
 */
static int whTest_CryptoEccSharedSecretCacheKey_OneCurve(whClientContext* ctx,
                                                         WC_RNG*          rng,
                                                         int         keySize,
                                                         int         curveId,
                                                         const char* name)
{
    ecc_key  keyA[1]                    = {0};
    ecc_key  keyB[1]                    = {0};
    ecc_key  pubB[1]                    = {0};
    uint8_t  pubBx[ECC_MAXSIZE]         = {0};
    uint8_t  pubBy[ECC_MAXSIZE]         = {0};
    word32   pubBxLen                   = 0;
    word32   pubByLen                   = 0;
    uint8_t  exportSecret[ECC_MAXSIZE]  = {0};
    uint16_t exportSecretLen            = sizeof(exportSecret);
    uint8_t  cachedSecret[ECC_MAXSIZE]  = {0};
    uint16_t cachedSecretLen            = sizeof(cachedSecret);
    uint8_t  labelOut[WH_NVM_LABEL_LEN] = {0};
    whKeyId  privAId                    = WH_KEYID_ERASED;
    whKeyId  privBId                    = WH_KEYID_ERASED;
    whKeyId  pubBId                     = WH_KEYID_ERASED;
    whKeyId  secretId                   = WH_KEYID_ERASED;
    int      keyAInit                   = 0;
    int      keyBInit                   = 0;
    int      pubBInit                   = 0;
    uint8_t  secretLabel[]              = "TestEcdhCachedSecret";
    int      ret                        = WH_ERROR_OK;

    WH_TEST_PRINT("  Testing cache-mode ECDH %s curve...\n", name);

    pubBxLen = pubByLen = keySize;

    /* Generate two keys A and B, then import both private and public halves */
    ret = wc_ecc_init_ex(keyA, NULL, WH_CLIENT_DEVID(ctx));
    if (ret == 0) {
        keyAInit = 1;
        ret      = wc_ecc_make_key(rng, keySize, keyA);
    }
    if (ret == 0) {
        uint8_t lbl[] = "TestEcdhCachePrivA";
        privAId       = WH_KEYID_ERASED;
        ret           = wh_Client_EccImportKey(
            ctx, keyA, &privAId, WH_NVM_FLAGS_USAGE_DERIVE, sizeof(lbl), lbl);
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(keyB, NULL, WH_CLIENT_DEVID(ctx));
    }
    if (ret == 0) {
        keyBInit = 1;
        ret      = wc_ecc_make_key(rng, keySize, keyB);
    }
    if (ret == 0) {
        uint8_t lbl[] = "TestEcdhCachePrivB";
        privBId       = WH_KEYID_ERASED;
        ret           = wh_Client_EccImportKey(
            ctx, keyB, &privBId, WH_NVM_FLAGS_USAGE_DERIVE, sizeof(lbl), lbl);
    }
    if (ret == 0) {
        ret =
            wc_ecc_export_public_raw(keyB, pubBx, &pubBxLen, pubBy, &pubByLen);
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(pubB, NULL, INVALID_DEVID);
        if (ret == 0) {
            pubBInit = 1;
            ret = wc_ecc_import_unsigned(pubB, pubBx, pubBy, NULL, curveId);
        }
    }
    if (ret == 0) {
        uint8_t lbl[] = "TestEcdhCachePubB";
        ret           = wh_Client_EccImportKey(
            ctx, pubB, &pubBId, WH_NVM_FLAGS_USAGE_DERIVE, sizeof(lbl), lbl);
    }

    /* Reference: compute the secret in export mode using (privA, pubB) */
    if (ret == 0) {
        ret = wh_Client_EccSharedSecretRequest(ctx, privAId, pubBId);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_EccSharedSecretResponse(ctx, exportSecret,
                                                        &exportSecretLen);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    /* Cache mode: compute the same secret with (privA, pubB), get a keyId */
    if (ret == 0) {
        secretId = WH_KEYID_ERASED;
        ret      = wh_Client_EccSharedSecretCacheKeyRequest(
            ctx, privAId, pubBId, secretId, WH_NVM_FLAGS_USAGE_DERIVE,
            secretLabel, sizeof(secretLabel));
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_EccSharedSecretCacheKeyResponse(ctx, &secretId);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if ((ret == WH_ERROR_OK) && WH_KEYID_ISERASED(secretId)) {
            WH_ERROR_PRINT(
                "%s: server returned erased keyId from cache-mode ECDH\n",
                name);
            ret = WH_ERROR_ABORTED;
        }
    }

    /* Read back the cached secret and compare with the export-mode reference */
    if (ret == 0) {
        cachedSecretLen = sizeof(cachedSecret);
        ret = wh_Client_KeyExport(ctx, secretId, labelOut, sizeof(labelOut),
                                  cachedSecret, &cachedSecretLen);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT(
                "%s: failed to export cached ECDH secret (keyId=0x%x): %d\n",
                name, (unsigned)secretId, ret);
        }
    }
    if (ret == 0) {
        if ((cachedSecretLen != exportSecretLen) ||
            (memcmp(cachedSecret, exportSecret, exportSecretLen) != 0)) {
            WH_ERROR_PRINT("%s: cached ECDH secret does not match export\n",
                           name);
            ret = WH_ERROR_ABORTED;
        }
        if (memcmp(labelOut, secretLabel, sizeof(secretLabel)) != 0) {
            WH_ERROR_PRINT("%s: cached ECDH secret label mismatch\n", name);
            ret = WH_ERROR_ABORTED;
        }
    }
    if (!WH_KEYID_ISERASED(secretId)) {
        (void)wh_Client_KeyEvict(ctx, secretId);
        secretId = WH_KEYID_ERASED;
    }

    /* Cache mode with caller-supplied keyId: server must honor the slot */
    if (ret == 0) {
        whKeyId  requestedId                        = 0x42;
        whKeyId  returnedId                         = requestedId;
        uint8_t  suppliedCached[ECC_MAXSIZE]        = {0};
        uint16_t suppliedCachedLen                  = sizeof(suppliedCached);
        uint8_t  suppliedLabelOut[WH_NVM_LABEL_LEN] = {0};

        ret = wh_Client_EccSharedSecretCacheKeyRequest(
            ctx, privAId, pubBId, requestedId, WH_NVM_FLAGS_USAGE_DERIVE,
            secretLabel, sizeof(secretLabel));
        if (ret == WH_ERROR_OK) {
            do {
                ret =
                    wh_Client_EccSharedSecretCacheKeyResponse(ctx, &returnedId);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if ((ret == WH_ERROR_OK) && (returnedId != requestedId)) {
            WH_ERROR_PRINT("%s: caller-supplied keyId not honored "
                           "(asked 0x%x, got 0x%x)\n",
                           name, (unsigned)requestedId, (unsigned)returnedId);
            ret = WH_ERROR_ABORTED;
        }
        if (ret == 0) {
            ret = wh_Client_KeyExport(ctx, returnedId, suppliedLabelOut,
                                      sizeof(suppliedLabelOut), suppliedCached,
                                      &suppliedCachedLen);
        }
        if (ret == 0) {
            if ((suppliedCachedLen != exportSecretLen) ||
                (memcmp(suppliedCached, exportSecret, exportSecretLen) != 0)) {
                WH_ERROR_PRINT(
                    "%s: caller-supplied-keyId cached secret does not match "
                    "reference\n",
                    name);
                ret = WH_ERROR_ABORTED;
            }
        }
        if (!WH_KEYID_ISERASED(returnedId)) {
            (void)wh_Client_KeyEvict(ctx, returnedId);
        }
    }

    /* Cache mode with NONEXPORTABLE: export must be rejected */
    if (ret == 0) {
        whKeyId  nonExportId                  = WH_KEYID_ERASED;
        uint8_t  dummyBuf[ECC_MAXSIZE]        = {0};
        uint16_t dummyBufLen                  = sizeof(dummyBuf);
        uint8_t  dummyLabel[WH_NVM_LABEL_LEN] = {0};

        ret = wh_Client_EccSharedSecretCacheKeyRequest(
            ctx, privAId, pubBId, nonExportId,
            WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_DERIVE, secretLabel,
            sizeof(secretLabel));
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_EccSharedSecretCacheKeyResponse(ctx,
                                                                &nonExportId);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if ((ret == WH_ERROR_OK) && WH_KEYID_ISERASED(nonExportId)) {
            WH_ERROR_PRINT("%s: NONEXPORTABLE cache returned erased keyId\n",
                           name);
            ret = WH_ERROR_ABORTED;
        }
        if (ret == 0) {
            int rc =
                wh_Client_KeyExport(ctx, nonExportId, dummyLabel,
                                    sizeof(dummyLabel), dummyBuf, &dummyBufLen);
            if (rc != WH_ERROR_ACCESS) {
                WH_ERROR_PRINT(
                    "%s: KeyExport on NONEXPORTABLE secret returned %d "
                    "(expected WH_ERROR_ACCESS)\n",
                    name, rc);
                ret = WH_ERROR_ABORTED;
            }
        }
        if (!WH_KEYID_ISERASED(nonExportId)) {
            (void)wh_Client_KeyEvict(ctx, nonExportId);
        }
    }

    /* Guard: EPHEMERAL flag must be rejected client-side */
    if (ret == 0) {
        whKeyId tmp = WH_KEYID_ERASED;
        int     rc  = wh_Client_EccSharedSecretCacheKey(
            ctx, keyA, pubB, &tmp,
            WH_NVM_FLAGS_EPHEMERAL | WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: CacheKey with EPHEMERAL returned %d (expected BADARGS)\n",
                name, rc);
            ret = -1;
        }
    }
    /* Guard: NULL inout_key_id */
    if (ret == 0) {
        int rc = wh_Client_EccSharedSecretCacheKey(
            ctx, keyA, pubB, NULL, WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: CacheKey NULL inout returned %d (expected "
                           "BADARGS)\n",
                           name, rc);
            ret = -1;
        }
    }

    /* Blocking wrapper path with auto-imported local keys */
    if (ret == 0) {
        ecc_key  keyC[1]                         = {0};
        ecc_key  keyD[1]                         = {0};
        whKeyId  blockId                         = WH_KEYID_ERASED;
        uint8_t  blockRefSecret[ECC_MAXSIZE]     = {0};
        uint16_t blockRefSecretLen               = sizeof(blockRefSecret);
        uint8_t  blockCachedSecret[ECC_MAXSIZE]  = {0};
        uint16_t blockCachedSecretLen            = sizeof(blockCachedSecret);
        uint8_t  blockLabelOut[WH_NVM_LABEL_LEN] = {0};

        ret = wc_ecc_init_ex(keyC, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_ecc_make_key(rng, keySize, keyC);
        }
        if (ret == 0) {
            ret = wc_ecc_init_ex(keyD, NULL, INVALID_DEVID);
        }
        if (ret == 0) {
            ret = wc_ecc_make_key(rng, keySize, keyD);
        }
        /* Reference: export-mode blocking wrapper auto-imports the same keys */
        if (ret == 0) {
            ret = wh_Client_EccSharedSecret(ctx, keyC, keyD, blockRefSecret,
                                            &blockRefSecretLen);
        }
        if (ret == 0) {
            ret = wh_Client_EccSharedSecretCacheKey(
                ctx, keyC, keyD, &blockId, WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0);
        }
        if ((ret == 0) && WH_KEYID_ISERASED(blockId)) {
            WH_ERROR_PRINT("%s: blocking CacheKey returned erased keyId\n",
                           name);
            ret = WH_ERROR_ABORTED;
        }
        if (ret == 0) {
            ret = wh_Client_KeyExport(ctx, blockId, blockLabelOut,
                                      sizeof(blockLabelOut), blockCachedSecret,
                                      &blockCachedSecretLen);
            if (ret != WH_ERROR_OK) {
                WH_ERROR_PRINT("%s: failed to export blocking-cached secret "
                               "(keyId=0x%x): %d\n",
                               name, (unsigned)blockId, ret);
            }
        }
        if (ret == 0) {
            if ((blockCachedSecretLen != blockRefSecretLen) ||
                (memcmp(blockCachedSecret, blockRefSecret, blockRefSecretLen) !=
                 0)) {
                WH_ERROR_PRINT(
                    "%s: blocking-wrapper cached secret does not match "
                    "reference\n",
                    name);
                ret = WH_ERROR_ABORTED;
            }
        }
        if (!WH_KEYID_ISERASED(blockId)) {
            (void)wh_Client_KeyEvict(ctx, blockId);
        }
        wc_ecc_free(keyD);
        wc_ecc_free(keyC);
    }

    if (ret == 0) {
        WH_TEST_PRINT("    cache ECDH %s: PASS\n", name);
    }

    /* Cleanup */
    if (!WH_KEYID_ISERASED(pubBId)) {
        (void)wh_Client_KeyEvict(ctx, pubBId);
    }
    if (!WH_KEYID_ISERASED(privBId)) {
        (void)wh_Client_KeyEvict(ctx, privBId);
    }
    if (!WH_KEYID_ISERASED(privAId)) {
        (void)wh_Client_KeyEvict(ctx, privAId);
    }
    if (pubBInit) {
        wc_ecc_free(pubB);
    }
    if (keyBInit) {
        wc_ecc_free(keyB);
    }
    if (keyAInit) {
        wc_ecc_free(keyA);
    }
    return ret;
}
#endif /* HAVE_ECC_DHE */

/**
 * Test the async Request/Response API for ECC server-side keygen.
 *
 * For each curve:
 * 1. Use wh_Client_EccMakeCacheKeyRequest + poll
 *    wh_Client_EccMakeCacheKeyResponse to generate a server-cached key, then
 *    sign-and-software-verify against the cached keyId to prove the key is
 *    usable.
 * 2. Use wh_Client_EccMakeExportKeyRequest + poll
 *    wh_Client_EccMakeExportKeyResponse to generate an ephemeral key returned
 *    to the client; verify the wolfCrypt struct is populated and the curve
 *    matches.
 * 3. Assert the precondition / arg-shape contract on each async half.
 */
static int whTest_CryptoEccMakeKeyAsync_OneCurve(whClientContext* ctx,
                                                 WC_RNG* rng, int keySize,
                                                 int curveId, const char* name)
{
    ecc_key  exportKey[1]                = {0};
    ecc_key  swKey[1]                    = {0};
    uint8_t  hash[WH_TEST_ECC_HASH_SIZE] = {0};
    uint8_t  sig[ECC_MAX_SIG_SIZE]       = {0};
    uint8_t  pubX[ECC_MAXSIZE]           = {0};
    uint8_t  pubY[ECC_MAXSIZE]           = {0};
    word32   pubXLen                     = 0;
    word32   pubYLen                     = 0;
    uint16_t sigLen                      = 0;
    int      res                         = 0;
    whKeyId  cacheKeyId                  = WH_KEYID_ERASED;
    int      exportKeyInit               = 0;
    int      swKeyInit                   = 0;
    uint8_t  cacheLabel[]                = "TestEccAsyncCacheGen";
    int      ret                         = WH_ERROR_OK;
    int      i;

    /* Use non-repeating pattern so we'd notice silent truncation */
    for (i = 0; i < WH_TEST_ECC_HASH_SIZE; i++) {
        hash[i] = (uint8_t)i;
    }

    pubXLen = keySize;
    pubYLen = keySize;

    WH_TEST_PRINT("  Testing async MakeKey %s curve...\n", name);

    /* --- MakeCacheKey async: generate, then sign with the new keyId --- */
    if (ret == 0) {
        ret = wh_Client_EccMakeCacheKeyRequest(
            ctx, keySize, curveId, WH_KEYID_ERASED, WH_NVM_FLAGS_USAGE_SIGN,
            sizeof(cacheLabel), cacheLabel);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccMakeCacheKeyRequest failed: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccMakeCacheKeyResponse(ctx, &cacheKeyId);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccMakeCacheKeyResponse failed: %d\n", name,
                           ret);
        }
        else if (WH_KEYID_ISERASED(cacheKeyId)) {
            WH_ERROR_PRINT("%s: server returned erased keyId\n", name);
            ret = -1;
        }
    }
    /* Sign with the cached key via the existing async sign API to prove the
     * generated key is usable on the server. */
    if (ret == 0) {
        sigLen = sizeof(sig);
        ret    = wh_Client_EccSignRequest(ctx, cacheKeyId, hash, sizeof(hash));
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_EccSignResponse(ctx, sig, &sigLen);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: sign with cache-generated keyId failed: %d\n",
                           name, ret);
        }
    }
    /* Software-verify the signature using the public half exported from the
     * server cache. */
    if (ret == 0) {
        ecc_key pubOnly[1] = {0};
        uint8_t labelBuf[WH_NVM_LABEL_LEN];
        ret = wc_ecc_init_ex(pubOnly, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_EccExportKey(ctx, cacheKeyId, pubOnly,
                                         sizeof(labelBuf), labelBuf);
            if (ret == 0) {
                ret = wc_ecc_export_public_raw(pubOnly, pubX, &pubXLen, pubY,
                                               &pubYLen);
            }
            wc_ecc_free(pubOnly);
        }
        if (ret != 0) {
            WH_ERROR_PRINT("%s: export of cached pub failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(swKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            swKeyInit = 1;
            ret = wc_ecc_import_unsigned(swKey, pubX, pubY, NULL, curveId);
        }
        if (ret == 0) {
            res = 0;
            ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &res,
                                     swKey);
            if (ret == 0 && res != 1) {
                WH_ERROR_PRINT(
                    "%s: software verify of cache-generated key failed\n",
                    name);
                ret = -1;
            }
        }
    }
    if (swKeyInit) {
        wc_ecc_free(swKey);
    }

    /* --- MakeExportKey async: generate, sign locally, verify locally --- */
    if (ret == 0) {
        ret = wc_ecc_init_ex(exportKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            exportKeyInit = 1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_EccMakeExportKeyRequest(ctx, keySize, curveId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccMakeExportKeyRequest failed: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccMakeExportKeyResponse(ctx, exportKey);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccMakeExportKeyResponse failed: %d\n", name,
                           ret);
        }
    }
    /* Sanity-check the deserialized key by sign+verify entirely locally. */
    if (ret == 0) {
        word32 swSigLen = sizeof(sig);
        memset(sig, 0, sizeof(sig));
        ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &swSigLen, rng,
                               exportKey);
        if (ret == 0) {
            res = 0;
            ret = wc_ecc_verify_hash(sig, swSigLen, hash, sizeof(hash), &res,
                                     exportKey);
            if (ret == 0 && res != 1) {
                WH_ERROR_PRINT(
                    "%s: local verify of exported keygen key failed\n", name);
                ret = -1;
            }
        }
        if (ret != 0) {
            WH_ERROR_PRINT(
                "%s: local sign/verify of exported keygen key failed: %d\n",
                name, ret);
        }
    }

    /* --- BADARGS: NULL ctx must be rejected by every async half. --- */
    if (ret == 0) {
        int rc1 = wh_Client_EccMakeCacheKeyRequest(NULL, keySize, curveId,
                                                   WH_KEYID_ERASED,
                                                   WH_NVM_FLAGS_NONE, 0, NULL);
        int rc2 = wh_Client_EccMakeCacheKeyResponse(NULL, &cacheKeyId);
        int rc3 = wh_Client_EccMakeExportKeyRequest(NULL, keySize, curveId);
        int rc4 = wh_Client_EccMakeExportKeyResponse(NULL, exportKey);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS ||
            rc3 != WH_ERROR_BADARGS || rc4 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: NULL ctx async MakeKey rc=(%d,%d,%d,%d) want "
                           "all BADARGS\n",
                           name, rc1, rc2, rc3, rc4);
            ret = -1;
        }
    }

    /* --- BADARGS: NULL out args. ctx has no pending request, so this also
     * confirms these calls don't mutate state. --- */
    if (ret == 0) {
        int rc1 = wh_Client_EccMakeCacheKeyResponse(ctx, NULL);
        int rc2 = wh_Client_EccMakeExportKeyResponse(ctx, NULL);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: NULL out arg Response rc=(%d,%d) want both BADARGS\n",
                name, rc1, rc2);
            ret = -1;
        }
    }

    /* --- BADARGS: EPHEMERAL flag must be rejected by the cache Request so
     * the export pair owns ephemeral keygen unambiguously. --- */
    if (ret == 0) {
        int rc = wh_Client_EccMakeCacheKeyRequest(
            ctx, keySize, curveId, WH_KEYID_ERASED, WH_NVM_FLAGS_EPHEMERAL, 0,
            NULL);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: cache Request with EPHEMERAL flag returned %d "
                           "(want BADARGS)\n",
                           name, rc);
            ret = -1;
        }
    }

    /* --- Confirm ctx is still usable after the BADARGS rejections. --- */
    if (ret == 0) {
        whKeyId tmpId = WH_KEYID_ERASED;
        int     rc    = wh_Client_EccMakeCacheKeyRequest(
            ctx, keySize, curveId, WH_KEYID_ERASED, WH_NVM_FLAGS_USAGE_SIGN,
            sizeof(cacheLabel), cacheLabel);
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccMakeCacheKeyResponse(ctx, &tmpId);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: ctx stuck after MakeKey BADARGS (rc=%d)\n",
                           name, rc);
            ret = -1;
        }
        if (!WH_KEYID_ISERASED(tmpId)) {
            (void)wh_Client_KeyEvict(ctx, tmpId);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("    async MakeKey %s: PASS\n", name);
    }

    /* Cleanup */
    if (!WH_KEYID_ISERASED(cacheKeyId)) {
        (void)wh_Client_KeyEvict(ctx, cacheKeyId);
    }
    if (exportKeyInit) {
        wc_ecc_free(exportKey);
    }
    return ret;
}

static int whTest_CryptoEccAsync(whClientContext* ctx, WC_RNG* rng)
{
    int ret = WH_ERROR_OK;

    WH_TEST_PRINT("Testing ECC async API...\n");

#if !defined(NO_ECC256)
    if (ret == 0) {
        ret = whTest_CryptoEccSignVerifyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P256_KEY_SIZE, ECC_SECP256R1, "P-256");
    }
#ifdef HAVE_ECC_DHE
    if (ret == 0) {
        ret = whTest_CryptoEccSharedSecretAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P256_KEY_SIZE, ECC_SECP256R1, "P-256");
    }
    if (ret == 0) {
        ret = whTest_CryptoEccSharedSecretCacheKey_OneCurve(
            ctx, rng, WH_TEST_ECC_P256_KEY_SIZE, ECC_SECP256R1, "P-256");
    }
#endif
    if (ret == 0) {
        ret = whTest_CryptoEccMakeKeyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P256_KEY_SIZE, ECC_SECP256R1, "P-256");
    }
#endif

#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
    if (ret == 0) {
        ret = whTest_CryptoEccSignVerifyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P384_KEY_SIZE, ECC_SECP384R1, "P-384");
    }
#ifdef HAVE_ECC_DHE
    if (ret == 0) {
        ret = whTest_CryptoEccSharedSecretAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P384_KEY_SIZE, ECC_SECP384R1, "P-384");
    }
    if (ret == 0) {
        ret = whTest_CryptoEccSharedSecretCacheKey_OneCurve(
            ctx, rng, WH_TEST_ECC_P384_KEY_SIZE, ECC_SECP384R1, "P-384");
    }
#endif
    if (ret == 0) {
        ret = whTest_CryptoEccMakeKeyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P384_KEY_SIZE, ECC_SECP384R1, "P-384");
    }
#endif

#if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
    if (ret == 0) {
        ret = whTest_CryptoEccSignVerifyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P521_KEY_SIZE, ECC_SECP521R1, "P-521");
    }
#ifdef HAVE_ECC_DHE
    if (ret == 0) {
        ret = whTest_CryptoEccSharedSecretAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P521_KEY_SIZE, ECC_SECP521R1, "P-521");
    }
    if (ret == 0) {
        ret = whTest_CryptoEccSharedSecretCacheKey_OneCurve(
            ctx, rng, WH_TEST_ECC_P521_KEY_SIZE, ECC_SECP521R1, "P-521");
    }
#endif
    if (ret == 0) {
        ret = whTest_CryptoEccMakeKeyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P521_KEY_SIZE, ECC_SECP521R1, "P-521");
    }
#endif

    if (ret == 0) {
        WH_TEST_PRINT("ECC async API SUCCESS\n");
    }
    return ret;
}
#endif /* HAVE_ECC_SIGN && HAVE_ECC_VERIFY && !WOLF_CRYPTO_CB_ONLY_ECC */
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519

static int whTest_Ed25519ImportToServer(whClientContext* ctx, int devId,
                                        ed25519_key* key, ed25519_key* pubKey,
                                        uint8_t* label, uint16_t labelLen,
                                        whKeyId* outSignKeyId,
                                        whKeyId* outVerifyKeyId)
{
    int     ret = 0;
    byte    pubKeyRaw[ED25519_PUB_KEY_SIZE];
    word32  pubKeySize  = sizeof(pubKeyRaw);
    whKeyId signKeyId   = WH_KEYID_ERASED;
    whKeyId verifyKeyId = WH_KEYID_ERASED;

    ret = wc_ed25519_export_public(key, pubKeyRaw, &pubKeySize);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export Ed25519 public key: %d\n", ret);
    }
    else {
        ret = wc_ed25519_import_public(pubKeyRaw, pubKeySize, pubKey);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import Ed25519 public key: %d\n", ret);
        }
    }

    /* Write each out-keyId immediately after its import succeeds so the
     * caller can evict it if a later step fails. */
    if (ret == 0) {
        ret = wh_Client_Ed25519ImportKey(
            ctx, key, &signKeyId, WH_NVM_FLAGS_USAGE_SIGN, labelLen, label);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import Ed25519 key to server: %d\n", ret);
        }
        else {
            if (outSignKeyId != NULL) {
                *outSignKeyId = signKeyId;
            }
            /* remove key material from local key structure */
            wc_ed25519_free(key);
            ret = wc_ed25519_init_ex(key, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to re-initialize Ed25519 key: %d\n",
                               ret);
            }
            else {
                wh_Client_Ed25519SetKeyId(key, signKeyId);
            }
        }
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519ImportKey(ctx, pubKey, &verifyKeyId,
                                         WH_NVM_FLAGS_USAGE_VERIFY, labelLen,
                                         label);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to import Ed25519 public key to server: %d\n", ret);
        }
        else {
            if (outVerifyKeyId != NULL) {
                *outVerifyKeyId = verifyKeyId;
            }
            /* remove key material from local key structure */
            wc_ed25519_free(pubKey);
            ret = wc_ed25519_init_ex(pubKey, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed to re-initialize Ed25519 public key: %d\n", ret);
            }
            else {
                wh_Client_Ed25519SetKeyId(pubKey, verifyKeyId);
            }
        }
    }

    return ret;
}

static int whTest_CryptoEd25519Inline(whClientContext* ctx, int devId,
                                      WC_RNG* rng)
{
    (void)ctx;

    int          ret       = 0;
    ed25519_key  key[1]    = {0};
    ed25519_key  pubKey[1] = {0};
    byte         msg[]     = "Test message for Ed25519 signing";
    byte         sig[ED25519_SIG_SIZE];
    word32       sigSz    = sizeof(sig);
    int          verified = 0;
    const word32 msgSz    = (word32)sizeof(msg);
    byte         pubKeyRaw[ED25519_PUB_KEY_SIZE];
    word32       pubKeySize = sizeof(pubKeyRaw);

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 key: %d\n", ret);
        return ret;
    }

    ret = wc_ed25519_init_ex(pubKey, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 public key: %d\n", ret);
        wc_ed25519_free(key);
        return ret;
    }

    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate Ed25519 key: %d\n", ret);
    }
    else {
        ret = wc_ed25519_export_public(key, pubKeyRaw, &pubKeySize);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to export Ed25519 public key: %d\n", ret);
        }
        else {
            ret = wc_ed25519_import_public(pubKeyRaw, pubKeySize, pubKey);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to import Ed25519 public key: %d\n",
                               ret);
            }
        }
    }

    if (ret == 0) {
        sigSz = sizeof(sig);
        ret   = wc_ed25519_sign_msg(msg, msgSz, sig, &sigSz, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign message with Ed25519: %d\n", ret);
        }
        else {
            ret = wc_ed25519_verify_msg(sig, sigSz, msg, msgSz, &verified,
                                        pubKey);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to verify Ed25519 signature: %d\n", ret);
            }
            else if (verified != 1) {
                WH_ERROR_PRINT("Ed25519 signature verification failed\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        /* Corrupt signature to ensure verification fails. wolfCrypt may
         * signal rejection either as ret==0 with verified==0, or as
         * ret==SIG_VERIFY_E (path-dependent inside wolfCrypt). Anything
         * else is a real error. */
        sig[0] ^= 0xFF;
        verified = 0;
        ret = wc_ed25519_verify_msg(sig, sigSz, msg, msgSz, &verified, pubKey);
        if (verified != 0) {
            WH_ERROR_PRINT(
                "Modified Ed25519 signature unexpectedly verified\n");
            ret = -1;
        }
        else if (ret == 0 || ret == SIG_VERIFY_E) {
            ret = 0;
        }
        else {
            WH_ERROR_PRINT(
                "wc_ed25519_verify_msg of tampered sig errored: %d\n", ret);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 INLINE DEVID=0x%X SUCCESS\n", devId);
    }

    wc_ed25519_free(pubKey);
    wc_ed25519_free(key);
    return ret;
}

static int whTest_CryptoEd25519ServerKey(whClientContext* ctx, int devId,
                                         WC_RNG* rng)
{
    int         ret         = 0;
    ed25519_key key[1]      = {0};
    ed25519_key pubKey[1]   = {0};
    whKeyId     signKeyId   = WH_KEYID_ERASED;
    whKeyId     verifyKeyId = WH_KEYID_ERASED;
    byte        msg[]       = "Ed25519 server key message";
    byte        sig[ED25519_SIG_SIZE];
    uint32_t    sigSz    = sizeof(sig);
    int         verified = 0;
    uint8_t     label[]  = "Ed25519 Server Key";

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 key: %d\n", ret);
        return ret;
    }

    ret = wc_ed25519_init_ex(pubKey, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 public key: %d\n", ret);
        wc_ed25519_free(key);
        return ret;
    }

    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate Ed25519 key: %d\n", ret);
    }
    else {
        ret = whTest_Ed25519ImportToServer(ctx, devId, key, pubKey, label,
                                           sizeof(label), &signKeyId,
                                           &verifyKeyId);
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519Sign(ctx, key, msg, (uint32_t)sizeof(msg),
                                    (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with server Ed25519 key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519Verify(ctx, pubKey, sig, sigSz, msg,
                                      (uint32_t)sizeof(msg), (uint8_t)Ed25519,
                                      NULL, 0, &verified);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify server Ed25519 signature: %d\n",
                           ret);
        }
        else if (verified != 1) {
            WH_ERROR_PRINT("Server Ed25519 signature verification failed\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Sign-only key should not be allowed to verify */
        int negVerified = 0;
        int negRet      = wh_Client_Ed25519Verify(
            ctx, key, sig, sigSz, msg, (uint32_t)sizeof(msg), (uint8_t)Ed25519,
            NULL, 0, &negVerified);
        if (negRet == 0) {
            WH_ERROR_PRINT("Sign-only Ed25519 key unexpectedly verified\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Same shape as the inline tampered-sig case above. */
        sig[0] ^= 0xAA;
        verified = 0;
        ret      = wh_Client_Ed25519Verify(ctx, pubKey, sig, sigSz, msg,
                                           (uint32_t)sizeof(msg), (uint8_t)Ed25519,
                                           NULL, 0, &verified);
        if (verified != 0) {
            WH_ERROR_PRINT("Modified server Ed25519 signature unexpectedly "
                           "verified\n");
            ret = -1;
        }
        else if (ret == 0 || ret == SIG_VERIFY_E) {
            ret = 0;
        }
        else {
            WH_ERROR_PRINT(
                "Server Ed25519 verify of tampered sig errored: %d\n", ret);
        }
    }

    if (!WH_KEYID_ISERASED(signKeyId)) {
        (void)wh_Client_KeyEvict(ctx, signKeyId);
    }
    if (!WH_KEYID_ISERASED(verifyKeyId)) {
        (void)wh_Client_KeyEvict(ctx, verifyKeyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 SERVER KEY DEVID=0x%X SUCCESS\n", devId);
    }

    wc_ed25519_free(pubKey);
    wc_ed25519_free(key);
    return ret;
}

static int whTest_CryptoEd25519ExportPublic(whClientContext* ctx, int devId,
                                            WC_RNG* rng)
{
    int         ret       = 0;
    whKeyId     keyId     = WH_KEYID_ERASED;
    ed25519_key hsmKey[1] = {0};
    ed25519_key pubKey[1] = {0};
    byte        msg[]     = "Ed25519 export-public message";
    byte        sig[ED25519_SIG_SIZE];
    uint32_t    sigSz    = sizeof(sig);
    int         verified = 0;
    /* Large enough to hold an Ed25519 key DER so the access-control assertion
     * doesn't get masked by a buffer-too-small failure. */
    uint8_t     denyBuf[256];
    uint16_t    denyLen = sizeof(denyBuf);
    (void)devId;

    ret = wh_Client_Ed25519MakeCacheKey(ctx, &keyId,
                                        WH_NVM_FLAGS_USAGE_SIGN |
                                            WH_NVM_FLAGS_USAGE_VERIFY |
                                            WH_NVM_FLAGS_NONEXPORTABLE,
                                        0, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT(
            "Failed to make NONEXPORTABLE cached Ed25519 key %d\n", ret);
        return ret;
    }

    /* Full export must be denied */
    {
        int denyRet = wh_Client_KeyExport(ctx, keyId, NULL, 0, denyBuf,
                                          &denyLen);
        if (denyRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT(
                "NONEXPORTABLE Ed25519 full export was not denied: %d\n",
                denyRet);
            ret = -1;
        }
    }

    /* Sign on HSM */
    if (ret == 0) {
        ret = wc_ed25519_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
        if (ret == 0) {
            ret = wh_Client_Ed25519SetKeyId(hsmKey, keyId);
        }
        if (ret == 0) {
            ret = wh_Client_Ed25519Sign(ctx, hsmKey, msg, (uint32_t)sizeof(msg),
                                        (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
            if (ret != 0) {
                WH_ERROR_PRINT("HSM Ed25519 sign failed %d\n", ret);
            }
        }
        wc_ed25519_free(hsmKey);
    }

    /* Export public, verify client-side */
    if (ret == 0) {
        ret = wc_ed25519_init_ex(pubKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_Ed25519ExportPublicKey(ctx, keyId, pubKey, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_Ed25519ExportPublicKey failed %d\n",
                               ret);
            }
            else if (pubKey->pubKeySet != 1 || pubKey->privKeySet != 0) {
                WH_ERROR_PRINT(
                    "Exported Ed25519 key flags wrong: pub=%d priv=%d\n",
                    (int)pubKey->pubKeySet, (int)pubKey->privKeySet);
                ret = -1;
            }
            else {
                ret = wc_ed25519_verify_msg(sig, sigSz, msg,
                                            (word32)sizeof(msg), &verified,
                                            pubKey);
                if (ret != 0 || verified != 1) {
                    WH_ERROR_PRINT(
                        "Client-side Ed25519 verify failed ret=%d verify=%d\n",
                        ret, verified);
                    if (ret == 0) {
                        ret = -1;
                    }
                }
            }
            wc_ed25519_free(pubKey);
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    (void)rng;
    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 EXPORT-PUBLIC SUCCESS\n");
    }
    return ret;
}

/* One keygen call caches the private key and returns the public key. Verify
 * the returned public key byte-matches wh_Client_Ed25519ExportPublicKey and
 * that it verifies a signature made by the cached private key. */
static int whTest_CryptoEd25519CacheKeyAndExportPublic(whClientContext* ctx,
                                                       int devId, WC_RNG* rng)
{
    int         ret       = 0;
    whKeyId     keyId     = WH_KEYID_ERASED;
    ed25519_key genPub[1] = {0};
    ed25519_key refPub[1] = {0};
    byte        msg[]     = "Ed25519 cache-export-public message";
    byte        sig[ED25519_SIG_SIZE];
    uint32_t    sigSz     = sizeof(sig);
    int         verified  = 0;
    byte        genDer[128];
    byte        refDer[128];
    int         genDerSz  = 0;
    int         refDerSz  = 0;
    (void)devId;

    ret = wc_ed25519_init_ex(genPub, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Client_Ed25519MakeCacheKeyAndExportPublic(
            ctx, &keyId, WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, 0,
            NULL, genPub);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519MakeCacheKeyAndExportPublic failed %d\n",
                           ret);
        }
    }

    /* Cross-check the keygen-returned public key against ExportPublicKey. */
    if (ret == 0) {
        ret = wc_ed25519_init_ex(refPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_Ed25519ExportPublicKey(ctx, keyId, refPub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_Ed25519ExportPublicKey failed %d\n",
                               ret);
            }
        }
    }
    if (ret == 0) {
        genDerSz = wc_Ed25519PublicKeyToDer(genPub, genDer, sizeof(genDer), 1);
        refDerSz = wc_Ed25519PublicKeyToDer(refPub, refDer, sizeof(refDer), 1);
        if ((genDerSz <= 0) || (genDerSz != refDerSz) ||
            (memcmp(genDer, refDer, (size_t)genDerSz) != 0)) {
            WH_ERROR_PRINT("keygen pubkey mismatch vs ExportPublicKey\n");
            ret = -1;
        }
    }

    /* Prove usability: sign on the HSM using genPub directly as the private-key
     * handle (no separate key object), then verify locally with the exported
     * public key (refPub) the client holds. */
    if (ret == 0) {
        ret = wh_Client_Ed25519Sign(ctx, genPub, msg, (uint32_t)sizeof(msg),
                                    (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
        if (ret != 0) {
            WH_ERROR_PRINT("HSM Ed25519 sign failed %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_ed25519_verify_msg(sig, sigSz, msg, (word32)sizeof(msg),
                                    &verified, refPub);
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("verify with keygen pub failed ret=%d verify=%d\n",
                           ret, verified);
            if (ret == 0) {
                ret = -1;
            }
        }
    }

    wc_ed25519_free(refPub);
    wc_ed25519_free(genPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    (void)rng;
    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 CACHE-AND-EXPORT-PUBLIC SUCCESS\n");
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int whTest_CryptoEd25519Dma(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int         ret         = 0;
    ed25519_key key[1]      = {0};
    ed25519_key pubKey[1]   = {0};
    whKeyId     signKeyId   = WH_KEYID_ERASED;
    whKeyId     verifyKeyId = WH_KEYID_ERASED;
    byte        msg[]       = "Ed25519 DMA message";
    byte        sig[ED25519_SIG_SIZE];
    uint32_t    sigSz    = sizeof(sig);
    int         verified = 0;
    uint8_t     label[]  = "Ed25519 DMA Key";

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 key (DMA): %d\n", ret);
        return ret;
    }

    ret = wc_ed25519_init_ex(pubKey, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 public key (DMA): %d\n",
                       ret);
        wc_ed25519_free(key);
        return ret;
    }

    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate Ed25519 key (DMA): %d\n", ret);
    }
    else {
        ret = whTest_Ed25519ImportToServer(ctx, devId, key, pubKey, label,
                                           sizeof(label), &signKeyId,
                                           &verifyKeyId);
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519SignDma(ctx, key, msg, (uint32_t)sizeof(msg),
                                       (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign via DMA Ed25519 key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519VerifyDma(ctx, pubKey, sig, sigSz, msg,
                                         (uint32_t)sizeof(msg),
                                         (uint8_t)Ed25519, NULL, 0, &verified);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify DMA Ed25519 signature: %d\n", ret);
        }
        else if (verified != 1) {
            WH_ERROR_PRINT("DMA Ed25519 signature verification failed\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Sign-only key should not be allowed to verify (DMA) */
        int negVerified = 0;
        int negRet      = wh_Client_Ed25519VerifyDma(
            ctx, key, sig, sigSz, msg, (uint32_t)sizeof(msg), (uint8_t)Ed25519,
            NULL, 0, &negVerified);
        if (negRet == 0) {
            WH_ERROR_PRINT(
                "Sign-only Ed25519 key unexpectedly verified (DMA)\n");
            ret = -1;
        }
    }

    if (!WH_KEYID_ISERASED(signKeyId)) {
        (void)wh_Client_KeyEvict(ctx, signKeyId);
    }
    if (!WH_KEYID_ISERASED(verifyKeyId)) {
        (void)wh_Client_KeyEvict(ctx, verifyKeyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 DMA DEVID=0x%X SUCCESS\n", devId);
    }

    wc_ed25519_free(pubKey);
    wc_ed25519_free(key);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_ED25519 */

#ifdef HAVE_CURVE25519
static int whTest_CryptoCurve25519(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int ret = 0;
    curve25519_key key_a[1] = {0};
    curve25519_key key_b[1] = {0};
    uint8_t shared_ab[CURVE25519_KEYSIZE] = {0};
    uint8_t shared_ba[CURVE25519_KEYSIZE] = {0};
    int key_size = CURVE25519_KEYSIZE;
    whNvmFlags     flags                         = WH_NVM_FLAGS_USAGE_DERIVE;
    whKeyId key_id_a = WH_KEYID_ERASED;
    uint8_t label_a[WH_NVM_LABEL_LEN] = "Curve25519 Label A";
    whKeyId key_id_b = 42;
    uint8_t label_b[WH_NVM_LABEL_LEN] = "Curve25519 Label B";
    word32 len = 0;

    /* Use wolfcrypt ephemeral local keys */
    ret = wc_curve25519_init_ex(key_a, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
    }
    else {
        ret = wc_curve25519_init_ex(key_b, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        } else {
            ret = wc_curve25519_make_key(rng, key_size, key_a);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_curve25519_make_key %d\n", ret);
            }
            if (ret == 0) {
                ret = wc_curve25519_make_key(rng, key_size, key_b);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_curve25519_make_key %d\n",
                            ret);
                }
            }
            if (ret == 0) {
                len = sizeof(shared_ab);
                ret =
                    wc_curve25519_shared_secret(key_a, key_b, shared_ab, &len);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to compute shared secret %d\n", ret);
                }
            }
            if (ret == 0) {
                len = sizeof(shared_ba);
                ret =
                    wc_curve25519_shared_secret(key_b, key_a, shared_ba, &len);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to compute shared secret %d\n", ret);
                }
            }
            if (ret == 0) {
                if (memcmp(shared_ab, shared_ba, len) != 0) {
                    WH_ERROR_PRINT("CURVE25519 secrets don't match\n");
                    ret = -1;
                }
            }
            wc_curve25519_free(key_b);
        }
        wc_curve25519_free(key_a);
    }

    if (ret == 0) {
        /* Test using wh_Client ephemeral local keys */
        ret = wc_curve25519_init_ex(key_a, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        } else {
            ret = wc_curve25519_init_ex(key_b, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
            } else {
                ret = wh_Client_Curve25519MakeExportKey(ctx, key_size, key_a);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to make exported key %d\n", ret);
                }
                if (ret == 0) {
                    ret = wh_Client_Curve25519MakeExportKey(ctx, key_size,
                            key_b);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to make exported key %d\n", ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ab);
                    ret = wc_curve25519_shared_secret(
                            key_a, key_b, shared_ab, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ba);
                    ret = wc_curve25519_shared_secret(
                            key_b, key_a, shared_ba, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    if (memcmp(shared_ab, shared_ba, len) != 0) {
                        WH_ERROR_PRINT("CURVE25519 secrets don't match\n");
                        ret = -1;
                    }
                }
                wc_curve25519_free(key_b);
            }
            wc_curve25519_free(key_a);
        }
    }
    if (ret == 0) {
        /* Test using wolfHSM server keys */
        ret = wc_curve25519_init_ex(key_a, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        } else {
            ret = wc_curve25519_init_ex(key_b, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
            } else {
                ret = wh_Client_Curve25519MakeCacheKey(ctx, key_size,
                        &key_id_a, flags, label_a, sizeof(label_a));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
                }
                if (ret == 0) {
                    ret = wh_Client_Curve25519MakeCacheKey(ctx, key_size,
                            &key_id_b, flags, label_b, sizeof(label_b));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ab);
                    wh_Client_Curve25519SetKeyId(key_a, key_id_a);
                    wh_Client_Curve25519SetKeyId(key_b, key_id_b);
                    ret = wc_curve25519_shared_secret(
                            key_a, key_b, shared_ab, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ba);
                    ret = wc_curve25519_shared_secret(
                            key_b, key_a, shared_ba, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    if (memcmp(shared_ab, shared_ba, len) != 0) {
                        WH_ERROR_PRINT("CURVE25519 secrets don't match\n");
                        ret = -1;
                    }
                }
                if (!WH_KEYID_ISERASED(key_id_a)) {
                    (void)wh_Client_KeyEvict(ctx, key_id_a);
                }
                if (!WH_KEYID_ISERASED(key_id_b)) {
                    (void)wh_Client_KeyEvict(ctx, key_id_b);
                }
                wc_curve25519_free(key_b);
            }
            wc_curve25519_free(key_a);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("CURVE25519 SUCCESS\n");
    }
    return ret;
}

/**
 * Test the cache-mode X25519 shared-secret API.
 *
 * 1. Generate two X25519 keys on the server, plus a public-only copy of B.
 * 2. Compute the secret in export mode via the async Request/Response pair and
 *    capture the bytes.
 * 3. Compute the same secret in cache mode (USAGE_DERIVE), read it back, and
 *    confirm the bytes match.
 * 4. Exercise the blocking CacheKey wrapper with locally-generated keys so the
 *    auto-import and eviction path is covered.
 * 5. Verify BADARGS guards.
 */
static int whTest_CryptoCurve25519SharedSecretCacheKey(whClientContext* ctx,
                                                       int devId, WC_RNG* rng)
{
    int            ret                              = 0;
    curve25519_key key_a[1]                         = {0};
    curve25519_key key_b[1]                         = {0};
    curve25519_key pubB[1]                          = {0};
    uint8_t        exportSecret[CURVE25519_KEYSIZE] = {0};
    uint16_t       exportSecretLen                  = sizeof(exportSecret);
    uint8_t        cachedSecret[CURVE25519_KEYSIZE] = {0};
    uint16_t       cachedSecretLen                  = sizeof(cachedSecret);
    uint8_t        labelOut[WH_NVM_LABEL_LEN]       = {0};
    uint8_t        secretLabel[]                    = "TestX25519CachedSecret";
    whKeyId        privAId                          = WH_KEYID_ERASED;
    whKeyId        privBId                          = WH_KEYID_ERASED;
    whKeyId        pubBId                           = WH_KEYID_ERASED;
    whKeyId        secretId                         = WH_KEYID_ERASED;
    int            pubBInit                         = 0;
    int            key_size                         = CURVE25519_KEYSIZE;

    WH_TEST_PRINT("Testing cache-mode CURVE25519...\n");

    ret = wc_curve25519_init_ex(key_a, NULL, devId);
    if (ret == 0) {
        ret = wc_curve25519_init_ex(key_b, NULL, devId);
    }
    if (ret == 0) {
        ret = wh_Client_Curve25519MakeCacheKey(
            ctx, (uint16_t)key_size, &privAId, WH_NVM_FLAGS_USAGE_DERIVE,
            (const uint8_t*)"X25519CachePrivA", 16);
    }
    if (ret == 0) {
        ret = wh_Client_Curve25519MakeCacheKey(
            ctx, (uint16_t)key_size, &privBId, WH_NVM_FLAGS_USAGE_DERIVE,
            (const uint8_t*)"X25519CachePrivB", 16);
    }
    if (ret == 0) {
        ret = wh_Client_Curve25519SetKeyId(key_a, privAId);
    }
    if (ret == 0) {
        ret = wh_Client_Curve25519SetKeyId(key_b, privBId);
    }

    /* Public-only copy of B, imported as its own cache slot, so shared-secret
     * calls receive a real (private, public-only) pair instead of two private
     * keyIds. */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(pubB, NULL, INVALID_DEVID);
        if (ret == 0) {
            pubBInit = 1;
            ret = wh_Client_Curve25519ExportPublicKey(ctx, privBId, pubB, 0,
                                                      NULL);
        }
    }
    if (ret == 0) {
        uint8_t lbl[] = "X25519CachePubB";
        ret           = wh_Client_Curve25519ImportKey(
            ctx, pubB, &pubBId, WH_NVM_FLAGS_USAGE_DERIVE, sizeof(lbl), lbl);
    }

    /* Export-mode reference via the async Request/Response pair. Doubles as
     * direct coverage for wh_Client_Curve25519SharedSecretRequest/Response. */
    if (ret == 0) {
        ret = wh_Client_Curve25519SharedSecretRequest(ctx, privAId, pubBId,
                                                      EC25519_LITTLE_ENDIAN);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Curve25519SharedSecretResponse(
                    ctx, exportSecret, &exportSecretLen);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    /* Cache mode via the async pair */
    if (ret == 0) {
        secretId = WH_KEYID_ERASED;
        ret      = wh_Client_Curve25519SharedSecretCacheKeyRequest(
            ctx, privAId, pubBId, EC25519_LITTLE_ENDIAN, secretId,
            WH_NVM_FLAGS_USAGE_DERIVE, secretLabel, sizeof(secretLabel));
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Curve25519SharedSecretCacheKeyResponse(
                    ctx, &secretId);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if ((ret == 0) && WH_KEYID_ISERASED(secretId)) {
            WH_ERROR_PRINT(
                "X25519: server returned erased keyId from cache mode\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* Read back cached secret and compare with export-mode reference */
    if (ret == 0) {
        cachedSecretLen = sizeof(cachedSecret);
        ret = wh_Client_KeyExport(ctx, secretId, labelOut, sizeof(labelOut),
                                  cachedSecret, &cachedSecretLen);
    }
    if (ret == 0) {
        if ((cachedSecretLen != exportSecretLen) ||
            (memcmp(cachedSecret, exportSecret, exportSecretLen) != 0)) {
            WH_ERROR_PRINT(
                "X25519: cached secret does not match export-mode secret\n");
            ret = WH_ERROR_ABORTED;
        }
        if (memcmp(labelOut, secretLabel, sizeof(secretLabel)) != 0) {
            WH_ERROR_PRINT("X25519: cached secret label mismatch\n");
            ret = WH_ERROR_ABORTED;
        }
    }
    if (!WH_KEYID_ISERASED(secretId)) {
        (void)wh_Client_KeyEvict(ctx, secretId);
        secretId = WH_KEYID_ERASED;
    }

    /* Cache mode with caller-supplied keyId: server must honor the slot */
    if (ret == 0) {
        whKeyId  requestedId                        = 0x42;
        whKeyId  returnedId                         = requestedId;
        uint8_t  suppliedCached[CURVE25519_KEYSIZE] = {0};
        uint16_t suppliedCachedLen                  = sizeof(suppliedCached);
        uint8_t  suppliedLabelOut[WH_NVM_LABEL_LEN] = {0};

        ret = wh_Client_Curve25519SharedSecretCacheKeyRequest(
            ctx, privAId, pubBId, EC25519_LITTLE_ENDIAN, requestedId,
            WH_NVM_FLAGS_USAGE_DERIVE, secretLabel, sizeof(secretLabel));
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Curve25519SharedSecretCacheKeyResponse(
                    ctx, &returnedId);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if ((ret == WH_ERROR_OK) && (returnedId != requestedId)) {
            WH_ERROR_PRINT("X25519: caller-supplied keyId not honored "
                           "(asked 0x%x, got 0x%x)\n",
                           (unsigned)requestedId, (unsigned)returnedId);
            ret = WH_ERROR_ABORTED;
        }
        if (ret == 0) {
            ret = wh_Client_KeyExport(ctx, returnedId, suppliedLabelOut,
                                      sizeof(suppliedLabelOut), suppliedCached,
                                      &suppliedCachedLen);
        }
        if (ret == 0) {
            if ((suppliedCachedLen != exportSecretLen) ||
                (memcmp(suppliedCached, exportSecret, exportSecretLen) != 0)) {
                WH_ERROR_PRINT(
                    "X25519: caller-supplied-keyId cached secret does not "
                    "match reference\n");
                ret = WH_ERROR_ABORTED;
            }
        }
        if (!WH_KEYID_ISERASED(returnedId)) {
            (void)wh_Client_KeyEvict(ctx, returnedId);
        }
    }

    /* Cache mode with NONEXPORTABLE: export must be rejected */
    if (ret == 0) {
        whKeyId  nonExportId                  = WH_KEYID_ERASED;
        uint8_t  dummyBuf[CURVE25519_KEYSIZE] = {0};
        uint16_t dummyBufLen                  = sizeof(dummyBuf);
        uint8_t  dummyLabel[WH_NVM_LABEL_LEN] = {0};

        ret = wh_Client_Curve25519SharedSecretCacheKeyRequest(
            ctx, privAId, pubBId, EC25519_LITTLE_ENDIAN, nonExportId,
            WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_DERIVE, secretLabel,
            sizeof(secretLabel));
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Curve25519SharedSecretCacheKeyResponse(
                    ctx, &nonExportId);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if ((ret == WH_ERROR_OK) && WH_KEYID_ISERASED(nonExportId)) {
            WH_ERROR_PRINT(
                "X25519: NONEXPORTABLE cache returned erased keyId\n");
            ret = WH_ERROR_ABORTED;
        }
        if (ret == 0) {
            int rc =
                wh_Client_KeyExport(ctx, nonExportId, dummyLabel,
                                    sizeof(dummyLabel), dummyBuf, &dummyBufLen);
            if (rc != WH_ERROR_ACCESS) {
                WH_ERROR_PRINT(
                    "X25519: KeyExport on NONEXPORTABLE secret returned %d "
                    "(expected WH_ERROR_ACCESS)\n",
                    rc);
                ret = WH_ERROR_ABORTED;
            }
        }
        if (!WH_KEYID_ISERASED(nonExportId)) {
            (void)wh_Client_KeyEvict(ctx, nonExportId);
        }
    }

    /* Guards */
    if (ret == 0) {
        whKeyId tmp = WH_KEYID_ERASED;
        int     rc  = wh_Client_Curve25519SharedSecretCacheKey(
            ctx, key_a, key_b, EC25519_LITTLE_ENDIAN, &tmp,
            WH_NVM_FLAGS_EPHEMERAL | WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "X25519: CacheKey with EPHEMERAL returned %d (expected "
                "BADARGS)\n",
                rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc = wh_Client_Curve25519SharedSecretCacheKey(
            ctx, key_a, key_b, EC25519_LITTLE_ENDIAN, NULL,
            WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "X25519: CacheKey NULL inout returned %d (expected BADARGS)\n",
                rc);
            ret = -1;
        }
    }

    /* Blocking wrapper path with auto-imported local keys */
    if (ret == 0) {
        curve25519_key keyC[1]                            = {0};
        curve25519_key keyD[1]                            = {0};
        int            keyCInit                           = 0;
        int            keyDInit                           = 0;
        whKeyId        blockId                            = WH_KEYID_ERASED;
        uint8_t        blockRefSecret[CURVE25519_KEYSIZE] = {0};
        uint16_t       blockRefSecretLen = sizeof(blockRefSecret);
        uint8_t        blockCachedSecret[CURVE25519_KEYSIZE] = {0};
        uint16_t       blockCachedSecretLen = sizeof(blockCachedSecret);
        uint8_t        blockLabelOut[WH_NVM_LABEL_LEN] = {0};

        ret = wc_curve25519_init_ex(keyC, NULL, INVALID_DEVID);
        if (ret == 0) {
            keyCInit = 1;
            ret      = wc_curve25519_make_key(rng, (word32)key_size, keyC);
        }
        if (ret == 0) {
            ret = wc_curve25519_init_ex(keyD, NULL, INVALID_DEVID);
        }
        if (ret == 0) {
            keyDInit = 1;
            ret      = wc_curve25519_make_key(rng, (word32)key_size, keyD);
        }
        /* Reference: blocking export wrapper auto-imports the same local keys
         */
        if (ret == 0) {
            ret = wh_Client_Curve25519SharedSecret(
                ctx, keyC, keyD, EC25519_LITTLE_ENDIAN, blockRefSecret,
                &blockRefSecretLen);
        }
        if (ret == 0) {
            ret = wh_Client_Curve25519SharedSecretCacheKey(
                ctx, keyC, keyD, EC25519_LITTLE_ENDIAN, &blockId,
                WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0);
        }
        if ((ret == 0) && WH_KEYID_ISERASED(blockId)) {
            WH_ERROR_PRINT("X25519: blocking CacheKey returned erased keyId\n");
            ret = WH_ERROR_ABORTED;
        }
        if (ret == 0) {
            ret = wh_Client_KeyExport(ctx, blockId, blockLabelOut,
                                      sizeof(blockLabelOut), blockCachedSecret,
                                      &blockCachedSecretLen);
        }
        if (ret == 0) {
            if ((blockCachedSecretLen != blockRefSecretLen) ||
                (memcmp(blockCachedSecret, blockRefSecret, blockRefSecretLen) !=
                 0)) {
                WH_ERROR_PRINT(
                    "X25519: blocking-wrapper cached secret does not match "
                    "reference\n");
                ret = WH_ERROR_ABORTED;
            }
        }
        if (!WH_KEYID_ISERASED(blockId)) {
            (void)wh_Client_KeyEvict(ctx, blockId);
        }
        if (keyDInit) {
            wc_curve25519_free(keyD);
        }
        if (keyCInit) {
            wc_curve25519_free(keyC);
        }
    }

    /* Cleanup */
    if (!WH_KEYID_ISERASED(pubBId)) {
        (void)wh_Client_KeyEvict(ctx, pubBId);
    }
    if (!WH_KEYID_ISERASED(privBId)) {
        (void)wh_Client_KeyEvict(ctx, privBId);
    }
    if (!WH_KEYID_ISERASED(privAId)) {
        (void)wh_Client_KeyEvict(ctx, privAId);
    }
    if (pubBInit) {
        wc_curve25519_free(pubB);
    }
    wc_curve25519_free(key_b);
    wc_curve25519_free(key_a);

    if (ret == 0) {
        WH_TEST_PRINT("CURVE25519 cache-mode SUCCESS\n");
    }
    return ret;
}

static int whTest_CryptoCurve25519ExportPublic(whClientContext* ctx, int devId,
                                               WC_RNG* rng)
{
    int            ret       = 0;
    whKeyId        keyId     = WH_KEYID_ERASED;
    curve25519_key hsmPub[1] = {0};   /* exported public half */
    curve25519_key hsmPriv[1] = {0};  /* HSM-side priv, referenced by keyId */
    curve25519_key localKey[1] = {0}; /* client-side ephemeral keypair */
    uint8_t        shared_hsm[CURVE25519_KEYSIZE]   = {0};
    uint8_t        shared_local[CURVE25519_KEYSIZE] = {0};
    word32         len     = 0;
    /* Large enough to hold a Curve25519 key DER so the access-control
     * assertion doesn't get masked by a buffer-too-small failure. */
    uint8_t        denyBuf[256];
    uint16_t       denyLen = sizeof(denyBuf);

    /* Cache an X25519 keypair on the HSM with NONEXPORTABLE set. */
    ret = wh_Client_Curve25519MakeCacheKey(
        ctx, (uint16_t)CURVE25519_KEYSIZE, &keyId,
        WH_NVM_FLAGS_USAGE_DERIVE | WH_NVM_FLAGS_NONEXPORTABLE, NULL, 0);
    if (ret != 0) {
        WH_ERROR_PRINT(
            "Failed to make NONEXPORTABLE cached Curve25519 key %d\n", ret);
        return ret;
    }

    /* Full export must be denied */
    {
        int denyRet = wh_Client_KeyExport(ctx, keyId, NULL, 0, denyBuf,
                                          &denyLen);
        if (denyRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT(
                "NONEXPORTABLE Curve25519 full export was not denied: %d\n",
                denyRet);
            ret = -1;
        }
    }

    /* Export public; assert it parses */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(hsmPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_Curve25519ExportPublicKey(ctx, keyId, hsmPub, 0,
                                                      NULL);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "wh_Client_Curve25519ExportPublicKey failed %d\n", ret);
            }
        }
    }

    /* Shared-secret round-trip: HSM-side private + local public, vs.
     * local private + HSM-side public. Both sides must agree. */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(localKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, localKey);
        }
    }

    if (ret == 0) {
        /* Local side: localKey (priv) * hsmPub (pub) */
        len = sizeof(shared_local);
        ret = wc_curve25519_shared_secret(localKey, hsmPub, shared_local, &len);
        if (ret != 0) {
            WH_ERROR_PRINT("Local Curve25519 shared secret failed %d\n", ret);
        }
    }

    if (ret == 0) {
        /* HSM side: reference the cached private by keyId (dispatch through
         * the wolfHSM cryptoCb), pair it with the client-side localKey as
         * the public half. */
        ret = wc_curve25519_init_ex(hsmPriv, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_Curve25519SetKeyId(hsmPriv, keyId);
        }
        if (ret == 0) {
            len = sizeof(shared_hsm);
            ret = wc_curve25519_shared_secret(hsmPriv, localKey, shared_hsm,
                                              &len);
            if (ret != 0) {
                WH_ERROR_PRINT("HSM Curve25519 shared secret failed %d\n", ret);
            }
        }
        wc_curve25519_free(hsmPriv);
    }

    if (ret == 0) {
        if (memcmp(shared_hsm, shared_local, len) != 0) {
            WH_ERROR_PRINT(
                "Curve25519 export-public shared secret mismatch\n");
            ret = -1;
        }
    }

    wc_curve25519_free(localKey);
    wc_curve25519_free(hsmPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("CURVE25519 EXPORT-PUBLIC SUCCESS\n");
    }
    return ret;
}

/* One keygen call caches the private key and returns the public key. Verify
 * the returned public key byte-matches wh_Client_Curve25519ExportPublicKey and
 * that an X25519 shared secret round-trips against the cached private key. */
static int whTest_CryptoCurve25519CacheKeyAndExportPublic(whClientContext* ctx,
                                                          int devId,
                                                          WC_RNG* rng)
{
    int            ret        = 0;
    whKeyId        keyId      = WH_KEYID_ERASED;
    curve25519_key genPub[1]  = {0};
    curve25519_key refPub[1]  = {0};
    curve25519_key localKey[1] = {0};
    uint8_t        genRaw[CURVE25519_KEYSIZE] = {0};
    uint8_t        refRaw[CURVE25519_KEYSIZE] = {0};
    word32         genRawLen  = sizeof(genRaw);
    word32         refRawLen  = sizeof(refRaw);
    uint8_t        shared_hsm[CURVE25519_KEYSIZE]   = {0};
    uint8_t        shared_local[CURVE25519_KEYSIZE] = {0};
    word32         len        = 0;
    (void)devId;

    ret = wc_curve25519_init_ex(genPub, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Client_Curve25519MakeCacheKeyAndExportPublic(
            ctx, (uint16_t)CURVE25519_KEYSIZE, &keyId,
            WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0, genPub);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Curve25519MakeCacheKeyAndExportPublic failed %d\n", ret);
        }
    }

    /* Cross-check the keygen-returned public key against ExportPublicKey. */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(refPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_Curve25519ExportPublicKey(ctx, keyId, refPub, 0,
                                                      NULL);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "wh_Client_Curve25519ExportPublicKey failed %d\n", ret);
            }
        }
    }
    if (ret == 0) {
        ret = wc_curve25519_export_public(genPub, genRaw, &genRawLen);
        if (ret == 0) {
            ret = wc_curve25519_export_public(refPub, refRaw, &refRawLen);
        }
        if (ret != 0) {
            WH_ERROR_PRINT("Curve25519 export_public failed %d\n", ret);
        }
        else if ((genRawLen != refRawLen) ||
                 (memcmp(genRaw, refRaw, genRawLen) != 0)) {
            WH_ERROR_PRINT("keygen pubkey mismatch vs ExportPublicKey\n");
            ret = -1;
        }
    }

    /* Shared-secret round-trip using genPub directly as the HSM private-key
     * handle (no separate key object): our local private key * genPub's
     * exported public key (computed locally) must equal genPub's HSM private
     * key * our local public key (computed on the server). */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(localKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, localKey);
        }
    }
    if (ret == 0) {
        len = sizeof(shared_local);
        ret = wc_curve25519_shared_secret(localKey, genPub, shared_local, &len);
        if (ret != 0) {
            WH_ERROR_PRINT("Local Curve25519 shared secret failed %d\n", ret);
        }
    }
    if (ret == 0) {
        len = sizeof(shared_hsm);
        ret = wc_curve25519_shared_secret(genPub, localKey, shared_hsm, &len);
        if (ret != 0) {
            WH_ERROR_PRINT("HSM Curve25519 shared secret failed %d\n", ret);
        }
    }
    if (ret == 0) {
        if (memcmp(shared_hsm, shared_local, len) != 0) {
            WH_ERROR_PRINT("Curve25519 keygen-pub shared secret mismatch\n");
            ret = -1;
        }
    }

    wc_curve25519_free(localKey);
    wc_curve25519_free(refPub);
    wc_curve25519_free(genPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("CURVE25519 CACHE-AND-EXPORT-PUBLIC SUCCESS\n");
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifndef NO_SHA256
static int whTest_CryptoSha256(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx; (void)rng; /* Not currently used */
    int ret = WH_ERROR_OK;
    wc_Sha256 sha256[1];
    uint8_t   out[WC_SHA256_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA256_DIGEST_SIZE] = {
        0xff, 0xe0, 0x54, 0xfe, 0x7a, 0xe0, 0xcb, 0x6d, 0xc6, 0x5c, 0x3a,
        0xf9, 0xb6, 0x1d, 0x52, 0x09, 0xf4, 0x39, 0x85, 0x1d, 0xb4, 0x3d,
        0x0b, 0xa5, 0x99, 0x73, 0x37, 0xdf, 0x15, 0x46, 0x68, 0xeb};
    /* Vector long enough to span a SHA256 block */
    const char inMulti[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA256_DIGEST_SIZE] = {
        0x7b, 0x54, 0x45, 0x86, 0xb3, 0x51, 0x43, 0x4e, 0xf6, 0x83, 0xdb,
        0x78, 0x1d, 0x94, 0xd6, 0xb0, 0x36, 0x9b, 0x36, 0x56, 0x93, 0x0e,
        0xf4, 0x47, 0x9b, 0xae, 0xff, 0xfa, 0x1f, 0x36, 0x38, 0x64};

    /* Initialize SHA256 structure */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha256 on devId 0x%X: %d\n", devId,
                ret);
    } else {
        /* Test SHA256 on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha256Update(sha256,
                (const byte*)inOne,
                WC_SHA256_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha256Update %d\n", ret);
        } else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha256Final(sha256, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha256Final %d\n", ret);
            } else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA256_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA256 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA256_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha256Free(sha256);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha256_ex(sha256, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha256 for devId 0x%X: %d\n",
                    devId, ret);
        } else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha256Update(sha256,
                    (const byte*)inMulti,
                    1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha256Update (first) %d\n", ret);
            } else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha256Update(sha256,
                        (const byte*)inMulti + 1,
                        WC_SHA256_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha256Update (mid) %d\n", ret);
                } else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha256Update(sha256,
                            (const byte*)inMulti + 1 + WC_SHA256_BLOCK_SIZE,
                           strlen(inMulti) - 1 - WC_SHA256_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha256Update (last) %d\n",
                                ret);
                    } else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha256Final(sha256, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha256Final %d\n",
                                    ret);
                        } else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA256_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA256 hash does not match the "
                                        "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha256Free(sha256);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("SHA256 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Hash a buffer with a pure-software SHA256 (no devId) so we can compare. */
static int whTest_Sha256Reference(const uint8_t* in, uint32_t inLen,
                                  uint8_t out[WC_SHA256_DIGEST_SIZE])
{
    wc_Sha256 sw[1];
    int       ret = wc_InitSha256_ex(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha256Update(sw, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(sw, out);
    }
    (void)wc_Sha256Free(sw);
    return ret;
}

/* Drive the new multi-block wire format through the blocking wrapper. Tests:
 *  - large multi-request input,
 *  - exact per-call inline capacity boundary,
 *  - one-byte-over-capacity boundary (forces a tail in the client buffer),
 *  - non-aligned chunked update sequence.
 *
 * Buffer is sized to comfortably exceed the per-call inline capacity at any
 * reasonable comm-buffer size. We use a static buffer to keep stack pressure
 * low under ASAN. */
static uint8_t
    whTest_Sha256BigBuf[2 *
                        (WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ + 64u)];

static int whTest_CryptoSha256LargeInput(whClientContext* ctx, int devId,
                                         WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha256 sha256[1];
    uint8_t   out[WC_SHA256_DIGEST_SIZE];
    uint8_t   ref[WC_SHA256_DIGEST_SIZE];
    uint8_t*  buf   = whTest_Sha256BigBuf;
    uint32_t  BUFSZ = (uint32_t)sizeof(whTest_Sha256BigBuf);
    uint32_t  i;

    (void)ctx;
    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }

    /* Test 1: large single-update */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha256Update(sha256, buf, BUFSZ);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(sha256, out);
    }
    (void)wc_Sha256Free(sha256);
    if (ret == 0) {
        ret = whTest_Sha256Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("SHA256 large input mismatch\n");
        ret = -1;
    }

    /* Test 2: exactly the per-call inline capacity in one shot */
    if (ret == 0) {
        const uint32_t cap = WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ;
        ret                = wc_InitSha256_ex(sha256, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha256Update(sha256, buf, cap);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(sha256, out);
        }
        (void)wc_Sha256Free(sha256);
        if (ret == 0) {
            ret = whTest_Sha256Reference(buf, cap, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA256 capacity-boundary mismatch\n");
            ret = -1;
        }
    }

    /* Test 3: capacity + 1 byte (one full request, then a tail buffered) */
    if (ret == 0) {
        const uint32_t cap1 =
            WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ + 1u;
        ret = wc_InitSha256_ex(sha256, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha256Update(sha256, buf, cap1);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(sha256, out);
        }
        (void)wc_Sha256Free(sha256);
        if (ret == 0) {
            ret = whTest_Sha256Reference(buf, cap1, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA256 capacity+1 mismatch\n");
            ret = -1;
        }
    }

    /* Test 4: non-aligned chunk stress test */
    if (ret == 0) {
        const uint32_t chunks[] = {13, 17, 1280, 41, 1};
        const size_t   nChunks  = sizeof(chunks) / sizeof(chunks[0]);
        uint32_t       total    = 0;
        size_t         k;
        for (k = 0; k < nChunks; k++) {
            total += chunks[k];
        }
        if (total > BUFSZ) {
            WH_ERROR_PRINT("test buffer too small for chunked stress test\n");
            ret = -1;
        }
        if (ret == 0) {
            uint32_t off = 0;
            ret          = wc_InitSha256_ex(sha256, NULL, devId);
            for (k = 0; ret == 0 && k < nChunks; k++) {
                ret = wc_Sha256Update(sha256, buf + off, chunks[k]);
                off += chunks[k];
            }
            if (ret == 0) {
                ret = wc_Sha256Final(sha256, out);
            }
            (void)wc_Sha256Free(sha256);
            if (ret == 0) {
                ret = whTest_Sha256Reference(buf, total, ref);
            }
            if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT("SHA256 chunked stress mismatch\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA256 LARGE-INPUT DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the new async non-DMA SHA256 primitives. */
static int whTest_CryptoSha256Async(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha256 sha256[1];
    uint8_t   out[WC_SHA256_DIGEST_SIZE];
    uint8_t   ref[WC_SHA256_DIGEST_SIZE];
    /* Use the same large static buffer as the LargeInput test. */
    uint8_t* buf   = whTest_Sha256BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha256BigBuf);
    uint32_t i;
    bool     sent;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    }

    /* Case A: basic UpdateRequest -> UpdateResponse -> Final */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret == 0) {
        sent = false;
        ret  = wh_Client_Sha256UpdateRequest(ctx, sha256, buf, 256, &sent);
    }
    if (ret == 0 && sent) {
        do {
            ret = wh_Client_Sha256UpdateResponse(ctx, sha256);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_Sha256FinalRequest(ctx, sha256);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha256FinalResponse(ctx, sha256, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha256Reference(buf, 256, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA256 case A mismatch\n");
        ret = -1;
    }

    /* Case B: pure-buffer-fill update (sent must be false), then finalize */
    if (ret == 0) {
        (void)wc_Sha256Free(sha256);
        ret = wc_InitSha256_ex(sha256, NULL, devId);
    }
    if (ret == 0) {
        sent = true; /* expect to be cleared to false */
        ret  = wh_Client_Sha256UpdateRequest(ctx, sha256, buf, 10, &sent);
        if (ret == 0 && sent != false) {
            WH_ERROR_PRINT(
                "Async SHA256: expected sent==false on small update\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha256FinalRequest(ctx, sha256);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha256FinalResponse(ctx, sha256, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha256Reference(buf, 10, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA256 case B mismatch\n");
        ret = -1;
    }

    /* Case C: multi-round async updates that span more than the per-call
     * inline capacity (forces multiple Request/Response pairs). */
    if (ret == 0) {
        uint32_t consumed = 0;
        (void)wc_Sha256Free(sha256);
        ret = wc_InitSha256_ex(sha256, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            /* arbitrary, 70% of max inline */
            uint32_t chunk =
                (WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ * 7 / 10);
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            sent = false;
            ret  = wh_Client_Sha256UpdateRequest(ctx, sha256, buf + consumed,
                                                 chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha256UpdateResponse(ctx, sha256);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha256FinalRequest(ctx, sha256);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha256FinalResponse(ctx, sha256, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = whTest_Sha256Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async SHA256 case C mismatch\n");
            ret = -1;
        }
    }

    /* Case D: oversized-input rejection. UpdateRequest with inLen > capacity
     * must return BADARGS without mutating sha. */
    if (ret == 0) {
        uint8_t  savedDigest[WC_SHA256_DIGEST_SIZE];
        word32   savedBuffLen;
        uint32_t cap;
        int      rc;
        (void)wc_Sha256Free(sha256);
        ret = wc_InitSha256_ex(sha256, NULL, devId);
        if (ret == 0) {
            memcpy(savedDigest, sha256->digest, WC_SHA256_DIGEST_SIZE);
            savedBuffLen = sha256->buffLen;
            cap          = WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ +
                  (uint32_t)(WC_SHA256_BLOCK_SIZE - 1u - sha256->buffLen);
            sent = true;
            rc   = wh_Client_Sha256UpdateRequest(ctx, sha256, buf, cap + 1u,
                                                 &sent);
            if (rc != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT("Async SHA256: expected BADARGS, got %d\n", rc);
                ret = -1;
            }
            else if (sent != false) {
                WH_ERROR_PRINT(
                    "Async SHA256: sent should remain false on err\n");
                ret = -1;
            }
            else if (sha256->buffLen != savedBuffLen ||
                     memcmp(sha256->digest, savedDigest,
                            WC_SHA256_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT(
                    "Async SHA256: state mutated on rejected call\n");
                ret = -1;
            }
        }
        (void)wc_Sha256Free(sha256);
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA256 ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA SHA256 primitives. */
static int whTest_CryptoSha256DmaAsync(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha256 sha256[1];
    uint8_t   out[WC_SHA256_DIGEST_SIZE];
    uint8_t   ref[WC_SHA256_DIGEST_SIZE];
    /* DMA bypasses the comm buffer, so any size goes; reuse the shared
     * static buffer to keep stack pressure low. */
    uint8_t* buf   = whTest_Sha256BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha256BigBuf);
    uint32_t i;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 17u + 3u) & 0xff);
    }

    /* Case A: single large DMA Update + Final */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_Sha256DmaUpdateRequest(ctx, sha256, buf, BUFSZ, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_Sha256DmaUpdateResponse(ctx, sha256);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha256DmaFinalRequest(ctx, sha256);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha256DmaFinalResponse(ctx, sha256, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    (void)wc_Sha256Free(sha256);
    if (ret == 0) {
        ret = whTest_Sha256Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA SHA256 case A mismatch\n");
        ret = -1;
    }

    /* Case B: multiple DMA Update round-trips, then Final */
    if (ret == 0) {
        uint32_t consumed = 0;
        ret               = wc_InitSha256_ex(sha256, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            uint32_t chunk = 1024;
            bool     sent  = false;
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            ret = wh_Client_Sha256DmaUpdateRequest(ctx, sha256, buf + consumed,
                                                   chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha256DmaUpdateResponse(ctx, sha256);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha256DmaFinalRequest(ctx, sha256);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha256DmaFinalResponse(ctx, sha256, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        (void)wc_Sha256Free(sha256);
        if (ret == 0) {
            ret = whTest_Sha256Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async DMA SHA256 case B mismatch\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA256 DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA224
static int whTest_CryptoSha224(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng; /* Not currently used */
    int       ret = WH_ERROR_OK;
    wc_Sha224 sha224[1];
    uint8_t   out[WC_SHA224_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA224_DIGEST_SIZE] = {
        0xa8, 0x8c, 0xd5, 0xcd, 0xe6, 0xd6, 0xfe, 0x91, 0x36, 0xa4,
        0xe5, 0x8b, 0x49, 0x16, 0x74, 0x61, 0xea, 0x95, 0xd3, 0x88,
        0xca, 0x2b, 0xdb, 0x7a, 0xfd, 0xc3, 0xcb, 0xf4};
    /* Vector long enough to span a SHA224 block */
    const char inMulti[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
                           "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA224_DIGEST_SIZE] = {
        0xb4, 0x22, 0xdc, 0xe8, 0xf9, 0x48, 0x8c, 0x4b, 0xc3, 0xef,
        0x8e, 0x7d, 0xbe, 0x11, 0xc7, 0x21, 0xba, 0x38, 0xcb, 0x61,
        0xf5, 0x6b, 0x7d, 0xc5, 0x30, 0xa7, 0x9c, 0xfd};
    /* Initialize SHA224 structure */
    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha224 on devId 0x%X: %d\n", devId,
                       ret);
    }
    else {
        /* Test SHA224 on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha224Update(sha224, (const byte*)inOne, WC_SHA224_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha224Update %d\n", ret);
        }
        else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha224Final(sha224, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha224Final %d\n", ret);
            }
            else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA224_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA224 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA224_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha224Free(sha224);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha224_ex(sha224, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha224 for devId 0x%X: %d\n",
                           devId, ret);
        }
        else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha224Update(sha224, (const byte*)inMulti, 1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha224Update (first) %d\n", ret);
            }
            else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha224Update(sha224, (const byte*)inMulti + 1,
                                      WC_SHA224_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha224Update (mid) %d\n", ret);
                }
                else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha224Update(
                        sha224, (const byte*)inMulti + 1 + WC_SHA224_BLOCK_SIZE,
                        strlen(inMulti) - 1 - WC_SHA224_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha224Update (last) %d\n",
                                       ret);
                    }
                    else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha224Final(sha224, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha224Final %d\n",
                                           ret);
                        }
                        else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA224_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA224 hash does not match the "
                                               "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha224Free(sha224);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("SHA224 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Hash a buffer with a pure-software SHA224 (no devId) so we can compare. */
static int whTest_Sha224Reference(const uint8_t* in, uint32_t inLen,
                                  uint8_t out[WC_SHA224_DIGEST_SIZE])
{
    wc_Sha224 sw[1];
    int       ret = wc_InitSha224_ex(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha224Update(sw, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha224Final(sw, out);
    }
    (void)wc_Sha224Free(sw);
    return ret;
}

/* Drive the new multi-block wire format through the blocking wrapper. Tests:
 *  - large multi-request input,
 *  - exact per-call inline capacity boundary,
 *  - one-byte-over-capacity boundary (forces a tail in the client buffer),
 *  - non-aligned chunked update sequence.
 *
 * Buffer is sized to comfortably exceed the per-call inline capacity at any
 * reasonable comm-buffer size. We use a static buffer to keep stack pressure
 * low under ASAN. */
static uint8_t
    whTest_Sha224BigBuf[2 *
                        (WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ + 64u)];

static int whTest_CryptoSha224LargeInput(whClientContext* ctx, int devId,
                                         WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha224 sha224[1];
    uint8_t   out[WC_SHA224_DIGEST_SIZE];
    uint8_t   ref[WC_SHA224_DIGEST_SIZE];
    uint8_t*  buf   = whTest_Sha224BigBuf;
    uint32_t  BUFSZ = (uint32_t)sizeof(whTest_Sha224BigBuf);
    uint32_t  i;

    (void)ctx;
    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }

    /* Test 1: large single-update */
    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha224Update(sha224, buf, BUFSZ);
    }
    if (ret == 0) {
        ret = wc_Sha224Final(sha224, out);
    }
    (void)wc_Sha224Free(sha224);
    if (ret == 0) {
        ret = whTest_Sha224Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("SHA224 large input mismatch\n");
        ret = -1;
    }

    /* Test 2: exactly the per-call inline capacity in one shot */
    if (ret == 0) {
        const uint32_t cap = WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ;
        ret                = wc_InitSha224_ex(sha224, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha224Update(sha224, buf, cap);
        }
        if (ret == 0) {
            ret = wc_Sha224Final(sha224, out);
        }
        (void)wc_Sha224Free(sha224);
        if (ret == 0) {
            ret = whTest_Sha224Reference(buf, cap, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA224 capacity-boundary mismatch\n");
            ret = -1;
        }
    }

    /* Test 3: capacity + 1 byte (one full request, then a tail buffered) */
    if (ret == 0) {
        const uint32_t cap1 =
            WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ + 1u;
        ret = wc_InitSha224_ex(sha224, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha224Update(sha224, buf, cap1);
        }
        if (ret == 0) {
            ret = wc_Sha224Final(sha224, out);
        }
        (void)wc_Sha224Free(sha224);
        if (ret == 0) {
            ret = whTest_Sha224Reference(buf, cap1, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA224 capacity+1 mismatch\n");
            ret = -1;
        }
    }

    /* Test 4: non-aligned chunk stress test */
    if (ret == 0) {
        const uint32_t chunks[] = {13, 17, 1280, 41, 1};
        const size_t   nChunks  = sizeof(chunks) / sizeof(chunks[0]);
        uint32_t       total    = 0;
        size_t         k;
        for (k = 0; k < nChunks; k++) {
            total += chunks[k];
        }
        if (total > BUFSZ) {
            WH_ERROR_PRINT("test buffer too small for chunked stress test\n");
            ret = -1;
        }
        if (ret == 0) {
            uint32_t off = 0;
            ret          = wc_InitSha224_ex(sha224, NULL, devId);
            for (k = 0; ret == 0 && k < nChunks; k++) {
                ret = wc_Sha224Update(sha224, buf + off, chunks[k]);
                off += chunks[k];
            }
            if (ret == 0) {
                ret = wc_Sha224Final(sha224, out);
            }
            (void)wc_Sha224Free(sha224);
            if (ret == 0) {
                ret = whTest_Sha224Reference(buf, total, ref);
            }
            if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT("SHA224 chunked stress mismatch\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA224 LARGE-INPUT DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the new async non-DMA SHA224 primitives. */
static int whTest_CryptoSha224Async(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha224 sha224[1];
    uint8_t   out[WC_SHA224_DIGEST_SIZE];
    uint8_t   ref[WC_SHA224_DIGEST_SIZE];
    /* Use the same large static buffer as the LargeInput test. */
    uint8_t* buf   = whTest_Sha224BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha224BigBuf);
    uint32_t i;
    bool     sent;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    }

    /* Case A: basic UpdateRequest -> UpdateResponse -> Final */
    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret == 0) {
        sent = false;
        ret  = wh_Client_Sha224UpdateRequest(ctx, sha224, buf, 256, &sent);
    }
    if (ret == 0 && sent) {
        do {
            ret = wh_Client_Sha224UpdateResponse(ctx, sha224);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_Sha224FinalRequest(ctx, sha224);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha224FinalResponse(ctx, sha224, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha224Reference(buf, 256, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA224 case A mismatch\n");
        ret = -1;
    }

    /* Case B: pure-buffer-fill update (sent must be false), then finalize */
    if (ret == 0) {
        (void)wc_Sha224Free(sha224);
        ret = wc_InitSha224_ex(sha224, NULL, devId);
    }
    if (ret == 0) {
        sent = true; /* expect to be cleared to false */
        ret  = wh_Client_Sha224UpdateRequest(ctx, sha224, buf, 10, &sent);
        if (ret == 0 && sent != false) {
            WH_ERROR_PRINT(
                "Async SHA224: expected sent==false on small update\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha224FinalRequest(ctx, sha224);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha224FinalResponse(ctx, sha224, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha224Reference(buf, 10, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA224 case B mismatch\n");
        ret = -1;
    }

    /* Case C: multi-round async updates that span more than the per-call
     * inline capacity (forces multiple Request/Response pairs). */
    if (ret == 0) {
        uint32_t consumed = 0;
        (void)wc_Sha224Free(sha224);
        ret = wc_InitSha224_ex(sha224, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            /* arbitrary, 70% of max inline */
            uint32_t chunk =
                (WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ * 7 / 10);
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            sent = false;
            ret  = wh_Client_Sha224UpdateRequest(ctx, sha224, buf + consumed,
                                                 chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha224UpdateResponse(ctx, sha224);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha224FinalRequest(ctx, sha224);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha224FinalResponse(ctx, sha224, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = whTest_Sha224Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async SHA224 case C mismatch\n");
            ret = -1;
        }
    }

    /* Case D: oversized-input rejection. UpdateRequest with inLen > capacity
     * must return BADARGS without mutating sha. */
    if (ret == 0) {
        uint8_t  savedDigest[WC_SHA256_DIGEST_SIZE];
        word32   savedBuffLen;
        uint32_t cap;
        int      rc;
        (void)wc_Sha224Free(sha224);
        ret = wc_InitSha224_ex(sha224, NULL, devId);
        if (ret == 0) {
            memcpy(savedDigest, sha224->digest, WC_SHA256_DIGEST_SIZE);
            savedBuffLen = sha224->buffLen;
            cap          = WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ +
                  (uint32_t)(WC_SHA224_BLOCK_SIZE - 1u - sha224->buffLen);
            sent = true;
            rc   = wh_Client_Sha224UpdateRequest(ctx, sha224, buf, cap + 1u,
                                                 &sent);
            if (rc != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT("Async SHA224: expected BADARGS, got %d\n", rc);
                ret = -1;
            }
            else if (sent != false) {
                WH_ERROR_PRINT(
                    "Async SHA224: sent should remain false on err\n");
                ret = -1;
            }
            else if (sha224->buffLen != savedBuffLen ||
                     memcmp(sha224->digest, savedDigest,
                            WC_SHA256_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT(
                    "Async SHA224: state mutated on rejected call\n");
                ret = -1;
            }
        }
        (void)wc_Sha224Free(sha224);
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA224 ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA SHA224 primitives. */
static int whTest_CryptoSha224DmaAsync(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha224 sha224[1];
    uint8_t   out[WC_SHA224_DIGEST_SIZE];
    uint8_t   ref[WC_SHA224_DIGEST_SIZE];
    /* DMA bypasses the comm buffer, so any size goes; reuse the shared
     * static buffer to keep stack pressure low. */
    uint8_t* buf   = whTest_Sha224BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha224BigBuf);
    uint32_t i;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 17u + 3u) & 0xff);
    }

    /* Case A: single large DMA Update + Final */
    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_Sha224DmaUpdateRequest(ctx, sha224, buf, BUFSZ, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_Sha224DmaUpdateResponse(ctx, sha224);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha224DmaFinalRequest(ctx, sha224);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha224DmaFinalResponse(ctx, sha224, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    (void)wc_Sha224Free(sha224);
    if (ret == 0) {
        ret = whTest_Sha224Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA SHA224 case A mismatch\n");
        ret = -1;
    }

    /* Case B: multiple DMA Update round-trips, then Final */
    if (ret == 0) {
        uint32_t consumed = 0;
        ret               = wc_InitSha224_ex(sha224, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            uint32_t chunk = 1024;
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            {
                bool sent = false;
                ret       = wh_Client_Sha224DmaUpdateRequest(
                    ctx, sha224, buf + consumed, chunk, &sent);
                if (ret == 0 && sent) {
                    do {
                        ret = wh_Client_Sha224DmaUpdateResponse(ctx, sha224);
                    } while (ret == WH_ERROR_NOTREADY);
                }
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha224DmaFinalRequest(ctx, sha224);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha224DmaFinalResponse(ctx, sha224, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        (void)wc_Sha224Free(sha224);
        if (ret == 0) {
            ret = whTest_Sha224Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async DMA SHA224 case B mismatch\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA224 DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384
static int whTest_CryptoSha384(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng; /* Not currently used */
    int       ret = WH_ERROR_OK;
    wc_Sha384 sha384[1];
    uint8_t   out[WC_SHA384_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA384_DIGEST_SIZE] = {
        0xed, 0xb1, 0x27, 0x30, 0xa3, 0x66, 0x09, 0x8b, 0x3b, 0x2b, 0xea, 0xc7,
        0x5a, 0x3b, 0xef, 0x1b, 0x09, 0x69, 0xb1, 0x5c, 0x48, 0xe2, 0x16, 0x3c,
        0x23, 0xd9, 0x69, 0x94, 0xf8, 0xd1, 0xbe, 0xf7, 0x60, 0xc7, 0xe2, 0x7f,
        0x3c, 0x46, 0x4d, 0x38, 0x29, 0xf5, 0x6c, 0x0d, 0x53, 0x80, 0x8b, 0x0b};
    /* Vector long enough to span a SHA384 block */
    const char inMulti[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA384_DIGEST_SIZE] = {
        0xe2, 0x56, 0x2a, 0x4b, 0xe2, 0x0a, 0x40, 0x34, 0xc1, 0x23, 0x8b, 0x1d,
        0x68, 0x49, 0x17, 0xdb, 0x8d, 0x3a, 0x78, 0xab, 0x22, 0xf3, 0xa1, 0x51,
        0x70, 0xae, 0x26, 0x80, 0x06, 0x25, 0x99, 0xa5, 0x3d, 0x0f, 0xc3, 0x7a,
        0xbd, 0xe1, 0xe2, 0xc6, 0x07, 0xdf, 0xd9, 0x6a, 0x89, 0xa8, 0x2b, 0x99};
    /* Initialize SHA384 structure */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha384 on devId 0x%X: %d\n", devId,
                       ret);
    }
    else {
        /* Test SHA384on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha384Update(sha384, (const byte*)inOne, WC_SHA384_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha384Update %d\n", ret);
        }
        else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha384Final(sha384, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha384Final %d\n", ret);
            }
            else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA384_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA384 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA384_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha384Free(sha384);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha384_ex(sha384, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha384 for devId 0x%X: %d\n",
                           devId, ret);
        }
        else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha384Update(sha384, (const byte*)inMulti, 1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha384Update (first) %d\n", ret);
            }
            else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha384Update(sha384, (const byte*)inMulti + 1,
                                      WC_SHA384_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha384Update (mid) %d\n", ret);
                }
                else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha384Update(
                        sha384, (const byte*)inMulti + 1 + WC_SHA384_BLOCK_SIZE,
                        strlen(inMulti) - 1 - WC_SHA384_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha384Update (last) %d\n",
                                       ret);
                    }
                    else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha384Final(sha384, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha384Final %d\n",
                                           ret);
                        }
                        else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA384_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA384 hash does not match the "
                                               "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha384Free(sha384);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("SHA384 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Hash a buffer with a pure-software SHA384 (no devId) so we can compare. */
static int whTest_Sha384Reference(const uint8_t* in, uint32_t inLen,
                                  uint8_t out[WC_SHA384_DIGEST_SIZE])
{
    wc_Sha384 sw[1];
    int       ret = wc_InitSha384_ex(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha384Update(sw, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha384Final(sw, out);
    }
    (void)wc_Sha384Free(sw);
    return ret;
}

/* Drive the new multi-block wire format through the blocking wrapper. Tests:
 *  - large multi-request input,
 *  - exact per-call inline capacity boundary,
 *  - one-byte-over-capacity boundary (forces a tail in the client buffer),
 *  - non-aligned chunked update sequence.
 *
 * Buffer is sized to comfortably exceed the per-call inline capacity at any
 * reasonable comm-buffer size. We use a static buffer to keep stack pressure
 * low under ASAN. */
static uint8_t
    whTest_Sha384BigBuf[2 *
                        (WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ + 128u)];

static int whTest_CryptoSha384LargeInput(whClientContext* ctx, int devId,
                                         WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha384 sha384[1];
    uint8_t   out[WC_SHA384_DIGEST_SIZE];
    uint8_t   ref[WC_SHA384_DIGEST_SIZE];
    uint8_t*  buf   = whTest_Sha384BigBuf;
    uint32_t  BUFSZ = (uint32_t)sizeof(whTest_Sha384BigBuf);
    uint32_t  i;

    (void)ctx;
    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }

    /* Test 1: large single-update */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha384Update(sha384, buf, BUFSZ);
    }
    if (ret == 0) {
        ret = wc_Sha384Final(sha384, out);
    }
    (void)wc_Sha384Free(sha384);
    if (ret == 0) {
        ret = whTest_Sha384Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("SHA384 large input mismatch\n");
        ret = -1;
    }

    /* Test 2: exactly the per-call inline capacity in one shot */
    if (ret == 0) {
        const uint32_t cap = WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ;
        ret                = wc_InitSha384_ex(sha384, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha384Update(sha384, buf, cap);
        }
        if (ret == 0) {
            ret = wc_Sha384Final(sha384, out);
        }
        (void)wc_Sha384Free(sha384);
        if (ret == 0) {
            ret = whTest_Sha384Reference(buf, cap, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA384 capacity-boundary mismatch\n");
            ret = -1;
        }
    }

    /* Test 3: capacity + 1 byte (one full request, then a tail buffered) */
    if (ret == 0) {
        const uint32_t cap1 =
            WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ + 1u;
        ret = wc_InitSha384_ex(sha384, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha384Update(sha384, buf, cap1);
        }
        if (ret == 0) {
            ret = wc_Sha384Final(sha384, out);
        }
        (void)wc_Sha384Free(sha384);
        if (ret == 0) {
            ret = whTest_Sha384Reference(buf, cap1, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA384 capacity+1 mismatch\n");
            ret = -1;
        }
    }

    /* Test 4: non-aligned chunk stress test */
    if (ret == 0) {
        const uint32_t chunks[] = {13, 17, 1280, 41, 1};
        const size_t   nChunks  = sizeof(chunks) / sizeof(chunks[0]);
        uint32_t       total    = 0;
        size_t         k;
        for (k = 0; k < nChunks; k++) {
            total += chunks[k];
        }
        if (total > BUFSZ) {
            WH_ERROR_PRINT("test buffer too small for chunked stress test\n");
            ret = -1;
        }
        if (ret == 0) {
            uint32_t off = 0;
            ret          = wc_InitSha384_ex(sha384, NULL, devId);
            for (k = 0; ret == 0 && k < nChunks; k++) {
                ret = wc_Sha384Update(sha384, buf + off, chunks[k]);
                off += chunks[k];
            }
            if (ret == 0) {
                ret = wc_Sha384Final(sha384, out);
            }
            (void)wc_Sha384Free(sha384);
            if (ret == 0) {
                ret = whTest_Sha384Reference(buf, total, ref);
            }
            if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT("SHA384 chunked stress mismatch\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA384 LARGE-INPUT DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the new async non-DMA SHA384 primitives. */
static int whTest_CryptoSha384Async(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha384 sha384[1];
    uint8_t   out[WC_SHA384_DIGEST_SIZE];
    uint8_t   ref[WC_SHA384_DIGEST_SIZE];
    /* Use the same large static buffer as the LargeInput test. */
    uint8_t* buf   = whTest_Sha384BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha384BigBuf);
    uint32_t i;
    bool     sent;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    }

    /* Case A: basic UpdateRequest -> UpdateResponse -> Final */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret == 0) {
        sent = false;
        ret  = wh_Client_Sha384UpdateRequest(ctx, sha384, buf, 256, &sent);
    }
    if (ret == 0 && sent) {
        do {
            ret = wh_Client_Sha384UpdateResponse(ctx, sha384);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_Sha384FinalRequest(ctx, sha384);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha384FinalResponse(ctx, sha384, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha384Reference(buf, 256, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA384 case A mismatch\n");
        ret = -1;
    }

    /* Case B: pure-buffer-fill update (sent must be false), then finalize */
    if (ret == 0) {
        (void)wc_Sha384Free(sha384);
        ret = wc_InitSha384_ex(sha384, NULL, devId);
    }
    if (ret == 0) {
        sent = true; /* expect to be cleared to false */
        ret  = wh_Client_Sha384UpdateRequest(ctx, sha384, buf, 10, &sent);
        if (ret == 0 && sent != false) {
            WH_ERROR_PRINT(
                "Async SHA384: expected sent==false on small update\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha384FinalRequest(ctx, sha384);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha384FinalResponse(ctx, sha384, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha384Reference(buf, 10, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA384 case B mismatch\n");
        ret = -1;
    }

    /* Case C: multi-round async updates that span more than the per-call
     * inline capacity (forces multiple Request/Response pairs). */
    if (ret == 0) {
        uint32_t consumed = 0;
        (void)wc_Sha384Free(sha384);
        ret = wc_InitSha384_ex(sha384, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            /* arbitrary, 70% of max inline */
            uint32_t chunk =
                (WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ * 7 / 10);
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            sent = false;
            ret  = wh_Client_Sha384UpdateRequest(ctx, sha384, buf + consumed,
                                                 chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha384UpdateResponse(ctx, sha384);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha384FinalRequest(ctx, sha384);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha384FinalResponse(ctx, sha384, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = whTest_Sha384Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async SHA384 case C mismatch\n");
            ret = -1;
        }
    }

    /* Case D: oversized-input rejection. UpdateRequest with inLen > capacity
     * must return BADARGS without mutating sha. */
    if (ret == 0) {
        uint8_t  savedDigest[WC_SHA512_DIGEST_SIZE];
        word32   savedBuffLen;
        uint32_t cap;
        int      rc;
        (void)wc_Sha384Free(sha384);
        ret = wc_InitSha384_ex(sha384, NULL, devId);
        if (ret == 0) {
            memcpy(savedDigest, sha384->digest, WC_SHA512_DIGEST_SIZE);
            savedBuffLen = sha384->buffLen;
            cap          = WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ +
                  (uint32_t)(WC_SHA384_BLOCK_SIZE - 1u - sha384->buffLen);
            sent = true;
            rc   = wh_Client_Sha384UpdateRequest(ctx, sha384, buf, cap + 1u,
                                                 &sent);
            if (rc != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT("Async SHA384: expected BADARGS, got %d\n", rc);
                ret = -1;
            }
            else if (sent != false) {
                WH_ERROR_PRINT(
                    "Async SHA384: sent should remain false on err\n");
                ret = -1;
            }
            else if (sha384->buffLen != savedBuffLen ||
                     memcmp(sha384->digest, savedDigest,
                            WC_SHA512_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT(
                    "Async SHA384: state mutated on rejected call\n");
                ret = -1;
            }
        }
        (void)wc_Sha384Free(sha384);
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA384 ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA SHA384 primitives. */
static int whTest_CryptoSha384DmaAsync(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha384 sha384[1];
    uint8_t   out[WC_SHA384_DIGEST_SIZE];
    uint8_t   ref[WC_SHA384_DIGEST_SIZE];
    /* DMA bypasses the comm buffer, so any size goes; reuse the shared
     * static buffer to keep stack pressure low. */
    uint8_t* buf   = whTest_Sha384BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha384BigBuf);
    uint32_t i;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 17u + 3u) & 0xff);
    }

    /* Case A: single large DMA Update + Final */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_Sha384DmaUpdateRequest(ctx, sha384, buf, BUFSZ, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_Sha384DmaUpdateResponse(ctx, sha384);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha384DmaFinalRequest(ctx, sha384);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha384DmaFinalResponse(ctx, sha384, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    (void)wc_Sha384Free(sha384);
    if (ret == 0) {
        ret = whTest_Sha384Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA SHA384 case A mismatch\n");
        ret = -1;
    }

    /* Case B: multiple DMA Update round-trips, then Final */
    if (ret == 0) {
        uint32_t consumed = 0;
        ret               = wc_InitSha384_ex(sha384, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            uint32_t chunk = 1024;
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            {
                bool sent = false;
                ret       = wh_Client_Sha384DmaUpdateRequest(
                    ctx, sha384, buf + consumed, chunk, &sent);
                if (ret == 0 && sent) {
                    do {
                        ret = wh_Client_Sha384DmaUpdateResponse(ctx, sha384);
                    } while (ret == WH_ERROR_NOTREADY);
                }
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha384DmaFinalRequest(ctx, sha384);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha384DmaFinalResponse(ctx, sha384, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        (void)wc_Sha384Free(sha384);
        if (ret == 0) {
            ret = whTest_Sha384Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async DMA SHA384 case B mismatch\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA384 DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
static int whTest_CryptoSha512(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng; /* Not currently used */
    int       ret = WH_ERROR_OK;
    wc_Sha512 sha512[1];
    uint8_t   out[WC_SHA512_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA512_DIGEST_SIZE] = {
        0xb7, 0x3d, 0x19, 0x29, 0xaa, 0x61, 0x59, 0x34, 0xe6, 0x1a, 0x87,
        0x15, 0x96, 0xb3, 0xf3, 0xb3, 0x33, 0x59, 0xf4, 0x2b, 0x81, 0x75,
        0x60, 0x2e, 0x89, 0xf7, 0xe0, 0x6e, 0x5f, 0x65, 0x8a, 0x24, 0x36,
        0x67, 0x80, 0x7e, 0xd3, 0x00, 0x31, 0x4b, 0x95, 0xca, 0xcd, 0xd5,
        0x79, 0xf3, 0xe3, 0x3a, 0xbd, 0xfb, 0xe3, 0x51, 0x90, 0x95, 0x19,
        0xa8, 0x46, 0xd4, 0x65, 0xc5, 0x95, 0x82, 0xf3, 0x21};
    /* Vector long enough to span a SHA512 block */
    const char inMulti[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA512_DIGEST_SIZE] = {
        0xf9, 0x09, 0xb7, 0xb7, 0x7d, 0xa2, 0x32, 0xc8, 0xcf, 0xa8, 0xcc,
        0xde, 0xc4, 0x36, 0x44, 0x74, 0x29, 0x4f, 0xc4, 0x9a, 0xcb, 0x60,
        0x13, 0x6b, 0xdb, 0x10, 0xd6, 0xa6, 0x9d, 0x1b, 0x45, 0xb2, 0x70,
        0xf5, 0x27, 0x9c, 0xe7, 0x80, 0x99, 0x19, 0x9b, 0x91, 0xb3, 0x83,
        0x7f, 0x70, 0xaf, 0x8e, 0x02, 0xd9, 0x6d, 0x20, 0xab, 0x1e, 0x72,
        0xde, 0x7a, 0x25, 0xa3, 0xe5, 0x60, 0x9e, 0xb0, 0x43};
    /* Initialize SHA512 structure */
    ret = wc_InitSha512_ex(sha512, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha512 on devId 0x%X: %d\n", devId,
                       ret);
    }
    else {
        /* Test SHA512 on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha512Update(sha512, (const byte*)inOne, WC_SHA512_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha512Update %d\n", ret);
        }
        else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha512Final(sha512, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha512Final %d\n", ret);
            }
            else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA512_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA512 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA512_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha512Free(sha512);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha512_ex(sha512, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha512 for devId 0x%X: %d\n",
                           devId, ret);
        }
        else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha512Update(sha512, (const byte*)inMulti, 1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha512Update (first) %d\n", ret);
            }
            else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha512Update(sha512, (const byte*)inMulti + 1,
                                      WC_SHA512_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha512Update (mid) %d\n", ret);
                }
                else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha512Update(
                        sha512, (const byte*)inMulti + 1 + WC_SHA512_BLOCK_SIZE,
                        strlen(inMulti) - 1 - WC_SHA512_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha512Update (last) %d\n",
                                       ret);
                    }
                    else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha512Final(sha512, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha512Final %d\n",
                                           ret);
                        }
                        else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA512_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA512 hash does not match the "
                                               "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha512Free(sha512);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("SHA512 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Hash a buffer with a pure-software SHA512 (no devId) so we can compare. */
static int whTest_Sha512Reference(const uint8_t* in, uint32_t inLen,
                                  uint8_t out[WC_SHA512_DIGEST_SIZE])
{
    wc_Sha512 sw[1];
    int       ret = wc_InitSha512_ex(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha512Update(sw, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha512Final(sw, out);
    }
    (void)wc_Sha512Free(sw);
    return ret;
}

/* Drive the new multi-block wire format through the blocking wrapper. Tests:
 *  - large multi-request input,
 *  - exact per-call inline capacity boundary,
 *  - one-byte-over-capacity boundary (forces a tail in the client buffer),
 *  - non-aligned chunked update sequence.
 *
 * Buffer is sized to comfortably exceed the per-call inline capacity at any
 * reasonable comm-buffer size. We use a static buffer to keep stack pressure
 * low under ASAN. */
static uint8_t
    whTest_Sha512BigBuf[2 *
                        (WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ + 128u)];

static int whTest_CryptoSha512LargeInput(whClientContext* ctx, int devId,
                                         WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha512 sha512[1];
    uint8_t   out[WC_SHA512_DIGEST_SIZE];
    uint8_t   ref[WC_SHA512_DIGEST_SIZE];
    uint8_t*  buf   = whTest_Sha512BigBuf;
    uint32_t  BUFSZ = (uint32_t)sizeof(whTest_Sha512BigBuf);
    uint32_t  i;

    (void)ctx;
    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }

    /* Test 1: large single-update */
    ret = wc_InitSha512_ex(sha512, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha512Update(sha512, buf, BUFSZ);
    }
    if (ret == 0) {
        ret = wc_Sha512Final(sha512, out);
    }
    (void)wc_Sha512Free(sha512);
    if (ret == 0) {
        ret = whTest_Sha512Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("SHA512 large input mismatch\n");
        ret = -1;
    }

    /* Test 2: exactly the per-call inline capacity in one shot */
    if (ret == 0) {
        const uint32_t cap = WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ;
        ret                = wc_InitSha512_ex(sha512, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha512Update(sha512, buf, cap);
        }
        if (ret == 0) {
            ret = wc_Sha512Final(sha512, out);
        }
        (void)wc_Sha512Free(sha512);
        if (ret == 0) {
            ret = whTest_Sha512Reference(buf, cap, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA512 capacity-boundary mismatch\n");
            ret = -1;
        }
    }

    /* Test 3: capacity + 1 byte (one full request, then a tail buffered) */
    if (ret == 0) {
        const uint32_t cap1 =
            WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ + 1u;
        ret = wc_InitSha512_ex(sha512, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha512Update(sha512, buf, cap1);
        }
        if (ret == 0) {
            ret = wc_Sha512Final(sha512, out);
        }
        (void)wc_Sha512Free(sha512);
        if (ret == 0) {
            ret = whTest_Sha512Reference(buf, cap1, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA512 capacity+1 mismatch\n");
            ret = -1;
        }
    }

    /* Test 4: non-aligned chunk stress test */
    if (ret == 0) {
        const uint32_t chunks[] = {13, 17, 1280, 41, 1};
        const size_t   nChunks  = sizeof(chunks) / sizeof(chunks[0]);
        uint32_t       total    = 0;
        size_t         k;
        for (k = 0; k < nChunks; k++) {
            total += chunks[k];
        }
        if (total > BUFSZ) {
            WH_ERROR_PRINT("test buffer too small for chunked stress test\n");
            ret = -1;
        }
        if (ret == 0) {
            uint32_t off = 0;
            ret          = wc_InitSha512_ex(sha512, NULL, devId);
            for (k = 0; ret == 0 && k < nChunks; k++) {
                ret = wc_Sha512Update(sha512, buf + off, chunks[k]);
                off += chunks[k];
            }
            if (ret == 0) {
                ret = wc_Sha512Final(sha512, out);
            }
            (void)wc_Sha512Free(sha512);
            if (ret == 0) {
                ret = whTest_Sha512Reference(buf, total, ref);
            }
            if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT("SHA512 chunked stress mismatch\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA512 LARGE-INPUT DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the new async non-DMA SHA512 primitives. */
static int whTest_CryptoSha512Async(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha512 sha512[1];
    uint8_t   out[WC_SHA512_DIGEST_SIZE];
    uint8_t   ref[WC_SHA512_DIGEST_SIZE];
    /* Use the same large static buffer as the LargeInput test. */
    uint8_t* buf   = whTest_Sha512BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha512BigBuf);
    uint32_t i;
    bool     sent;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    }

    /* Case A: basic UpdateRequest -> UpdateResponse -> Final */
    ret = wc_InitSha512_ex(sha512, NULL, devId);
    if (ret == 0) {
        sent = false;
        ret  = wh_Client_Sha512UpdateRequest(ctx, sha512, buf, 256, &sent);
    }
    if (ret == 0 && sent) {
        do {
            ret = wh_Client_Sha512UpdateResponse(ctx, sha512);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_Sha512FinalRequest(ctx, sha512);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha512FinalResponse(ctx, sha512, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha512Reference(buf, 256, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA512 case A mismatch\n");
        ret = -1;
    }

    /* Case B: pure-buffer-fill update (sent must be false), then finalize */
    if (ret == 0) {
        (void)wc_Sha512Free(sha512);
        ret = wc_InitSha512_ex(sha512, NULL, devId);
    }
    if (ret == 0) {
        sent = true; /* expect to be cleared to false */
        ret  = wh_Client_Sha512UpdateRequest(ctx, sha512, buf, 10, &sent);
        if (ret == 0 && sent != false) {
            WH_ERROR_PRINT(
                "Async SHA512: expected sent==false on small update\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha512FinalRequest(ctx, sha512);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha512FinalResponse(ctx, sha512, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha512Reference(buf, 10, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA512 case B mismatch\n");
        ret = -1;
    }

    /* Case C: multi-round async updates that span more than the per-call
     * inline capacity (forces multiple Request/Response pairs). */
    if (ret == 0) {
        uint32_t consumed = 0;
        (void)wc_Sha512Free(sha512);
        ret = wc_InitSha512_ex(sha512, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            /* arbitrary, 70% of max inline */
            uint32_t chunk =
                (WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ * 7 / 10);
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            sent = false;
            ret  = wh_Client_Sha512UpdateRequest(ctx, sha512, buf + consumed,
                                                 chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha512UpdateResponse(ctx, sha512);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha512FinalRequest(ctx, sha512);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha512FinalResponse(ctx, sha512, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = whTest_Sha512Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async SHA512 case C mismatch\n");
            ret = -1;
        }
    }

    /* Case D: oversized-input rejection. UpdateRequest with inLen > capacity
     * must return BADARGS without mutating sha. */
    if (ret == 0) {
        uint8_t  savedDigest[WC_SHA512_DIGEST_SIZE];
        word32   savedBuffLen;
        uint32_t cap;
        int      rc;
        (void)wc_Sha512Free(sha512);
        ret = wc_InitSha512_ex(sha512, NULL, devId);
        if (ret == 0) {
            memcpy(savedDigest, sha512->digest, WC_SHA512_DIGEST_SIZE);
            savedBuffLen = sha512->buffLen;
            cap          = WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ +
                  (uint32_t)(WC_SHA512_BLOCK_SIZE - 1u - sha512->buffLen);
            sent = true;
            rc   = wh_Client_Sha512UpdateRequest(ctx, sha512, buf, cap + 1u,
                                                 &sent);
            if (rc != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT("Async SHA512: expected BADARGS, got %d\n", rc);
                ret = -1;
            }
            else if (sent != false) {
                WH_ERROR_PRINT(
                    "Async SHA512: sent should remain false on err\n");
                ret = -1;
            }
            else if (sha512->buffLen != savedBuffLen ||
                     memcmp(sha512->digest, savedDigest,
                            WC_SHA512_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT(
                    "Async SHA512: state mutated on rejected call\n");
                ret = -1;
            }
        }
        (void)wc_Sha512Free(sha512);
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA512 ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA SHA512 primitives. */
static int whTest_CryptoSha512DmaAsync(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha512 sha512[1];
    uint8_t   out[WC_SHA512_DIGEST_SIZE];
    uint8_t   ref[WC_SHA512_DIGEST_SIZE];
    /* DMA bypasses the comm buffer, so any size goes; reuse the shared
     * static buffer to keep stack pressure low. */
    uint8_t* buf   = whTest_Sha512BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha512BigBuf);
    uint32_t i;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 17u + 3u) & 0xff);
    }

    /* Case A: single large DMA Update + Final */
    ret = wc_InitSha512_ex(sha512, NULL, devId);
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_Sha512DmaUpdateRequest(ctx, sha512, buf, BUFSZ, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_Sha512DmaUpdateResponse(ctx, sha512);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha512DmaFinalRequest(ctx, sha512);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha512DmaFinalResponse(ctx, sha512, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    (void)wc_Sha512Free(sha512);
    if (ret == 0) {
        ret = whTest_Sha512Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA SHA512 case A mismatch\n");
        ret = -1;
    }

    /* Case B: multiple DMA Update round-trips, then Final */
    if (ret == 0) {
        uint32_t consumed = 0;
        ret               = wc_InitSha512_ex(sha512, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            uint32_t chunk = 1024;
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            {
                bool sent = false;
                ret       = wh_Client_Sha512DmaUpdateRequest(
                    ctx, sha512, buf + consumed, chunk, &sent);
                if (ret == 0 && sent) {
                    do {
                        ret = wh_Client_Sha512DmaUpdateResponse(ctx, sha512);
                    } while (ret == WH_ERROR_NOTREADY);
                }
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha512DmaFinalRequest(ctx, sha512);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha512DmaFinalResponse(ctx, sha512, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        (void)wc_Sha512Free(sha512);
        if (ret == 0) {
            ret = whTest_Sha512Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async DMA SHA512 case B mismatch\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA512 DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA512 */

#if defined(WOLFSSL_SHA3)
/* SHA3 native crypto tests.
 *
 * A single set of tests runs against all four variants (224/256/384/512)
 * via a small dispatch table. Tests check both the wolfCrypt API path
 * (devId-dispatched -> our cryptocb) and the native async API.
 */

typedef struct {
    const char* name;
    int         hashType;
    uint32_t    blockSize;
    uint32_t    digestSize;
    uint32_t    maxInlineSz;
    int (*initFn)(wc_Sha3* sha, void* heap, int devId);
    int (*updateFn)(wc_Sha3* sha, const byte* data, word32 len);
    int (*finalFn)(wc_Sha3* sha, byte* hash);
    /* native async client helpers */
    int (*asyncUpdateRequest)(whClientContext*, wc_Sha3*, const uint8_t*,
                              uint32_t, bool*);
    int (*asyncUpdateResponse)(whClientContext*, wc_Sha3*);
    int (*asyncFinalRequest)(whClientContext*, wc_Sha3*);
    int (*asyncFinalResponse)(whClientContext*, wc_Sha3*, uint8_t*);
    /* native one-shot helpers */
    int (*oneshotFn)(whClientContext*, wc_Sha3*, const uint8_t*, uint32_t,
                     uint8_t*);
#ifdef WOLFHSM_CFG_DMA
    int (*dmaUpdateRequest)(whClientContext*, wc_Sha3*, const uint8_t*,
                            uint32_t, bool*);
    int (*dmaUpdateResponse)(whClientContext*, wc_Sha3*);
    int (*dmaFinalRequest)(whClientContext*, wc_Sha3*);
    int (*dmaFinalResponse)(whClientContext*, wc_Sha3*, uint8_t*);
    int (*dmaOneshotFn)(whClientContext*, wc_Sha3*, const uint8_t*, uint32_t,
                        uint8_t*);
#endif
} whTestSha3Variant;

static const whTestSha3Variant whTestSha3Variants[] = {
#ifndef WOLFSSL_NOSHA3_224
    {
        "SHA3-224",
        WC_HASH_TYPE_SHA3_224,
        WC_SHA3_224_BLOCK_SIZE,
        WC_SHA3_224_DIGEST_SIZE,
        WH_MESSAGE_CRYPTO_SHA3_224_MAX_INLINE_UPDATE_SZ,
        wc_InitSha3_224,
        wc_Sha3_224_Update,
        wc_Sha3_224_Final,
        wh_Client_Sha3_224UpdateRequest,
        wh_Client_Sha3_224UpdateResponse,
        wh_Client_Sha3_224FinalRequest,
        wh_Client_Sha3_224FinalResponse,
        wh_Client_Sha3_224,
#ifdef WOLFHSM_CFG_DMA
        wh_Client_Sha3_224DmaUpdateRequest,
        wh_Client_Sha3_224DmaUpdateResponse,
        wh_Client_Sha3_224DmaFinalRequest,
        wh_Client_Sha3_224DmaFinalResponse,
        wh_Client_Sha3_224Dma,
#endif
    },
#endif
#ifndef WOLFSSL_NOSHA3_256
    {
        "SHA3-256",
        WC_HASH_TYPE_SHA3_256,
        WC_SHA3_256_BLOCK_SIZE,
        WC_SHA3_256_DIGEST_SIZE,
        WH_MESSAGE_CRYPTO_SHA3_256_MAX_INLINE_UPDATE_SZ,
        wc_InitSha3_256,
        wc_Sha3_256_Update,
        wc_Sha3_256_Final,
        wh_Client_Sha3_256UpdateRequest,
        wh_Client_Sha3_256UpdateResponse,
        wh_Client_Sha3_256FinalRequest,
        wh_Client_Sha3_256FinalResponse,
        wh_Client_Sha3_256,
#ifdef WOLFHSM_CFG_DMA
        wh_Client_Sha3_256DmaUpdateRequest,
        wh_Client_Sha3_256DmaUpdateResponse,
        wh_Client_Sha3_256DmaFinalRequest,
        wh_Client_Sha3_256DmaFinalResponse,
        wh_Client_Sha3_256Dma,
#endif
    },
#endif
#ifndef WOLFSSL_NOSHA3_384
    {
        "SHA3-384",
        WC_HASH_TYPE_SHA3_384,
        WC_SHA3_384_BLOCK_SIZE,
        WC_SHA3_384_DIGEST_SIZE,
        WH_MESSAGE_CRYPTO_SHA3_384_MAX_INLINE_UPDATE_SZ,
        wc_InitSha3_384,
        wc_Sha3_384_Update,
        wc_Sha3_384_Final,
        wh_Client_Sha3_384UpdateRequest,
        wh_Client_Sha3_384UpdateResponse,
        wh_Client_Sha3_384FinalRequest,
        wh_Client_Sha3_384FinalResponse,
        wh_Client_Sha3_384,
#ifdef WOLFHSM_CFG_DMA
        wh_Client_Sha3_384DmaUpdateRequest,
        wh_Client_Sha3_384DmaUpdateResponse,
        wh_Client_Sha3_384DmaFinalRequest,
        wh_Client_Sha3_384DmaFinalResponse,
        wh_Client_Sha3_384Dma,
#endif
    },
#endif
#ifndef WOLFSSL_NOSHA3_512
    {
        "SHA3-512",
        WC_HASH_TYPE_SHA3_512,
        WC_SHA3_512_BLOCK_SIZE,
        WC_SHA3_512_DIGEST_SIZE,
        WH_MESSAGE_CRYPTO_SHA3_512_MAX_INLINE_UPDATE_SZ,
        wc_InitSha3_512,
        wc_Sha3_512_Update,
        wc_Sha3_512_Final,
        wh_Client_Sha3_512UpdateRequest,
        wh_Client_Sha3_512UpdateResponse,
        wh_Client_Sha3_512FinalRequest,
        wh_Client_Sha3_512FinalResponse,
        wh_Client_Sha3_512,
#ifdef WOLFHSM_CFG_DMA
        wh_Client_Sha3_512DmaUpdateRequest,
        wh_Client_Sha3_512DmaUpdateResponse,
        wh_Client_Sha3_512DmaFinalRequest,
        wh_Client_Sha3_512DmaFinalResponse,
        wh_Client_Sha3_512Dma,
#endif
    },
#endif
};

/* Reference hash via software (INVALID_DEVID) for cross-checks. */
static int whTest_Sha3Reference(const whTestSha3Variant* v, const uint8_t* in,
                                uint32_t inLen, uint8_t* out)
{
    wc_Sha3 sw[1];
    int     ret = v->initFn(sw, NULL, INVALID_DEVID);
    if (ret == 0 && inLen > 0) {
        ret = v->updateFn(sw, in, inLen);
    }
    if (ret == 0) {
        ret = v->finalFn(sw, out);
    }
    /* No Free variant function in our table — wc_Sha3 doesn't allocate by
     * default on POSIX so this is fine. */
    return ret;
}

/* Static buffer sized to cover all variants' max inline + tail slack.
 * SHA3-512 has the smallest block (72) so its floor((P)/block)*block lands
 * closest to the payload cap, making it the upper bound (possibly tied
 * with SHA3-224) across variants. 2x multiplier + 256 tail adds margin. */
#define WH_TEST_SHA3_BIGBUF_SZ \
    (2u * (WH_MESSAGE_CRYPTO_SHA3_512_MAX_INLINE_UPDATE_SZ + 256u))
static uint8_t whTest_Sha3BigBuf[WH_TEST_SHA3_BIGBUF_SZ];

static void whTest_Sha3FillBuf(uint8_t* buf, uint32_t sz)
{
    uint32_t i;
    for (i = 0; i < sz; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xffu);
    }
}

/* Per-variant basic + large-input test using the wolfCrypt API. */
static int whTest_CryptoSha3OneVariant(whClientContext* ctx, int devId,
                                       const whTestSha3Variant* v)
{
    int      ret = WH_ERROR_OK;
    wc_Sha3  sha[1];
    uint8_t  out[WC_SHA3_512_DIGEST_SIZE];
    uint8_t  ref[WC_SHA3_512_DIGEST_SIZE];
    uint32_t cases[] = {0u,
                        1u,
                        v->blockSize - 1u,
                        v->blockSize,
                        v->blockSize + 1u,
                        3u * v->blockSize,
                        v->maxInlineSz,
                        v->maxInlineSz + 1u,
                        WH_TEST_SHA3_BIGBUF_SZ - 1u};
    size_t   n;
    (void)ctx;

    whTest_Sha3FillBuf(whTest_Sha3BigBuf, WH_TEST_SHA3_BIGBUF_SZ);

    for (n = 0; n < sizeof(cases) / sizeof(cases[0]) && ret == 0; n++) {
        uint32_t len = cases[n];
        if (len > WH_TEST_SHA3_BIGBUF_SZ)
            continue;

        ret = whTest_Sha3Reference(v, whTest_Sha3BigBuf, len, ref);
        if (ret != 0) {
            WH_ERROR_PRINT("%s reference failed: %d\n", v->name, ret);
            break;
        }

        ret = v->initFn(sha, NULL, devId);
        if (ret == 0 && len > 0) {
            ret = v->updateFn(sha, whTest_Sha3BigBuf, len);
        }
        if (ret == 0) {
            ret = v->finalFn(sha, out);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s mismatch at len=%u devId=0x%X\n", v->name,
                           (unsigned)len, devId);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("%s DEVID=0x%X SUCCESS\n", v->name, devId);
    }
    return ret;
}

/* One-shot wrapper bad-arg coverage: (in == NULL, inLen != 0) must be
 * rejected before any state mutation. Regression check: the oneshot
 * wrappers previously skipped the update branch on this input and silently
 * returned a digest of the (empty) state. */
static int whTest_CryptoSha3OneshotBadArgs(whClientContext*         ctx,
                                           const whTestSha3Variant* v)
{
    int     ret;
    wc_Sha3 sha[1];
    uint8_t out[WC_SHA3_512_DIGEST_SIZE];
    uint8_t in[1] = {0};

    ret = v->initFn(sha, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = v->oneshotFn(ctx, sha, NULL, 1u, out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("%s oneshot(NULL,1): expected BADARGS, got %d\n",
                       v->name, ret);
        return -1;
    }

    /* sha == NULL with valid input must be rejected, not dereferenced: the
     * oneshot reads sha->i to size each chunk before the lower-level helper's
     * NULL check runs. */
    ret = v->oneshotFn(ctx, NULL, in, sizeof(in), out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("%s oneshot(sha=NULL): expected BADARGS, got %d\n",
                       v->name, ret);
        return -1;
    }

#ifdef WOLFHSM_CFG_DMA
    ret = v->initFn(sha, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;
    ret = v->dmaOneshotFn(ctx, sha, NULL, 1u, out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("%s dma oneshot(NULL,1): expected BADARGS, got %d\n",
                       v->name, ret);
        return -1;
    }
    ret = v->dmaOneshotFn(ctx, NULL, in, sizeof(in), out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("%s dma oneshot(sha=NULL): expected BADARGS, got %d\n",
                       v->name, ret);
        return -1;
    }
#endif

    WH_TEST_PRINT("%s ONESHOT BADARGS SUCCESS\n", v->name);
    return 0;
}

#if defined(WOLFSSL_HASH_FLAGS) && !defined(WOLFSSL_NOSHA3_256)
/* Keccak-mode (legacy 0x01-padding) SHA3-256 is a software-only mode. Lock in
 * the deliberate behavioral split for a KECCAK256-flagged context:
 *   - wolfCrypt API path (HSM devId): the cryptocb returns CRYPTOCB_UNAVAILABLE
 *     so wolfCrypt falls back to software and still produces the Keccak digest
 *     (NOT a standard SHA3-256 digest, which is what a silent offload of the
 *     0x06-padding wire format would yield).
 *   - direct client API (and DMA variant): must be rejected with
 *     WH_ERROR_BADARGS, since the wire format would re-pad as standard SHA3. */
static int whTest_CryptoSha3Keccak(whClientContext* ctx, int devId)
{
    int        ret;
    wc_Sha3    sha[1];
    uint8_t    out[WC_SHA3_256_DIGEST_SIZE];
    uint8_t    keccakRef[WC_SHA3_256_DIGEST_SIZE];
    uint8_t    sha3Ref[WC_SHA3_256_DIGEST_SIZE];
    const char in[]  = "wolfHSM SHA3 Keccak-mode fallback vector";
    uint32_t   inLen = (uint32_t)(sizeof(in) - 1u);

    /* Software Keccak reference (0x01 padding). */
    ret = wc_InitSha3_256(sha, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha3_SetFlags(sha, WC_HASH_SHA3_KECCAK256);
    }
    if (ret == 0) {
        ret = wc_Sha3_256_Update(sha, (const byte*)in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha3_256_Final(sha, keccakRef);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("Keccak reference failed: %d\n", ret);
        return ret;
    }

    /* Software standard SHA3-256 reference (0x06 padding). Must differ from the
     * Keccak digest, else the comparisons below would prove nothing. */
    ret = wc_InitSha3_256(sha, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha3_256_Update(sha, (const byte*)in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha3_256_Final(sha, sha3Ref);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("SHA3-256 reference failed: %d\n", ret);
        return ret;
    }
    if (memcmp(keccakRef, sha3Ref, WC_SHA3_256_DIGEST_SIZE) == 0) {
        WH_ERROR_PRINT("Keccak and SHA3-256 digests unexpectedly equal\n");
        return -1;
    }

    /* cryptocb contract: HSM devId + KECCAK256 flag falls back to software and
     * matches the Keccak (not the standard SHA3) reference. */
    ret = wc_InitSha3_256(sha, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha3_SetFlags(sha, WC_HASH_SHA3_KECCAK256);
    }
    if (ret == 0) {
        ret = wc_Sha3_256_Update(sha, (const byte*)in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha3_256_Final(sha, out);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("Keccak cryptocb fallback failed: %d\n", ret);
        return ret;
    }
    if (memcmp(out, keccakRef, WC_SHA3_256_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Keccak cryptocb fallback mismatch (devId=0x%X)\n",
                       devId);
        return -1;
    }

    /* direct client API contract: KECCAK256 flag must be rejected. */
    ret = wc_InitSha3_256(sha, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha3_SetFlags(sha, WC_HASH_SHA3_KECCAK256);
    }
    if (ret != 0) {
        return ret;
    }
    ret = wh_Client_Sha3_256(ctx, sha, (const uint8_t*)in, inLen, out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("Keccak direct API: expected BADARGS, got %d\n", ret);
        return -1;
    }

#ifdef WOLFHSM_CFG_DMA
    ret = wc_InitSha3_256(sha, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha3_SetFlags(sha, WC_HASH_SHA3_KECCAK256);
    }
    if (ret != 0) {
        return ret;
    }
    ret = wh_Client_Sha3_256Dma(ctx, sha, (const uint8_t*)in, inLen, out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("Keccak direct DMA API: expected BADARGS, got %d\n",
                       ret);
        return -1;
    }
#endif

    WH_TEST_PRINT("SHA3-256 KECCAK fallback/reject DEVID=0x%X SUCCESS\n",
                  devId);
    return 0;
}
#endif /* WOLFSSL_HASH_FLAGS && !WOLFSSL_NOSHA3_256 */

static int whTest_CryptoSha3(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int    ret = WH_ERROR_OK;
    size_t v;
    (void)rng;
    for (v = 0; v < sizeof(whTestSha3Variants) / sizeof(whTestSha3Variants[0]);
         v++) {
        ret = whTest_CryptoSha3OneVariant(ctx, devId, &whTestSha3Variants[v]);
        if (ret != 0)
            break;
        ret = whTest_CryptoSha3OneshotBadArgs(ctx, &whTestSha3Variants[v]);
        if (ret != 0)
            break;
    }
#if defined(WOLFSSL_HASH_FLAGS) && !defined(WOLFSSL_NOSHA3_256)
    if (ret == 0) {
        ret = whTest_CryptoSha3Keccak(ctx, devId);
    }
#endif
    return ret;
}

/* Per-variant native async test. Exercises: basic single round, pure-buffer
 * fill, multi-round, and oversized-input rejection. */
static int whTest_CryptoSha3AsyncOneVariant(whClientContext* ctx, int devId,
                                            const whTestSha3Variant* v)
{
    int     ret = WH_ERROR_OK;
    wc_Sha3 sha[1];
    uint8_t out[WC_SHA3_512_DIGEST_SIZE];
    uint8_t ref[WC_SHA3_512_DIGEST_SIZE];

    whTest_Sha3FillBuf(whTest_Sha3BigBuf, WH_TEST_SHA3_BIGBUF_SZ);

    /* Case A: basic Update + Final via the async API */
    if (ret == 0) {
        uint32_t len  = 3u * v->blockSize + 17u;
        bool     sent = false;
        ret           = whTest_Sha3Reference(v, whTest_Sha3BigBuf, len, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        if (ret == 0)
            ret =
                v->asyncUpdateRequest(ctx, sha, whTest_Sha3BigBuf, len, &sent);
        if (ret == 0 && sent) {
            do {
                ret = v->asyncUpdateResponse(ctx, sha);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0)
            ret = v->asyncFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->asyncFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s async case A mismatch\n", v->name);
            ret = -1;
        }
    }

    /* Case B: pure-buffer-fill update (less than one block), Final */
    if (ret == 0) {
        uint32_t len  = v->blockSize - 1u;
        bool     sent = false;
        ret           = whTest_Sha3Reference(v, whTest_Sha3BigBuf, len, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        if (ret == 0)
            ret =
                v->asyncUpdateRequest(ctx, sha, whTest_Sha3BigBuf, len, &sent);
        if (ret == 0 && sent) {
            /* unexpected — should have been fully buffered */
            WH_ERROR_PRINT("%s case B: unexpected sent==true\n", v->name);
            ret = -1;
        }
        if (ret == 0)
            ret = v->asyncFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->asyncFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s async case B mismatch\n", v->name);
            ret = -1;
        }
    }

    /* Case C: multi-round, ~70% of per-call capacity per chunk */
    if (ret == 0) {
        uint32_t total    = WH_TEST_SHA3_BIGBUF_SZ;
        uint32_t consumed = 0;
        uint32_t cap;
        ret = whTest_Sha3Reference(v, whTest_Sha3BigBuf, total, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        while (ret == 0 && consumed < total) {
            cap = v->maxInlineSz + (uint32_t)(v->blockSize - 1u - sha->i);
            uint32_t chunk = (cap * 7u) / 10u;
            uint32_t rem   = total - consumed;
            bool     sent  = false;
            if (chunk == 0)
                chunk = 1;
            if (chunk > cap)
                chunk = cap;
            if (chunk > rem)
                chunk = rem;
            ret = v->asyncUpdateRequest(ctx, sha, whTest_Sha3BigBuf + consumed,
                                        chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = v->asyncUpdateResponse(ctx, sha);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0)
                consumed += chunk;
        }
        if (ret == 0)
            ret = v->asyncFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->asyncFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s async case C mismatch\n", v->name);
            ret = -1;
        }
    }

    /* Case D: oversize input must be rejected without state mutation. */
    if (ret == 0) {
        uint32_t cap, oversz;
        wc_Sha3  saved;
        bool     sent = false;
        ret           = v->initFn(sha, NULL, devId);
        cap           = v->maxInlineSz + (uint32_t)(v->blockSize - 1u - sha->i);
        oversz        = cap + 1u;
        if (oversz > WH_TEST_SHA3_BIGBUF_SZ)
            oversz = WH_TEST_SHA3_BIGBUF_SZ;
        if (ret == 0) {
            saved = *sha;
            ret   = v->asyncUpdateRequest(ctx, sha, whTest_Sha3BigBuf, oversz,
                                          &sent);
            if (ret != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT("%s case D: expected BADARGS, got %d\n", v->name,
                               ret);
                ret = -1;
            }
            else if (sent) {
                WH_ERROR_PRINT("%s case D: sent should be false\n", v->name);
                ret = -1;
            }
            else if (memcmp(&saved, sha, sizeof(saved)) != 0) {
                WH_ERROR_PRINT("%s case D: sha state mutated\n", v->name);
                ret = -1;
            }
            else {
                ret = WH_ERROR_OK;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("%s ASYNC DEVID=0x%X SUCCESS\n", v->name, devId);
    }
    return ret;
}

static int whTest_CryptoSha3Async(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int    ret = WH_ERROR_OK;
    size_t v;
    (void)rng;
    for (v = 0; v < sizeof(whTestSha3Variants) / sizeof(whTestSha3Variants[0]);
         v++) {
        ret = whTest_CryptoSha3AsyncOneVariant(ctx, devId,
                                               &whTestSha3Variants[v]);
        if (ret != 0)
            break;
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int whTest_CryptoSha3DmaAsyncOneVariant(whClientContext* ctx, int devId,
                                               const whTestSha3Variant* v)
{
    int     ret = WH_ERROR_OK;
    wc_Sha3 sha[1];
    uint8_t out[WC_SHA3_512_DIGEST_SIZE];
    uint8_t ref[WC_SHA3_512_DIGEST_SIZE];

    whTest_Sha3FillBuf(whTest_Sha3BigBuf, WH_TEST_SHA3_BIGBUF_SZ);

    /* Case A: single large DMA update + final */
    if (ret == 0) {
        uint32_t len  = WH_TEST_SHA3_BIGBUF_SZ;
        bool     sent = false;
        ret           = whTest_Sha3Reference(v, whTest_Sha3BigBuf, len, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        if (ret == 0)
            ret = v->dmaUpdateRequest(ctx, sha, whTest_Sha3BigBuf, len, &sent);
        if (ret == 0 && sent) {
            do {
                ret = v->dmaUpdateResponse(ctx, sha);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0)
            ret = v->dmaFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->dmaFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s DMA async case A mismatch\n", v->name);
            ret = -1;
        }
    }

    /* Case B: multi-round DMA with 1024-byte chunks */
    if (ret == 0) {
        uint32_t       total    = WH_TEST_SHA3_BIGBUF_SZ;
        uint32_t       consumed = 0;
        const uint32_t chunkSz  = 1024u;
        ret = whTest_Sha3Reference(v, whTest_Sha3BigBuf, total, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        while (ret == 0 && consumed < total) {
            uint32_t rem   = total - consumed;
            uint32_t chunk = (rem < chunkSz) ? rem : chunkSz;
            bool     sent  = false;
            ret = v->dmaUpdateRequest(ctx, sha, whTest_Sha3BigBuf + consumed,
                                      chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = v->dmaUpdateResponse(ctx, sha);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0)
                consumed += chunk;
        }
        if (ret == 0)
            ret = v->dmaFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->dmaFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s DMA async case B mismatch\n", v->name);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("%s DMA ASYNC DEVID=0x%X SUCCESS\n", v->name, devId);
    }
    return ret;
}

static int whTest_CryptoSha3DmaAsync(whClientContext* ctx, int devId,
                                     WC_RNG* rng)
{
    int    ret = WH_ERROR_OK;
    size_t v;
    (void)rng;
    for (v = 0; v < sizeof(whTestSha3Variants) / sizeof(whTestSha3Variants[0]);
         v++) {
        ret = whTest_CryptoSha3DmaAsyncOneVariant(ctx, devId,
                                                  &whTestSha3Variants[v]);
        if (ret != 0)
            break;
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA3 */

#ifdef HAVE_HKDF
static int whTest_CryptoHkdf(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)rng; /* Not currently used */

    int ret = WH_ERROR_OK;

#define WH_TEST_HKDF_IKM_SIZE 22
#define WH_TEST_HKDF_SALT_SIZE 13
#define WH_TEST_HKDF_INFO_SIZE 10
#define WH_TEST_HKDF_OKM_SIZE 42

    /* Test vectors from RFC 5869 Test Case 1 */
    const uint8_t ikm[WH_TEST_HKDF_IKM_SIZE] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    const uint8_t salt[WH_TEST_HKDF_SALT_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04,
                                                  0x05, 0x06, 0x07, 0x08, 0x09,
                                                  0x0a, 0x0b, 0x0c};
    const uint8_t info[WH_TEST_HKDF_INFO_SIZE] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                                  0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    const uint8_t expected[WH_TEST_HKDF_OKM_SIZE] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
        0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
        0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
        0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

    uint8_t okm[WH_TEST_HKDF_OKM_SIZE];
    uint8_t okm2[WH_TEST_HKDF_OKM_SIZE];
    whKeyId key_id  = WH_KEYID_ERASED;
    uint8_t label[] = "HKDF Test Label";

    /* Test 1: Direct wc_HKDF call (uses crypto callback) */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF_ex(WC_SHA256, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
                     WH_TEST_HKDF_SALT_SIZE, info, WH_TEST_HKDF_INFO_SIZE, okm,
                     WH_TEST_HKDF_OKM_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_HKDF: %d\n", ret);
        return ret;
    }

    /* Verify output matches expected */
    if (memcmp(okm, expected, WH_TEST_HKDF_OKM_SIZE) != 0) {
        WH_ERROR_PRINT("HKDF output does not match expected (wc_HKDF)\n");
        return -1;
    }

    /* Test 2: HKDF without salt. Just ensure no errors */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF_ex(
        WC_SHA256, ikm, WH_TEST_HKDF_IKM_SIZE, NULL, 0, /* No salt */
        info, WH_TEST_HKDF_INFO_SIZE, okm, WH_TEST_HKDF_OKM_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_HKDF (no salt): %d\n", ret);
        return ret;
    }

    /* Test 3: HKDF without info. Just ensure no errors */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF_ex(WC_SHA256, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
                     WH_TEST_HKDF_SALT_SIZE, NULL, 0, /* No info */
                     okm, WH_TEST_HKDF_OKM_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_HKDF (no info): %d\n", ret);
        return ret;
    }

    /* Test 4: wh_Client_HkdfMakeExportKey */
    memset(okm, 0, sizeof(okm));
    ret = wh_Client_HkdfMakeExportKey(
        ctx, WC_SHA256, WH_KEYID_ERASED, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
        WH_TEST_HKDF_SALT_SIZE, info, WH_TEST_HKDF_INFO_SIZE, okm,
        WH_TEST_HKDF_OKM_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_HkdfMakeExportKey: %d\n", ret);
        return ret;
    }

    /* Verify output matches expected vector, should be same as wolfCrypt API */
    if (memcmp(okm, expected, WH_TEST_HKDF_OKM_SIZE) != 0) {
        WH_ERROR_PRINT("HKDF output does not match expected (MakeExportKey)\n");
        return -1;
    }

    /* Test 5: wh_Client_HkdfMakeCacheKey */
    key_id = WH_KEYID_ERASED;
    ret    = wh_Client_HkdfMakeCacheKey(
           ctx, WC_SHA256, WH_KEYID_ERASED, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
           WH_TEST_HKDF_SALT_SIZE, info, WH_TEST_HKDF_INFO_SIZE, &key_id,
           WH_NVM_FLAGS_NONE, label, sizeof(label), WH_TEST_HKDF_OKM_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_HkdfMakeCacheKey: %d\n", ret);
        return ret;
    }

    /* Verify key was cached */
    if (key_id == WH_KEYID_ERASED) {
        WH_ERROR_PRINT("Key ID was not assigned\n");
        (void)wh_Client_KeyEvict(ctx, key_id);
        return -1;
    }

    /* Export the cached key to verify its contents */
    memset(okm2, 0, sizeof(okm2));
    {
        uint8_t  export_label[sizeof(label)] = {0};
        uint16_t export_len                  = WH_TEST_HKDF_OKM_SIZE;
        ret = wh_Client_KeyExport(ctx, key_id, export_label,
                                  sizeof(export_label), okm2, &export_len);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyExport: %d\n", ret);
            (void)wh_Client_KeyEvict(ctx, key_id);
            return ret;
        }

        /* Verify exported length matches expected */
        if (export_len != WH_TEST_HKDF_OKM_SIZE) {
            WH_ERROR_PRINT("Exported key length mismatch: %u != %u\n",
                           export_len, WH_TEST_HKDF_OKM_SIZE);
            (void)wh_Client_KeyEvict(ctx, key_id);
            return -1;
        }

        /* Verify output matches expected */
        if (memcmp(okm2, expected, WH_TEST_HKDF_OKM_SIZE) != 0) {
            WH_ERROR_PRINT(
                "HKDF output does not match expected (MakeCacheKey)\n");
            (void)wh_Client_KeyEvict(ctx, key_id);
            return -1;
        }
    }

    /* Evict the cached HKDF key */
    ret = wh_Client_KeyEvict(ctx, key_id);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to evict HKDF cached key: %d\n", ret);
        return ret;
    }

    /* Test 6: HKDF with cached input key */
    {
        whKeyId keyIdIn    = WH_KEYID_ERASED;
        uint8_t label_in[] = "input-key";
        byte    ikm2[]     = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                              0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F};
        byte    salt2[]    = {0xB0, 0xB1, 0xB2, 0xB3};
        byte    info2[]    = {0xC0, 0xC1, 0xC2};
        byte    okm_cache[WH_TEST_HKDF_OKM_SIZE];
        byte    okm_direct[WH_TEST_HKDF_OKM_SIZE];

        /* First, cache the input key */
        ret =
            wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_DERIVE, label_in,
                               sizeof(label_in), ikm2, sizeof(ikm2), &keyIdIn);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache input key: %d\n", ret);
            return ret;
        }

        /* Derive using cached input key (inKey=NULL, inKeySz=0) */
        memset(okm_cache, 0, sizeof(okm_cache));
        ret = wh_Client_HkdfMakeExportKey(
            ctx, WC_SHA256, keyIdIn, NULL, 0, salt2, sizeof(salt2), info2,
            sizeof(info2), okm_cache, sizeof(okm_cache));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed HKDF with cached input key: %d\n", ret);
            (void)wh_Client_KeyEvict(ctx, keyIdIn);
            return ret;
        }

        /* Derive the same way but with direct key input for comparison */
        memset(okm_direct, 0, sizeof(okm_direct));
        ret = wh_Client_HkdfMakeExportKey(ctx, WC_SHA256, WH_KEYID_ERASED, ikm2,
                                          sizeof(ikm2), salt2, sizeof(salt2),
                                          info2, sizeof(info2), okm_direct,
                                          sizeof(okm_direct));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed HKDF with direct input key: %d\n", ret);
            (void)wh_Client_KeyEvict(ctx, keyIdIn);
            return ret;
        }

        /* Verify both methods produce the same output */
        if (memcmp(okm_cache, okm_direct, sizeof(okm_cache)) != 0) {
            WH_ERROR_PRINT(
                "HKDF output mismatch (cached vs direct input key)\n");
            (void)wh_Client_KeyEvict(ctx, keyIdIn);
            return -1;
        }

        /* Clean up - evict the cached input key */
        ret = wh_Client_KeyEvict(ctx, keyIdIn);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to evict input key: %d\n", ret);
            return ret;
        }
    }

    WH_TEST_PRINT("HKDF SUCCESS\n");
    return 0;
}
#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
#define WH_TEST_CMAC_KDF_SALT_SIZE 24
#define WH_TEST_CMAC_KDF_Z_SIZE 32
#define WH_TEST_CMAC_KDF_FIXED_INFO_SIZE 60
#define WH_TEST_CMAC_KDF_OUT_SIZE 40

static int whTest_CryptoCmacKdf(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)rng;

    int ret = WH_ERROR_OK;

    /* Test vectors based on wolfSSL CMAC KDF implementation test vectors for
     * NIST SP 800-108 KDF in Counter Mode using CMAC */
    static const uint8_t salt[WH_TEST_CMAC_KDF_SALT_SIZE] = {
        0x20, 0x51, 0xaf, 0x34, 0x76, 0x2e, 0xbe, 0x55, 0x6f, 0x72, 0xa5, 0xc6,
        0xed, 0xc7, 0x77, 0x1e, 0xb9, 0x24, 0x5f, 0xad, 0x76, 0xf0, 0x34, 0xbe};
    static const uint8_t z[WH_TEST_CMAC_KDF_Z_SIZE] = {
        0xae, 0x8e, 0x93, 0xc9, 0xc9, 0x91, 0xcf, 0x89, 0x6a, 0x49, 0x1a,
        0x89, 0x07, 0xdf, 0x4e, 0x4b, 0xe5, 0x18, 0x6a, 0xe4, 0x96, 0xcd,
        0x34, 0x0d, 0xc1, 0x9b, 0x23, 0x78, 0x21, 0xdb, 0x7b, 0x60};
    static const uint8_t fixedInfo[WH_TEST_CMAC_KDF_FIXED_INFO_SIZE] = {
        0xa2, 0x59, 0xca, 0xe2, 0xc4, 0xa3, 0x6b, 0x89, 0x56, 0x3c, 0xb1, 0x48,
        0xc7, 0x82, 0x51, 0x34, 0x3b, 0xbf, 0xab, 0xdc, 0x13, 0xca, 0x7a, 0xc2,
        0x17, 0x1c, 0x2e, 0xb6, 0x02, 0x1f, 0x44, 0x77, 0xfe, 0xa3, 0x3b, 0x28,
        0x72, 0x4d, 0xa7, 0x21, 0xee, 0x08, 0x7b, 0xff, 0xd7, 0x94, 0xa1, 0x56,
        0x37, 0x54, 0xb4, 0x25, 0xa8, 0xd0, 0x9b, 0x3e, 0x0d, 0xa5, 0xff, 0xed};
    static const uint8_t expected[WH_TEST_CMAC_KDF_OUT_SIZE] = {
        0xb4, 0x0c, 0x32, 0xbe, 0x01, 0x27, 0x93, 0xba, 0xfd, 0xf7,
        0x78, 0xc5, 0xf4, 0x54, 0x43, 0xf4, 0xc9, 0x71, 0x23, 0x93,
        0x17, 0x63, 0xd8, 0x3a, 0x59, 0x27, 0x07, 0xbf, 0xf2, 0xd3,
        0x60, 0x59, 0x50, 0x27, 0x29, 0xca, 0xb8, 0x8b, 0x29, 0x38};

    uint8_t  out[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  out_direct[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  out_cached_input[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  exported[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  exportLabel[12] = {0};
    uint16_t export_len      = WH_TEST_CMAC_KDF_OUT_SIZE;
    whKeyId  key_id          = WH_KEYID_ERASED;
    uint8_t  keyLabel[]      = "CMAC KDF Key";

    /* 1. Direct wolfCrypt API call that routes through the callback */
    memset(out, 0, sizeof(out));
    ret = wc_KDA_KDF_twostep_cmac(salt, WH_TEST_CMAC_KDF_SALT_SIZE, z,
                                  WH_TEST_CMAC_KDF_Z_SIZE, fixedInfo,
                                  WH_TEST_CMAC_KDF_FIXED_INFO_SIZE, out,
                                  WH_TEST_CMAC_KDF_OUT_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wc_KDA_KDF_twostep_cmac: %d\n", ret);
        return ret;
    }
    if (memcmp(out, expected, sizeof(out)) != 0) {
        WH_ERROR_PRINT("CMAC KDF output mismatch (direct wolfCrypt)\n");
        return -1;
    }

    /* 2. Client export path using direct input buffers */
    memset(out_direct, 0, sizeof(out_direct));
    ret = wh_Client_CmacKdfMakeExportKey(
        ctx, WH_KEYID_ERASED, salt, WH_TEST_CMAC_KDF_SALT_SIZE, WH_KEYID_ERASED,
        z, WH_TEST_CMAC_KDF_Z_SIZE, fixedInfo, WH_TEST_CMAC_KDF_FIXED_INFO_SIZE,
        out_direct, sizeof(out_direct));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wh_Client_CmacKdfMakeExportKey: %d\n", ret);
        return ret;
    }
    if (memcmp(out_direct, expected, sizeof(out_direct)) != 0) {
        WH_ERROR_PRINT("CMAC KDF output mismatch (export key)\n");
        return -1;
    }

    /* 3. Client cache path with direct input buffers */
    key_id = WH_KEYID_ERASED;
    ret    = wh_Client_CmacKdfMakeCacheKey(
           ctx, WH_KEYID_ERASED, salt, WH_TEST_CMAC_KDF_SALT_SIZE, WH_KEYID_ERASED,
           z, WH_TEST_CMAC_KDF_Z_SIZE, fixedInfo, WH_TEST_CMAC_KDF_FIXED_INFO_SIZE,
           &key_id, WH_NVM_FLAGS_NONE, keyLabel, sizeof(keyLabel),
           WH_TEST_CMAC_KDF_OUT_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wh_Client_CmacKdfMakeCacheKey: %d\n", ret);
        return ret;
    }
    if (key_id == WH_KEYID_ERASED) {
        WH_ERROR_PRINT("CMAC KDF cache did not return a key id\n");
        return -1;
    }

    memset(exported, 0, sizeof(exported));
    export_len = (uint16_t)sizeof(exported);
    memset(exportLabel, 0, sizeof(exportLabel));
    ret = wh_Client_KeyExport(ctx, key_id, exportLabel, sizeof(exportLabel),
                              exported, &export_len);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export cached CMAC KDF key: %d\n", ret);
        (void)wh_Client_KeyEvict(ctx, key_id);
        return ret;
    }
    if ((export_len != WH_TEST_CMAC_KDF_OUT_SIZE) ||
        (memcmp(exported, expected, sizeof(exported)) != 0)) {
        WH_ERROR_PRINT("Exported CMAC KDF key mismatch\n");
        (void)wh_Client_KeyEvict(ctx, key_id);
        return -1;
    }
    ret = wh_Client_KeyEvict(ctx, key_id);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to evict cached CMAC KDF key: %d\n", ret);
        return ret;
    }

    /* 4. Use cached salt and Z inputs */
    whKeyId saltKeyId = WH_KEYID_ERASED;
    whKeyId zKeyId    = WH_KEYID_ERASED;
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0, salt,
                             WH_TEST_CMAC_KDF_SALT_SIZE, &saltKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache CMAC KDF salt: %d\n", ret);
        return ret;
    }
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0, z,
                             WH_TEST_CMAC_KDF_Z_SIZE, &zKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache CMAC KDF Z input: %d\n", ret);
        (void)wh_Client_KeyEvict(ctx, saltKeyId);
        return ret;
    }

    memset(out_cached_input, 0, sizeof(out_cached_input));
    ret = wh_Client_CmacKdfMakeExportKey(
        ctx, saltKeyId, NULL, 0, zKeyId, NULL, 0, fixedInfo,
        WH_TEST_CMAC_KDF_FIXED_INFO_SIZE, out_cached_input,
        sizeof(out_cached_input));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed CMAC KDF export with cached inputs: %d\n", ret);
        goto cleanup_inputs;
    }
    if (memcmp(out_cached_input, expected, sizeof(out_cached_input)) != 0) {
        WH_ERROR_PRINT("CMAC KDF mismatch (cached inputs export)\n");
        ret = -1;
        goto cleanup_inputs;
    }

    key_id = WH_KEYID_ERASED;
    ret    = wh_Client_CmacKdfMakeCacheKey(
           ctx, saltKeyId, NULL, 0, zKeyId, NULL, 0, fixedInfo,
           WH_TEST_CMAC_KDF_FIXED_INFO_SIZE, &key_id, WH_NVM_FLAGS_NONE, keyLabel,
           sizeof(keyLabel), WH_TEST_CMAC_KDF_OUT_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed CMAC KDF cache with cached inputs: %d\n", ret);
        goto cleanup_inputs;
    }
    if (key_id == WH_KEYID_ERASED) {
        WH_ERROR_PRINT(
            "CMAC KDF cache (cached inputs) did not return key id\n");
        ret = -1;
        goto cleanup_inputs;
    }

    memset(exported, 0, sizeof(exported));
    export_len = (uint16_t)sizeof(exported);
    memset(exportLabel, 0, sizeof(exportLabel));
    ret = wh_Client_KeyExport(ctx, key_id, exportLabel, sizeof(exportLabel),
                              exported, &export_len);
    if ((ret != 0) || (export_len != WH_TEST_CMAC_KDF_OUT_SIZE) ||
        (memcmp(exported, expected, sizeof(exported)) != 0)) {
        WH_ERROR_PRINT("Export mismatch for CMAC KDF cached inputs (ret=%d)\n",
                       ret);
        if (ret == 0) {
            ret = -1;
        }
    }

    (void)wh_Client_KeyEvict(ctx, key_id);

cleanup_inputs:
    (void)wh_Client_KeyEvict(ctx, saltKeyId);
    (void)wh_Client_KeyEvict(ctx, zKeyId);

    if (ret != WH_ERROR_OK) {
        return ret;
    }

    WH_TEST_PRINT("CMAC KDF SUCCESS\n");
    return 0;
}
#endif /* HAVE_CMAC_KDF */

static int whTest_CacheExportKey(whClientContext* ctx, whKeyId* inout_key_id,
        uint8_t* label_in,  uint8_t* label_out, uint16_t label_len,
        uint8_t* key_in, uint8_t* key_out, uint16_t key_len)
{
    int ret = 0;
    uint16_t label_len_out = label_len;
    uint16_t key_len_out = key_len;
    whKeyId key_id_out = *inout_key_id;
    ret = wh_Client_KeyCache(ctx, 0, label_in, label_len, key_in, key_len,
            &key_id_out);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
    } else {
        ret = wh_Client_KeyExport(ctx, key_id_out, label_out, label_len_out,
                key_out, &key_len_out);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        } else {
            if ((key_len_out != key_len) ||
                (memcmp(key_in, key_out, key_len_out) != 0) ||
                (memcmp(label_in, label_out, label_len) != 0)) {
                ret = -1;
            }
        }
    }
    *inout_key_id = key_id_out;
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int whTest_CacheExportKeyDma(whClientContext* ctx, whKeyId* inout_key_id,
                                    uint8_t* label_in, uint8_t* label_out,
                                    uint16_t label_len, uint8_t* key_in,
                                    uint8_t* key_out, uint16_t key_len)
{
    int      ret           = 0;
    uint16_t label_len_out = label_len;
    uint16_t key_len_out   = key_len;
    whKeyId  key_id_out    = *inout_key_id;

    ret = wh_Client_KeyCacheDma(ctx, 0, label_in, label_len, key_in, key_len,
                                &key_id_out);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCacheDma %d\n", ret);
    }
    else {
        ret = wh_Client_KeyExportDma(ctx, key_id_out, key_out, key_len_out,
                                     label_out, label_len_out, &key_len_out);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyExportDma %d\n", ret);
        }
        else {
            if ((key_len_out != key_len) ||
                (memcmp(key_in, key_out, key_len_out) != 0) ||
                (memcmp(label_in, label_out, label_len) != 0)) {
                ret = -1;
            }
        }
    }
    *inout_key_id = key_id_out;
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

static int whTest_KeyCacheRandom(whClientContext* ctx, int devId,
                                     WC_RNG* rng)
{
    (void)devId;
    (void)rng; /* Unused */

#define WH_TEST_KEYCACHERANDOM_KEYSIZE 32
    int      ret;
    int      i;
    int      isZero;
    uint16_t outLen;
    uint16_t keyId;
    uint16_t keyId2;
    uint8_t  keyOut[WH_TEST_KEYCACHERANDOM_KEYSIZE]  = {0};
    uint8_t  keyOut2[WH_TEST_KEYCACHERANDOM_KEYSIZE] = {0};
    uint8_t  labelIn[WH_NVM_LABEL_LEN]      = "KeyCacheRandom Test";
    uint8_t  labelOut[WH_NVM_LABEL_LEN]     = {0};

    /* Generate a key from the server RNG and cache it */
    keyId = WH_KEYID_ERASED;
    ret   = wh_Client_KeyCacheRandom(ctx, 0, labelIn, sizeof(labelIn),
                                         WH_TEST_KEYCACHERANDOM_KEYSIZE, &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCacheRandom %d\n", ret);
    }
    else if (keyId == WH_KEYID_ERASED) {
        WH_ERROR_PRINT("KeyCacheRandom returned erased keyId\n");
        ret = -1;
    }

    /* Export it back and verify size, label, and that RNG actually ran */
    if (ret == 0) {
        outLen = sizeof(keyOut);
        ret    = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut),
                                     keyOut, &outLen);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        }
        else if (outLen != WH_TEST_KEYCACHERANDOM_KEYSIZE) {
            WH_ERROR_PRINT("KeyCacheRandom bad length %u\n", outLen);
            ret = -1;
        }
        else if (memcmp(labelIn, labelOut, sizeof(labelIn)) != 0) {
            WH_ERROR_PRINT("KeyCacheRandom label mismatch\n");
            ret = -1;
        }
        else {
            /* sanity: generated key should not be all zeros */
            isZero = 1;
            for (i = 0; i < (int)outLen; i++) {
                if (keyOut[i] != 0) {
                    isZero = 0;
                    break;
                }
            }
            if (isZero) {
                WH_ERROR_PRINT("KeyCacheRandom produced all-zero key\n");
                ret = -1;
            }
        }
    }

    /* A second generation should yield a distinct auto-assigned keyId and
     * distinct key material */
    if (ret == 0) {
        keyId2 = WH_KEYID_ERASED;
        ret    = wh_Client_KeyCacheRandom(ctx, 0, labelIn, sizeof(labelIn),
                                              WH_TEST_KEYCACHERANDOM_KEYSIZE, &keyId2);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCacheRandom(2) %d\n", ret);
        }
        else if (keyId2 == keyId) {
            WH_ERROR_PRINT("KeyCacheRandom reused keyId 0x%X\n", keyId);
            ret = -1;
        }
        else {
            /* Export the second key and confirm its bytes differ from the
             * first — two RNG generations must not produce the same key */
            outLen = sizeof(keyOut2);
            ret    = wh_Client_KeyExport(ctx, keyId2, labelOut,
                                         sizeof(labelOut), keyOut2, &outLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyExport(2) %d\n", ret);
            }
            else if (outLen != WH_TEST_KEYCACHERANDOM_KEYSIZE) {
                WH_ERROR_PRINT("KeyCacheRandom(2) bad length %u\n", outLen);
                ret = -1;
            }
            else if (memcmp(keyOut, keyOut2, outLen) == 0) {
                WH_ERROR_PRINT("KeyCacheRandom produced identical keys\n");
                ret = -1;
            }
        }
        (void)wh_Client_KeyEvict(ctx, keyId2);
    }

    (void)wh_Client_KeyEvict(ctx, keyId);

    if (ret == 0) {
        WH_TEST_PRINT("KEY CACHE RANDOM SUCCESS\n");
    }
    return ret;
}

static int whTest_KeyCache(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)devId; (void)rng; /* Unused */

#define WH_TEST_KEYCACHE_KEYSIZE 16
    int ret;
    int i;
    uint16_t outLen;
    uint16_t keyId;
    uint8_t key[WH_TEST_KEYCACHE_KEYSIZE];
    uint8_t keyOut[WH_TEST_KEYCACHE_KEYSIZE] = {0};
    uint8_t labelIn[WH_NVM_LABEL_LEN] = "KeyCache Test Label";
    uint8_t labelOut[WH_NVM_LABEL_LEN] = {0};

    /* Randomize inputs */
    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
    }

    /* test regular cache/export */
    keyId = WH_KEYID_ERASED;
    if (ret == 0) {
        ret = whTest_CacheExportKey(ctx, &keyId,
            labelIn, labelOut, sizeof(labelIn),
            key, keyOut, sizeof(key));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to Test CacheExportKey %d\n", ret);
        } else {
            WH_TEST_PRINT("KEY CACHE/EXPORT SUCCESS\n");
        }
    }
#ifdef WOLFHSM_CFG_IS_TEST_SERVER
    /* WOLFHSM_CFG_IS_TEST_SERVER protects the client test code that
     * expects to interop with the custom server (also defined in this
     * file), so that this test can be run against a standard server app
     *
     * TODO: This is a temporary bodge until we properly split tests into
     * single client and multi client */

    if (ret == 0) {
        /* test cache with duplicate keyId for a different user */
        ret = wh_Client_CommClose(ctx);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to CommClose:%d\n",ret);
        } else {
            ctx->comm->client_id = ALT_CLIENT_ID;
            ret = wh_Client_CommInit(ctx, NULL, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to CommInit:%d\n", ret);
            } else {
                /* Check that evicting the other client's key fails */
                ret = wh_Client_KeyEvict(ctx, keyId);
                if (ret != WH_ERROR_NOTFOUND) {
                    WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n",
                            ret);
                } else {
                    ret = whTest_CacheExportKey(ctx, &keyId,
                            labelIn, labelOut, sizeof(labelIn),
                            key, keyOut, sizeof(key));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to Test CacheExportKey %d\n",
                                ret);
                    } else {
                        /* evict for this client */
                        (void)wh_Client_KeyEvict(ctx, keyId);
                    }
                }
                /* switch back and verify original key */
                (void)wh_Client_CommClose(ctx);
                ctx->comm->client_id = WH_TEST_DEFAULT_CLIENT_ID;
                ret = wh_Client_CommInit(ctx, NULL, NULL);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to reconnect: %d\n", ret);
                } else {
                    outLen = sizeof(keyOut);
                    ret = wh_Client_KeyExport(ctx, keyId, labelOut,
                            sizeof(labelOut), keyOut, &outLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n",
                                ret);
                    } else {
                        if ((outLen != sizeof(key)) ||
                            (memcmp(key, keyOut, outLen) != 0) ||
                            (memcmp(labelIn, labelOut, sizeof(labelIn)) != 0)) {
                            WH_ERROR_PRINT("Failed to match\n");
                            ret = -1;
                        }
                        else {
                            WH_TEST_PRINT("KEY CACHE USER EXCLUSION SUCCESS\n");
                        }
                    }
                }
            }
        }
    }
#endif /* WOLFHSM_CFG_IS_TEST_SERVER */
    if (ret == 0) {
        /* test evict for original client */
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
        } else {
            outLen = sizeof(keyOut);
            ret = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut),
                    keyOut, &outLen);
            if (ret != WH_ERROR_NOTFOUND) {
                WH_ERROR_PRINT("Failed to not find evicted key %d\n", ret);
            } else {
                WH_TEST_PRINT("KEY CACHE EVICT SUCCESS\n");
                ret = 0;
            }
        }
    }

    if (ret == 0) {
        /* test commit/erase */
        keyId = WH_KEYID_ERASED;
        ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                sizeof(key), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        } else {
            ret = wh_Client_KeyCommit(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
            } else {
                ret = wh_Client_KeyEvict(ctx, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
                } else {
                    outLen = sizeof(keyOut);
                    ret = wh_Client_KeyExport(ctx, keyId, labelOut,
                            sizeof(labelOut), keyOut, &outLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n",
                                ret);
                    } else {
                        if ((outLen != sizeof(key) ||
                             (memcmp(key, keyOut, outLen) != 0) ||
                             (memcmp(labelIn, labelOut, sizeof(labelIn))) !=
                                 0)) {
                            WH_ERROR_PRINT("Failed to match committed key\n");
                            ret = -1;
                        }
                        else {
                            /* verify commit isn't using new nvm objects */
                            for (i = 0; i < WOLFHSM_CFG_NVM_OBJECT_COUNT; i++) {
                                ret = wh_Client_KeyCommit(ctx, keyId);
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to over commit %d\n",
                                            ret);
                                }
                            }
                            if (ret == 0) {
                                ret = wh_Client_KeyErase(ctx, keyId);
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to erase key %d\n",
                                            ret);
                                } else {
                                    outLen = sizeof(keyOut);
                                    ret = wh_Client_KeyExport(ctx, keyId,
                                            labelOut, sizeof(labelOut), keyOut,
                                            &outLen);
                                    if (ret != WH_ERROR_NOTFOUND) {
                                        WH_ERROR_PRINT("Failed to not find "
                                                        "erased key\n");
                                        ret = -1;
                                    } else {
                                        ret = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (ret == 0) {
            WH_TEST_PRINT("KEY COMMIT/ERASE SUCCESS\n");
        }
    }

    /* Test cross-cache key eviction and replacement */
    if (ret == 0) {
        uint16_t keyId;
        /* Key for regular cache (≤ WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const size_t smallKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE / 2;
        uint8_t      smallKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE/2];
        /* Key for big cache (> WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const size_t bigKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100;
        uint8_t      bigKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE+100];

        uint8_t labelSmall[WH_NVM_LABEL_LEN] = "Small Key Label";
        uint8_t labelBig[WH_NVM_LABEL_LEN]   = "Big Key Label";

        /* Buffer for exported key and metadata */
        uint8_t  exportedKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE+100];
        uint8_t  exportedLabel[WH_NVM_LABEL_LEN];
        uint16_t exportedKeySize;

        /* Initialize test keys with different data */
        memset(smallKey, 0xAA, sizeof(smallKey));
        memset(bigKey, 0xBB, sizeof(bigKey));

        /* Test 1: Cache small key first, then cache same keyId with big key */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, 0, labelSmall, sizeof(labelSmall),
                                   smallKey, sizeof(smallKey), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache small key: %d\n", ret);
        }
        else {
            /* Now cache big key with same keyId - should succeed and evict the
             * small key */
            ret = wh_Client_KeyCache(ctx, 0, labelBig, sizeof(labelBig), bigKey,
                                     sizeof(bigKey), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed to cache big key (expected success): %d\n", ret);
            }
            else {
                /* Verify the cached key is the big key by exporting it */
                exportedKeySize = sizeof(exportedKey);
                ret = wh_Client_KeyExport(ctx, keyId, exportedLabel,
                                          sizeof(exportedLabel), exportedKey,
                                          &exportedKeySize);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to export key after cache: %d\n",
                                   ret);
                }
                else {
                    /* Verify exported key matches the big key */
                    if (exportedKeySize != bigKeySize ||
                        memcmp(exportedKey, bigKey, bigKeySize) != 0) {
                        WH_ERROR_PRINT(
                            "Exported key data doesn't match big key\n");
                        ret = -1;
                    }
                    /* Verify exported label matches the big key label */
                    else if (memcmp(exportedLabel, labelBig,
                                    sizeof(labelBig)) != 0) {
                        WH_ERROR_PRINT(
                            "Exported label doesn't match big key label\n");
                        ret = -1;
                    }
                    else {
                        ret = 0;
                    }
                }
                /* Clean up */
                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, keyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                    }
                }
                else {
                    /* On error, try our best to clean up */
                    (void)wh_Client_KeyEvict(ctx, keyId);
                }

                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, keyId);
                    if (ret != 0) {
                        /* double evict should fail */
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT("Double evict shouldn't succeed, "
                                       "cross-cache duplication test failed\n");
                        ret = -1;
                    }
                }
            }
        }

        /* Test 2: Cache big key first, then cache same keyId with small key */
        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret = wh_Client_KeyCache(ctx, 0, labelBig, sizeof(labelBig), bigKey,
                                     sizeof(bigKey), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to cache big key: %d\n", ret);
            }
            else {
                /* Now cache small key with same keyId - should succeed and
                 * evict the big key */
                ret = wh_Client_KeyCache(ctx, 0, labelSmall, sizeof(labelSmall),
                                         smallKey, sizeof(smallKey), &keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Failed to cache small key (expected success): %d\n",
                        ret);
                }
                else {
                    /* Verify the cached key is the small key by exporting it */
                    exportedKeySize = sizeof(exportedKey);
                    ret = wh_Client_KeyExport(ctx, keyId, exportedLabel,
                                              sizeof(exportedLabel),
                                              exportedKey, &exportedKeySize);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to export key after cache: %d\n", ret);
                    }
                    else {
                        /* Verify exported key matches the small key */
                        if (exportedKeySize != smallKeySize ||
                            memcmp(exportedKey, smallKey, smallKeySize) != 0) {
                            WH_ERROR_PRINT(
                                "Exported key data doesn't match small key\n");
                            ret = -1;
                        }
                        /* Verify exported label matches the small key label */
                        else if (memcmp(exportedLabel, labelSmall,
                                        sizeof(labelSmall)) != 0) {
                            WH_ERROR_PRINT("Exported label doesn't match small "
                                           "key label\n");
                            ret = -1;
                        }
                        else {
                            ret = 0;
                        }
                    }
                    /* Clean up */
                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, keyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                        }
                    }
                    else {
                        /* On error, try our best to clean up */
                        (void)wh_Client_KeyEvict(ctx, keyId);
                    }

                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, keyId);
                        if (ret != 0) {
                            /* double evict should fail */
                            ret = 0;
                        }
                        else {
                            WH_ERROR_PRINT(
                                "Double evict shouldn't succeed, "
                                "cross-cache duplication test failed\n");
                            ret = -1;
                        }
                    }
                }
            }
        }

        if (ret == 0) {
            WH_TEST_PRINT("KEY CROSS-CACHE EVICTION AND REPLACEMENT SUCCESS\n");
        }
    }

#ifdef WOLFHSM_CFG_DMA
    /* test cache/export using DMA */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret =
            whTest_CacheExportKeyDma(ctx, &keyId, labelIn, labelOut,
                                     sizeof(labelIn), key, keyOut, sizeof(key));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to Test CacheExportKeyDma %d\n", ret);
        }
        else {
            ret = wh_Client_KeyEvict(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
            }
            else {
                WH_TEST_PRINT("KEY CACHE/EXPORT DMA SUCCESS\n");
            }
        }
    }

    /* Test cross-cache key eviction and replacement with DMA */
    if (ret == 0) {
        uint16_t keyId;
        /* Key for regular cache (≤ WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const size_t smallKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE / 2;
        uint8_t      smallKey[smallKeySize];
        /* Key for big cache (> WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const size_t bigKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100;
        uint8_t      bigKey[bigKeySize];

        uint8_t labelSmall[WH_NVM_LABEL_LEN] = "Small DMA Key Label";
        uint8_t labelBig[WH_NVM_LABEL_LEN]   = "Big DMA Key Label";

        /* Buffer for exported key and metadata */
        uint8_t  exportedKey[bigKeySize];
        uint8_t  exportedLabel[WH_NVM_LABEL_LEN];
        uint16_t exportedKeySize;

        /* Initialize test keys with different data */
        memset(smallKey, 0xCC, sizeof(smallKey));
        memset(bigKey, 0xDD, sizeof(bigKey));

        /* Test 1: Cache small key with DMA first, then cache same keyId
         * with big key using DMA */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCacheDma(ctx, 0, labelSmall, sizeof(labelSmall),
                                      smallKey, sizeof(smallKey), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache small key with DMA: %d\n", ret);
        }
        else {
            /* Now cache big key with same keyId using DMA - should succeed and
             * evict the small key */
            ret = wh_Client_KeyCacheDma(ctx, 0, labelBig, sizeof(labelBig),
                                        bigKey, sizeof(bigKey), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed to cache big key with DMA (expected success): %d\n",
                    ret);
            }
            else {
                /* Verify the cached key is the big key by exporting it */
                exportedKeySize = bigKeySize;
                ret             = wh_Client_KeyExportDma(
                    ctx, keyId, exportedKey, exportedKeySize, exportedLabel,
                    sizeof(exportedLabel), &exportedKeySize);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to export key after cache: %d\n",
                                   ret);
                }
                else {
                    /* Verify exported key matches the big key */
                    if (exportedKeySize != bigKeySize ||
                        memcmp(exportedKey, bigKey, bigKeySize) != 0) {
                        WH_ERROR_PRINT(
                            "Exported key data doesn't match big key\n");
                        ret = -1;
                    }
                    /* Verify exported label matches the big key label */
                    else if (memcmp(exportedLabel, labelBig,
                                    sizeof(labelBig)) != 0) {
                        WH_ERROR_PRINT(
                            "Exported label doesn't match big key label\n");
                        ret = -1;
                    }
                    else {
                        ret = 0;
                    }
                }
                /* Clean up */
                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, keyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                    }
                }
                else {
                    /* On error, try our best to clean up */
                    (void)wh_Client_KeyEvict(ctx, keyId);
                }

                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, keyId);
                    if (ret != 0) {
                        /* double evict should fail */
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT("Double evict shouldn't succeed, "
                                       "cross-cache duplication test failed\n");
                        ret = -1;
                    }
                }
            }
        }

        /* Test 2: Cache big key with DMA first, then cache
         * same keyId with small key using DMA */
        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCacheDma(ctx, 0, labelBig, sizeof(labelBig),
                                          bigKey, sizeof(bigKey), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to cache big key with DMA: %d\n", ret);
            }
            else {
                /* Now cache small key with same keyId using DMA - should
                 * succeed and evict the big key */
                ret = wh_Client_KeyCacheDma(ctx, 0, labelSmall,
                                            sizeof(labelSmall), smallKey,
                                            sizeof(smallKey), &keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to cache small key with DMA "
                                   "(expected success): %d\n",
                                   ret);
                }
                else {
                    /* Verify the cached key is the small key by exporting it */
                    exportedKeySize = smallKeySize;
                    ret             = wh_Client_KeyExportDma(
                        ctx, keyId, exportedKey, exportedKeySize, exportedLabel,
                        sizeof(exportedLabel), &exportedKeySize);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to export key after cache: %d\n", ret);
                    }
                    else {
                        /* Verify exported key matches the small key */
                        if (exportedKeySize != smallKeySize ||
                            memcmp(exportedKey, smallKey, smallKeySize) != 0) {
                            WH_ERROR_PRINT(
                                "Exported key data doesn't match small key\n");
                            ret = -1;
                        }
                        /* Verify exported label matches the small key label */
                        else if (memcmp(exportedLabel, labelSmall,
                                        sizeof(labelSmall)) != 0) {
                            WH_ERROR_PRINT("Exported label doesn't match small "
                                           "key label\n");
                            ret = -1;
                        }
                        else {
                            ret = 0;
                        }
                    }
                    /* Clean up */
                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, keyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                        }
                    }
                    else {
                        /* On error, try our best to clean up */
                        (void)wh_Client_KeyEvict(ctx, keyId);
                    }

                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, keyId);
                        if (ret != 0) {
                            /* double evict should fail */
                            ret = 0;
                        }
                        else {
                            WH_ERROR_PRINT(
                                "Double evict shouldn't succeed, "
                                "cross-cache duplication test failed\n");
                            ret = -1;
                        }
                    }
                }
            }
        }

        if (ret == 0) {
            WH_TEST_PRINT("KEY CROSS-CACHE EVICTION AND REPLACEMENT DMA SUCCESS\n");
        }
    }
#endif /* WOLFHSM_CFG_DMA */

    /* Ensure cache entries read from NVM are evictable.
     * Max out the cache with NVM-backed keys, then try caching a new key. */
    if (ret == 0) {
        const int nvmKeyCount = WOLFHSM_CFG_SERVER_KEYCACHE_COUNT;
        /* {0} == WH_KEYID_ERASED, so unused entries are skipped on cleanup
         * and each cache call requests a server-assigned id. */
        uint16_t  nvmKeyIds[WOLFHSM_CFG_SERVER_KEYCACHE_COUNT] = {0};
        uint16_t  extraKeyId = WH_KEYID_ERASED;

        /* Commit each key to NVM then evict it, so the keys live only in
         * the backing store and not in the cache. */
        for (i = 0; (i < nvmKeyCount) && (ret == 0); i++) {
            ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                                     sizeof(key), &nvmKeyIds[i]);
            if (ret == 0) {
                ret = wh_Client_KeyCommit(ctx, nvmKeyIds[i]);
            }
            if (ret == 0) {
                ret = wh_Client_KeyEvict(ctx, nvmKeyIds[i]);
            }
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to stage NVM key %d: %d\n", i, ret);
            }
        }

        /* Read each key back, which caches it from NVM and fills the
         * cache with NVM-backed entries. */
        for (i = 0; (i < nvmKeyCount) && (ret == 0); i++) {
            outLen = sizeof(keyOut);
            ret = wh_Client_KeyExport(ctx, nvmKeyIds[i], labelOut,
                                      sizeof(labelOut), keyOut, &outLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to read back NVM key %d: %d\n", i, ret);
            }
        }

        /* With the cache full of NVM-backed keys, caching a new key must
         * still succeed by evicting one of them. */
        if (ret == 0) {
            ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                                     sizeof(key), &extraKeyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to cache key with NVM-backed cache "
                               "full: %d\n", ret);
            }
        }

        /* Restore state regardless of the outcome above. */
        if (extraKeyId != WH_KEYID_ERASED) {
            (void)wh_Client_KeyEvict(ctx, extraKeyId);
        }
        for (i = 0; i < nvmKeyCount; i++) {
            if (nvmKeyIds[i] != WH_KEYID_ERASED) {
                (void)wh_Client_KeyErase(ctx, nvmKeyIds[i]);
            }
        }

        if (ret == 0) {
            WH_TEST_PRINT("KEY CACHE NVM-BACKED EVICTION SUCCESS\n");
        }
    }

    return ret;
}

#define WH_TEST_KEYSTORE_TEST_SZ (32)
static int whTest_NonExportableKeystore(whClientContext* ctx, int devId,
                                        WC_RNG* rng)
{
    (void)devId;
    (void)rng;

    int     ret                   = 0;
    whKeyId keyId                 = WH_KEYID_ERASED;
    uint8_t key[WH_TEST_KEYSTORE_TEST_SZ] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
    uint8_t  exportedKey[WH_TEST_KEYSTORE_TEST_SZ] = {0};
    uint8_t  label[WH_NVM_LABEL_LEN]         = "NonExportableTestKey";
    uint8_t  exportedLabel[WH_NVM_LABEL_LEN] = {0};
    uint16_t exportedKeySize;

    WH_TEST_PRINT("Testing non-exportable keystore enforcement...\n");

    /* Test 1: Cache a key with non-exportable flag and try to export it */
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONEXPORTABLE, label,
                             sizeof(label), key, sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache non-exportable key: %d\n", ret);
        return ret;
    }

    /* Try to export the non-exportable key - should fail */
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExport(ctx, keyId, exportedLabel, sizeof(exportedLabel),
                              exportedKey, &exportedKeySize);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("Non-exportable key was exported unexpectedly: %d\n",
                       ret);
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Non-exportable key export correctly denied\n");

    /* Clean up the key */
    wh_Client_KeyEvict(ctx, keyId);

    /* Test 2: Cache a key without non-exportable flag and verify it can be
     * exported */
    keyId = WH_KEYID_ERASED;
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE, label, sizeof(label), key,
                             sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache exportable key: %d\n", ret);
        return ret;
    }

    /* Try to export the exportable key - should succeed */
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExport(ctx, keyId, exportedLabel, sizeof(exportedLabel),
                              exportedKey, &exportedKeySize);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export exportable key: %d\n", ret);
        return ret;
    }

    /* Verify exported data matches original */
    if (exportedKeySize != sizeof(key) ||
        memcmp(key, exportedKey, exportedKeySize) != 0 ||
        memcmp(label, exportedLabel, sizeof(label)) != 0) {
        WH_ERROR_PRINT("Exported key data doesn't match original\n");
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Exportable key export succeeded\n");

    /* Clean up */
    wh_Client_KeyEvict(ctx, keyId);

#ifdef WOLFHSM_CFG_DMA
    /* Test 3: Test DMA export with non-exportable key */
    WH_TEST_PRINT("Testing DMA key export protection...\n");

    /* Cache a key with non-exportable flag */
    keyId = WH_KEYID_ERASED;
    ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONEXPORTABLE, label,
                               sizeof(label), key, sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache non-exportable key for DMA test: %d\n",
                       ret);
        return ret;
    }

    /* Try to export the non-exportable key via DMA - should fail */
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExportDma(ctx, keyId, exportedKey, sizeof(exportedKey),
                                 exportedLabel, sizeof(exportedLabel),
                                 &exportedKeySize);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT(
            "Non-exportable key was exported via DMA unexpectedly: %d\n", ret);
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Non-exportable key DMA export correctly denied\n");

    /* Clean up the key */
    wh_Client_KeyEvict(ctx, keyId);

    /* Test 4: Test DMA export with exportable key */
    keyId = WH_KEYID_ERASED;
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE, label, sizeof(label), key,
                             sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache exportable key for DMA test: %d\n",
                       ret);
        return ret;
    }

    /* Try to export the exportable key via DMA - should succeed */
    memset(exportedKey, 0, sizeof(exportedKey));
    memset(exportedLabel, 0, sizeof(exportedLabel));
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExportDma(ctx, keyId, exportedKey, sizeof(exportedKey),
                                 exportedLabel, sizeof(exportedLabel),
                                 &exportedKeySize);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export exportable key via DMA: %d\n", ret);
        return ret;
    }

    /* Verify exported data matches original */
    if (exportedKeySize != sizeof(key) ||
        memcmp(key, exportedKey, exportedKeySize) != 0 ||
        memcmp(label, exportedLabel, sizeof(label)) != 0) {
        WH_ERROR_PRINT("DMA exported key data doesn't match original\n");
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Exportable key DMA export succeeded\n");

    /* Clean up */
    wh_Client_KeyEvict(ctx, keyId);
#endif /* WOLFHSM_CFG_DMA */

    WH_TEST_PRINT("NON-EXPORTABLE KEYSTORE TEST SUCCESS\n");
    return 0;
}

#ifndef NO_AES
static int whTestCrypto_Aes(whClientContext* ctx, int devId, WC_RNG* rng)
{
#define WH_TEST_AES_KEYSIZE 16
#define WH_TEST_AES_TEXTSIZE 64
    int ret = 0;
    Aes aes[1];
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t key[WH_TEST_AES_KEYSIZE];
    uint8_t plainIn[WH_TEST_AES_TEXTSIZE];
    uint8_t cipher[WH_TEST_AES_TEXTSIZE] = { 0 };
    uint8_t plainOut[WH_TEST_AES_TEXTSIZE] = { 0 };
    whKeyId keyId = WH_KEYID_ERASED;
    uint8_t labelIn[WH_NVM_LABEL_LEN] = "AES Key Label";

    memset(plainIn, 0xAA, sizeof(plainIn));

    /* Randomize inputs */
    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
    } else {
        ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        }
    }
#ifdef WOLFSSL_AES_COUNTER
    if (ret == 0) {
        /* test aes CTR with client side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        else {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n", ret);
            }
            else {
                ret = wc_AesCtrEncrypt(aes, cipher, plainIn, sizeof(plainIn));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
                }
                else {
                    ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv,
                                             AES_DECRYPTION);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n",
                                       ret);
                    }
                    else {
                        ret = wc_AesCtrEncrypt(aes, plainOut, cipher,
                                               sizeof(cipher));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n",
                                           ret);
                        }
                        else {
                            if (memcmp(plainIn, plainOut, sizeof(plainIn)) !=
                                0) {
                                WH_ERROR_PRINT("Failed to match AES-CTR\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
        }
    }
    if (ret == 0) {
        /* test aes CTR with HSM side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        else {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                  ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
                  labelIn, sizeof(labelIn), key, sizeof(key), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
            }
            else {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdAes %d\n", ret);
                }
                else {
                    ret = wc_AesSetIV(aes, iv);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n", ret);
                    }
                    else {
                        ret = wc_AesCtrEncrypt(aes, cipher, plainIn,
                                               sizeof(plainIn));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n",
                                           ret);
                        }
                        else {
                            /* Reset the IV to support decryption */
                            ret = wc_AesSetIV(aes, iv);
                            if (ret != 0) {
                                WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n",
                                               ret);
                            }
                            else {
                                ret = wc_AesCtrEncrypt(aes, plainOut, cipher,
                                                       sizeof(plainIn));
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to decrypt %d\n",
                                                   ret);
                                }
                                else {
                                    if (memcmp(plainIn, plainOut,
                                               sizeof(plainIn)) != 0) {
                                        WH_ERROR_PRINT("Failed to match\n");
                                        ret = -1;
                                    }
                                }
                            }
                        }
                    }
                }
                (void)wh_Client_KeyEvict(ctx, keyId);
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
        }
        if (ret == 0) {
            WH_TEST_PRINT("AES CTR DEVID=0x%X SUCCESS\n", devId);
        }
    }
    if (ret == 0) {
        /* test aes CTR with incremental steps (block size multiple) */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCtrEncrypt(aes, cipher, plainIn, sizeof(plainIn)/2);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCtrEncrypt(aes, cipher+(sizeof(plainIn)/2),
                                   plainIn+(sizeof(plainIn)/2),
                                   sizeof(plainIn)/2);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_DECRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCtrEncrypt(aes, plainOut, cipher, sizeof(cipher)/2);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCtrEncrypt(aes, plainOut+sizeof(plainOut)/2,
                                   cipher+sizeof(cipher)/2, sizeof(cipher)/2);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            if (memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
                WH_ERROR_PRINT("Failed to match AES-CTR\n");
                ret = -1;
            }
        }

        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }
    if (ret == 0) {
        /* test aes CTR with incremental steps (non block size multiple) */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCtrEncrypt(aes, cipher, plainIn, (sizeof(plainIn)/2)-1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCtrEncrypt(aes, cipher+((sizeof(plainIn)/2)-1),
                                   plainIn+((sizeof(plainIn)/2)-1),
                                   (sizeof(plainIn)/2)+1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_DECRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCtrEncrypt(aes, plainOut, cipher, (sizeof(cipher)/2)+1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCtrEncrypt(aes, plainOut+((sizeof(plainOut)/2)+1),
                                   cipher+((sizeof(cipher)/2)+1),
                                   (sizeof(cipher)/2)-1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            if (memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
                WH_ERROR_PRINT("Failed to match AES-CTR\n");
                ret = -1;
            }
        }

        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }
#endif

#ifdef HAVE_AES_ECB
    if (ret == 0) {
        /* test aes ECB with client side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        else {
            /* AES-ECB does not use IV */
            ret = wc_AesSetKey(aes, key, sizeof(key), NULL, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
            }
            else {
                ret = wc_AesEcbEncrypt(aes, cipher, plainIn, sizeof(plainIn));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_AesEcbEncrypt %d\n", ret);
                }
                else {
                    ret =
                        wc_AesSetKey(aes, key, sizeof(key), NULL, AES_DECRYPTION);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
                    }
                    else {
                        ret = wc_AesEcbDecrypt(aes, plainOut, cipher,
                                               sizeof(cipher));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesEcbDecrypt %d\n",
                                           ret);
                        }
                        else {
                            if (memcmp(plainIn, plainOut, sizeof(plainIn)) !=
                                0) {
                                WH_ERROR_PRINT("Failed to match AES-ECB\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
        }
    }
    if (ret == 0) {
        /* test aes ECB with HSM side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        else {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                  ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
                  labelIn, sizeof(labelIn), key, sizeof(key), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
            }
            else {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdAes %d\n", ret);
                }
                else {
                    /* AES-ECB does not use IV */
                    ret = wc_AesSetIV(aes, NULL);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n", ret);
                    }
                    else {
                        ret = wc_AesEcbEncrypt(aes, cipher, plainIn,
                                               sizeof(plainIn));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesEcbEncrypt %d\n",
                                           ret);
                        }
                        else {
                            /* AES-ECB does not use IV */
                            ret = wc_AesSetIV(aes, NULL);
                            if (ret != 0) {
                                WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n",
                                               ret);
                            }
                            else {
                                ret = wc_AesEcbDecrypt(aes, plainOut, cipher,
                                                       sizeof(plainIn));
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to decrypt %d\n",
                                                   ret);
                                }
                                else {
                                    if (memcmp(plainIn, plainOut,
                                               sizeof(plainIn)) != 0) {
                                        WH_ERROR_PRINT("Failed to match\n");
                                        ret = -1;
                                    }
                                }
                            }
                        }
                    }
                }
                (void)wh_Client_KeyEvict(ctx, keyId);
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
        }
        if (ret == 0) {
            WH_TEST_PRINT("AES ECB DEVID=0x%X SUCCESS\n", devId);
        }
    }
    /* AES ECB doesn't need a test with incremental steps as each block is
     * processed independently. */
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
    if (ret == 0) {
        /* test aes CBC with client side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        } else {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
            } else {
                ret = wc_AesCbcEncrypt(aes, cipher, plainIn,
                        sizeof(plainIn));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_AesCbcEncrypt %d\n", ret);
                } else {
                    ret = wc_AesSetKey(aes, key, sizeof(key), iv,
                            AES_DECRYPTION);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
                    } else {
                        ret = wc_AesCbcDecrypt(aes, plainOut, cipher,
                                sizeof(cipher));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesCbcDecrypt %d\n",
                                    ret);
                        } else {
                            if (memcmp(plainIn, plainOut, sizeof(plainIn)) !=
                                0) {
                                WH_ERROR_PRINT("Failed to match AES-CBC\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
        }
    }
    if (ret == 0) {
        /* test aes CBC with HSM side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        } else {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                  ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
                  labelIn, sizeof(labelIn), key, sizeof(key), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
            } else {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdAes %d\n", ret);
                } else {
                    ret = wc_AesSetIV(aes, iv);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n", ret);
                    } else {
                        ret = wc_AesCbcEncrypt(aes, cipher, plainIn,
                                sizeof(plainIn));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesCbcEncrypt %d\n",
                                    ret);
                        } else {
                            /* Reset the IV to support decryption */
                            ret = wc_AesSetIV(aes, iv);
                            if (ret != 0) {
                                WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n",
                                        ret);
                            } else {
                                ret = wc_AesCbcDecrypt(aes, plainOut,
                                        cipher, sizeof(plainIn));
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to decrypt %d\n",
                                            ret);
                                } else {
                                    if (memcmp(plainIn, plainOut,
                                               sizeof(plainIn)) != 0) {
                                        WH_ERROR_PRINT("Failed to match\n");
                                        ret = -1;
                                    }
                                }
                            }
                        }
                    }
                }
                (void)wh_Client_KeyEvict(ctx, keyId);
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
        }
        if (ret == 0) {
            WH_TEST_PRINT("AES CBC DEVID=0x%X SUCCESS\n", devId);
        }
    }
    if (ret == 0) {
        /* test aes CBC with incremental steps (block size multiple) */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCbcEncrypt(aes, cipher, plainIn, sizeof(plainIn)/2);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCbcEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCbcEncrypt(aes, cipher+(sizeof(plainIn)/2),
                                   plainIn+(sizeof(plainIn)/2),
                                   sizeof(plainIn)/2);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCbcEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_DECRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCbcDecrypt(aes, plainOut, cipher, sizeof(cipher)/2);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCbcEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = wc_AesCbcDecrypt(aes, plainOut+sizeof(plainOut)/2,
                                   cipher+sizeof(cipher)/2, sizeof(cipher)/2);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCbcEncrypt %d\n", ret);
            }
        }
        if (ret == WH_ERROR_OK) {
            if (memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
                WH_ERROR_PRINT("Failed to match AES-CBC\n");
                ret = -1;
            }
        }

        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }
    if (ret == 0) {
        /* test async AES CBC with incremental steps (streaming IV chaining) */
        uint32_t outSize = 0;
        uint32_t halfSize = sizeof(plainIn) / 2;

        WH_TEST_PRINT("AES CBC ASYNC STREAMING test\n");
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }

        /* Encrypt first half */
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_AesCbcRequest(ctx, aes, 1, plainIn, halfSize);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to AesCbcRequest enc1 %d\n", ret);
            }
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCbcResponse(ctx, aes, cipher, &outSize);
            } while (ret == WH_ERROR_NOTREADY);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to AesCbcResponse enc1 %d\n", ret);
            }
        }

        /* Encrypt second half (IV should chain from first half) */
        if (ret == 0) {
            ret = wh_Client_AesCbcRequest(ctx, aes, 1,
                                           plainIn + halfSize, halfSize);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to AesCbcRequest enc2 %d\n", ret);
            }
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCbcResponse(ctx, aes,
                                                cipher + halfSize, &outSize);
            } while (ret == WH_ERROR_NOTREADY);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to AesCbcResponse enc2 %d\n", ret);
            }
        }

        /* Decrypt first half */
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_DECRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKey dec %d\n", ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_AesCbcRequest(ctx, aes, 0, cipher, halfSize);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to AesCbcRequest dec1 %d\n", ret);
            }
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCbcResponse(ctx, aes, plainOut, &outSize);
            } while (ret == WH_ERROR_NOTREADY);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to AesCbcResponse dec1 %d\n", ret);
            }
        }

        /* Decrypt second half (IV should chain from first half) */
        if (ret == 0) {
            ret = wh_Client_AesCbcRequest(ctx, aes, 0,
                                           cipher + halfSize, halfSize);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to AesCbcRequest dec2 %d\n", ret);
            }
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCbcResponse(ctx, aes,
                                                plainOut + halfSize, &outSize);
            } while (ret == WH_ERROR_NOTREADY);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to AesCbcResponse dec2 %d\n", ret);
            }
        }

        /* Verify round-trip */
        if (ret == 0) {
            if (memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
                WH_ERROR_PRINT("Failed to match async AES-CBC streaming\n");
                ret = -1;
            }
        }

        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));

        if (ret == 0) {
            WH_TEST_PRINT("AES CBC ASYNC STREAMING DEVID=0x%X SUCCESS\n",
                           devId);
        }
    }
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
#define WH_TEST_AES_AUTHSIZE 16
#define WH_TEST_AES_TAGSIZE 16
    uint8_t authIn[WH_TEST_AES_AUTHSIZE];
    uint8_t authTag[WH_TEST_AES_TAGSIZE] = { 0 };

    /* Generate random auth */
    if (ret == 0){
        ret = wc_RNG_GenerateBlock(rng, authIn, sizeof(authIn));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        }
    }

    if (ret == 0) {
        /* test aes GCM with client side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        } else {
            ret = wc_AesGcmSetKey(aes, key, sizeof(key));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesGcmSetKey %d\n", ret);
            } else {
                ret = wc_AesGcmEncrypt(aes, cipher, plainIn,
                        sizeof(plainIn), iv, sizeof(iv), authTag,
                        sizeof(authTag), authIn, sizeof(authIn));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_AesGcmEncrypt %d\n", ret);
                } else {
                    ret = wc_AesGcmDecrypt(aes, plainOut, cipher,
                            sizeof(plainIn), iv, sizeof(iv), authTag,
                            sizeof(authTag), authIn, sizeof(authIn));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesGcmDecrypt %d\n", ret);
                    } else {
                        if (memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
                            WH_ERROR_PRINT("AES GCM FAILED TO MATCH\n");
                            ret = -1;
                        }
                    }
                }
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
            memset(authTag, 0, sizeof(authTag));
        }
    }

    if (ret == 0) {
        /* test aes GCM with HSM side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        } else {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                  ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
                  labelIn, sizeof(labelIn), key, sizeof(key), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
            } else {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to set key id:%d\n", ret);
                } else {
                    ret = wc_AesGcmEncrypt(aes, (byte*)cipher, (byte*)plainIn,
                                           sizeof(plainIn), iv, sizeof(iv),
                                           authTag, sizeof(authTag), authIn,
                                           sizeof(authIn));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesGcmEncrypt %d\n", ret);
                    } else {
                        ret = wc_AesGcmDecrypt(
                            aes, (byte*)plainOut, (byte*)cipher,
                            sizeof(plainIn), iv, sizeof(iv), authTag,
                            sizeof(authTag), authIn, sizeof(authIn));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesGcmDecrypt %d\n",
                                           ret);
                        } else {
                            if (memcmp(plainIn, plainOut, sizeof(plainIn)) !=
                                0) {
                                WH_ERROR_PRINT("AES GCM FAILED TO MATCH\n");
                                ret = -1;
                            }
                        }
                    }
                }
                (void)wh_Client_KeyEvict(ctx, keyId);
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
            memset(authTag, 0, sizeof(authTag));
        }
        if (ret == 0) {
            WH_TEST_PRINT("AES GCM DEVID=0x%X SUCCESS\n", devId);
        }
    }
#endif /* HAVE_AES_GCM */
    return ret;
}

/* Direct exercise of the native async AES primitives
 * (wh_Client_AesXxxRequest / wh_Client_AesXxxResponse).
 * Covers each mode's round-trip, state continuity, and argument rejection. */
static int whTest_CryptoAesAsync(whClientContext* ctx, int devId, WC_RNG* rng)
{
#define WH_TEST_AES_ASYNC_KEYSZ 16
#define WH_TEST_AES_ASYNC_BUFSZ 64
    int     ret = 0;
    Aes     aes[1];
    uint8_t key[WH_TEST_AES_ASYNC_KEYSZ];
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t plainIn[WH_TEST_AES_ASYNC_BUFSZ];
    uint8_t cipher[WH_TEST_AES_ASYNC_BUFSZ];
    uint8_t plainOut[WH_TEST_AES_ASYNC_BUFSZ];

    memset(plainIn, 0xAA, sizeof(plainIn));
    memset(cipher, 0, sizeof(cipher));
    memset(plainOut, 0, sizeof(plainOut));

    if (wc_RNG_GenerateBlock(rng, key, sizeof(key)) != 0 ||
        wc_RNG_GenerateBlock(rng, iv, sizeof(iv)) != 0) {
        WH_ERROR_PRINT("AES async: failed to generate key/iv\n");
        return -1;
    }

#ifdef HAVE_AES_CBC
    /* CBC: round-trip via async Request/Response pair */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret =
                wh_Client_AesCbcRequest(ctx, aes, 1, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCbcResponse(ctx, aes, cipher, NULL);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_DECRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesCbcRequest(ctx, aes, 0, cipher, sizeof(cipher));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCbcResponse(ctx, aes, plainOut, NULL);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-CBC async round-trip mismatch\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }

    /* CBC: argument validation */
    if (ret == 0 && wh_Client_AesCbcRequest(NULL, aes, 1, plainIn, 16) !=
                        WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("AES-CBC async: NULL ctx should be BADARGS\n");
        ret = -1;
    }
    if (ret == 0 && wh_Client_AesCbcRequest(ctx, NULL, 1, plainIn, 16) !=
                        WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("AES-CBC async: NULL aes should be BADARGS\n");
        ret = -1;
    }
    if (ret == 0 &&
        wh_Client_AesCbcResponse(ctx, aes, NULL, NULL) != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("AES-CBC async: NULL out should be BADARGS\n");
        ret = -1;
    }
    /* CBC: non-block-aligned length rejected */
    if (ret == 0) {
        int tmp;
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            tmp = wh_Client_AesCbcRequest(ctx, aes, 1, plainIn, 15);
            if (tmp != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT(
                    "AES-CBC async: non-block-aligned should be BADARGS, "
                    "got %d\n",
                    tmp);
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CBC ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
    /* CTR: round-trip via async Request/Response pair. CTR is symmetric, so
     * wolfCrypt's wc_AesCtrEncrypt is used for both directions — the enc
     * flag and key schedule are always ENCRYPTION even when the caller's
     * intent is to decrypt. */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret =
                wh_Client_AesCtrRequest(ctx, aes, 1, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCtrResponse(ctx, aes, cipher, NULL);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesCtrRequest(ctx, aes, 1, cipher, sizeof(cipher));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCtrResponse(ctx, aes, plainOut, NULL);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-CTR async round-trip mismatch\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }

    /* CTR: state continuity — two halves via async must equal single-shot */
    if (ret == 0) {
        uint8_t refCipher[WH_TEST_AES_ASYNC_BUFSZ];
        uint8_t chunkCipher[WH_TEST_AES_ASYNC_BUFSZ];
        Aes     aesRef[1];
        ret = wc_AesInit(aesRef, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aesRef, key, sizeof(key), iv,
                                     AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesCtr(ctx, aesRef, 1, plainIn, sizeof(plainIn),
                                   refCipher);
        }
        (void)wc_AesFree(aesRef);

        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, devId);
        }
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesCtrRequest(ctx, aes, 1, plainIn,
                                          sizeof(plainIn) / 2);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCtrResponse(ctx, aes, chunkCipher, NULL);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = wh_Client_AesCtrRequest(ctx, aes, 1,
                                          plainIn + sizeof(plainIn) / 2,
                                          sizeof(plainIn) / 2);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCtrResponse(
                    ctx, aes, chunkCipher + sizeof(plainIn) / 2, NULL);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 &&
            memcmp(refCipher, chunkCipher, sizeof(refCipher)) != 0) {
            WH_ERROR_PRINT(
                "AES-CTR async: split state did not match single-shot\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
    }

    /* CTR: server must reject left > AES_BLOCK_SIZE.
     * wc_AesCtrEncrypt indexes aes->tmp via AES_BLOCK_SIZE - aes->left;
     * an oversized client-supplied value would cause an out-of-bounds read
     * disclosing server-side memory across the HSM trust boundary. */
    if (ret == 0) {
        int tmp;
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            aes->left = AES_BLOCK_SIZE + 1;
            tmp = wh_Client_AesCtr(ctx, aes, 1, plainIn, sizeof(plainIn),
                                   cipher);
            if (tmp != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT(
                    "AES-CTR async: left > AES_BLOCK_SIZE should be "
                    "BADARGS, got %d\n",
                    tmp);
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CTR ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
    /* ECB: round-trip via async Request/Response pair */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret =
                wh_Client_AesEcbRequest(ctx, aes, 1, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesEcbResponse(ctx, aes, cipher, NULL);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_DECRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesEcbRequest(ctx, aes, 0, cipher, sizeof(cipher));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesEcbResponse(ctx, aes, plainOut, NULL);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-ECB async round-trip mismatch\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }

    /* ECB: non-block-aligned length rejected */
    if (ret == 0) {
        int tmp;
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            tmp = wh_Client_AesEcbRequest(ctx, aes, 1, plainIn, 15);
            if (tmp != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT(
                    "AES-ECB async: non-block-aligned should be BADARGS\n");
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES ECB ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AESGCM
    /* GCM: round-trip via async Request/Response pair */
    if (ret == 0) {
        uint8_t authin[16];
        uint8_t enc_tag[AES_BLOCK_SIZE];
        uint8_t dec_tag[AES_BLOCK_SIZE];

        memset(authin, 0x5A, sizeof(authin));
        memset(enc_tag, 0, sizeof(enc_tag));

        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesGcmSetKey(aes, key, sizeof(key));
        }
        if (ret == 0) {
            ret = wh_Client_AesGcmRequest(
                ctx, aes, 1, plainIn, sizeof(plainIn), iv, AES_BLOCK_SIZE,
                authin, sizeof(authin), NULL, sizeof(enc_tag));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesGcmResponse(ctx, aes, cipher, sizeof(cipher),
                                               NULL, enc_tag, sizeof(enc_tag));
            } while (ret == WH_ERROR_NOTREADY);
        }

        /* Decrypt with correct tag succeeds */
        if (ret == 0) {
            memcpy(dec_tag, enc_tag, sizeof(dec_tag));
            ret = wh_Client_AesGcmRequest(
                ctx, aes, 0, cipher, sizeof(cipher), iv, AES_BLOCK_SIZE, authin,
                sizeof(authin), dec_tag, sizeof(dec_tag));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesGcmResponse(ctx, aes, plainOut,
                                               sizeof(plainOut), NULL, NULL, 0);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-GCM async round-trip mismatch\n");
            ret = -1;
        }

        /* Decrypt with corrupted tag must fail */
        if (ret == 0) {
            int tmp;
            dec_tag[0] ^= 0x01;
            tmp = wh_Client_AesGcmRequest(
                ctx, aes, 0, cipher, sizeof(cipher), iv, AES_BLOCK_SIZE, authin,
                sizeof(authin), dec_tag, sizeof(dec_tag));
            if (tmp == WH_ERROR_OK) {
                do {
                    tmp = wh_Client_AesGcmResponse(
                        ctx, aes, plainOut, sizeof(plainOut), NULL, NULL, 0);
                } while (tmp == WH_ERROR_NOTREADY);
            }
            if (tmp == 0) {
                WH_ERROR_PRINT(
                    "AES-GCM async: decrypt with bad tag unexpectedly OK\n");
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES GCM ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AESGCM */

#ifdef HAVE_AES_CBC
    /* CBC: stacked async Request must return REQUEST_PENDING, and the second
     * Request must not mutate aes->reg before fail-fast. */
    if (ret == 0) {
        uint8_t ivBefore[AES_BLOCK_SIZE];
        uint8_t ivAfter[AES_BLOCK_SIZE];
        int     tmp;
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        /* Issue the first Request but do NOT consume the Response. The
         * transport stays "request pending" until the matching Response is
         * read. */
        if (ret == 0) {
            ret =
                wh_Client_AesCbcRequest(ctx, aes, 1, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            /* Snapshot aes->reg before attempting a stacked decrypt Request */
            memcpy(ivBefore, (uint8_t*)aes->reg, sizeof(ivBefore));
            tmp =
                wh_Client_AesCbcRequest(ctx, aes, 0, plainIn, sizeof(plainIn));
            if (tmp != WH_ERROR_REQUEST_PENDING) {
                WH_ERROR_PRINT("AES-CBC async: stacked Request expected "
                               "REQUEST_PENDING, got %d\n",
                               tmp);
                ret = -1;
            }
            memcpy(ivAfter, (uint8_t*)aes->reg, sizeof(ivAfter));
            if (ret == 0 && memcmp(ivBefore, ivAfter, sizeof(ivBefore)) != 0) {
                WH_ERROR_PRINT(
                    "AES-CBC async: stacked Request mutated aes->reg\n");
                ret = -1;
            }
        }
        /* Drain the outstanding response to leave the transport idle */
        if (ret == 0 || ret == -1) {
            int drainRet;
            do {
                drainRet = wh_Client_AesCbcResponse(ctx, aes, cipher, NULL);
            } while (drainRet == WH_ERROR_NOTREADY);
            if (ret == 0 && drainRet != WH_ERROR_OK) {
                WH_ERROR_PRINT(
                    "AES-CBC async: failed to drain pending response: %d\n",
                    drainRet);
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CBC ASYNC FAILURE-PATH DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
    /* CTR: stacked async Request must return REQUEST_PENDING, and the second
     * Request must not mutate aes->reg, aes->tmp, or aes->left before the
     * fail-fast check. */
    if (ret == 0) {
        uint8_t regBefore[AES_BLOCK_SIZE];
        uint8_t regAfter[AES_BLOCK_SIZE];
        uint8_t tmpBefore[AES_BLOCK_SIZE];
        uint8_t tmpAfter[AES_BLOCK_SIZE];
        word32  leftBefore = 0;
        word32  leftAfter  = 0;
        int     tmp;
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        /* Issue the first Request but do NOT consume the Response. The
         * transport stays "request pending" until the matching Response is
         * read. */
        if (ret == 0) {
            ret =
                wh_Client_AesCtrRequest(ctx, aes, 1, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            /* Snapshot per-call state before attempting a stacked Request */
            memcpy(regBefore, (uint8_t*)aes->reg, sizeof(regBefore));
            memcpy(tmpBefore, (uint8_t*)aes->tmp, sizeof(tmpBefore));
            leftBefore = aes->left;
            tmp =
                wh_Client_AesCtrRequest(ctx, aes, 1, plainIn, sizeof(plainIn));
            if (tmp != WH_ERROR_REQUEST_PENDING) {
                WH_ERROR_PRINT("AES-CTR async: stacked Request expected "
                               "REQUEST_PENDING, got %d\n",
                               tmp);
                ret = -1;
            }
            memcpy(regAfter, (uint8_t*)aes->reg, sizeof(regAfter));
            memcpy(tmpAfter, (uint8_t*)aes->tmp, sizeof(tmpAfter));
            leftAfter = aes->left;
            if (ret == 0 &&
                memcmp(regBefore, regAfter, sizeof(regBefore)) != 0) {
                WH_ERROR_PRINT(
                    "AES-CTR async: stacked Request mutated aes->reg\n");
                ret = -1;
            }
            if (ret == 0 &&
                memcmp(tmpBefore, tmpAfter, sizeof(tmpBefore)) != 0) {
                WH_ERROR_PRINT(
                    "AES-CTR async: stacked Request mutated aes->tmp\n");
                ret = -1;
            }
            if (ret == 0 && leftBefore != leftAfter) {
                WH_ERROR_PRINT(
                    "AES-CTR async: stacked Request mutated aes->left\n");
                ret = -1;
            }
        }
        /* Drain the outstanding response to leave the transport idle */
        if (ret == 0 || ret == -1) {
            int drainRet;
            do {
                drainRet = wh_Client_AesCtrResponse(ctx, aes, cipher, NULL);
            } while (drainRet == WH_ERROR_NOTREADY);
            if (ret == 0 && drainRet != WH_ERROR_OK) {
                WH_ERROR_PRINT(
                    "AES-CTR async: failed to drain pending response: %d\n",
                    drainRet);
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CTR ASYNC FAILURE-PATH DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AESGCM
    /* GCM: out_capacity smaller than the server's reported payload must be
     * rejected by Response without overflowing out. */
    if (ret == 0) {
        uint8_t authin[8];
        uint8_t enc_tag[AES_BLOCK_SIZE];
        uint8_t tinyOut[8]; /* deliberately smaller than plainIn */
        int     tmp;

        memset(authin, 0x37, sizeof(authin));
        memset(enc_tag, 0, sizeof(enc_tag));

        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesGcmSetKey(aes, key, sizeof(key));
        }
        if (ret == 0) {
            ret = wh_Client_AesGcmRequest(
                ctx, aes, 1, plainIn, sizeof(plainIn), iv, AES_BLOCK_SIZE,
                authin, sizeof(authin), NULL, sizeof(enc_tag));
        }
        if (ret == 0) {
            do {
                tmp =
                    wh_Client_AesGcmResponse(ctx, aes, tinyOut, sizeof(tinyOut),
                                             NULL, enc_tag, sizeof(enc_tag));
            } while (tmp == WH_ERROR_NOTREADY);
            if (tmp != WH_ERROR_ABORTED) {
                WH_ERROR_PRINT(
                    "AES-GCM async: undersized out_capacity expected "
                    "ABORTED, got %d\n",
                    tmp);
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES GCM ASYNC OUT-CAPACITY DEVID=0x%X SUCCESS\n", devId);
    }

    /* GCM: undersized tag_len with non-NULL enc_tag must be rejected. The
     * previous implementation skipped the memcpy silently and still
     * returned WH_ERROR_OK, leaving enc_tag stale while telling the caller
     * the operation succeeded. */
    if (ret == 0) {
        uint8_t authin[8];
        uint8_t enc_tag[AES_BLOCK_SIZE];
        uint8_t tinyTag[4]; /* deliberately smaller than the GCM tag */
        int     tmp;

        memset(authin, 0x37, sizeof(authin));
        memset(enc_tag, 0, sizeof(enc_tag));
        memset(tinyTag, 0, sizeof(tinyTag));

        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesGcmSetKey(aes, key, sizeof(key));
        }
        if (ret == 0) {
            ret = wh_Client_AesGcmRequest(
                ctx, aes, 1, plainIn, sizeof(plainIn), iv, AES_BLOCK_SIZE,
                authin, sizeof(authin), NULL, sizeof(enc_tag));
        }
        if (ret == 0) {
            do {
                tmp = wh_Client_AesGcmResponse(ctx, aes, cipher, sizeof(cipher),
                                               NULL, tinyTag, sizeof(tinyTag));
            } while (tmp == WH_ERROR_NOTREADY);
            if (tmp != WH_ERROR_ABORTED) {
                WH_ERROR_PRINT("AES-GCM async: undersized tag_len expected "
                               "ABORTED, got %d\n",
                               tmp);
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES GCM ASYNC TAG-CAPACITY DEVID=0x%X SUCCESS\n", devId);
    }

    /* GCM: out=NULL with out_capacity>0 must not wedge the transport. The
     * previous implementation rejected the combination with BADARGS after
     * the Request had already been sent, leaving a stale response in the
     * comm queue that blocked subsequent calls with REQUEST_PENDING. */
    if (ret == 0) {
        uint8_t authin[8];
        uint8_t enc_tag[AES_BLOCK_SIZE];
        int     tmp;

        memset(authin, 0x37, sizeof(authin));
        memset(enc_tag, 0, sizeof(enc_tag));

        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesGcmSetKey(aes, key, sizeof(key));
        }
        if (ret == 0) {
            ret = wh_Client_AesGcmRequest(
                ctx, aes, 1, plainIn, sizeof(plainIn), iv, AES_BLOCK_SIZE,
                authin, sizeof(authin), NULL, sizeof(enc_tag));
        }
        if (ret == 0) {
            /* Pass out=NULL with a non-zero out_capacity (= plainIn size).
             * Must accept the call and drain the response; tag still comes
             * back via enc_tag. */
            do {
                tmp = wh_Client_AesGcmResponse(ctx, aes, NULL, sizeof(plainIn),
                                               NULL, enc_tag, sizeof(enc_tag));
            } while (tmp == WH_ERROR_NOTREADY);
            if (tmp != WH_ERROR_OK) {
                WH_ERROR_PRINT(
                    "AES-GCM async: out=NULL with out_capacity>0 should "
                    "succeed (GMAC-style), got %d\n",
                    tmp);
                ret = -1;
            }
        }
        /* Confirm the comm queue is idle — a subsequent Request must not
         * be blocked by a stale pending response. */
        if (ret == 0) {
            if (wh_CommClient_IsRequestPending(ctx->comm) != 0) {
                WH_ERROR_PRINT(
                    "AES-GCM async: comm queue wedged after out=NULL "
                    "Response\n");
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES GCM ASYNC OUT-NULL DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AESGCM */

    return ret;
#undef WH_TEST_AES_ASYNC_KEYSZ
#undef WH_TEST_AES_ASYNC_BUFSZ
}

/* Known-answer tests for the async AES primitives. Vectors are taken from
 * wolfCrypt's test.c (NIST SP 800-38A for CBC/CTR/ECB; NIST SP 800-38D /
 * GCM spec test cases for GCM) and are run through the async
 * Request/Response APIs to verify async-ification did not change output. */
static int whTest_CryptoAesAsyncKat(whClientContext* ctx, int devId)
{
    int     ret = 0;
    Aes     aes[1];
    uint8_t outBuf[64];

#ifdef HAVE_AES_CBC
    /* AES-CBC KATs from wolfCrypt test.c aes_cbc_test / aes192_test /
     * aes256_test. Each vector encrypts one AES block, decrypts it back,
     * and compares against the published ciphertext. */
    {
        /* AES-128-CBC: from aes_cbc_test */
        const uint8_t k128[16] = {
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f'
        };
        const uint8_t iv128[16] = {
            '1','2','3','4','5','6','7','8',
            '9','0','a','b','c','d','e','f'
        };
        const uint8_t p128[16] = {
            0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
            0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
        };
        const uint8_t c128[16] = {
            0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
            0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
        };
        /* AES-192-CBC: NIST SP 800-38A F.2.3 */
        const uint8_t k192[24] = {
            0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
            0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
            0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
        };
        const uint8_t iv_nist[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
        };
        const uint8_t p_nist[16] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        };
        const uint8_t c192[16] = {
            0x4f,0x02,0x1d,0xb2,0x43,0xbc,0x63,0x3d,
            0x71,0x78,0x18,0x3a,0x9f,0xa0,0x71,0xe8
        };
        /* AES-256-CBC: NIST SP 800-38A F.2.5 */
        const uint8_t k256[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        const uint8_t c256[16] = {
            0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
            0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
        };

        struct {
            const uint8_t* k;
            int            kSz;
            const uint8_t* iv;
            const uint8_t* p;
            const uint8_t* c;
        } v[] = {
            {k128, 16, iv128,   p128,   c128},
            {k192, 24, iv_nist, p_nist, c192},
            {k256, 32, iv_nist, p_nist, c256},
        };
        size_t i;
        for (i = 0; i < sizeof(v) / sizeof(v[0]) && ret == 0; i++) {
            memset(outBuf, 0, sizeof(outBuf));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                ret = wc_AesSetKey(aes, v[i].k, v[i].kSz, v[i].iv,
                                   AES_ENCRYPTION);
            }
            if (ret == 0) {
                ret = wh_Client_AesCbcRequest(ctx, aes, 1, v[i].p,
                                              AES_BLOCK_SIZE);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesCbcResponse(ctx, aes, outBuf, NULL);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(outBuf, v[i].c, AES_BLOCK_SIZE) != 0) {
                WH_ERROR_PRINT("AES-%d-CBC async KAT enc mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            if (ret == 0) {
                ret = wc_AesSetKey(aes, v[i].k, v[i].kSz, v[i].iv,
                                   AES_DECRYPTION);
            }
            if (ret == 0) {
                memset(outBuf, 0, sizeof(outBuf));
                ret = wh_Client_AesCbcRequest(ctx, aes, 0, v[i].c,
                                              AES_BLOCK_SIZE);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesCbcResponse(ctx, aes, outBuf, NULL);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(outBuf, v[i].p, AES_BLOCK_SIZE) != 0) {
                WH_ERROR_PRINT("AES-%d-CBC async KAT dec mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            (void)wc_AesFree(aes);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CBC ASYNC KAT DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
    /* AES-CTR KATs from wolfCrypt test.c aes_ctr_test (NIST SP 800-38A
     * F.5). 64-byte plaintext, single ciphertext per key size. */
    {
        const uint8_t ctrIv[16] = {
            0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
            0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
        };
        const uint8_t ctrPlain[64] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
            0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
            0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
            0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
            0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
        };
        const uint8_t ctr128Key[16] = {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        };
        const uint8_t ctr128Cipher[64] = {
            0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
            0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
            0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,
            0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
            0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,
            0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
            0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,
            0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
        };
        const uint8_t ctr192Key[24] = {
            0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
            0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
            0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
        };
        const uint8_t ctr192Cipher[64] = {
            0x1a,0xbc,0x93,0x24,0x17,0x52,0x1c,0xa2,
            0x4f,0x2b,0x04,0x59,0xfe,0x7e,0x6e,0x0b,
            0x09,0x03,0x39,0xec,0x0a,0xa6,0xfa,0xef,
            0xd5,0xcc,0xc2,0xc6,0xf4,0xce,0x8e,0x94,
            0x1e,0x36,0xb2,0x6b,0xd1,0xeb,0xc6,0x70,
            0xd1,0xbd,0x1d,0x66,0x56,0x20,0xab,0xf7,
            0x4f,0x78,0xa7,0xf6,0xd2,0x98,0x09,0x58,
            0x5a,0x97,0xda,0xec,0x58,0xc6,0xb0,0x50
        };
        const uint8_t ctr256Key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        const uint8_t ctr256Cipher[64] = {
            0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,
            0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,
            0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,
            0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,
            0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,
            0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,
            0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,
            0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6
        };

        struct {
            const uint8_t* k;
            int            kSz;
            const uint8_t* c;
        } v[] = {
            {ctr128Key, 16, ctr128Cipher},
            {ctr192Key, 24, ctr192Cipher},
            {ctr256Key, 32, ctr256Cipher},
        };
        size_t i;
        for (i = 0; i < sizeof(v) / sizeof(v[0]) && ret == 0; i++) {
            memset(outBuf, 0, sizeof(outBuf));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                ret = wc_AesSetKeyDirect(aes, v[i].k, v[i].kSz, ctrIv,
                                         AES_ENCRYPTION);
            }
            if (ret == 0) {
                ret = wh_Client_AesCtrRequest(ctx, aes, 1, ctrPlain,
                                              sizeof(ctrPlain));
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesCtrResponse(ctx, aes, outBuf, NULL);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 &&
                memcmp(outBuf, v[i].c, sizeof(ctrPlain)) != 0) {
                WH_ERROR_PRINT("AES-%d-CTR async KAT enc mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            /* CTR is symmetric: applying the same op to ciphertext
             * recovers plaintext */
            if (ret == 0) {
                ret = wc_AesSetKeyDirect(aes, v[i].k, v[i].kSz, ctrIv,
                                         AES_ENCRYPTION);
            }
            if (ret == 0) {
                memset(outBuf, 0, sizeof(outBuf));
                ret = wh_Client_AesCtrRequest(ctx, aes, 1, v[i].c,
                                              sizeof(ctrPlain));
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesCtrResponse(ctx, aes, outBuf, NULL);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 &&
                memcmp(outBuf, ctrPlain, sizeof(ctrPlain)) != 0) {
                WH_ERROR_PRINT("AES-%d-CTR async KAT dec mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            (void)wc_AesFree(aes);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CTR ASYNC KAT DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
    /* AES-ECB KATs from wolfCrypt test.c aes_ecb_test. */
    {
        const uint8_t ecbIv[16] = {
            '1','2','3','4','5','6','7','8',
            '9','0','a','b','c','d','e','f'
        };
        const uint8_t ecbMsg[16] = {
            0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
            0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
        };
        const uint8_t ecbK128[16] = {
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f'
        };
        const uint8_t ecbC128[16] = {
            0xd0,0xc9,0xd9,0xc9,0x40,0xe8,0x97,0xb6,
            0xc8,0x8c,0x33,0x3b,0xb5,0x8f,0x85,0xd1
        };
        const uint8_t ecbK192[24] = {
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f',
            '0','1','2','3','4','5','6','7'
        };
        const uint8_t ecbC192[16] = {
            0x06,0x57,0xee,0x78,0x3f,0x96,0x00,0xb1,
            0xec,0x76,0x94,0x30,0x29,0xbe,0x15,0xab
        };
        const uint8_t ecbK256[32] = {
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f',
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f'
        };
        const uint8_t ecbC256[16] = {
            0xcd,0xf2,0x81,0x3e,0x73,0x3e,0xf7,0x33,
            0x3d,0x18,0xfd,0x41,0x85,0x37,0x04,0x82
        };

        struct {
            const uint8_t* k;
            int            kSz;
            const uint8_t* c;
        } v[] = {
            {ecbK128, 16, ecbC128},
            {ecbK192, 24, ecbC192},
            {ecbK256, 32, ecbC256},
        };
        size_t i;
        for (i = 0; i < sizeof(v) / sizeof(v[0]) && ret == 0; i++) {
            memset(outBuf, 0, sizeof(outBuf));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                ret = wc_AesSetKey(aes, v[i].k, v[i].kSz, ecbIv,
                                   AES_ENCRYPTION);
            }
            if (ret == 0) {
                ret = wh_Client_AesEcbRequest(ctx, aes, 1, ecbMsg,
                                              AES_BLOCK_SIZE);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesEcbResponse(ctx, aes, outBuf, NULL);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(outBuf, v[i].c, AES_BLOCK_SIZE) != 0) {
                WH_ERROR_PRINT("AES-%d-ECB async KAT enc mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            if (ret == 0) {
                ret = wc_AesSetKey(aes, v[i].k, v[i].kSz, ecbIv,
                                   AES_DECRYPTION);
            }
            if (ret == 0) {
                memset(outBuf, 0, sizeof(outBuf));
                ret = wh_Client_AesEcbRequest(ctx, aes, 0, v[i].c,
                                              AES_BLOCK_SIZE);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesEcbResponse(ctx, aes, outBuf, NULL);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(outBuf, ecbMsg, AES_BLOCK_SIZE) != 0) {
                WH_ERROR_PRINT("AES-%d-ECB async KAT dec mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            (void)wc_AesFree(aes);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES ECB ASYNC KAT DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AESGCM
    /* AES-GCM KATs from wolfCrypt test.c aesgcm_test (GCM spec test
     * cases). Verifies ciphertext, tag, and decrypt round-trip. */
    {
        /* AES-128-GCM: k3/p3/c3_3/t3_3, IV iv1, no AAD */
        const uint8_t gcmIv[12] = {
            0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
            0xde,0xca,0xf8,0x88
        };
        const uint8_t gcm128Key[16] = {
            0xbb,0x01,0xd7,0x03,0x81,0x1c,0x10,0x1a,
            0x35,0xe0,0xff,0xd2,0x91,0xba,0xf2,0x4b
        };
        const uint8_t gcm128Plain[16] = {
            0x57,0xce,0x45,0x1f,0xa5,0xe2,0x35,0xa5,
            0x8e,0x1a,0xa2,0x3b,0x77,0xcb,0xaf,0xe2
        };
        const uint8_t gcm128Cipher[16] = {
            0x79,0xa7,0x08,0xd4,0xad,0x1f,0x3b,0xac,
            0x70,0x16,0x64,0x40,0xde,0x03,0xed,0xea
        };
        const uint8_t gcm128Tag[16] = {
            0x39,0xb1,0x1e,0x73,0x18,0xda,0x04,0x75,
            0xa1,0xed,0x52,0xb9,0x0d,0x5c,0xe7,0x28
        };
        /* AES-256-GCM: GCM Test Case 16 (k1/p/c1/t1) with AAD a */
        const uint8_t gcm256Key[32] = {
            0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
            0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
            0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
            0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
        };
        const uint8_t gcm256Plain[60] = {
            0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
            0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
            0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
            0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
            0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
            0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
            0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
            0xba,0x63,0x7b,0x39
        };
        const uint8_t gcm256Aad[20] = {
            0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
            0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
            0xab,0xad,0xda,0xd2
        };
        const uint8_t gcm256Cipher[60] = {
            0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07,
            0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
            0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9,
            0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
            0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d,
            0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
            0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a,
            0xbc,0xc9,0xf6,0x62
        };
        const uint8_t gcm256Tag[16] = {
            0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68,
            0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b
        };

        struct {
            const uint8_t* k;
            int            kSz;
            const uint8_t* p;
            int            pSz;
            const uint8_t* aad;
            int            aadSz;
            const uint8_t* c;
            const uint8_t* t;
        } v[] = {
            {gcm128Key, 16, gcm128Plain, sizeof(gcm128Plain),
             NULL,        0, gcm128Cipher, gcm128Tag},
            {gcm256Key, 32, gcm256Plain, sizeof(gcm256Plain),
             gcm256Aad, sizeof(gcm256Aad), gcm256Cipher, gcm256Tag},
        };
        uint8_t cipherBuf[64];
        uint8_t plainBuf[64];
        uint8_t tagBuf[AES_BLOCK_SIZE];
        size_t  i;
        for (i = 0; i < sizeof(v) / sizeof(v[0]) && ret == 0; i++) {
            memset(cipherBuf, 0, sizeof(cipherBuf));
            memset(plainBuf, 0, sizeof(plainBuf));
            memset(tagBuf, 0, sizeof(tagBuf));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                ret = wc_AesGcmSetKey(aes, v[i].k, v[i].kSz);
            }
            if (ret == 0) {
                ret = wh_Client_AesGcmRequest(
                    ctx, aes, 1, v[i].p, v[i].pSz, gcmIv, sizeof(gcmIv),
                    v[i].aad, v[i].aadSz, NULL, sizeof(tagBuf));
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesGcmResponse(ctx, aes, cipherBuf,
                                                   sizeof(cipherBuf), NULL,
                                                   tagBuf, sizeof(tagBuf));
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(cipherBuf, v[i].c, v[i].pSz) != 0) {
                WH_ERROR_PRINT("AES-%d-GCM async KAT cipher mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            if (ret == 0 && memcmp(tagBuf, v[i].t, sizeof(tagBuf)) != 0) {
                WH_ERROR_PRINT("AES-%d-GCM async KAT tag mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            if (ret == 0) {
                ret = wh_Client_AesGcmRequest(
                    ctx, aes, 0, v[i].c, v[i].pSz, gcmIv, sizeof(gcmIv),
                    v[i].aad, v[i].aadSz, v[i].t, sizeof(tagBuf));
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesGcmResponse(ctx, aes, plainBuf,
                                                   sizeof(plainBuf), NULL,
                                                   NULL, 0);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(plainBuf, v[i].p, v[i].pSz) != 0) {
                WH_ERROR_PRINT("AES-%d-GCM async KAT plain mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            (void)wc_AesFree(aes);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES GCM ASYNC KAT DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AESGCM */

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the native async DMA AES primitives. */
static int whTest_CryptoAesDmaAsync(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
#define WH_TEST_AES_ASYNC_DMA_KEYSZ 32
#define WH_TEST_AES_ASYNC_DMA_BUFSZ 128
    int     ret = 0;
    Aes     aes[1];
    uint8_t key[WH_TEST_AES_ASYNC_DMA_KEYSZ];
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t plainIn[WH_TEST_AES_ASYNC_DMA_BUFSZ];
    uint8_t cipher[WH_TEST_AES_ASYNC_DMA_BUFSZ];
    uint8_t plainOut[WH_TEST_AES_ASYNC_DMA_BUFSZ];

    memset(plainIn, 0xBB, sizeof(plainIn));
    memset(cipher, 0, sizeof(cipher));
    memset(plainOut, 0, sizeof(plainOut));

    if (wc_RNG_GenerateBlock(rng, key, sizeof(key)) != 0 ||
        wc_RNG_GenerateBlock(rng, iv, sizeof(iv)) != 0) {
        WH_ERROR_PRINT("AES DMA async: failed to generate key/iv\n");
        return -1;
    }

#ifdef HAVE_AES_CBC
    /* CBC DMA: round-trip via async DMA Request/Response pair */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesCbcDmaRequest(ctx, aes, 1, plainIn,
                                             sizeof(plainIn), cipher);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCbcDmaResponse(ctx, aes);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_DECRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesCbcDmaRequest(ctx, aes, 0, cipher,
                                             sizeof(cipher), plainOut);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCbcDmaResponse(ctx, aes);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-CBC DMA async round-trip mismatch\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CBC DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
    /* CTR DMA: round-trip. CTR is symmetric (see non-DMA test comment). */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesCtrDmaRequest(ctx, aes, 1, plainIn,
                                             sizeof(plainIn), cipher);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCtrDmaResponse(ctx, aes);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesCtrDmaRequest(ctx, aes, 1, cipher,
                                             sizeof(cipher), plainOut);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesCtrDmaResponse(ctx, aes);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-CTR DMA async round-trip mismatch\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }

    /* CTR DMA: same left > AES_BLOCK_SIZE rejection as the non-DMA path. */
    if (ret == 0) {
        int tmp;
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            aes->left = AES_BLOCK_SIZE + 1;
            tmp = wh_Client_AesCtrDma(ctx, aes, 1, plainIn, sizeof(plainIn),
                                      cipher);
            if (tmp != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT(
                    "AES-CTR DMA async: left > AES_BLOCK_SIZE should be "
                    "BADARGS, got %d\n",
                    tmp);
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CTR DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
    /* ECB DMA: round-trip */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesEcbDmaRequest(ctx, aes, 1, plainIn,
                                             sizeof(plainIn), cipher);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesEcbDmaResponse(ctx, aes);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_DECRYPTION);
        }
        if (ret == 0) {
            ret = wh_Client_AesEcbDmaRequest(ctx, aes, 0, cipher,
                                             sizeof(cipher), plainOut);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesEcbDmaResponse(ctx, aes);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-ECB DMA async round-trip mismatch\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES ECB DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AESGCM
    /* GCM DMA: round-trip with AAD via DMA */
    if (ret == 0) {
        uint8_t authin[32];
        uint8_t enc_tag[AES_BLOCK_SIZE];
        uint8_t dec_tag[AES_BLOCK_SIZE];

        memset(authin, 0x5A, sizeof(authin));
        memset(enc_tag, 0, sizeof(enc_tag));

        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesGcmSetKey(aes, key, sizeof(key));
        }
        if (ret == 0) {
            ret = wh_Client_AesGcmDmaRequest(
                ctx, aes, 1, plainIn, sizeof(plainIn), cipher, iv,
                AES_BLOCK_SIZE, authin, sizeof(authin), NULL, sizeof(enc_tag));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesGcmDmaResponse(ctx, aes, enc_tag,
                                                  sizeof(enc_tag));
            } while (ret == WH_ERROR_NOTREADY);
        }

        if (ret == 0) {
            memcpy(dec_tag, enc_tag, sizeof(dec_tag));
            ret = wh_Client_AesGcmDmaRequest(
                ctx, aes, 0, cipher, sizeof(cipher), plainOut, iv,
                AES_BLOCK_SIZE, authin, sizeof(authin), dec_tag,
                sizeof(dec_tag));
        }
        if (ret == 0) {
            do {
                ret = wh_Client_AesGcmDmaResponse(ctx, aes, NULL, 0);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-GCM DMA async round-trip mismatch\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES GCM DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AESGCM */

    return ret;
#undef WH_TEST_AES_ASYNC_DMA_KEYSZ
#undef WH_TEST_AES_ASYNC_DMA_BUFSZ
}

/* Known-answer tests for the DMA async AES primitives. Same vectors as
 * whTest_CryptoAesAsyncKat run through the DMA Request/Response APIs. */
static int whTest_CryptoAesDmaAsyncKat(whClientContext* ctx, int devId)
{
    int     ret = 0;
    Aes     aes[1];
    uint8_t outBuf[64];

#ifdef HAVE_AES_CBC
    {
        const uint8_t k128[16] = {
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f'
        };
        const uint8_t iv128[16] = {
            '1','2','3','4','5','6','7','8',
            '9','0','a','b','c','d','e','f'
        };
        const uint8_t p128[16] = {
            0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
            0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
        };
        const uint8_t c128[16] = {
            0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
            0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
        };
        const uint8_t k192[24] = {
            0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
            0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
            0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
        };
        const uint8_t iv_nist[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
        };
        const uint8_t p_nist[16] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        };
        const uint8_t c192[16] = {
            0x4f,0x02,0x1d,0xb2,0x43,0xbc,0x63,0x3d,
            0x71,0x78,0x18,0x3a,0x9f,0xa0,0x71,0xe8
        };
        const uint8_t k256[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        const uint8_t c256[16] = {
            0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
            0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
        };

        struct {
            const uint8_t* k;
            int            kSz;
            const uint8_t* iv;
            const uint8_t* p;
            const uint8_t* c;
        } v[] = {
            {k128, 16, iv128,   p128,   c128},
            {k192, 24, iv_nist, p_nist, c192},
            {k256, 32, iv_nist, p_nist, c256},
        };
        size_t i;
        for (i = 0; i < sizeof(v) / sizeof(v[0]) && ret == 0; i++) {
            memset(outBuf, 0, sizeof(outBuf));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                ret = wc_AesSetKey(aes, v[i].k, v[i].kSz, v[i].iv,
                                   AES_ENCRYPTION);
            }
            if (ret == 0) {
                ret = wh_Client_AesCbcDmaRequest(ctx, aes, 1, v[i].p,
                                                 AES_BLOCK_SIZE, outBuf);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesCbcDmaResponse(ctx, aes);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(outBuf, v[i].c, AES_BLOCK_SIZE) != 0) {
                WH_ERROR_PRINT("AES-%d-CBC DMA async KAT enc mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            if (ret == 0) {
                ret = wc_AesSetKey(aes, v[i].k, v[i].kSz, v[i].iv,
                                   AES_DECRYPTION);
            }
            if (ret == 0) {
                memset(outBuf, 0, sizeof(outBuf));
                ret = wh_Client_AesCbcDmaRequest(ctx, aes, 0, v[i].c,
                                                 AES_BLOCK_SIZE, outBuf);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesCbcDmaResponse(ctx, aes);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(outBuf, v[i].p, AES_BLOCK_SIZE) != 0) {
                WH_ERROR_PRINT("AES-%d-CBC DMA async KAT dec mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            (void)wc_AesFree(aes);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CBC DMA ASYNC KAT DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
    {
        const uint8_t ctrIv[16] = {
            0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
            0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
        };
        const uint8_t ctrPlain[64] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
            0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
            0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
            0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
            0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
        };
        const uint8_t ctr128Key[16] = {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        };
        const uint8_t ctr128Cipher[64] = {
            0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
            0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
            0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,
            0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
            0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,
            0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
            0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,
            0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
        };
        const uint8_t ctr192Key[24] = {
            0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
            0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
            0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
        };
        const uint8_t ctr192Cipher[64] = {
            0x1a,0xbc,0x93,0x24,0x17,0x52,0x1c,0xa2,
            0x4f,0x2b,0x04,0x59,0xfe,0x7e,0x6e,0x0b,
            0x09,0x03,0x39,0xec,0x0a,0xa6,0xfa,0xef,
            0xd5,0xcc,0xc2,0xc6,0xf4,0xce,0x8e,0x94,
            0x1e,0x36,0xb2,0x6b,0xd1,0xeb,0xc6,0x70,
            0xd1,0xbd,0x1d,0x66,0x56,0x20,0xab,0xf7,
            0x4f,0x78,0xa7,0xf6,0xd2,0x98,0x09,0x58,
            0x5a,0x97,0xda,0xec,0x58,0xc6,0xb0,0x50
        };
        const uint8_t ctr256Key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        const uint8_t ctr256Cipher[64] = {
            0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,
            0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,
            0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,
            0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,
            0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,
            0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,
            0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,
            0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6
        };

        struct {
            const uint8_t* k;
            int            kSz;
            const uint8_t* c;
        } v[] = {
            {ctr128Key, 16, ctr128Cipher},
            {ctr192Key, 24, ctr192Cipher},
            {ctr256Key, 32, ctr256Cipher},
        };
        size_t i;
        for (i = 0; i < sizeof(v) / sizeof(v[0]) && ret == 0; i++) {
            memset(outBuf, 0, sizeof(outBuf));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                ret = wc_AesSetKeyDirect(aes, v[i].k, v[i].kSz, ctrIv,
                                         AES_ENCRYPTION);
            }
            if (ret == 0) {
                ret = wh_Client_AesCtrDmaRequest(ctx, aes, 1, ctrPlain,
                                                 sizeof(ctrPlain), outBuf);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesCtrDmaResponse(ctx, aes);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 &&
                memcmp(outBuf, v[i].c, sizeof(ctrPlain)) != 0) {
                WH_ERROR_PRINT("AES-%d-CTR DMA async KAT enc mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            if (ret == 0) {
                ret = wc_AesSetKeyDirect(aes, v[i].k, v[i].kSz, ctrIv,
                                         AES_ENCRYPTION);
            }
            if (ret == 0) {
                memset(outBuf, 0, sizeof(outBuf));
                ret = wh_Client_AesCtrDmaRequest(ctx, aes, 1, v[i].c,
                                                 sizeof(ctrPlain), outBuf);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesCtrDmaResponse(ctx, aes);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 &&
                memcmp(outBuf, ctrPlain, sizeof(ctrPlain)) != 0) {
                WH_ERROR_PRINT("AES-%d-CTR DMA async KAT dec mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            (void)wc_AesFree(aes);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CTR DMA ASYNC KAT DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
    {
        const uint8_t ecbIv[16] = {
            '1','2','3','4','5','6','7','8',
            '9','0','a','b','c','d','e','f'
        };
        const uint8_t ecbMsg[16] = {
            0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
            0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
        };
        const uint8_t ecbK128[16] = {
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f'
        };
        const uint8_t ecbC128[16] = {
            0xd0,0xc9,0xd9,0xc9,0x40,0xe8,0x97,0xb6,
            0xc8,0x8c,0x33,0x3b,0xb5,0x8f,0x85,0xd1
        };
        const uint8_t ecbK192[24] = {
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f',
            '0','1','2','3','4','5','6','7'
        };
        const uint8_t ecbC192[16] = {
            0x06,0x57,0xee,0x78,0x3f,0x96,0x00,0xb1,
            0xec,0x76,0x94,0x30,0x29,0xbe,0x15,0xab
        };
        const uint8_t ecbK256[32] = {
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f',
            '0','1','2','3','4','5','6','7',
            '8','9','a','b','c','d','e','f'
        };
        const uint8_t ecbC256[16] = {
            0xcd,0xf2,0x81,0x3e,0x73,0x3e,0xf7,0x33,
            0x3d,0x18,0xfd,0x41,0x85,0x37,0x04,0x82
        };

        struct {
            const uint8_t* k;
            int            kSz;
            const uint8_t* c;
        } v[] = {
            {ecbK128, 16, ecbC128},
            {ecbK192, 24, ecbC192},
            {ecbK256, 32, ecbC256},
        };
        size_t i;
        for (i = 0; i < sizeof(v) / sizeof(v[0]) && ret == 0; i++) {
            memset(outBuf, 0, sizeof(outBuf));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                ret = wc_AesSetKey(aes, v[i].k, v[i].kSz, ecbIv,
                                   AES_ENCRYPTION);
            }
            if (ret == 0) {
                ret = wh_Client_AesEcbDmaRequest(ctx, aes, 1, ecbMsg,
                                                 AES_BLOCK_SIZE, outBuf);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesEcbDmaResponse(ctx, aes);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(outBuf, v[i].c, AES_BLOCK_SIZE) != 0) {
                WH_ERROR_PRINT("AES-%d-ECB DMA async KAT enc mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            if (ret == 0) {
                ret = wc_AesSetKey(aes, v[i].k, v[i].kSz, ecbIv,
                                   AES_DECRYPTION);
            }
            if (ret == 0) {
                memset(outBuf, 0, sizeof(outBuf));
                ret = wh_Client_AesEcbDmaRequest(ctx, aes, 0, v[i].c,
                                                 AES_BLOCK_SIZE, outBuf);
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesEcbDmaResponse(ctx, aes);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(outBuf, ecbMsg, AES_BLOCK_SIZE) != 0) {
                WH_ERROR_PRINT("AES-%d-ECB DMA async KAT dec mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            (void)wc_AesFree(aes);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES ECB DMA ASYNC KAT DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AESGCM
    {
        const uint8_t gcmIv[12] = {
            0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
            0xde,0xca,0xf8,0x88
        };
        const uint8_t gcm128Key[16] = {
            0xbb,0x01,0xd7,0x03,0x81,0x1c,0x10,0x1a,
            0x35,0xe0,0xff,0xd2,0x91,0xba,0xf2,0x4b
        };
        const uint8_t gcm128Plain[16] = {
            0x57,0xce,0x45,0x1f,0xa5,0xe2,0x35,0xa5,
            0x8e,0x1a,0xa2,0x3b,0x77,0xcb,0xaf,0xe2
        };
        const uint8_t gcm128Cipher[16] = {
            0x79,0xa7,0x08,0xd4,0xad,0x1f,0x3b,0xac,
            0x70,0x16,0x64,0x40,0xde,0x03,0xed,0xea
        };
        const uint8_t gcm128Tag[16] = {
            0x39,0xb1,0x1e,0x73,0x18,0xda,0x04,0x75,
            0xa1,0xed,0x52,0xb9,0x0d,0x5c,0xe7,0x28
        };
        const uint8_t gcm256Key[32] = {
            0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
            0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
            0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
            0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
        };
        const uint8_t gcm256Plain[60] = {
            0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
            0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
            0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
            0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
            0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
            0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
            0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
            0xba,0x63,0x7b,0x39
        };
        const uint8_t gcm256Aad[20] = {
            0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
            0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
            0xab,0xad,0xda,0xd2
        };
        const uint8_t gcm256Cipher[60] = {
            0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07,
            0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
            0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9,
            0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
            0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d,
            0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
            0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a,
            0xbc,0xc9,0xf6,0x62
        };
        const uint8_t gcm256Tag[16] = {
            0x76,0xfc,0x6e,0xce,0x0f,0x4e,0x17,0x68,
            0xcd,0xdf,0x88,0x53,0xbb,0x2d,0x55,0x1b
        };

        struct {
            const uint8_t* k;
            int            kSz;
            const uint8_t* p;
            int            pSz;
            const uint8_t* aad;
            int            aadSz;
            const uint8_t* c;
            const uint8_t* t;
        } v[] = {
            {gcm128Key, 16, gcm128Plain, sizeof(gcm128Plain),
             NULL,        0, gcm128Cipher, gcm128Tag},
            {gcm256Key, 32, gcm256Plain, sizeof(gcm256Plain),
             gcm256Aad, sizeof(gcm256Aad), gcm256Cipher, gcm256Tag},
        };
        uint8_t cipherBuf[64];
        uint8_t plainBuf[64];
        uint8_t tagBuf[AES_BLOCK_SIZE];
        size_t  i;
        for (i = 0; i < sizeof(v) / sizeof(v[0]) && ret == 0; i++) {
            memset(cipherBuf, 0, sizeof(cipherBuf));
            memset(plainBuf, 0, sizeof(plainBuf));
            memset(tagBuf, 0, sizeof(tagBuf));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                ret = wc_AesGcmSetKey(aes, v[i].k, v[i].kSz);
            }
            if (ret == 0) {
                ret = wh_Client_AesGcmDmaRequest(
                    ctx, aes, 1, v[i].p, v[i].pSz, cipherBuf, gcmIv,
                    sizeof(gcmIv), v[i].aad, v[i].aadSz, NULL,
                    sizeof(tagBuf));
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesGcmDmaResponse(ctx, aes, tagBuf,
                                                      sizeof(tagBuf));
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(cipherBuf, v[i].c, v[i].pSz) != 0) {
                WH_ERROR_PRINT("AES-%d-GCM DMA async KAT cipher mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            if (ret == 0 && memcmp(tagBuf, v[i].t, sizeof(tagBuf)) != 0) {
                WH_ERROR_PRINT("AES-%d-GCM DMA async KAT tag mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            if (ret == 0) {
                ret = wh_Client_AesGcmDmaRequest(
                    ctx, aes, 0, v[i].c, v[i].pSz, plainBuf, gcmIv,
                    sizeof(gcmIv), v[i].aad, v[i].aadSz, v[i].t,
                    sizeof(tagBuf));
            }
            if (ret == 0) {
                do {
                    ret = wh_Client_AesGcmDmaResponse(ctx, aes, NULL, 0);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0 && memcmp(plainBuf, v[i].p, v[i].pSz) != 0) {
                WH_ERROR_PRINT("AES-%d-GCM DMA async KAT plain mismatch\n",
                               v[i].kSz * 8);
                ret = -1;
            }
            (void)wc_AesFree(aes);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES GCM DMA ASYNC KAT DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AESGCM */

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* !NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
/* Direct copy of wolfCrypt tests, but using cached keys local to HSM instead */
static int whTestCrypto_Cmac(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)rng;

    int     ret = 0;
    Cmac    cmac[1];
    uint8_t tag[AES_BLOCK_SIZE] = {0};
    word32  tagSz;
    whKeyId keyId;
    uint8_t labelIn[WH_NVM_LABEL_LEN] = "CMAC Key Label";
    word32  i;

    /* NIST SP 800-38B test vectors */
#ifdef WOLFSSL_AES_128
    const byte k128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
#endif
#ifdef WOLFSSL_AES_192
    const byte k192[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                         0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                         0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
#endif
#ifdef WOLFSSL_AES_256
    const byte k256[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                         0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                         0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                         0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
#endif

    const byte m[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    enum {
        CMAC_MLEN_0   = 0,
        CMAC_MLEN_128 = 128 / 8,
        CMAC_MLEN_319 = 320 / 8 - 1,
        CMAC_MLEN_320 = 320 / 8,
        CMAC_MLEN_512 = 512 / 8,
    };

    /* Expected tags */
#ifdef WOLFSSL_AES_128
    const byte t128_0[]   = {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
                             0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
    const byte t128_128[] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                             0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
    const byte t128_319[] = {0x2c, 0x17, 0x84, 0x4c, 0x93, 0x1c, 0x07, 0x95,
                             0x15, 0x92, 0x73, 0x0a, 0x34, 0xd0, 0xd9, 0xd2};
    const byte t128_320[] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                             0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
    const byte t128_512[] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
                             0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};
#endif
#ifdef WOLFSSL_AES_192
    const byte t192_0[]   = {0xd1, 0x7d, 0xdf, 0x46, 0xad, 0xaa, 0xcd, 0xe5,
                             0x31, 0xca, 0xc4, 0x83, 0xde, 0x7a, 0x93, 0x67};
    const byte t192_128[] = {0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90,
                             0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c, 0x51, 0x84};
    const byte t192_320[] = {0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad,
                             0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e};
    const byte t192_512[] = {0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79,
                             0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3, 0x9a, 0x11};
#endif
#ifdef WOLFSSL_AES_256
    const byte t256_0[]   = {0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e,
                             0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83};
    const byte t256_128[] = {0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
                             0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c};
    const byte t256_320[] = {0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
                             0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6};
    const byte t256_512[] = {0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5,
                             0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10};
#endif

    typedef struct {
        const byte* k;
        word32      kSz;
        const byte* m;
        word32      mSz;
        const byte* t;
        word32      tSz;
        word32      partial;
    } CmacTestCase;

    const CmacTestCase testCases[] = {
#ifdef WOLFSSL_AES_128
        {k128, sizeof(k128), m, CMAC_MLEN_0, t128_0, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_128, t128_128, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_319, t128_319, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_320, t128_320, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_512, t128_512, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_512, t128_512, AES_BLOCK_SIZE, 5},
#endif
#ifdef WOLFSSL_AES_192
        {k192, sizeof(k192), m, CMAC_MLEN_0, t192_0, AES_BLOCK_SIZE, 0},
        {k192, sizeof(k192), m, CMAC_MLEN_128, t192_128, AES_BLOCK_SIZE, 0},
        {k192, sizeof(k192), m, CMAC_MLEN_320, t192_320, AES_BLOCK_SIZE, 0},
        {k192, sizeof(k192), m, CMAC_MLEN_512, t192_512, AES_BLOCK_SIZE, 0},
#endif
#ifdef WOLFSSL_AES_256
        {k256, sizeof(k256), m, CMAC_MLEN_0, t256_0, AES_BLOCK_SIZE, 0},
        {k256, sizeof(k256), m, CMAC_MLEN_128, t256_128, AES_BLOCK_SIZE, 0},
        {k256, sizeof(k256), m, CMAC_MLEN_320, t256_320, AES_BLOCK_SIZE, 0},
        {k256, sizeof(k256), m, CMAC_MLEN_512, t256_512, AES_BLOCK_SIZE, 0},
#endif
    };
    const word32 numCases = sizeof(testCases) / sizeof(testCases[0]);

    for (i = 0; i < numCases && ret == 0; i++) {
        const CmacTestCase* tc = &testCases[i];

        /* (a) One-shot generate with cached key */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)tc->k, tc->kSz,
                                   &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache (gen) tc=%d %d\n", i,
                           ret);
            break;
        }
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_InitCmac_ex (gen) tc=%d %d\n", i, ret);
            break;
        }
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_CmacSetKeyId (gen) tc=%d %d\n",
                           i, ret);
            break;
        }
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret = wc_AesCmacGenerate_ex(cmac, tag, &tagSz, tc->m, tc->mSz, NULL, 0,
                                    NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_AesCmacGenerate_ex tc=%d %d\n", i, ret);
            break;
        }
        if (memcmp(tag, tc->t, AES_BLOCK_SIZE) != 0) {
            WH_ERROR_PRINT("CMAC generate mismatch tc=%d\n", i);
            ret = -1;
            break;
        }
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyEvict (gen) tc=%d %d\n", i,
                           ret);
            break;
        }

        /* (b) One-shot verify with cached key */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_VERIFY, labelIn,
                                   sizeof(labelIn), (uint8_t*)tc->k, tc->kSz,
                                   &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache (ver) tc=%d %d\n", i,
                           ret);
            break;
        }
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_CmacSetKeyId (ver) tc=%d %d\n",
                           i, ret);
            break;
        }
        ret = wc_AesCmacVerify_ex(cmac, tc->t, tc->tSz, tc->m, tc->mSz, NULL, 0,
                                  NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_AesCmacVerify_ex tc=%d %d\n", i, ret);
            break;
        }
        wc_CmacFree(cmac);
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyEvict (ver) tc=%d %d\n", i,
                           ret);
            break;
        }

        /* (c) Incremental init/update/final with cached key */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)tc->k, tc->kSz,
                                   &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache (inc) tc=%d %d\n", i,
                           ret);
            break;
        }
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_InitCmac_ex (inc) tc=%d %d\n", i, ret);
            break;
        }
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_CmacSetKeyId (inc) tc=%d %d\n",
                           i, ret);
            break;
        }
        if (tc->partial > 0) {
            word32 firstSz  = tc->mSz / 2 - tc->partial;
            word32 secondSz = tc->mSz / 2 + tc->partial;
            ret             = wc_CmacUpdate(cmac, tc->m, firstSz);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed wc_CmacUpdate (inc1) tc=%d %d\n", i,
                               ret);
                break;
            }
            ret = wc_CmacUpdate(cmac, tc->m + firstSz, secondSz);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed wc_CmacUpdate (inc2) tc=%d %d\n", i,
                               ret);
                break;
            }
        }
        else {
            ret = wc_CmacUpdate(cmac, tc->m, tc->mSz);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed wc_CmacUpdate (inc) tc=%d %d\n", i, ret);
                break;
            }
        }
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret   = wc_CmacFinal(cmac, tag, &tagSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_CmacFinal (inc) tc=%d %d\n", i, ret);
            break;
        }
        if (memcmp(tag, tc->t, AES_BLOCK_SIZE) != 0) {
            WH_ERROR_PRINT("CMAC incremental mismatch tc=%d\n", i);
            ret = -1;
            break;
        }
        wc_CmacFree(cmac);
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyEvict (inc) tc=%d %d\n", i,
                           ret);
            break;
        }
    }

    /* Test oneshot verify with committed (NVM) key using AES-128 */
    if (ret == 0) {
#ifdef WOLFSSL_AES_128
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_VERIFY, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache (commit) %d\n", ret);
        }
        else {
            ret = wh_Client_KeyCommit(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
            }
            else {
                ret = wh_Client_KeyEvict(ctx, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
                }
                else {
                    ret = wc_InitCmac_ex(cmac, k128, sizeof(k128), WC_CMAC_AES,
                                         NULL, NULL, devId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
                    }
                    else {
                        ret = wh_Client_CmacSetKeyId(cmac, keyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to wh_Client_CmacSetKeyId %d\n", ret);
                        }
                        else {
                            tagSz = sizeof(tag);
                            ret   = wc_AesCmacVerify_ex(
                                cmac, t128_512, sizeof(t128_512), m,
                                CMAC_MLEN_512, NULL, 0, NULL, devId);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed wc_AesCmacVerify_ex (commit) %d\n",
                                    ret);
                            }
                            else {
                                ret = wh_Client_KeyErase(ctx, keyId);
                                if (ret != 0) {
                                    WH_ERROR_PRINT(
                                        "Failed to wh_Client_KeyErase %d\n",
                                        ret);
                                }
                            }
                        }
                    }
                }
            }
        }
#endif /* WOLFSSL_AES_128 */
    }


    if (ret == 0) {
        WH_TEST_PRINT("CMAC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the new async non-DMA CMAC primitives. */
static int whTestCrypto_CmacAsync(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int      ret = WH_ERROR_OK;
    Cmac     cmac[1];
    uint8_t  tag[AES_BLOCK_SIZE] = {0};
    uint32_t tagSz;
    whKeyId  keyId;
    uint8_t  labelIn[WH_NVM_LABEL_LEN] = "CMAC Async Label";

    (void)rng;

#ifdef WOLFSSL_AES_128
    /* NIST SP 800-38B AES-128 vectors. m_long covers the 0/40/64-byte test
     * messages by prefix; the tags below are the canonical NIST outputs. */
    const byte k128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    const byte m128[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                         0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    const byte m_long[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    const byte t128[]     = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                             0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
    const byte t128_0[]   = {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
                             0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
    const byte t128_320[] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                             0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
    const byte t128_512[] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
                             0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};

    /* Case A: oneshot Generate via the async pair, with a cached HSM key. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Async CMAC: KeyCache(A) failed %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacGenerateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                            m128, sizeof(m128), AES_BLOCK_SIZE);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacGenerateResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async CMAC: Generate MAC mismatch (case A)\n");
        ret = -1;
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Case B: streaming Update + Final via the async pair. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0, m128,
                                          sizeof(m128), &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacFinalResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async CMAC: streaming MAC mismatch (case B)\n");
        ret = -1;
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Case C: oneshot Generate with inline key bytes (no HSM keyId). */
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
    }
    if (ret == 0) {
        ret = wh_Client_CmacGenerateRequest(ctx, cmac, WC_CMAC_AES, k128,
                                            sizeof(k128), m128, sizeof(m128),
                                            AES_BLOCK_SIZE);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacGenerateResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async CMAC: inline-key MAC mismatch (case C)\n");
        ret = -1;
    }

    /* Case D: empty-message streaming (Final with no preceding Update).
     * Exercises the zero-input round-trip of the resumeState. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacFinalResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128_0, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async CMAC: empty MAC mismatch (case D)\n");
        ret = -1;
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Case E: non-block-aligned single Update (40 bytes = 2 full blocks +
     * 8-byte tail). Confirms the server holds the tail in its buffer and
     * round-trips it back through resumeState. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret       = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                                m_long, 40, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacFinalResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128_320, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async CMAC: 40-byte MAC mismatch (case E)\n");
        ret = -1;
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Case F: multi-Update streaming, split at non-block boundary
     * (27 + 37 = 64 bytes). This is the canonical regression test for
     * partial-block state round-tripping between calls. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret       = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                                m_long, 27, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret       = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                                m_long + 27, 37, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacFinalResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128_512, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async CMAC: split-update MAC mismatch (case F)\n");
        ret = -1;
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Case G: reject inline keys longer than AES_256_KEY_SIZE in both
     * Generate and Update request paths (defends against the devKey
     * overflow). */
    if (ret == 0) {
        uint8_t bigKey[AES_256_KEY_SIZE + 1] = {0};
        bool    sent                         = true;
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0 &&
            wh_Client_CmacGenerateRequest(ctx, cmac, WC_CMAC_AES, bigKey,
                                          sizeof(bigKey), m128, sizeof(m128),
                                          AES_BLOCK_SIZE) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async CMAC: oversize keyLen not BADARGS (Generate)\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_CmacUpdateRequest(
                            ctx, cmac, WC_CMAC_AES, bigKey, sizeof(bigKey),
                            m128, sizeof(m128), &sent) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async CMAC: oversize keyLen not BADARGS (Update)\n");
            ret = -1;
        }
    }

    /* Case H: argument validation. NULL ctx / cmac / requestSent must
     * yield BADARGS without sending anything. */
    if (ret == 0) {
        bool sent = true;
        if (wh_Client_CmacGenerateRequest(NULL, cmac, WC_CMAC_AES, NULL, 0,
                                          m128, 1,
                                          AES_BLOCK_SIZE) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async CMAC: NULL ctx not BADARGS (Generate)\n");
            ret = -1;
        }
        if (ret == 0 &&
            wh_Client_CmacUpdateRequest(NULL, cmac, WC_CMAC_AES, NULL, 0, m128,
                                        1, &sent) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async CMAC: NULL ctx not BADARGS (Update)\n");
            ret = -1;
        }
        if (ret == 0 &&
            wh_Client_CmacFinalRequest(NULL, cmac) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async CMAC: NULL ctx not BADARGS (Final)\n");
            ret = -1;
        }
    }

    /* Case I: NULL key with nonzero keyLen must BADARGS in both Request
     * paths (defends against a NULL deref in the inline-key memcpy). */
    if (ret == 0) {
        bool sent = true;
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0 &&
            wh_Client_CmacGenerateRequest(ctx, cmac, WC_CMAC_AES, NULL,
                                          AES_128_KEY_SIZE, m128, sizeof(m128),
                                          AES_BLOCK_SIZE) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async CMAC: NULL key + nonzero keyLen not BADARGS (Gen)\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_CmacUpdateRequest(
                            ctx, cmac, WC_CMAC_AES, NULL, AES_128_KEY_SIZE,
                            m128, sizeof(m128), &sent) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async CMAC: NULL key + nonzero keyLen not BADARGS (Upd)\n");
            ret = -1;
        }
    }

    /* Case J: wh_Client_Cmac must reject caller tag lengths outside
     * [WC_CMAC_TAG_MIN_SZ, WC_CMAC_TAG_MAX_SZ] with WH_ERROR_BUFFER_SIZE,
     * matching wolfCrypt's wc_CmacFinal contract. Streaming Final hardcodes
     * outSz=AES_BLOCK_SIZE on the wire, so without this validation a
     * sub-min or over-max caller buffer would silently receive a truncated
     * tag. */
    if (ret == 0) {
        uint8_t  smallTag[3];
        uint32_t smallSz = sizeof(smallTag);
        uint8_t  bigTag[AES_BLOCK_SIZE + 1];
        uint32_t bigSz = sizeof(bigTag);
        if (wh_Client_Cmac(ctx, cmac, WC_CMAC_AES, k128, sizeof(k128), m128,
                           sizeof(m128), smallTag,
                           &smallSz) != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT(
                "Async CMAC: sub-min outMacLen not WH_ERROR_BUFFER_SIZE\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_Cmac(ctx, cmac, WC_CMAC_AES, k128,
                                       sizeof(k128), m128, sizeof(m128), bigTag,
                                       &bigSz) != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT(
                "Async CMAC: over-max outMacLen not WH_ERROR_BUFFER_SIZE\n");
            ret = -1;
        }
    }

    /* Case K: wh_Client_CmacFinalResponse must also reject bad tag lengths
     * (defense-in-depth for direct users of the async Final pair). Drive a
     * full Update via the async pair, then call FinalRequest and finally
     * FinalResponse with a sub-min outMacLen. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0, m128,
                                          sizeof(m128), &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        uint8_t  smallTag[3] = {0};
        uint32_t smallSz     = sizeof(smallTag);
        int      finalRet;
        do {
            finalRet =
                wh_Client_CmacFinalResponse(ctx, cmac, smallTag, &smallSz);
        } while (finalRet == WH_ERROR_NOTREADY);
        if (finalRet != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT("Async CMAC: FinalResponse sub-min outMacLen not "
                           "WH_ERROR_BUFFER_SIZE\n");
            ret = -1;
        }
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
#endif /* WOLFSSL_AES_128 */

    if (ret == 0) {
        WH_TEST_PRINT("CMAC ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA CMAC primitives. */
static int whTestCrypto_CmacDmaAsync(whClientContext* ctx, int devId,
                                     WC_RNG* rng)
{
    int      ret = WH_ERROR_OK;
    Cmac     cmac[1];
    uint8_t  tag[AES_BLOCK_SIZE] = {0};
    uint32_t tagSz;
    whKeyId  keyId;
    uint8_t  labelIn[WH_NVM_LABEL_LEN] = "CMAC DMA Async Label";

    (void)rng;

#ifdef WOLFSSL_AES_128
    const byte k128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    const byte m128[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                         0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    const byte m_long[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    const byte t128[]     = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                             0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
    const byte t128_320[] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                             0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
    const byte t128_512[] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
                             0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};

    /* Case A: DMA oneshot Generate. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacGenerateDmaRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                               m128, sizeof(m128),
                                               AES_BLOCK_SIZE);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacGenerateDmaResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA CMAC: Generate mismatch (case A)\n");
        ret = -1;
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Case B: DMA streaming Update + Final. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_CmacDmaUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                             m128, sizeof(m128), &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacDmaUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacDmaFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacDmaFinalResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA CMAC: streaming mismatch (case B)\n");
        ret = -1;
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Case C: DMA streaming with a 40-byte non-block-aligned message. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_CmacDmaUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                             m_long, 40, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacDmaUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacDmaFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacDmaFinalResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128_320, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA CMAC: 40-byte MAC mismatch (case C)\n");
        ret = -1;
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Case D: DMA multi-Update streaming, split at non-block boundary
     * (27 + 37 = 64 bytes). Regression test for state round-tripping. */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_CmacDmaUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                             m_long, 27, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacDmaUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_CmacDmaUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                             m_long + 27, 37, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacDmaUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacDmaFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        do {
            ret = wh_Client_CmacDmaFinalResponse(ctx, cmac, tag, &tagSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(tag, t128_512, AES_BLOCK_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA CMAC: split-update MAC mismatch (case D)\n");
        ret = -1;
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    /* Case E: reject inline keys longer than AES_256_KEY_SIZE in both DMA
     * Generate and Update request paths. */
    if (ret == 0) {
        uint8_t bigKey[AES_256_KEY_SIZE + 1] = {0};
        bool    sent                         = true;
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0 &&
            wh_Client_CmacGenerateDmaRequest(
                ctx, cmac, WC_CMAC_AES, bigKey, sizeof(bigKey), m128,
                sizeof(m128), AES_BLOCK_SIZE) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async DMA CMAC: oversize keyLen not BADARGS (Gen)\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_CmacDmaUpdateRequest(
                            ctx, cmac, WC_CMAC_AES, bigKey, sizeof(bigKey),
                            m128, sizeof(m128), &sent) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async DMA CMAC: oversize keyLen not BADARGS (Upd)\n");
            ret = -1;
        }
    }

    /* Case F: argument validation. */
    if (ret == 0) {
        bool sent = true;
        if (wh_Client_CmacGenerateDmaRequest(NULL, cmac, WC_CMAC_AES, NULL, 0,
                                             m128, 1, AES_BLOCK_SIZE) !=
            WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async DMA CMAC: NULL ctx not BADARGS (Gen)\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_CmacDmaUpdateRequest(
                            NULL, cmac, WC_CMAC_AES, NULL, 0, m128, 1, &sent) !=
                            WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async DMA CMAC: NULL ctx not BADARGS (Upd)\n");
            ret = -1;
        }
        if (ret == 0 &&
            wh_Client_CmacDmaFinalRequest(NULL, cmac) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async DMA CMAC: NULL ctx not BADARGS (Fin)\n");
            ret = -1;
        }
    }

    /* Case G: NULL key with nonzero keyLen must BADARGS in both DMA Request
     * paths (defends against a NULL deref in the inline-key memcpy). */
    if (ret == 0) {
        bool sent = true;
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0 &&
            wh_Client_CmacGenerateDmaRequest(
                ctx, cmac, WC_CMAC_AES, NULL, AES_128_KEY_SIZE, m128,
                sizeof(m128), AES_BLOCK_SIZE) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async DMA CMAC: NULL key + nonzero keyLen not "
                           "BADARGS (Gen)\n");
            ret = -1;
        }
        if (ret == 0 && wh_Client_CmacDmaUpdateRequest(
                            ctx, cmac, WC_CMAC_AES, NULL, AES_128_KEY_SIZE,
                            m128, sizeof(m128), &sent) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async DMA CMAC: NULL key + nonzero keyLen not "
                           "BADARGS (Upd)\n");
            ret = -1;
        }
    }

    /* Case H: wh_Client_CmacDma must reject caller tag lengths outside
     * [WC_CMAC_TAG_MIN_SZ, WC_CMAC_TAG_MAX_SZ] with WH_ERROR_BUFFER_SIZE,
     * and so must wh_Client_CmacDmaFinalResponse for direct users of the
     * async pair. */
    if (ret == 0) {
        uint8_t  smallTag[3];
        uint32_t smallSz = sizeof(smallTag);
        uint8_t  bigTag[AES_BLOCK_SIZE + 1];
        uint32_t bigSz = sizeof(bigTag);
        if (wh_Client_CmacDma(ctx, cmac, WC_CMAC_AES, k128, sizeof(k128), m128,
                              sizeof(m128), smallTag,
                              &smallSz) != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT(
                "Async DMA CMAC: sub-min outMacLen not WH_ERROR_BUFFER_SIZE\n");
            ret = -1;
        }
        if (ret == 0 &&
            wh_Client_CmacDma(ctx, cmac, WC_CMAC_AES, k128, sizeof(k128), m128,
                              sizeof(m128), bigTag,
                              &bigSz) != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT("Async DMA CMAC: over-max outMacLen not "
                           "WH_ERROR_BUFFER_SIZE\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128, sizeof(k128),
                                   &keyId);
    }
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
    }
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_CmacDmaUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                             m128, sizeof(m128), &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_CmacDmaUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacDmaFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        uint8_t  smallTag[3] = {0};
        uint32_t smallSz     = sizeof(smallTag);
        int      finalRet;
        do {
            finalRet =
                wh_Client_CmacDmaFinalResponse(ctx, cmac, smallTag, &smallSz);
        } while (finalRet == WH_ERROR_NOTREADY);
        if (finalRet != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT("Async DMA CMAC: FinalResponse sub-min outMacLen "
                           "not WH_ERROR_BUFFER_SIZE\n");
            ret = -1;
        }
    }
    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
#endif /* WOLFSSL_AES_128 */

    if (ret == 0) {
        WH_TEST_PRINT("CMAC DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#ifdef WOLFSSL_HAVE_MLDSA

#if !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
    !defined(WOLFSSL_MLDSA_NO_SIGN) &&   \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && !defined(WOLFSSL_NO_ML_DSA_44)
static int whTestCrypto_MlDsaWolfCrypt(whClientContext* ctx, int devId,
                                       WC_RNG* rng, int level)
{
    (void)ctx;

    int ret      = 0;
    int verified = 0;

    /* Test ML DSA key generation, signing and verification */
    wc_MlDsaKey key;
    byte        msg[] = "Test message for ML DSA signing";
    byte        sig[MLDSA_MAX_SIG_SIZE];
    word32      sigSz = sizeof(sig);

    /* Initialize key */
    ret = wc_MlDsaKey_Init(&key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML DSA key: %d\n", ret);
        return ret;
    }

    /* Set the requested ML-DSA security level */
    ret = wc_MlDsaKey_SetParams(&key, level);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set ML DSA params: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    /* Generate key pair */
    ret = wc_MlDsaKey_MakeKey(&key, rng);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate ML DSA key: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    /* Get the signature size */
    ret = wc_MlDsaKey_GetSigLen(&key, (int*)&sigSz);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to get ML DSA signature length: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    /* Sign message */
    ret = wc_MlDsaKey_SignCtx(&key, NULL, 0, sig, &sigSz, msg, sizeof(msg),
                              rng);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to sign with ML DSA: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    /* Verify signature */
    ret = wc_MlDsaKey_VerifyCtx(&key, sig, sigSz, NULL, 0, msg, sizeof(msg),
                                &verified);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to verify ML DSA signature: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    if (!verified) {
        WH_ERROR_PRINT("ML DSA signature verification failed\n");
    }
    if (ret == 0) {
        /* Modify signature to ensure verification fails */
        sig[0] ^= 1;

        ret = wc_MlDsaKey_VerifyCtx(&key, sig, sigSz, NULL, 0, msg,
                                    sizeof(msg), &verified);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify modified ML DSA signature: %d\n",
                           ret);
        }
        else if (verified) {
            WH_ERROR_PRINT("ML DSA signature verification succeeded when it"
                           " should have failed\n");
            ret = -1;
        }
        else {
            WH_TEST_PRINT("ML-DSA DEVID=0x%X SUCCESS\n", devId);
        }
    }

    wc_MlDsaKey_Free(&key);

    return ret;
}

static int whTestCrypto_MlDsaClient(whClientContext* ctx, int devId,
                                    WC_RNG* rng, int level)
{
    (void)devId;
    (void)rng;

    int         ret = 0;
    wc_MlDsaKey key[1];

    /* Initialize key */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML-DSA key: %d\n", ret);
        return ret;
    }

    /* Generate ephemeral key using non-DMA client API */
    if (ret == 0) {
        ret = wh_Client_MlDsaMakeExportKey(ctx, level, 0, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate ML-DSA key: %d\n", ret);
        }
    }

    /* Test basic sign/verify using the public API (no context) */
    if (ret == 0) {
        byte   msg[] = "Test message for non-DMA ML-DSA";
        byte   sig[MLDSA_MAX_SIG_SIZE];
        word32 sigLen   = sizeof(sig);
        int    verified = 0;

        ret = wh_Client_MlDsaSign(ctx, msg, sizeof(msg), sig, &sigLen, key,
                                     NULL, 0, WC_HASH_TYPE_NONE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign using ML-DSA non-DMA: %d\n", ret);
        }
        else {
            ret = wh_Client_MlDsaVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                        &verified, key, NULL, 0,
                                        WC_HASH_TYPE_NONE);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to verify ML-DSA non-DMA: %d\n", ret);
            }
            else if (!verified) {
                WH_ERROR_PRINT("ML-DSA non-DMA verification failed\n");
                ret = -1;
            }
            else {
                /* Modify signature - should fail verification */
                sig[0] ^= 0xFF;
                int vret = wh_Client_MlDsaVerify(ctx, sig, sigLen, msg,
                                                 sizeof(msg), &verified, key,
                                                 NULL, 0, WC_HASH_TYPE_NONE);
                if (vret != 0) {
                    WH_ERROR_PRINT("Failed to call verify with modified sig: "
                                   "%d\n", vret);
                    ret = vret;
                }
                else if (verified) {
                    WH_ERROR_PRINT("ML-DSA non-DMA verified bad signature\n");
                    ret = -1;
                }
            }
        }
    }

    /* Test sign/verify with FIPS 204 context string */
    if (ret == 0) {
        byte       msg[] = "Context test message non-DMA";
        byte       sig[MLDSA_MAX_SIG_SIZE];
        word32     sigLen   = sizeof(sig);
        int        verified = 0;
        const byte ctx_str[] = "test-context";

        ret = wh_Client_MlDsaSign(ctx, msg, sizeof(msg), sig, &sigLen, key,
                                     ctx_str, sizeof(ctx_str),
                                     WC_HASH_TYPE_NONE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with context non-DMA: %d\n", ret);
        }
        else {
            /* Verify with same context - should succeed */
            ret = wh_Client_MlDsaVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                           &verified, key, ctx_str,
                                           sizeof(ctx_str), WC_HASH_TYPE_NONE);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to verify with context non-DMA: %d\n",
                               ret);
            }
            else if (!verified) {
                WH_ERROR_PRINT("Context verification failed non-DMA\n");
                ret = -1;
            }
            else {
                /* Verify with wrong context - should fail verification */
                const byte wrong_ctx[] = "wrong-context";
                int wrong_verified = 0;
                int vret = wh_Client_MlDsaVerify(
                    ctx, sig, sigLen, msg, sizeof(msg), &wrong_verified, key,
                    wrong_ctx, sizeof(wrong_ctx), WC_HASH_TYPE_NONE);
                if (vret != 0) {
                    WH_ERROR_PRINT("Failed to call verify with wrong context "
                                   "non-DMA: %d\n", vret);
                    ret = vret;
                }
                else if (wrong_verified) {
                    WH_ERROR_PRINT("Verification succeeded with wrong context "
                                   "non-DMA\n");
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-DSA Client Non-DMA API SUCCESS\n");
    }

    wc_MlDsaKey_Free(key);
    return ret;
}

#if defined(WOLFSSL_MLDSA_PUBLIC_KEY) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && !defined(WOLFSSL_NO_ML_DSA_44)
static int whTestCrypto_MlDsaExportPublic(whClientContext* ctx, int devId,
                                          WC_RNG* rng, int level)
{
    (void)rng;

    int         ret    = 0;
    whKeyId     keyId  = WH_KEYID_ERASED;
    wc_MlDsaKey pub[1] = {0};
    /* Large enough to hold an ML-DSA key DER so the access-control assertion
     * doesn't get masked by a buffer-too-small failure. */
    uint8_t     denyBuf[MLDSA_MAX_BOTH_KEY_DER_SIZE];
    uint16_t    denyLen = sizeof(denyBuf);
    (void)devId;

    /* MakeCacheKey at the requested security level, with NONEXPORTABLE. */
    ret = wh_Client_MlDsaMakeCacheKey(
        ctx, 0, level, &keyId,
        WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |
            WH_NVM_FLAGS_NONEXPORTABLE,
        0, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to make NONEXPORTABLE cached ML-DSA key %d\n",
                       ret);
        return ret;
    }

    /* Full export must be denied */
    {
        int denyRet = wh_Client_KeyExport(ctx, keyId, NULL, 0, denyBuf,
                                          &denyLen);
        if (denyRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT(
                "NONEXPORTABLE ML-DSA full export was not denied: %d\n",
                denyRet);
            ret = -1;
        }
    }

    /* Public export must succeed and yield a public-only key struct */
    if (ret == 0) {
        ret = wc_MlDsaKey_Init(pub, NULL, INVALID_DEVID);
        if (ret == 0) {
            /* Must set params before the decoder can populate the key. */
            ret = wc_MlDsaKey_SetParams(pub, level);
        }
        if (ret == 0) {
            ret = wh_Client_MlDsaExportPublicKey(ctx, keyId, pub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "wh_Client_MlDsaExportPublicKey failed %d\n", ret);
            }
            else if (pub->pubKeySet != 1 || pub->prvKeySet != 0) {
                WH_ERROR_PRINT(
                    "Exported ML-DSA key flags wrong: pub=%d prv=%d\n",
                    (int)pub->pubKeySet, (int)pub->prvKeySet);
                ret = -1;
            }
        }
        wc_MlDsaKey_Free(pub);
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-DSA EXPORT-PUBLIC SUCCESS\n");
    }
    return ret;
}

/* One keygen call caches the private key and returns the public key. Verify
 * the returned public key byte-matches wh_Client_MlDsaExportPublicKey and that
 * it verifies a signature made by the cached private key. */
static int whTestCrypto_MlDsaCacheKeyAndExportPublic(whClientContext* ctx,
                                                     int devId, WC_RNG* rng,
                                                     int level)
{
    int         ret       = 0;
    whKeyId     keyId     = WH_KEYID_ERASED;
    wc_MlDsaKey genPub[1] = {0};
    wc_MlDsaKey refPub[1] = {0};
    byte        msg[]     = "ML-DSA cache-export-public message";
    byte        sig[MLDSA_MAX_SIG_SIZE];
    word32      sigLen    = sizeof(sig);
    int         verified  = 0;
    byte        genDer[MLDSA_MAX_BOTH_KEY_DER_SIZE];
    byte        refDer[MLDSA_MAX_BOTH_KEY_DER_SIZE];
    int         genDerSz  = 0;
    int         refDerSz  = 0;
    (void)devId;
    (void)rng;

    ret = wc_MlDsaKey_Init(genPub, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_MlDsaKey_SetParams(genPub, level);
    }
    if (ret == 0) {
        ret = wh_Client_MlDsaMakeCacheKeyAndExportPublic(
            ctx, 0, level, &keyId,
            WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, 0, NULL,
            genPub);
        if (ret != 0) {
            WH_ERROR_PRINT("MlDsaMakeCacheKeyAndExportPublic failed %d\n", ret);
        }
    }

    /* Cross-check the keygen-returned public key against ExportPublicKey. */
    if (ret == 0) {
        ret = wc_MlDsaKey_Init(refPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_MlDsaKey_SetParams(refPub, level);
        }
        if (ret == 0) {
            ret = wh_Client_MlDsaExportPublicKey(ctx, keyId, refPub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_MlDsaExportPublicKey failed %d\n",
                               ret);
            }
        }
    }
    if (ret == 0) {
        genDerSz = wc_MlDsaKey_PublicKeyToDer(genPub, genDer, sizeof(genDer), 1);
        refDerSz = wc_MlDsaKey_PublicKeyToDer(refPub, refDer, sizeof(refDer), 1);
        if ((genDerSz <= 0) || (genDerSz != refDerSz) ||
            (memcmp(genDer, refDer, (size_t)genDerSz) != 0)) {
            WH_ERROR_PRINT("keygen pubkey mismatch vs ExportPublicKey\n");
            ret = -1;
        }
    }

    /* Prove usability: sign on the HSM using genPub directly as the private-key
     * handle (no separate key object), then verify with its exported public
     * key. */
    if (ret == 0) {
        ret = wh_Client_MlDsaSign(ctx, msg, sizeof(msg), sig, &sigLen, genPub,
                                  NULL, 0, WC_HASH_TYPE_NONE);
        if (ret != 0) {
            WH_ERROR_PRINT("HSM ML-DSA sign failed %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wh_Client_MlDsaVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                    &verified, genPub, NULL, 0,
                                    WC_HASH_TYPE_NONE);
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("verify with keygen pub failed ret=%d verify=%d\n",
                           ret, verified);
            if (ret == 0) {
                ret = -1;
            }
        }
    }

    wc_MlDsaKey_Free(refPub);
    wc_MlDsaKey_Free(genPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-DSA CACHE-AND-EXPORT-PUBLIC SUCCESS\n");
    }
    return ret;
}
#endif /* WOLFSSL_MLDSA_PUBLIC_KEY && ML_DSA_44 available */

#ifdef WOLFHSM_CFG_DMA
static int whTestCrypto_MlDsaDmaClient(whClientContext* ctx, int devId,
                                       WC_RNG* rng, int level)
{
    (void)rng;

    int         ret = 0;
    wc_MlDsaKey key[1];
    wc_MlDsaKey imported_key[1];
    whKeyId     keyId       = WH_KEYID_ERASED;
    uint8_t     label[]     = "ML-DSA Test Key";
    int         keyImported = 0;

    /* Buffers for comparing serialized keys */
    byte   key_der1[MLDSA_MAX_PRV_KEY_SIZE];
    byte   key_der2[MLDSA_MAX_PRV_KEY_SIZE];
    word32 key_der1_len = sizeof(key_der1);
    word32 key_der2_len = sizeof(key_der2);

    /* Initialize keys */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML-DSA key: %d\n", ret);
        return ret;
    }

    ret = wc_MlDsaKey_Init(imported_key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize imported ML-DSA key: %d\n", ret);
        wc_MlDsaKey_Free(key);
        return ret;
    }

    /* Generate ephemeral key using DMA */
    if (ret == 0) {
        ret = wh_Client_MlDsaMakeExportKeyDma(ctx, level, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate ML-DSA key using DMA: %d\n",
                           ret);
        }
    }

    /* Serialize the generated key for comparison */
    if (ret == 0) {
        ret = wc_MlDsaKey_PrivateKeyToDer(key, key_der1, key_der1_len);
        if (ret < 0) {
            WH_ERROR_PRINT("Failed to serialize generated key: %d\n", ret);
        }
        else {
            key_der1_len = ret;
            ret          = 0;
        }
    }

    /* Import the key to cache using DMA */
    if (ret == 0) {
        ret = wh_Client_MlDsaImportKeyDma(ctx, key, &keyId, WH_NVM_FLAGS_NONE,
                                          sizeof(label), label);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import ML-DSA key using DMA: %d\n", ret);
        }
        keyImported = (ret == 0);
    }

    /* Export the key back using DMA */
    if (ret == 0) {
        ret = wh_Client_MlDsaExportKeyDma(ctx, keyId, imported_key,
                                          sizeof(label), label);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to export ML-DSA key using DMA: %d\n", ret);
        }
    }

    /* Serialize the exported key for comparison */
    if (ret == 0) {
        ret =
            wc_MlDsaKey_PrivateKeyToDer(imported_key, key_der2, key_der2_len);
        if (ret < 0) {
            WH_ERROR_PRINT("Failed to serialize exported key: %d\n", ret);
        }
        else {
            key_der2_len = ret;
            ret          = 0;
        }
    }

    /* Compare the keys */
    if (ret == 0) {
        if (key_der1_len != key_der2_len ||
            memcmp(key_der1, key_der2, key_der1_len) != 0) {
            WH_ERROR_PRINT("Exported key does not match generated key\n");
            ret = -1;
        }
    }
    /* Test signing and verification */
    if (ret == 0) {
        byte   msg[] = "Test message to sign";
        byte   sig[MLDSA_MAX_SIG_SIZE];
        word32 sigLen   = sizeof(sig);
        int    verified = 0;

        /* Sign the message */
        ret = wh_Client_MlDsaSignDma(ctx, msg, sizeof(msg), sig, &sigLen, key,
                                         NULL, 0, WC_HASH_TYPE_NONE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign message using ML-DSA: %d\n", ret);
        }
        else {
            /* Verify the signature - should succeed */
            ret = wh_Client_MlDsaVerifyDma(ctx, sig, sigLen, msg, sizeof(msg),
                                           &verified, key, NULL, 0,
                                           WC_HASH_TYPE_NONE);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to verify signature using ML-DSA: %d\n",
                               ret);
            }
            else if (!verified) {
                WH_ERROR_PRINT("Signature verification failed when it should "
                               "have succeeded\n");
                ret = -1;
            }
            else {
                /* Modify signature and verify again - should fail */
                sig[0] ^= 0xFF;
                ret = wh_Client_MlDsaVerifyDma(ctx, sig, sigLen, msg,
                                               sizeof(msg), &verified, key,
                                               NULL, 0, WC_HASH_TYPE_NONE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to verify modified signature using "
                                   "ML-DSA: %d\n",
                                   ret);
                }
                else if (verified) {
                    WH_ERROR_PRINT("Signature verification succeeded when it "
                                   "should have failed\n");
                    ret = -1;
                }
                else {
                    /* Test passed - verification failed as expected */
                    ret = 0;
                }
            }
        }
    }

    /* Test signing and verification with a FIPS 204 context string */
    if (ret == 0) {
        byte   msg[] = "Context test message";
        byte   sig[MLDSA_MAX_SIG_SIZE];
        word32 sigLen   = sizeof(sig);
        int    verified = 0;
        const byte ctx_str[] = "test-context";

        /* Sign with a context string */
        ret = wh_Client_MlDsaSignDma(ctx, msg, sizeof(msg), sig, &sigLen,
                                         key, ctx_str, sizeof(ctx_str),
                                         WC_HASH_TYPE_NONE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with context using ML-DSA: %d\n",
                           ret);
        }
        else {
            /* Verify with the same context - should succeed */
            ret = wh_Client_MlDsaVerifyDma(ctx, sig, sigLen, msg,
                                               sizeof(msg), &verified, key,
                                               ctx_str, sizeof(ctx_str),
                                               WC_HASH_TYPE_NONE);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to verify with context using ML-DSA: "
                               "%d\n", ret);
            }
            else if (!verified) {
                WH_ERROR_PRINT("Context verification failed when it should "
                               "have succeeded\n");
                ret = -1;
            }
            else {
                /* Verify with wrong context - should fail verification */
                const byte wrong_ctx[] = "wrong-context";
                int wrong_verified = 0;
                int vret = wh_Client_MlDsaVerifyDma(
                    ctx, sig, sigLen, msg, sizeof(msg), &wrong_verified, key,
                    wrong_ctx, sizeof(wrong_ctx), WC_HASH_TYPE_NONE);
                if (vret != 0) {
                    WH_ERROR_PRINT("Failed to call verify with wrong context: "
                                   "%d\n", vret);
                    ret = vret;
                }
                else if (wrong_verified) {
                    WH_ERROR_PRINT("Context verification succeeded with wrong "
                                   "context\n");
                    ret = -1;
                }
            }
        }
    }

    /* Clean up the cached key if it was imported */
    if (keyImported) {
        int evict_ret = wh_Client_KeyEvict(ctx, keyId);
        if (evict_ret != 0) {
            WH_ERROR_PRINT("Failed to evict ML-DSA key: %d\n", evict_ret);
            if (ret == 0) {
                ret = evict_ret;
            }
        }
    }


    if (ret == 0) {
        WH_TEST_PRINT("ML-DSA Client DMA API SUCCESS\n");
    }

    wc_MlDsaKey_Free(key);
    wc_MlDsaKey_Free(imported_key);
    return ret;
}

#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
static int whTestCrypto_MlDsaExportPublicDma(whClientContext* ctx, int devId,
                                             WC_RNG* rng, int level)
{
    (void)rng;
    (void)devId;

    int         ret    = 0;
    whKeyId     keyId  = WH_KEYID_ERASED;
    wc_MlDsaKey pub[1] = {0};
    uint8_t     denyBuf[1];
    uint16_t    denyLen = sizeof(denyBuf);

    /* Cache an ML-DSA keypair NONEXPORTABLE on the HSM at the given level. */
    ret = wh_Client_MlDsaMakeCacheKey(
        ctx, 0, level, &keyId,
        WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |
            WH_NVM_FLAGS_NONEXPORTABLE,
        0, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT(
            "Failed to make NONEXPORTABLE ML-DSA cached key (DMA test) %d\n",
            ret);
        return ret;
    }

    /* Full DMA export must be denied */
    {
        byte fullBuf[MLDSA_MAX_BOTH_KEY_DER_SIZE];
        uint16_t fullLen = sizeof(fullBuf);
        int denyRet = wh_Client_KeyExportDma(ctx, keyId, fullBuf, fullLen,
                                             NULL, 0, &denyLen);
        if (denyRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT(
                "NONEXPORTABLE ML-DSA full DMA export was not denied: %d\n",
                denyRet);
            ret = -1;
        }
    }

    /* Public DMA export must succeed and yield a usable public-only key. */
    if (ret == 0) {
        ret = wc_MlDsaKey_Init(pub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_MlDsaKey_SetParams(pub, level);
        }
        if (ret == 0) {
            ret = wh_Client_MlDsaExportPublicKeyDma(ctx, keyId, pub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "wh_Client_MlDsaExportPublicKeyDma failed %d\n", ret);
            }
            else if (pub->pubKeySet != 1 || pub->prvKeySet != 0) {
                WH_ERROR_PRINT(
                    "Exported ML-DSA key (DMA) flags wrong: pub=%d prv=%d\n",
                    (int)pub->pubKeySet, (int)pub->prvKeySet);
                ret = -1;
            }
        }
        wc_MlDsaKey_Free(pub);
    }

    /* Byte-identity check: the generic DMA transport and the non-DMA
     * transport must emit the same public-DER bytes for the same cached
     * key. This cross-validates that the DMA path isn't producing
     * subtly different output. */
    if (ret == 0) {
        byte     dmaDer[MLDSA_MAX_PUB_KEY_DER_SIZE];
        byte     nonDmaDer[MLDSA_MAX_PUB_KEY_DER_SIZE];
        uint16_t dmaSz    = sizeof(dmaDer);
        uint16_t nonDmaSz = sizeof(nonDmaDer);

        ret = wh_Client_KeyExportPublicDma(ctx, keyId, WH_KEY_ALGO_MLDSA,
                                           dmaDer, dmaSz, NULL, 0, &dmaSz);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Generic ML-DSA DMA export failed for re-encode check %d\n",
                ret);
        }
        else {
            ret = wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_MLDSA,
                                            NULL, 0, nonDmaDer, &nonDmaSz);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Non-DMA ML-DSA export failed for re-encode check %d\n",
                    ret);
            }
            else if (dmaSz != nonDmaSz ||
                     memcmp(dmaDer, nonDmaDer, dmaSz) != 0) {
                WH_ERROR_PRINT(
                    "ML-DSA DMA and non-DMA public DER differ "
                    "(dmaSz=%u nonDmaSz=%u)\n",
                    (unsigned)dmaSz, (unsigned)nonDmaSz);
                ret = -1;
            }
        }
    }

    /* Negative: a too-small client buffer must yield WH_ERROR_NOSPACE. */
    if (ret == 0) {
        byte     tinyBuf[8];
        uint16_t tinySz = sizeof(tinyBuf);
        int      negRet = wh_Client_KeyExportPublicDma(
            ctx, keyId, WH_KEY_ALGO_MLDSA, tinyBuf, tinySz, NULL, 0, &tinySz);
        if (negRet != WH_ERROR_NOSPACE) {
            WH_ERROR_PRINT(
                "Too-small DMA buffer did not return NOSPACE: %d\n", negRet);
            ret = -1;
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-DSA EXPORT-PUBLIC DMA SUCCESS\n");
    }
    return ret;
}

/* DMA variant: one keygen call caches the private key and streams the public
 * key back through the client's DMA buffer. Verify it byte-matches
 * wh_Client_MlDsaExportPublicKeyDma and that it verifies an HSM signature. */
static int whTestCrypto_MlDsaCacheKeyAndExportPublicDma(whClientContext* ctx,
                                                        int devId, WC_RNG* rng,
                                                        int level)
{
    int         ret       = 0;
    whKeyId     keyId     = WH_KEYID_ERASED;
    wc_MlDsaKey genPub[1] = {0};
    wc_MlDsaKey refPub[1] = {0};
    byte        msg[]     = "ML-DSA DMA cache-export-public message";
    byte        sig[MLDSA_MAX_SIG_SIZE];
    word32      sigLen    = sizeof(sig);
    int         verified  = 0;
    byte        genDer[MLDSA_MAX_PUB_KEY_DER_SIZE];
    byte        refDer[MLDSA_MAX_PUB_KEY_DER_SIZE];
    int         genDerSz  = 0;
    int         refDerSz  = 0;
    (void)devId;
    (void)rng;

    ret = wc_MlDsaKey_Init(genPub, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_MlDsaKey_SetParams(genPub, level);
    }
    if (ret == 0) {
        ret = wh_Client_MlDsaMakeCacheKeyDma(
            ctx, level, &keyId,
            WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, 0, NULL,
            genPub);
        if (ret != 0) {
            WH_ERROR_PRINT("MlDsaMakeCacheKeyDma failed %d\n", ret);
        }
    }

    /* Cross-check the keygen-returned public key against ExportPublicKeyDma. */
    if (ret == 0) {
        ret = wc_MlDsaKey_Init(refPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_MlDsaKey_SetParams(refPub, level);
        }
        if (ret == 0) {
            ret = wh_Client_MlDsaExportPublicKeyDma(ctx, keyId, refPub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_MlDsaExportPublicKeyDma failed %d\n",
                               ret);
            }
        }
    }
    if (ret == 0) {
        genDerSz = wc_MlDsaKey_PublicKeyToDer(genPub, genDer, sizeof(genDer), 1);
        refDerSz = wc_MlDsaKey_PublicKeyToDer(refPub, refDer, sizeof(refDer), 1);
        if ((genDerSz <= 0) || (genDerSz != refDerSz) ||
            (memcmp(genDer, refDer, (size_t)genDerSz) != 0)) {
            WH_ERROR_PRINT("keygen pubkey (DMA) mismatch vs export\n");
            ret = -1;
        }
    }

    /* Prove usability: sign on the HSM (DMA) using genPub directly as the
     * private-key handle (no separate key object), then verify with its
     * exported public key. */
    if (ret == 0) {
        ret = wh_Client_MlDsaSignDma(ctx, msg, sizeof(msg), sig, &sigLen,
                                     genPub, NULL, 0, WC_HASH_TYPE_NONE);
        if (ret != 0) {
            WH_ERROR_PRINT("HSM ML-DSA DMA sign failed %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wh_Client_MlDsaVerifyDma(ctx, sig, sigLen, msg, sizeof(msg),
                                       &verified, genPub, NULL, 0,
                                       WC_HASH_TYPE_NONE);
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT(
                "DMA verify with keygen pub failed ret=%d verify=%d\n", ret,
                verified);
            if (ret == 0) {
                ret = -1;
            }
        }
    }

    wc_MlDsaKey_Free(refPub);
    wc_MlDsaKey_Free(genPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-DSA CACHE-AND-EXPORT-PUBLIC DMA SUCCESS\n");
    }
    return ret;
}
#endif /* WOLFSSL_MLDSA_PUBLIC_KEY */

#endif /* WOLFHSM_CFG_DMA */
#endif /* !defined(WOLFSSL_MLDSA_NO_VERIFY) &&   \
          !defined(WOLFSSL_MLDSA_NO_SIGN) &&     \
          !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) */

#if !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
    !defined(WOLFSSL_NO_ML_DSA_44) && \
    defined(WOLFHSM_CFG_DMA)
int whTestCrypto_MlDsaVerifyOnlyDma(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    (void)rng;

    /* Vectors from wolfCrypt test vectors, but decoupled for isolated usage */
    const byte ml_dsa_44_pub_key[] = {
        0xd8, 0xac, 0xaf, 0xd8, 0x2e, 0x14, 0x23, 0x78, 0xf7, 0x0d, 0x9a, 0x04,
        0x2b, 0x92, 0x48, 0x67, 0x60, 0x55, 0x34, 0xd9, 0xac, 0x0b, 0xc4, 0x1f,
        0x46, 0xe8, 0x85, 0xb9, 0x2e, 0x1b, 0x10, 0x3a, 0x75, 0x7a, 0xc2, 0xbc,
        0x76, 0xf0, 0x6d, 0x05, 0xa4, 0x78, 0x48, 0x84, 0x26, 0x69, 0xbd, 0x26,
        0x1d, 0x73, 0x60, 0xaa, 0x57, 0x9d, 0x8c, 0x66, 0xb1, 0x19, 0xea, 0x11,
        0xff, 0xbb, 0xf6, 0xeb, 0x26, 0x26, 0xac, 0x78, 0x74, 0x46, 0x6d, 0x51,
        0x6e, 0x92, 0xdf, 0x6a, 0x98, 0x41, 0xe9, 0x10, 0xf2, 0xcc, 0xa8, 0x7a,
        0x50, 0xdb, 0x1f, 0x4c, 0x42, 0x19, 0xd5, 0xbc, 0x76, 0x20, 0x6f, 0x2f,
        0xbf, 0xc2, 0xc9, 0x1b, 0x02, 0xb5, 0xb1, 0x09, 0x46, 0x06, 0x87, 0x02,
        0xac, 0x3d, 0xcf, 0xc3, 0xa5, 0x1b, 0xf0, 0xce, 0xd4, 0x9e, 0x84, 0x34,
        0x3c, 0x24, 0x7d, 0x89, 0xf3, 0xbf, 0x9c, 0x18, 0x9d, 0x1b, 0x1d, 0xd4,
        0xf6, 0xda, 0xc9, 0xa4, 0x14, 0xc4, 0x6b, 0xd7, 0x05, 0x6d, 0xed, 0x54,
        0x42, 0x6b, 0x5f, 0x6d, 0x1e, 0xda, 0x6b, 0x47, 0x70, 0xe5, 0x4e, 0xe7,
        0x25, 0x06, 0xf8, 0x28, 0x24, 0x34, 0xd6, 0xe5, 0xbe, 0xc5, 0x4f, 0x9e,
        0x5d, 0x33, 0xfc, 0xef, 0xe4, 0xe9, 0x55, 0x67, 0x93, 0x1f, 0x2e, 0x11,
        0x3a, 0x2e, 0xf2, 0xbb, 0x82, 0x09, 0x8d, 0xb2, 0x09, 0xf3, 0x2f, 0xef,
        0x6f, 0x38, 0xc6, 0x56, 0xf2, 0x23, 0x08, 0x63, 0x99, 0x7f, 0x4e, 0xc0,
        0x9d, 0x08, 0x9d, 0xa1, 0x59, 0x6e, 0xe1, 0x00, 0x2c, 0x99, 0xec, 0x83,
        0x2f, 0x12, 0x97, 0x2f, 0x75, 0x04, 0x67, 0x44, 0xb5, 0x95, 0xce, 0xc6,
        0x3e, 0x7a, 0x10, 0x77, 0x5e, 0xbe, 0x9c, 0x0f, 0xb3, 0xc7, 0x38, 0xbf,
        0x9e, 0x35, 0x8f, 0xe4, 0x8d, 0x19, 0xc3, 0x41, 0xb1, 0x0b, 0x8c, 0x10,
        0x9a, 0x58, 0xec, 0x4f, 0xb3, 0xe9, 0x5b, 0x72, 0x4b, 0xb8, 0x99, 0x34,
        0x9a, 0xcd, 0xb0, 0x69, 0xd0, 0x67, 0xef, 0x96, 0xb9, 0xe5, 0x54, 0x92,
        0xb7, 0x1a, 0x52, 0xf6, 0x0a, 0xc2, 0x23, 0x8d, 0x4f, 0xad, 0x00, 0xae,
        0x0f, 0x97, 0xfa, 0xce, 0x96, 0xba, 0xe7, 0x74, 0x55, 0xd4, 0xaf, 0xbf,
        0xa1, 0x32, 0x91, 0x2d, 0x03, 0x9f, 0xe3, 0x10, 0x8c, 0x77, 0x5d, 0x26,
        0x76, 0xf1, 0x87, 0x90, 0xf0, 0x20, 0xd1, 0xea, 0xf7, 0xa4, 0xe8, 0x2c,
        0x32, 0x1c, 0x55, 0xc0, 0x5d, 0xc9, 0xcd, 0x4e, 0x8f, 0x0d, 0xef, 0x0a,
        0x27, 0xb6, 0x4f, 0xa4, 0xd3, 0xa4, 0xed, 0x33, 0x22, 0xa1, 0xd3, 0x15,
        0xac, 0x1a, 0x20, 0x4e, 0x28, 0x8c, 0x8c, 0xd0, 0x71, 0xd1, 0xf2, 0xdb,
        0x33, 0x63, 0xb6, 0xa4, 0xf2, 0x17, 0x3c, 0x12, 0xb0, 0xad, 0xef, 0x31,
        0x91, 0xfe, 0xe5, 0x53, 0x99, 0xb6, 0x85, 0x63, 0xfa, 0xe6, 0xcd, 0xf6,
        0xb9, 0xce, 0x4a, 0x7d, 0x4a, 0x49, 0x29, 0xd2, 0xd9, 0xc9, 0x47, 0x4a,
        0x8a, 0x5c, 0x14, 0x5e, 0x0f, 0x7c, 0xc3, 0x91, 0xb0, 0xab, 0x37, 0xf5,
        0x26, 0x8d, 0x46, 0x74, 0x49, 0xad, 0x51, 0xc3, 0x11, 0xfa, 0x85, 0x15,
        0xa5, 0x84, 0xc1, 0xe0, 0x3c, 0x13, 0x6d, 0x13, 0xa3, 0xe6, 0xa8, 0x3c,
        0x22, 0xac, 0x17, 0x48, 0x57, 0x7c, 0x81, 0xe2, 0x4e, 0xd8, 0x33, 0x5d,
        0x4d, 0x65, 0xf7, 0xe1, 0xb8, 0x00, 0x78, 0x09, 0x16, 0xb0, 0x0b, 0xca,
        0x15, 0x0d, 0xcd, 0x9a, 0xd8, 0x47, 0x4c, 0x9b, 0x69, 0xb2, 0xa0, 0x9d,
        0x96, 0x96, 0x52, 0x6d, 0x89, 0xad, 0xff, 0x55, 0xde, 0x7b, 0xd6, 0x3d,
        0x1d, 0x5e, 0x8d, 0xf1, 0xfc, 0x48, 0x1c, 0x50, 0x59, 0x55, 0xb9, 0x07,
        0xfd, 0x6b, 0xcb, 0x95, 0xa6, 0x14, 0x73, 0xdb, 0x40, 0x40, 0x1c, 0x44,
        0xe6, 0x79, 0x30, 0x88, 0xbd, 0xa0, 0xde, 0x9b, 0xb8, 0x76, 0xf8, 0x98,
        0x56, 0x4b, 0xb9, 0x7a, 0xf6, 0xd4, 0x73, 0x89, 0x6b, 0xf7, 0x7d, 0x05,
        0x33, 0xbe, 0xb6, 0x1c, 0x4d, 0xa7, 0x12, 0x3b, 0x3f, 0xed, 0x4a, 0x0f,
        0xae, 0xa7, 0x6a, 0x26, 0x0d, 0x01, 0x84, 0x84, 0xa8, 0x0e, 0xc1, 0xc1,
        0xfd, 0xe4, 0xa9, 0xe2, 0x3f, 0xab, 0xce, 0x20, 0x90, 0x86, 0x79, 0xa2,
        0x40, 0xd0, 0xef, 0x79, 0x34, 0x2b, 0xe8, 0xc9, 0x54, 0xa7, 0x19, 0x62,
        0xcc, 0x20, 0x79, 0x3f, 0x5b, 0x9c, 0x61, 0xc2, 0xc1, 0xd2, 0x36, 0x7c,
        0x8e, 0xe3, 0x01, 0xbe, 0xc4, 0xb2, 0xb8, 0x07, 0x51, 0x23, 0x5b, 0x5d,
        0x00, 0xe6, 0x7f, 0xd6, 0xbb, 0x32, 0xa9, 0x7e, 0xb4, 0x30, 0xeb, 0x5e,
        0x6d, 0xed, 0xb2, 0xc3, 0x88, 0x81, 0xa3, 0x3b, 0x1f, 0x1e, 0xf9, 0x48,
        0x10, 0xd6, 0x01, 0x65, 0x5f, 0x6d, 0xc5, 0xeb, 0x76, 0x5f, 0x10, 0x79,
        0xaa, 0xc0, 0x86, 0xe7, 0x44, 0x95, 0x44, 0x4b, 0x54, 0x0c, 0x46, 0x2a,
        0x98, 0x01, 0x6e, 0xc0, 0xb9, 0x59, 0x2a, 0xff, 0x8f, 0xb3, 0x80, 0x15,
        0xec, 0xcd, 0x39, 0x36, 0xd7, 0x2f, 0x20, 0x9e, 0x3a, 0xc1, 0x90, 0xe5,
        0x99, 0x27, 0x16, 0xd7, 0x6c, 0x30, 0x10, 0x12, 0x03, 0x3e, 0xdc, 0xb9,
        0x03, 0x25, 0xb0, 0x8a, 0x27, 0x4d, 0x1a, 0x32, 0x36, 0x54, 0xc0, 0xba,
        0x22, 0xb2, 0xe2, 0xf6, 0x39, 0x23, 0x03, 0xc4, 0xc9, 0xe4, 0x0d, 0x99,
        0xfb, 0x98, 0xa5, 0x9b, 0x12, 0x9b, 0x58, 0x44, 0x74, 0x9f, 0x65, 0x61,
        0x51, 0xba, 0x31, 0x60, 0x9c, 0xec, 0xf8, 0x4d, 0x36, 0x61, 0xd1, 0x33,
        0x6d, 0xa6, 0x28, 0x75, 0xba, 0x7c, 0x82, 0xcb, 0x7e, 0xbe, 0x8f, 0x2d,
        0x21, 0x84, 0xb9, 0xf2, 0x4e, 0x7b, 0x95, 0x99, 0x11, 0xf3, 0xe1, 0xc0,
        0x6a, 0x44, 0xae, 0x11, 0xcb, 0x04, 0xa0, 0xf2, 0x3e, 0x17, 0xdf, 0xb2,
        0x6a, 0xdf, 0x5c, 0xf3, 0x8a, 0xf8, 0x90, 0x86, 0x64, 0xea, 0x0a, 0x32,
        0x7f, 0x9f, 0x90, 0xa8, 0x9d, 0x33, 0x12, 0xa6, 0xa4, 0xe7, 0x74, 0xa0,
        0x75, 0xa9, 0x65, 0xf8, 0x39, 0xae, 0x14, 0x32, 0x79, 0xcc, 0xaa, 0x34,
        0x86, 0x55, 0xcc, 0x99, 0xb7, 0x00, 0x05, 0x8b, 0xe3, 0x76, 0x28, 0x12,
        0xb6, 0x2a, 0x3e, 0x44, 0x8d, 0xf4, 0xba, 0xef, 0xf6, 0xdc, 0x29, 0x08,
        0x29, 0x7d, 0xd1, 0x1d, 0x17, 0x15, 0xb6, 0xb6, 0x58, 0x67, 0xd5, 0xd3,
        0x12, 0x05, 0x4e, 0xb0, 0xc3, 0x83, 0xe0, 0x35, 0x30, 0x60, 0x59, 0xa0,
        0xc5, 0x97, 0x5b, 0x81, 0xd3, 0x68, 0x6c, 0x8c, 0x17, 0x28, 0xa9, 0x24,
        0x4f, 0x80, 0x20, 0xa5, 0x21, 0x9f, 0x8f, 0x15, 0x89, 0x2d, 0x87, 0xae,
        0x2e, 0xcc, 0x73, 0x3e, 0x06, 0x43, 0xbc, 0xb3, 0x1b, 0xa6, 0x72, 0xaa,
        0xa3, 0xaa, 0xbb, 0x6f, 0x2d, 0x68, 0x60, 0xcf, 0x05, 0x94, 0x25, 0x3e,
        0x59, 0xf3, 0x64, 0x61, 0x5e, 0x78, 0x9a, 0x7e, 0x0d, 0x50, 0x45, 0x78,
        0x51, 0xab, 0x11, 0xb1, 0xc6, 0x95, 0xfc, 0x29, 0x28, 0x10, 0x9c, 0x1a,
        0x8c, 0x37, 0xb5, 0x4f, 0x0e, 0xed, 0x4a, 0x28, 0x6c, 0xaa, 0xb7, 0x0d,
        0x12, 0xfa, 0x87, 0x5d, 0xd4, 0x9a, 0xb7, 0x2b, 0x46, 0x90, 0x58, 0x4e,
        0xd7, 0x8b, 0x41, 0x1b, 0xf8, 0xc4, 0xc2, 0xde, 0xda, 0xec, 0x61, 0xe7,
        0xbf, 0x11, 0xdd, 0x6e, 0x4e, 0x6a, 0xd4, 0x87, 0x01, 0xe4, 0xac, 0xe8,
        0xaf, 0x2b, 0x01, 0xe1, 0x09, 0x20, 0xe0, 0xbd, 0x7d, 0x03, 0x73, 0x23,
        0xdf, 0x77, 0x71, 0xa4, 0x25, 0x8b, 0x0a, 0x93, 0x49, 0x32, 0x45, 0x1a,
        0xa4, 0x94, 0x31, 0x61, 0x2e, 0x17, 0x39, 0x8a, 0x66, 0xc9, 0xf9, 0x20,
        0x2d, 0x6a, 0x97, 0x2f, 0xe7, 0x26, 0xd8, 0x01, 0x42, 0x65, 0xcf, 0xce,
        0xd4, 0x24, 0x41, 0xfb, 0x9b, 0x6f, 0xf1, 0xc2, 0x9e, 0xd5, 0x08, 0x0c,
        0xdc, 0x4d, 0x8e, 0xae, 0xcb, 0x5f, 0xd4, 0xcd, 0x7c, 0xf6, 0x82, 0xc6,
        0xee, 0xf9, 0x88, 0x3a, 0x34, 0x07, 0x04, 0xb4, 0x84, 0x69, 0xb3, 0xa4,
        0x67, 0xab, 0x09, 0xc0, 0x83, 0xfe, 0x59, 0xaf, 0x18, 0x2c, 0xc8, 0x09,
        0xc1, 0xbb, 0x13, 0x7c, 0xce, 0x01, 0x5d, 0x85, 0xaa, 0x10, 0x28, 0xa2,
        0x96, 0x98, 0x69, 0x23, 0xa3, 0xe7, 0x67, 0xbc, 0x7c, 0x7e, 0xde, 0x4b,
        0x36, 0xab, 0x94, 0xd2, 0xb8, 0xf9, 0xdf, 0xee, 0xa1, 0x69, 0xa1, 0xc8,
        0xe9, 0x83, 0x21, 0xac, 0x1b, 0x39, 0xf7, 0x6d, 0xbf, 0x8c, 0xdb, 0xd6,
        0x2f, 0xc9, 0x3c, 0x3d, 0x50, 0xcf, 0x7f, 0xbe, 0x4a, 0x8d, 0xd8, 0x14,
        0xad, 0x69, 0xb0, 0x3e, 0x8a, 0xaf, 0xeb, 0xd9, 0x1a, 0x15, 0x4a, 0xe4,
        0xdd, 0xd9, 0xb2, 0xf8, 0x6b, 0xe2, 0x42, 0x9e, 0x29, 0x16, 0xfc, 0x85,
        0x9c, 0x47, 0x4b, 0x1f, 0x3d, 0x7b, 0x8c, 0xe1, 0x6d, 0xa3, 0xb8, 0x0a,
        0xe6, 0xfa, 0x27, 0xfe, 0x52, 0x72, 0xab, 0x3a, 0xa6, 0x58, 0xd7, 0x53,
        0xaf, 0x9f, 0xee, 0x03, 0x85, 0xfc, 0xa4, 0x7a, 0x72, 0x29, 0x7e, 0x62,
        0x28, 0x08, 0x79, 0xa8, 0xb8, 0xc7, 0x51, 0x8d, 0xaa, 0x40, 0x2d, 0x4a,
        0xd9, 0x47, 0xb4, 0xa8, 0xa2, 0x0a, 0x43, 0xd0, 0xe0, 0x4a, 0x39, 0xa3,
        0x06, 0x08, 0x9a, 0xe2, 0xf3, 0xf2, 0xf8, 0xb9, 0x9f, 0x63, 0x32, 0xa0,
        0x65, 0x0b, 0xb0, 0x50, 0x96, 0xa6, 0xa8, 0x7a, 0x18, 0xdd, 0x6c, 0xd1,
        0x9b, 0xd9, 0x4e, 0x76, 0x8f, 0xfb, 0x22, 0xa6, 0x1d, 0x29, 0xfc, 0xb8,
        0x47, 0x29, 0xb6, 0xd1, 0xb1, 0x63, 0x4a, 0x36, 0x1b, 0x10, 0xe6, 0x4c,
        0x65, 0x68, 0x1f, 0xad, 0x4f, 0x7d, 0x6b, 0x01, 0x41, 0x18, 0x5f, 0xba,
        0x3d, 0xa6, 0x54, 0x28, 0x58, 0xd5, 0x81, 0x60, 0xdf, 0x84, 0x76, 0x00,
        0x21, 0x53, 0xeb, 0xd3, 0xa6, 0xec, 0x7d, 0x3c, 0xb8, 0xcd, 0x91, 0x4c,
        0x2f, 0x4b, 0x2e, 0x23, 0x4c, 0x0f, 0x0f, 0xe0, 0x14, 0xa5, 0xe7, 0xe5,
        0x70, 0x8d, 0x8b, 0x9c};
    const byte ml_dsa_44_sig[] = {
        0x27, 0x3b, 0x58, 0xa0, 0xcf, 0x00, 0x29, 0x5e, 0x1a, 0x63, 0xbf, 0xb4,
        0x97, 0x16, 0xa1, 0x9c, 0x78, 0xd1, 0x33, 0xdc, 0x72, 0xde, 0xa3, 0xfc,
        0xf4, 0x09, 0xb1, 0x09, 0x16, 0x3f, 0x80, 0x72, 0x22, 0x68, 0x65, 0x68,
        0xb9, 0x80, 0x5a, 0x4a, 0x0d, 0x73, 0x49, 0xe1, 0xc6, 0xde, 0xca, 0x08,
        0x4f, 0xca, 0xf8, 0xb2, 0xf8, 0x45, 0x3b, 0x6b, 0x8c, 0x6c, 0xfd, 0x3a,
        0xf4, 0xde, 0xde, 0x82, 0xd8, 0x04, 0xbe, 0x4f, 0x4a, 0xdb, 0x92, 0x47,
        0x83, 0x2d, 0xc4, 0x55, 0xed, 0x20, 0x4f, 0x71, 0xb1, 0x58, 0xd9, 0x70,
        0x73, 0xbd, 0xb0, 0x3a, 0xb4, 0x8f, 0xd6, 0x9e, 0x32, 0x98, 0x2b, 0x9e,
        0xff, 0x2a, 0x7c, 0xcb, 0x05, 0x1b, 0x8e, 0xe6, 0x3a, 0x45, 0xc6, 0x7a,
        0xc8, 0xaf, 0x62, 0xd3, 0x04, 0xfa, 0x69, 0x4f, 0xda, 0x1b, 0x74, 0x16,
        0x0d, 0xb3, 0x1a, 0xee, 0x71, 0xd7, 0xb0, 0xef, 0x69, 0xf5, 0xe2, 0xe9,
        0xc2, 0xcc, 0x15, 0x66, 0x28, 0x0a, 0xac, 0xe2, 0x63, 0x06, 0xb7, 0x21,
        0x0d, 0xd8, 0x5c, 0x94, 0x63, 0xfd, 0x51, 0x18, 0x9f, 0x07, 0x19, 0x3d,
        0xa2, 0x50, 0x40, 0xd3, 0xe9, 0x05, 0xd4, 0x11, 0x13, 0x15, 0xaa, 0x46,
        0xda, 0x3e, 0x5f, 0xcd, 0x3c, 0xfa, 0x42, 0xba, 0x79, 0x4a, 0xb7, 0x43,
        0x91, 0xa5, 0xcb, 0xbc, 0xeb, 0x37, 0x94, 0xf1, 0x9c, 0xb9, 0xdb, 0x41,
        0x06, 0xd8, 0x7b, 0x5e, 0x90, 0xe3, 0x3c, 0x8a, 0x10, 0x62, 0x9a, 0x15,
        0x27, 0x78, 0xed, 0x69, 0x11, 0x2c, 0xb5, 0xb4, 0xdb, 0xc8, 0x70, 0x50,
        0x62, 0x47, 0x96, 0xcb, 0xd9, 0xb2, 0x3e, 0x59, 0x2f, 0x1c, 0xac, 0xcb,
        0xcf, 0x22, 0xc2, 0x9b, 0xc7, 0x92, 0xe9, 0x4d, 0x8d, 0x5d, 0xcf, 0x06,
        0x53, 0x7e, 0xf4, 0x4e, 0xfe, 0x9e, 0x41, 0x5d, 0x00, 0x8c, 0x08, 0xf4,
        0x02, 0x79, 0x33, 0x1c, 0x27, 0x1d, 0xe3, 0x94, 0xac, 0xe6, 0x87, 0xa0,
        0x08, 0xb4, 0x60, 0x0c, 0xff, 0x47, 0xdc, 0x16, 0x3a, 0x1d, 0x89, 0xc0,
        0x6a, 0xa4, 0x3d, 0x71, 0x33, 0xdd, 0x1e, 0x70, 0xfe, 0xd4, 0x8b, 0xed,
        0x7c, 0x91, 0xe4, 0xe2, 0x15, 0x06, 0xc1, 0x83, 0x24, 0x55, 0xa7, 0x2a,
        0x9f, 0x4e, 0xd9, 0x56, 0x7a, 0x95, 0xa8, 0xdd, 0xc4, 0xf0, 0x71, 0x3a,
        0x99, 0x65, 0x31, 0x4b, 0xb7, 0x96, 0x2c, 0x53, 0x54, 0x83, 0xec, 0xc9,
        0x97, 0x2f, 0x0c, 0xa4, 0x8f, 0xbb, 0x93, 0x9d, 0xea, 0xae, 0xf9, 0xcb,
        0xb2, 0xb9, 0xa3, 0x61, 0x5f, 0x77, 0x8c, 0xb6, 0x5a, 0x56, 0xbe, 0x5f,
        0x85, 0xd1, 0xb5, 0x0a, 0x53, 0xe2, 0xc7, 0xbf, 0x76, 0x8b, 0x97, 0x6f,
        0x10, 0xdd, 0x1f, 0x44, 0x69, 0x66, 0x03, 0xc4, 0x6b, 0x59, 0xf7, 0xb4,
        0xc1, 0x12, 0xcc, 0x00, 0x70, 0xe8, 0xbd, 0x44, 0x28, 0xf5, 0xfa, 0x96,
        0xf3, 0x59, 0xed, 0x81, 0x67, 0xe0, 0xbe, 0x47, 0x75, 0xb3, 0xa8, 0x9f,
        0x21, 0x70, 0x2e, 0x6f, 0xef, 0x54, 0x11, 0x3f, 0x34, 0xaf, 0x0d, 0x73,
        0x5b, 0x9e, 0x6d, 0x86, 0x58, 0xb7, 0x34, 0xc2, 0xc2, 0xb3, 0x64, 0xd5,
        0x9b, 0x6e, 0xb9, 0x99, 0x6a, 0xe4, 0xfd, 0xc3, 0x17, 0xf3, 0x10, 0xfc,
        0x6e, 0xf5, 0x65, 0xe1, 0x9c, 0x59, 0x15, 0x11, 0x00, 0xea, 0x96, 0x81,
        0x69, 0x9b, 0x05, 0x4d, 0xf3, 0xce, 0xf3, 0xf0, 0xa9, 0x01, 0x3f, 0x13,
        0xbb, 0xb0, 0xac, 0xc3, 0x92, 0x1c, 0x2b, 0x61, 0xe3, 0x01, 0x22, 0x45,
        0x4a, 0x23, 0x19, 0x80, 0xca, 0xb9, 0xef, 0x4e, 0x76, 0x52, 0xc5, 0x9d,
        0x91, 0x33, 0x17, 0xc4, 0x28, 0x83, 0x55, 0x61, 0x49, 0x72, 0x04, 0xaa,
        0xf8, 0xe3, 0x4b, 0x20, 0xf7, 0x6a, 0x74, 0x56, 0x64, 0xf9, 0xb3, 0xc9,
        0x67, 0x5b, 0x55, 0x29, 0x9a, 0x89, 0xa5, 0x14, 0x67, 0xea, 0x6d, 0x6a,
        0xde, 0x98, 0x58, 0x73, 0x25, 0xa3, 0xdb, 0xed, 0x3d, 0x62, 0xaa, 0xe0,
        0x79, 0x7f, 0xa3, 0xd9, 0xb5, 0x4c, 0xe9, 0xa8, 0xdf, 0xfd, 0x59, 0x31,
        0x42, 0x81, 0x9e, 0xb7, 0x81, 0x3f, 0x0e, 0xfb, 0xef, 0x80, 0x71, 0x9d,
        0xb7, 0xa5, 0xfc, 0xb1, 0x80, 0xc9, 0x7e, 0x31, 0xd9, 0x47, 0xe2, 0xca,
        0x10, 0x7b, 0xd1, 0xa1, 0x1c, 0x28, 0xc7, 0x7f, 0x51, 0x26, 0xb1, 0x4e,
        0x57, 0xdd, 0x7d, 0x76, 0x5c, 0x5a, 0x85, 0xa7, 0x7b, 0x8c, 0xc5, 0x6e,
        0xac, 0x20, 0xf8, 0x49, 0x16, 0xd6, 0x64, 0xf5, 0xf4, 0x2c, 0x32, 0xa1,
        0x5d, 0xfb, 0x87, 0xb6, 0x14, 0xfe, 0x68, 0x7c, 0x4d, 0xce, 0xd7, 0x94,
        0xf9, 0x8b, 0xf0, 0x61, 0xfd, 0xe0, 0x83, 0x7f, 0x13, 0xec, 0x7a, 0xb7,
        0x41, 0x04, 0x51, 0x6e, 0x30, 0xa2, 0x01, 0xf7, 0x30, 0x12, 0xec, 0xd2,
        0x8f, 0x73, 0xe7, 0x8e, 0x12, 0xb4, 0xe5, 0xc1, 0xff, 0xdf, 0x67, 0x14,
        0xb1, 0xe9, 0xba, 0x36, 0x19, 0x18, 0xf4, 0xaa, 0xe0, 0xe4, 0x9d, 0xcd,
        0xe8, 0xe7, 0x2b, 0x33, 0xb3, 0xdc, 0xb9, 0x19, 0xd7, 0xad, 0xa4, 0x68,
        0xcd, 0x83, 0x77, 0x98, 0x36, 0x49, 0xd9, 0x32, 0x20, 0xfd, 0xfc, 0x34,
        0xe7, 0x54, 0xd9, 0xb5, 0x05, 0xab, 0x0e, 0x08, 0x0e, 0x16, 0x8a, 0x7d,
        0x91, 0x4c, 0xaa, 0x19, 0x04, 0x37, 0x35, 0xa5, 0xab, 0x6c, 0xee, 0xc4,
        0x90, 0xf0, 0x5f, 0xc7, 0xae, 0x82, 0xfd, 0x59, 0x53, 0xe5, 0x36, 0x5a,
        0x56, 0x37, 0x61, 0x69, 0xda, 0xe5, 0x8f, 0xfd, 0x2e, 0xd4, 0x9c, 0x7f,
        0xb6, 0x39, 0xa4, 0x8d, 0x0a, 0xab, 0x82, 0x0f, 0xfe, 0x84, 0x69, 0x44,
        0x8a, 0xa6, 0xd0, 0x39, 0xf9, 0x72, 0x68, 0xe7, 0x97, 0xd8, 0x6c, 0x7b,
        0xec, 0x85, 0x8c, 0x52, 0xc9, 0x97, 0xbb, 0xc4, 0x7a, 0x67, 0x22, 0x60,
        0x46, 0x9f, 0x16, 0xf1, 0x67, 0x0e, 0x1b, 0x50, 0x7c, 0xc4, 0x29, 0x15,
        0xbc, 0x55, 0x6a, 0x67, 0xf6, 0xa8, 0x85, 0x66, 0x89, 0x9f, 0xff, 0x38,
        0x28, 0xaa, 0x87, 0x91, 0xce, 0xde, 0x8d, 0x45, 0x5c, 0xa1, 0x25, 0x95,
        0xe2, 0x86, 0xdd, 0xa1, 0x87, 0x6a, 0x0a, 0xa8, 0x3e, 0x63, 0x0e, 0x21,
        0xa5, 0x6e, 0x08, 0x4d, 0x07, 0xb6, 0x26, 0xa8, 0x92, 0xdb, 0xed, 0x13,
        0x01, 0xc3, 0xba, 0xcf, 0xad, 0x01, 0xbc, 0xe5, 0xc0, 0xba, 0xbe, 0x7c,
        0x75, 0xf1, 0xb9, 0xfe, 0xd3, 0xf0, 0xa5, 0x2c, 0x8e, 0x10, 0xff, 0x99,
        0xcb, 0xe2, 0x2d, 0xdc, 0x2f, 0x76, 0x00, 0xf8, 0x51, 0x7c, 0xcc, 0x52,
        0x16, 0x0f, 0x18, 0x98, 0xea, 0x34, 0x06, 0x7f, 0xb7, 0x2e, 0xe9, 0x40,
        0xf0, 0x2d, 0x30, 0x3d, 0xc0, 0x67, 0x4c, 0xe6, 0x63, 0x40, 0x41, 0x42,
        0x96, 0xbb, 0x0b, 0xd6, 0xc9, 0x1c, 0x22, 0x7a, 0xa9, 0x4d, 0xcc, 0x5b,
        0xaa, 0x03, 0xc6, 0x3b, 0x1e, 0x2f, 0x11, 0xae, 0x34, 0x6f, 0x0c, 0xe9,
        0x16, 0x9c, 0x82, 0x3b, 0x90, 0x4c, 0x0e, 0xf0, 0xf9, 0x7f, 0x02, 0xca,
        0xb9, 0xa9, 0x49, 0x6d, 0x27, 0x73, 0xd0, 0xbf, 0x15, 0x61, 0x52, 0xbc,
        0xd6, 0x31, 0x59, 0x2b, 0x52, 0x5b, 0xaf, 0x3c, 0xc0, 0x8f, 0xdc, 0xd5,
        0x2c, 0x1d, 0xe4, 0xe9, 0x41, 0xe8, 0xd3, 0x35, 0xd6, 0xb1, 0xf3, 0x32,
        0xe0, 0x52, 0x08, 0x73, 0x99, 0xb6, 0x6b, 0xbc, 0x26, 0xfb, 0x2e, 0xa7,
        0xb7, 0xcd, 0x14, 0xf0, 0xf9, 0xe5, 0x3a, 0xd0, 0x05, 0x5b, 0x2b, 0x38,
        0xbd, 0x7c, 0xda, 0xd4, 0x15, 0x45, 0xfa, 0x3b, 0x6f, 0x94, 0x8e, 0x22,
        0xce, 0xfa, 0x53, 0xe0, 0x5f, 0xa6, 0x9d, 0x1c, 0x26, 0x91, 0x8a, 0xab,
        0x72, 0x5b, 0x18, 0x78, 0x69, 0x98, 0x3f, 0x8d, 0x33, 0x7c, 0x21, 0x93,
        0x9e, 0xf0, 0xaf, 0xb7, 0x30, 0xc8, 0xac, 0xbc, 0xdb, 0x9c, 0x29, 0x17,
        0x6b, 0x9d, 0x0f, 0x16, 0xd6, 0xc0, 0xcc, 0x3b, 0xce, 0x11, 0xe9, 0x64,
        0xc8, 0xd4, 0x4c, 0x98, 0x7c, 0x8f, 0xf1, 0x5e, 0x84, 0xe4, 0x72, 0xf9,
        0x69, 0xf5, 0x9d, 0xad, 0x95, 0x3b, 0xfb, 0x6d, 0x30, 0x7e, 0x0a, 0x47,
        0x5b, 0x26, 0xb2, 0x4e, 0xeb, 0x1a, 0xc3, 0x37, 0x16, 0x28, 0x79, 0x62,
        0xb4, 0x36, 0x85, 0x4a, 0x15, 0x5a, 0xc3, 0x6e, 0xbe, 0x7e, 0x00, 0xe9,
        0x4a, 0xa5, 0xd7, 0x90, 0xcf, 0x59, 0x63, 0x2d, 0x2b, 0xc2, 0xc6, 0x47,
        0xe6, 0x77, 0xb7, 0x6e, 0x9b, 0xc8, 0x0d, 0x18, 0x2b, 0x45, 0x2b, 0xc9,
        0x5a, 0x6e, 0xb4, 0x50, 0xa5, 0x23, 0x7d, 0x17, 0xcc, 0x49, 0xe2, 0xb3,
        0xf4, 0x6d, 0xb4, 0xb7, 0xbb, 0x9e, 0xdd, 0x20, 0x99, 0x19, 0xf5, 0x53,
        0x1f, 0xd0, 0xff, 0x67, 0xf3, 0x8e, 0x6a, 0xcd, 0x2a, 0x6e, 0x2b, 0x0a,
        0x90, 0xd7, 0xdb, 0xe1, 0xff, 0x1c, 0x40, 0xa1, 0xb0, 0x5d, 0x94, 0x4d,
        0x20, 0x14, 0x01, 0xa1, 0xa8, 0xd1, 0x15, 0xd2, 0xd9, 0x1b, 0xbf, 0xc2,
        0x8a, 0xd0, 0x02, 0xf6, 0x16, 0xa1, 0xb7, 0x40, 0xe0, 0x36, 0x88, 0xc8,
        0x17, 0x0a, 0xf0, 0xb6, 0x0d, 0x3c, 0x53, 0xb9, 0x51, 0xed, 0xef, 0x20,
        0x6f, 0xf3, 0x0c, 0xb5, 0xce, 0x0e, 0x9e, 0xfd, 0x0f, 0x5e, 0x3f, 0x8f,
        0x3c, 0xb7, 0x2a, 0xdb, 0xc6, 0xa7, 0xf2, 0x11, 0x6e, 0xdc, 0x05, 0x33,
        0xd4, 0xd8, 0xb0, 0x2d, 0x8a, 0xe5, 0x39, 0x82, 0x00, 0x49, 0x7d, 0xfd,
        0x32, 0x29, 0xbb, 0x79, 0x5d, 0xcb, 0x21, 0x7b, 0x2d, 0x36, 0x58, 0x73,
        0x52, 0x57, 0x52, 0x96, 0x4d, 0x89, 0x61, 0xf4, 0xad, 0x1f, 0x48, 0xd5,
        0x7a, 0x4a, 0xaa, 0x1c, 0xa1, 0xf4, 0xb4, 0x9c, 0x43, 0x3b, 0x95, 0x72,
        0xd0, 0x0e, 0x35, 0x82, 0x26, 0xd4, 0x2e, 0xe3, 0x83, 0x96, 0x97, 0x5a,
        0x7b, 0xfc, 0x48, 0x17, 0x3c, 0xba, 0x9e, 0x5f, 0x46, 0x1a, 0x53, 0xe3,
        0x2e, 0x78, 0x79, 0x80, 0xf6, 0x2d, 0x24, 0xcf, 0x62, 0xb6, 0x86, 0xeb,
        0xee, 0xec, 0xf2, 0x1d, 0x00, 0xc8, 0x28, 0x9d, 0x93, 0x16, 0xa7, 0xd9,
        0x11, 0x47, 0xe3, 0xc4, 0xb6, 0xc4, 0xa0, 0x99, 0x83, 0xc1, 0x17, 0xd8,
        0x8e, 0xde, 0x69, 0x1d, 0xcb, 0xdd, 0xe7, 0x86, 0x6f, 0xf2, 0x36, 0x07,
        0x23, 0x86, 0x0d, 0xe9, 0xad, 0x87, 0xae, 0x76, 0x98, 0x95, 0x51, 0xf2,
        0xb3, 0x11, 0xc5, 0x34, 0xf0, 0x0c, 0xf8, 0x29, 0x9c, 0x84, 0x4f, 0x81,
        0x49, 0x85, 0x63, 0x25, 0x16, 0xb0, 0xc3, 0xaa, 0xd7, 0x8a, 0x2e, 0x4b,
        0x97, 0x60, 0x74, 0xf8, 0xa7, 0x39, 0xec, 0x6c, 0x2c, 0x9b, 0x33, 0x3a,
        0x11, 0xbd, 0xa6, 0x90, 0x48, 0x65, 0xb1, 0xe7, 0x38, 0x53, 0x47, 0x1b,
        0x62, 0xd5, 0xb7, 0xa8, 0xd4, 0xae, 0xf5, 0x12, 0x06, 0x12, 0x54, 0xa2,
        0xce, 0xf1, 0x6b, 0x3a, 0xda, 0x63, 0x2e, 0x37, 0x2a, 0x25, 0x89, 0x30,
        0x98, 0x77, 0x1d, 0x4b, 0x5a, 0x1e, 0xb7, 0x3d, 0xed, 0x19, 0xec, 0x9f,
        0x64, 0x46, 0xa8, 0x2a, 0x79, 0xf3, 0x70, 0x39, 0x9f, 0x8c, 0xc3, 0x28,
        0xcc, 0x2a, 0xc0, 0xd0, 0xe6, 0x80, 0xf5, 0x01, 0x78, 0x72, 0x7f, 0xe7,
        0x2e, 0x7b, 0x5f, 0x05, 0xc3, 0x41, 0x33, 0x07, 0xdb, 0x9c, 0xa8, 0x96,
        0xa7, 0x21, 0x20, 0x23, 0xd0, 0x59, 0x39, 0x06, 0x19, 0xa4, 0x29, 0xe5,
        0x72, 0x39, 0x69, 0x23, 0xe3, 0xfa, 0x28, 0x63, 0xf5, 0x42, 0x3b, 0xca,
        0x88, 0x5d, 0x7e, 0x47, 0x93, 0xa8, 0x8c, 0x75, 0xf2, 0x19, 0x44, 0x43,
        0x15, 0x39, 0x03, 0x42, 0xd8, 0x1d, 0x81, 0x30, 0x8e, 0x84, 0x31, 0x24,
        0x75, 0x67, 0x4e, 0xbe, 0xfe, 0x0a, 0xd8, 0xc3, 0xe7, 0x5b, 0xe1, 0xd5,
        0x12, 0x6a, 0x69, 0x99, 0xcd, 0x35, 0xca, 0x22, 0x02, 0x65, 0xb3, 0x0f,
        0x50, 0xb6, 0xaa, 0xc6, 0x91, 0x5c, 0x4d, 0xd4, 0x07, 0x93, 0x46, 0xf0,
        0xcc, 0xe1, 0x92, 0x14, 0x91, 0x21, 0x43, 0xc4, 0xba, 0x45, 0x1c, 0x47,
        0x29, 0xdf, 0xff, 0x89, 0x60, 0xee, 0x89, 0x1e, 0xc3, 0xb4, 0xb9, 0x0b,
        0xc9, 0x7e, 0xd9, 0x15, 0xb0, 0x80, 0x91, 0xbe, 0xb9, 0x43, 0x48, 0x12,
        0x86, 0x8e, 0x79, 0x38, 0x4d, 0xce, 0x36, 0x7f, 0xc3, 0xe8, 0xb7, 0xb9,
        0x92, 0xbf, 0x27, 0x20, 0x54, 0xc8, 0x05, 0x63, 0x3b, 0xf5, 0x48, 0x1a,
        0xa9, 0x04, 0x6c, 0xb6, 0x0e, 0x11, 0xea, 0xf3, 0x59, 0xb9, 0xa6, 0xf6,
        0xf8, 0x0b, 0x15, 0xed, 0x30, 0xf9, 0xe4, 0xe5, 0x26, 0x2d, 0xbb, 0xc6,
        0x5b, 0x36, 0xbb, 0x73, 0xa6, 0x4f, 0xf5, 0x43, 0x9f, 0xd7, 0xb9, 0x0f,
        0xbc, 0x4f, 0x8d, 0xb8, 0xec, 0x1d, 0x42, 0x19, 0x56, 0x37, 0xc4, 0xcb,
        0xd0, 0x16, 0x85, 0xff, 0xd3, 0x9b, 0xef, 0xc8, 0x75, 0x37, 0xd1, 0x92,
        0xad, 0x21, 0x94, 0x1e, 0x9a, 0xf6, 0x2f, 0x6d, 0x30, 0xba, 0x37, 0xc3,
        0xdc, 0x11, 0xe0, 0x79, 0xa4, 0x92, 0x1f, 0xe4, 0xaa, 0x7a, 0x6b, 0x2a,
        0xe4, 0x04, 0xb7, 0xf9, 0x86, 0x95, 0xdb, 0xa8, 0xfc, 0x8a, 0x53, 0x21,
        0x31, 0x14, 0xf7, 0x40, 0x01, 0x78, 0x4e, 0x73, 0x18, 0xb3, 0x54, 0xd7,
        0xa6, 0x93, 0xf0, 0x70, 0x04, 0x1c, 0xe0, 0x2b, 0xef, 0xee, 0xd4, 0x64,
        0xa7, 0xd9, 0x9f, 0x81, 0x4f, 0xe5, 0x1e, 0xbe, 0x6e, 0xd2, 0xf6, 0x3a,
        0xba, 0xcf, 0x8c, 0x96, 0x2a, 0x3d, 0xf7, 0xe5, 0x5c, 0x59, 0x40, 0x9c,
        0xe3, 0xf9, 0x2b, 0x6d, 0x3d, 0xf2, 0x6f, 0x81, 0xd6, 0xab, 0x9c, 0xab,
        0xc6, 0xf7, 0x8f, 0xaa, 0xe5, 0x71, 0xe3, 0xc9, 0x8c, 0x1a, 0xeb, 0xc5,
        0x87, 0xe7, 0xb0, 0xde, 0x18, 0xba, 0xaa, 0x1e, 0xda, 0x12, 0x32, 0x16,
        0x94, 0x3a, 0x6e, 0x4f, 0x84, 0x06, 0x8e, 0x33, 0xf7, 0xfa, 0x35, 0xb8,
        0x45, 0xe4, 0x5e, 0x9e, 0x46, 0x05, 0x7a, 0xf7, 0xf4, 0x99, 0xad, 0xb9,
        0xdd, 0x55, 0xd9, 0x52, 0x3b, 0x93, 0xe3, 0x9b, 0x54, 0x1b, 0xe6, 0xa9,
        0x70, 0xd3, 0x48, 0xf9, 0x3d, 0xdb, 0x88, 0x63, 0x66, 0xa0, 0xab, 0x72,
        0x83, 0x6e, 0x8f, 0x78, 0x9d, 0x55, 0x46, 0x21, 0xca, 0x7c, 0xb7, 0x5d,
        0x16, 0xe8, 0x66, 0x3b, 0x7b, 0xaa, 0xfe, 0x9c, 0x9c, 0x33, 0xc9, 0xc2,
        0xa4, 0x3c, 0x78, 0x97, 0xf3, 0x5b, 0xc2, 0x29, 0x36, 0x98, 0x68, 0x28,
        0xfe, 0x0a, 0xae, 0x6f, 0xe5, 0xf7, 0xfb, 0x9d, 0xf8, 0x8c, 0xd9, 0xd0,
        0x4d, 0xfe, 0xc7, 0xd0, 0xb0, 0xe3, 0x9c, 0xdb, 0xac, 0x9e, 0x1b, 0x55,
        0x7e, 0x24, 0xfe, 0xc4, 0x12, 0xcb, 0xc2, 0xdd, 0x0a, 0xda, 0x31, 0x40,
        0x41, 0xb7, 0xfc, 0x3f, 0x6d, 0xe2, 0xd3, 0x8a, 0x0f, 0x21, 0x33, 0x3a,
        0xbc, 0xa7, 0x62, 0x18, 0xb3, 0xaf, 0x48, 0xc6, 0xe2, 0xa3, 0xdd, 0x1d,
        0x20, 0x62, 0xe4, 0x4b, 0x81, 0x6b, 0x3a, 0xc5, 0xb1, 0x07, 0xe1, 0xf1,
        0xe1, 0xba, 0xf6, 0x01, 0xc6, 0xf2, 0xea, 0xc0, 0x97, 0x73, 0x79, 0x19,
        0x06, 0xaa, 0x62, 0x42, 0xcb, 0x21, 0x5f, 0x08, 0x97, 0x7d, 0x72, 0xb5,
        0x39, 0x4d, 0x99, 0xe3, 0xa2, 0x3f, 0xb9, 0xb4, 0xed, 0xf4, 0x61, 0x35,
        0xe1, 0x50, 0xfb, 0x56, 0x7c, 0x35, 0xfd, 0x44, 0x8a, 0x57, 0x22, 0xed,
        0x30, 0x33, 0xc3, 0x0b, 0xf1, 0x88, 0xe4, 0x44, 0x46, 0xf5, 0x73, 0x6d,
        0x9b, 0x98, 0x88, 0x92, 0xf5, 0x34, 0x85, 0x18, 0x66, 0xef, 0x70, 0xbe,
        0x7b, 0xc1, 0x0f, 0x1c, 0x78, 0x2d, 0x42, 0x13, 0x2d, 0x2f, 0x4d, 0x40,
        0x8e, 0xe2, 0x6f, 0xe0, 0x04, 0xdb, 0x58, 0xbc, 0x65, 0x80, 0xba, 0xfc,
        0x89, 0xee, 0xf3, 0x78, 0xb2, 0xd9, 0x78, 0x93, 0x6d, 0xbf, 0xd4, 0x74,
        0x24, 0xf4, 0x5c, 0x37, 0x89, 0x0c, 0x14, 0xd5, 0xbd, 0xc5, 0xfc, 0x37,
        0xe8, 0x8b, 0xe0, 0xc5, 0x89, 0xc9, 0x70, 0xb3, 0x76, 0x46, 0xce, 0x0d,
        0x7c, 0x3d, 0xa4, 0x5d, 0x02, 0x95, 0x03, 0xba, 0x24, 0xaa, 0xf7, 0xd0,
        0x75, 0x35, 0x78, 0x27, 0x9c, 0x6d, 0x2a, 0xef, 0xaa, 0xac, 0x85, 0xef,
        0x8d, 0xfc, 0xc0, 0xfc, 0x72, 0x02, 0xf4, 0xa3, 0xd3, 0x87, 0xfc, 0x4d,
        0xce, 0x3d, 0xcb, 0xc2, 0x74, 0x5b, 0xb0, 0x83, 0xc5, 0x72, 0x72, 0xd6,
        0xa1, 0x67, 0x4d, 0xa1, 0xd6, 0xaa, 0xe7, 0x9b, 0xe7, 0xc0, 0xfd, 0x86,
        0x91, 0x08, 0xfa, 0x48, 0x2f, 0x50, 0xce, 0x17, 0xea, 0x1c, 0xe3, 0x90,
        0x35, 0xe6, 0x6c, 0xc9, 0x66, 0x7d, 0x51, 0x32, 0x20, 0x0c, 0x2d, 0x4b,
        0xa1, 0xbf, 0x78, 0x87, 0xe1, 0x5a, 0x28, 0x0e, 0x9a, 0x85, 0xf6, 0x7e,
        0x39, 0x60, 0xbc, 0x64, 0x42, 0x5d, 0xf0, 0x0a, 0xd7, 0x3e, 0xbb, 0xa0,
        0x6d, 0x7c, 0xfa, 0x75, 0xee, 0x34, 0x39, 0x23, 0x0e, 0xbd, 0x50, 0x19,
        0x7a, 0x2a, 0xb7, 0x17, 0x3a, 0x8b, 0xb7, 0xb6, 0xf4, 0xd8, 0x47, 0x71,
        0x6b, 0x21, 0x1b, 0x56, 0xcc, 0xfb, 0x7b, 0x81, 0x99, 0x46, 0x88, 0x23,
        0x40, 0x49, 0x66, 0x8b, 0xac, 0x84, 0x16, 0x8a, 0x86, 0xae, 0x38, 0xc4,
        0x5b, 0x1f, 0x2b, 0xfa, 0xf2, 0x8b, 0x81, 0xc1, 0x22, 0x61, 0x61, 0x6c,
        0x43, 0x16, 0x8c, 0x1d, 0x37, 0xb2, 0xaf, 0x3c, 0x3a, 0x90, 0x33, 0xed,
        0xf5, 0x08, 0x78, 0xfd, 0x5a, 0xde, 0xd3, 0x38, 0x6d, 0xd7, 0x1c, 0x23,
        0xeb, 0xb4, 0x9b, 0x8e, 0xc2, 0x48, 0x47, 0x8e, 0x84, 0xbb, 0xc4, 0xd0,
        0xcc, 0xf9, 0x55, 0x5a, 0x57, 0xb9, 0x99, 0x52, 0x82, 0x21, 0x3b, 0x83,
        0xda, 0x8f, 0xa3, 0x88, 0x9c, 0x57, 0xe0, 0x4b, 0xc1, 0xce, 0xbe, 0xd3,
        0xea, 0xdd, 0xf2, 0x07, 0xc1, 0x73, 0x6f, 0xc0, 0x5e, 0x8e, 0x85, 0x72,
        0xab, 0x2f, 0xa9, 0xac, 0x39, 0xee, 0x05, 0x34, 0x13, 0x16, 0x1b, 0x1c,
        0x21, 0x24, 0x41, 0x49, 0x78, 0x87, 0x8b, 0x97, 0x9c, 0x9f, 0xa3, 0xa8,
        0xb9, 0xbc, 0xc6, 0xcc, 0xf2, 0xfd, 0x18, 0x2a, 0x46, 0x58, 0x5a, 0x88,
        0xa2, 0xb5, 0xcc, 0xd2, 0xda, 0xe1, 0xe3, 0x0d, 0x20, 0x23, 0x2b, 0x2f,
        0x47, 0x57, 0x5e, 0x64, 0x87, 0x97, 0x9c, 0xa7, 0xaa, 0xbc, 0xc1, 0xe4,
        0xe5, 0xea, 0x0b, 0x16, 0x3b, 0x3c, 0x3e, 0x45, 0x58, 0x63, 0x6a, 0x6f,
        0x7c, 0x8c, 0x8d, 0x92, 0x99, 0x9c, 0xad, 0xb5, 0xb7, 0xce, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x16, 0x23, 0x36, 0x4a};
    static byte test_msg[512] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
        0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
        0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
        0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3,
        0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
        0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
        0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
        0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3,
        0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
        0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
        0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb,
        0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

    int         ret;
    wc_MlDsaKey key[1];
    whNvmId     keyId    = WH_KEYID_ERASED;
    int         evictKey = 0;

    /* Initialize keys */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML-DSA key: %d\n", ret);
        return ret;
    }
    else {
        ret = wc_MlDsaKey_SetParams(key, WC_ML_DSA_44);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to set ML-DSA level: %d\n", ret);
        }
    }

    /* make dummy msg */
    int i = 0;
    for (i = 0; i < (int)sizeof(test_msg); i++) {
        test_msg[i] = (byte)i;
    }

    /* Import the raw public key into the wolfCrypt structure */
    if (ret == 0) {
        ret = wc_MlDsaKey_ImportPubRaw(key, ml_dsa_44_pub_key,
                                       sizeof(ml_dsa_44_pub_key));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import ML-DSA public key: %d\n", ret);
        }
    }
    /* Import the key into wolfHSM via the wolfCrypt structure. This is the
     * DMA-only verify test, so always import via the DMA path. The key must
     * carry the verify usage flag, which the DMA verify handler enforces. */
    if (ret == 0) {
        ret = wh_Client_MlDsaImportKeyDma(ctx, key, &keyId,
                                          WH_NVM_FLAGS_USAGE_VERIFY, 0, NULL);
        if (ret == WH_ERROR_OK) {
            evictKey = 1;
        }
        else {
            WH_ERROR_PRINT("Failed to import ML-DSA key: %d\n", ret);
        }
    }

    /* Cache the key using DMA and set the key ID */
    if (ret == 0) {
        ret = wh_Client_MlDsaSetKeyId(key, keyId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to set key ID: %d\n", ret);
        }
    }

    /* Verify the message signature */
    if (ret == 0) {
        int verifyResult;
        ret = wc_MlDsaKey_VerifyCtx(key, ml_dsa_44_sig, sizeof(ml_dsa_44_sig),
                                    NULL, 0, test_msg, sizeof(test_msg),
                                    &verifyResult);
        if (ret != 0) {
            WH_ERROR_PRINT("Signature did not verify\n");
        }
    }

    if (evictKey) {
        if (WH_ERROR_OK != wh_Client_KeyEvict(ctx, keyId)) {
            WH_ERROR_PRINT("Failed to evict key\n");
        }
    }
    wc_MlDsaKey_Free(key);

    if (ret == WH_ERROR_OK) {
        WH_TEST_PRINT("ML-DSA VERIFY ONLY: SUCCESS\n");
    }

    return ret;
}
#endif /* !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) && \
          defined(WOLFHSM_CFG_DMA) */


#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM
#if !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) &&    \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
static int whTestCrypto_MlKemGetLevels(int* levels, int maxLevels)
{
    int count = 0;

#ifndef WOLFSSL_NO_ML_KEM_512
    if (count < maxLevels) {
        levels[count++] = WC_ML_KEM_512;
    }
#endif
#ifndef WOLFSSL_NO_ML_KEM_768
    if (count < maxLevels) {
        levels[count++] = WC_ML_KEM_768;
    }
#endif
#ifndef WOLFSSL_NO_ML_KEM_1024
    if (count < maxLevels) {
        levels[count++] = WC_ML_KEM_1024;
    }
#endif

    return count;
}

static int whTestCrypto_MlKemWolfCrypt(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int    ret      = 0;
    int    levels[3];
    int    levelCnt = 0;
    int    i;
    byte   ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte   ssEnc[WC_ML_KEM_SS_SZ];
    byte   ssDec[WC_ML_KEM_SS_SZ];
    word32 ctLen;
    word32 ssEncLen;
    word32 ssDecLen;

    (void)ctx;

    levelCnt =
        whTestCrypto_MlKemGetLevels(levels, (int)(sizeof(levels) / sizeof(levels[0])));

    for (i = 0; (ret == 0) && (i < levelCnt); i++) {
        MlKemKey key[1];
        int      keyInited = 0;

        ctLen    = sizeof(ct);
        ssEncLen = sizeof(ssEnc);
        ssDecLen = sizeof(ssDec);
        memset(ct, 0, sizeof(ct));
        memset(ssEnc, 0, sizeof(ssEnc));
        memset(ssDec, 0, sizeof(ssDec));

        ret = wc_MlKemKey_Init(key, levels[i], NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to init ML-KEM key level=%d ret=%d\n",
                           levels[i], ret);
            break;
        }
        keyInited = 1;

        ret = wc_MlKemKey_MakeKey(key, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to make ML-KEM key level=%d ret=%d\n",
                           levels[i], ret);
        }
        if (ret == 0) {
            ret = wc_MlKemKey_CipherTextSize(key, &ctLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to get ML-KEM ct size level=%d ret=%d\n",
                               levels[i], ret);
            }
        }
        if (ret == 0) {
            ret = wc_MlKemKey_SharedSecretSize(key, &ssEncLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to get ML-KEM ss size level=%d ret=%d\n",
                               levels[i], ret);
            }
            else {
                ssDecLen = ssEncLen;
            }
        }
        if (ret == 0) {
            ret = wc_MlKemKey_Encapsulate(key, ct, ssEnc, rng);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM encapsulate level=%d ret=%d\n",
                               levels[i], ret);
            }
        }
        if (ret == 0) {
            ret = wc_MlKemKey_Decapsulate(key, ssDec, ct, ctLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM decapsulate level=%d ret=%d\n",
                               levels[i], ret);
            }
            else if ((ssEncLen != ssDecLen) ||
                     (memcmp(ssEnc, ssDec, ssEncLen) != 0)) {
                WH_ERROR_PRINT("ML-KEM shared secret mismatch level=%d\n",
                               levels[i]);
                ret = -1;
            }
        }

        if (keyInited) {
            wc_MlKemKey_Free(key);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-KEM DEVID=0x%X SUCCESS\n", devId);
    }

    return ret;
}

static int whTestCrypto_MlKemClient(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int    ret      = 0;
    int    levels[3];
    int    levelCnt = 0;
    int    i;
    byte   ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte   ssEnc[WC_ML_KEM_SS_SZ];
    byte   ssDec[WC_ML_KEM_SS_SZ];
    byte   ssWrong[WC_ML_KEM_SS_SZ];
    byte   usageCt[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte   usageSs[WC_ML_KEM_SS_SZ];
    word32 ctLen;
    word32 ssEncLen;
    word32 ssDecLen;
    word32 ssWrongLen;
    word32 usageCtLen;
    word32 usageSsLen;
    const uint8_t usageLabel[] = "mlkem-no-derive";

    (void)rng;

    levelCnt =
        whTestCrypto_MlKemGetLevels(levels, (int)(sizeof(levels) / sizeof(levels[0])));

    for (i = 0; (ret == 0) && (i < levelCnt); i++) {
        MlKemKey key[1];
        MlKemKey wrongKey[1];
        MlKemKey usageKey[1];
        int      keyInited      = 0;
        int      wrongInited    = 0;
        int      usageInited    = 0;
        whKeyId  usageKeyId     = WH_KEYID_ERASED;
        int      usageKeyCached = 0;

        ctLen      = sizeof(ct);
        ssEncLen   = sizeof(ssEnc);
        ssDecLen   = sizeof(ssDec);
        ssWrongLen = sizeof(ssWrong);
        usageCtLen = sizeof(usageCt);
        usageSsLen = sizeof(usageSs);
        memset(ct, 0, sizeof(ct));
        memset(ssEnc, 0, sizeof(ssEnc));
        memset(ssDec, 0, sizeof(ssDec));
        memset(ssWrong, 0, sizeof(ssWrong));
        memset(usageCt, 0, sizeof(usageCt));
        memset(usageSs, 0, sizeof(usageSs));

        ret = wc_MlKemKey_Init(key, levels[i], NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to init ML-KEM client key level=%d ret=%d\n",
                           levels[i], ret);
            break;
        }
        keyInited = 1;

        ret = wc_MlKemKey_Init(wrongKey, levels[i], NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to init ML-KEM wrong key level=%d ret=%d\n",
                levels[i], ret);
        }
        else {
            wrongInited = 1;
        }

        if (ret == 0) {
            ret = wh_Client_MlKemMakeExportKey(ctx, levels[i], key);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed ML-KEM make export key level=%d ret=%d\n",
                    levels[i], ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemMakeExportKey(ctx, levels[i], wrongKey);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed ML-KEM make wrong export key level=%d ret=%d\n",
                    levels[i], ret);
            }
        }

        if (ret == 0) {
            ret = wh_Client_MlKemEncapsulate(ctx, key, ct, &ctLen, ssEnc,
                                             &ssEncLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM encapsulate level=%d ret=%d\n",
                               levels[i], ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemDecapsulate(ctx, key, ct, ctLen, ssDec,
                                             &ssDecLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM decapsulate level=%d ret=%d\n",
                               levels[i], ret);
            }
            else if ((ssEncLen != ssDecLen) ||
                     (memcmp(ssEnc, ssDec, ssEncLen) != 0)) {
                WH_ERROR_PRINT("ML-KEM client shared secret mismatch level=%d\n",
                               levels[i]);
                ret = -1;
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemDecapsulate(ctx, wrongKey, ct, ctLen, ssWrong,
                                             &ssWrongLen);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed ML-KEM wrong-key decapsulate level=%d ret=%d\n",
                    levels[i], ret);
            }
            else if ((ssWrongLen == ssEncLen) &&
                     (memcmp(ssWrong, ssEnc, ssEncLen) == 0)) {
                WH_ERROR_PRINT(
                    "ML-KEM wrong-key decaps unexpectedly matched level=%d\n",
                    levels[i]);
                ret = -1;
            }
        }

        if (ret == 0) {
            ret = wh_Client_MlKemMakeCacheKey(
                ctx, levels[i], &usageKeyId, WH_NVM_FLAGS_NONE,
                (uint16_t)strlen((const char*)usageLabel), (uint8_t*)usageLabel);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed ML-KEM cache key without derive level=%d ret=%d\n",
                    levels[i], ret);
            }
            else {
                usageKeyCached = 1;
            }
        }
        if (ret == 0) {
            ret = wc_MlKemKey_Init(usageKey, levels[i], NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed init ML-KEM usage key level=%d ret=%d\n",
                               levels[i], ret);
            }
            else {
                usageInited = 1;
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemSetKeyId(usageKey, usageKeyId);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed set ML-KEM usage key ID level=%d ret=%d\n",
                    levels[i], ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemEncapsulate(ctx, usageKey, usageCt, &usageCtLen,
                                             usageSs, &usageSsLen);
            if (ret == WH_ERROR_USAGE) {
                ret = 0;
            }
            else {
                WH_ERROR_PRINT("Expected WH_ERROR_USAGE for ML-KEM derive "
                               "policy encaps level=%d got=%d\n",
                               levels[i], ret);
                ret = WH_ERROR_ABORTED;
            }
        }
        /* Negative test: decapsulate with key lacking derive usage */
        if (ret == 0) {
            byte   dummyCt[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE] = {0};
            word32 dummyCtLen = sizeof(dummyCt);
            ret = wh_Client_MlKemDecapsulate(ctx, usageKey, dummyCt,
                                             dummyCtLen, usageSs,
                                             &usageSsLen);
            if (ret == WH_ERROR_USAGE) {
                ret = 0;
            }
            else {
                WH_ERROR_PRINT("Expected WH_ERROR_USAGE for ML-KEM derive "
                               "policy decaps level=%d got=%d\n",
                               levels[i], ret);
                ret = WH_ERROR_ABORTED;
            }
        }

        if (usageKeyCached) {
            int evictRet = wh_Client_KeyEvict(ctx, usageKeyId);
            if ((evictRet != 0) && (ret == 0)) {
                WH_ERROR_PRINT("Failed ML-KEM usage key evict level=%d ret=%d\n",
                               levels[i], evictRet);
                ret = evictRet;
            }
            usageKeyCached = 0;
        }
        if (usageInited) {
            wc_MlKemKey_Free(usageKey);
            usageInited = 0;
        }

        /* Positive test: cached key WITH derive usage should succeed */
        if (ret == 0) {
            const uint8_t deriveLabel[] = "mlkem-derive-ok";
            byte   deriveCt[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
            byte   deriveSsEnc[WC_ML_KEM_SS_SZ];
            byte   deriveSsDec[WC_ML_KEM_SS_SZ];
            word32 deriveCtLen  = sizeof(deriveCt);
            word32 deriveSsEncLen = sizeof(deriveSsEnc);
            word32 deriveSsDecLen = sizeof(deriveSsDec);

            ret = wh_Client_MlKemMakeCacheKey(
                ctx, levels[i], &usageKeyId, WH_NVM_FLAGS_USAGE_DERIVE,
                (uint16_t)strlen((const char*)deriveLabel),
                (uint8_t*)deriveLabel);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed ML-KEM cache key with derive level=%d ret=%d\n",
                    levels[i], ret);
            }
            else {
                usageKeyCached = 1;
            }
            if (ret == 0) {
                ret = wc_MlKemKey_Init(usageKey, levels[i], NULL, devId);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Failed init ML-KEM derive key level=%d ret=%d\n",
                        levels[i], ret);
                }
                else {
                    usageInited = 1;
                }
            }
            if (ret == 0) {
                ret = wh_Client_MlKemSetKeyId(usageKey, usageKeyId);
            }
            if (ret == 0) {
                ret = wh_Client_MlKemEncapsulate(ctx, usageKey, deriveCt,
                                                 &deriveCtLen, deriveSsEnc,
                                                 &deriveSsEncLen);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed ML-KEM encaps with derive key "
                                   "level=%d ret=%d\n",
                                   levels[i], ret);
                }
            }
            if (ret == 0) {
                ret = wh_Client_MlKemDecapsulate(ctx, usageKey, deriveCt,
                                                 deriveCtLen, deriveSsDec,
                                                 &deriveSsDecLen);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed ML-KEM decaps with derive key "
                                   "level=%d ret=%d\n",
                                   levels[i], ret);
                }
                else if ((deriveSsEncLen != deriveSsDecLen) ||
                         (memcmp(deriveSsEnc, deriveSsDec,
                                 deriveSsEncLen) != 0)) {
                    WH_ERROR_PRINT("ML-KEM derive key shared secret mismatch "
                                   "level=%d\n",
                                   levels[i]);
                    ret = -1;
                }
            }
            if (usageKeyCached) {
                int evictRet = wh_Client_KeyEvict(ctx, usageKeyId);
                if ((evictRet != 0) && (ret == 0)) {
                    WH_ERROR_PRINT("Failed ML-KEM derive key evict level=%d "
                                   "ret=%d\n",
                                   levels[i], evictRet);
                    ret = evictRet;
                }
            }
            if (usageInited) {
                wc_MlKemKey_Free(usageKey);
            }
        }

        if (wrongInited) {
            wc_MlKemKey_Free(wrongKey);
        }
        if (keyInited) {
            wc_MlKemKey_Free(key);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-KEM Client Non-DMA API SUCCESS\n");
    }

    return ret;
}

static int whTestCrypto_MlKemExportPublic(whClientContext* ctx, int devId,
                                          WC_RNG* rng)
{
    int      ret      = 0;
    int      levels[3];
    int      levelCnt = 0;
    int      i;

    levelCnt = whTestCrypto_MlKemGetLevels(
        levels, (int)(sizeof(levels) / sizeof(levels[0])));

    for (i = 0; (ret == 0) && (i < levelCnt); i++) {
        whKeyId  keyId  = WH_KEYID_ERASED;
        MlKemKey pub[1] = {0};
        MlKemKey cached[1] = {0};
        int      pubInited    = 0;
        int      cachedInited = 0;
        uint8_t  denyBuf[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
        uint16_t denyLen = sizeof(denyBuf);
        byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
        byte     ssEnc[WC_ML_KEM_SS_SZ];
        byte     ssDec[WC_ML_KEM_SS_SZ];
        word32   ctLen    = sizeof(ct);
        word32   ssEncLen = sizeof(ssEnc);
        word32   ssDecLen = sizeof(ssDec);

        ret = wh_Client_MlKemMakeCacheKey(
            ctx, levels[i], &keyId,
            WH_NVM_FLAGS_USAGE_DERIVE | WH_NVM_FLAGS_NONEXPORTABLE,
            0, NULL);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to make NONEXPORTABLE ML-KEM cached key level=%d %d\n",
                levels[i], ret);
            break;
        }

        /* Full export must be denied */
        {
            int denyRet = wh_Client_KeyExport(ctx, keyId, NULL, 0, denyBuf,
                                              &denyLen);
            if (denyRet != WH_ERROR_ACCESS) {
                WH_ERROR_PRINT(
                    "NONEXPORTABLE ML-KEM full export was not denied "
                    "level=%d: %d\n", levels[i], denyRet);
                ret = -1;
            }
        }

        /* Public export must succeed and yield a public-only key. */
        if (ret == 0) {
            ret = wc_MlKemKey_Init(pub, levels[i], NULL, devId);
            if (ret == 0) {
                pubInited = 1;
                ret = wh_Client_MlKemExportPublicKey(ctx, keyId, pub, 0, NULL);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "wh_Client_MlKemExportPublicKey failed level=%d %d\n",
                        levels[i], ret);
                }
                else if (((pub->flags & MLKEM_FLAG_PUB_SET) == 0) ||
                         ((pub->flags & MLKEM_FLAG_PRIV_SET) != 0)) {
                    WH_ERROR_PRINT(
                        "Exported ML-KEM key flags wrong level=%d "
                        "flags=0x%x\n",
                        levels[i], (unsigned)pub->flags);
                    ret = -1;
                }
            }
        }

        /* Roundtrip: encapsulate locally with the exported public key,
         * decapsulate on the server-cached private key. */
        if (ret == 0) {
            ret = wc_MlKemKey_CipherTextSize(pub, &ctLen);
            if (ret == 0) {
                ret = wc_MlKemKey_SharedSecretSize(pub, &ssEncLen);
            }
            if (ret == 0) {
                ssDecLen = ssEncLen;
                ret      = wc_MlKemKey_Encapsulate(pub, ct, ssEnc, rng);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Local encapsulate against exported pub failed "
                        "level=%d %d\n", levels[i], ret);
                }
            }
        }
        if (ret == 0) {
            ret = wc_MlKemKey_Init(cached, levels[i], NULL, devId);
            if (ret == 0) {
                cachedInited = 1;
                ret          = wh_Client_MlKemSetKeyId(cached, keyId);
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemDecapsulate(ctx, cached, ct, ctLen, ssDec,
                                             &ssDecLen);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Server decapsulate of locally-encapsulated ct failed "
                    "level=%d %d\n", levels[i], ret);
            }
            else if ((ssEncLen != ssDecLen) ||
                     (memcmp(ssEnc, ssDec, ssEncLen) != 0)) {
                WH_ERROR_PRINT(
                    "ML-KEM export-public roundtrip ss mismatch level=%d\n",
                    levels[i]);
                ret = -1;
            }
        }

        /* Negative: missing keyId must return NOTFOUND. 0xBADE is well clear
         * of the auto-assigned IDs the server hands out near IDMAX. */
        if (ret == 0) {
            uint8_t  bogusBuf[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
            uint16_t bogusLen = sizeof(bogusBuf);
            whKeyId  missing  = (whKeyId)0xBADE;
            int negRet = wh_Client_KeyExportPublic(
                ctx, missing, WH_KEY_ALGO_MLKEM, NULL, 0, bogusBuf, &bogusLen);
            if (negRet != WH_ERROR_NOTFOUND) {
                WH_ERROR_PRINT(
                    "ExportPublic on missing ML-KEM keyId returned %d, "
                    "expected WH_ERROR_NOTFOUND (level=%d)\n",
                    negRet, levels[i]);
                ret = -1;
            }
        }

        if (cachedInited) {
            wc_MlKemKey_Free(cached);
        }
        if (pubInited) {
            wc_MlKemKey_Free(pub);
        }
        if (!WH_KEYID_ISERASED(keyId)) {
            (void)wh_Client_KeyEvict(ctx, keyId);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-KEM EXPORT-PUBLIC SUCCESS\n");
    }
    return ret;
}

/* One keygen call caches the private key and returns the public key. Verify
 * the returned public key byte-matches wh_Client_MlKemExportPublicKey and that
 * a KEM encapsulate/decapsulate round-trips against the cached private key. */
static int whTestCrypto_MlKemCacheKeyAndExportPublic(whClientContext* ctx,
                                                     int devId, WC_RNG* rng)
{
    int      ret      = 0;
    int      levels[3];
    int      levelCnt = 0;
    int      i;

    levelCnt = whTestCrypto_MlKemGetLevels(
        levels, (int)(sizeof(levels) / sizeof(levels[0])));

    for (i = 0; (ret == 0) && (i < levelCnt); i++) {
        whKeyId  keyId        = WH_KEYID_ERASED;
        MlKemKey genPub[1]    = {0};
        MlKemKey refPub[1]    = {0};
        int      genInited    = 0;
        int      refInited    = 0;
        byte     genRaw[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
        byte     refRaw[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
        word32   genRawSz     = 0;
        word32   refRawSz     = 0;
        byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
        byte     ssEnc[WC_ML_KEM_SS_SZ];
        byte     ssDec[WC_ML_KEM_SS_SZ];
        word32   ctLen    = sizeof(ct);
        word32   ssEncLen = sizeof(ssEnc);
        word32   ssDecLen = sizeof(ssDec);
        (void)devId;

        ret = wc_MlKemKey_Init(genPub, levels[i], NULL, INVALID_DEVID);
        if (ret == 0) {
            genInited = 1;
            ret       = wh_Client_MlKemMakeCacheKeyAndExportPublic(
                ctx, levels[i], &keyId, WH_NVM_FLAGS_USAGE_DERIVE, 0, NULL,
                genPub);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "MlKemMakeCacheKeyAndExportPublic failed level=%d %d\n",
                    levels[i], ret);
            }
        }

        /* Cross-check the keygen-returned public key against ExportPublicKey. */
        if (ret == 0) {
            ret = wc_MlKemKey_Init(refPub, levels[i], NULL, INVALID_DEVID);
            if (ret == 0) {
                refInited = 1;
                ret = wh_Client_MlKemExportPublicKey(ctx, keyId, refPub, 0,
                                                     NULL);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "wh_Client_MlKemExportPublicKey failed level=%d %d\n",
                        levels[i], ret);
                }
            }
        }
        if (ret == 0) {
            ret = wc_MlKemKey_PublicKeySize(genPub, &genRawSz);
            if (ret == 0) {
                ret = wc_MlKemKey_EncodePublicKey(genPub, genRaw, genRawSz);
            }
            if (ret == 0) {
                ret = wc_MlKemKey_PublicKeySize(refPub, &refRawSz);
            }
            if (ret == 0) {
                ret = wc_MlKemKey_EncodePublicKey(refPub, refRaw, refRawSz);
            }
            if ((ret == 0) && ((genRawSz != refRawSz) ||
                               (memcmp(genRaw, refRaw, genRawSz) != 0))) {
                WH_ERROR_PRINT(
                    "keygen pubkey mismatch vs ExportPublicKey level=%d\n",
                    levels[i]);
                ret = -1;
            }
        }

        /* Roundtrip: encapsulate locally with the exported public key (refPub)
         * the client holds, decapsulate on the HSM using genPub directly as the
         * private-key handle (no separate key object). */
        if (ret == 0) {
            ret = wc_MlKemKey_CipherTextSize(refPub, &ctLen);
            if (ret == 0) {
                ret = wc_MlKemKey_SharedSecretSize(refPub, &ssEncLen);
            }
            if (ret == 0) {
                ssDecLen = ssEncLen;
                ret      = wc_MlKemKey_Encapsulate(refPub, ct, ssEnc, rng);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Encapsulate against keygen pub failed level=%d %d\n",
                        levels[i], ret);
                }
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemDecapsulate(ctx, genPub, ct, ctLen, ssDec,
                                             &ssDecLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Server decapsulate failed level=%d %d\n",
                               levels[i], ret);
            }
            else if ((ssEncLen != ssDecLen) ||
                     (memcmp(ssEnc, ssDec, ssEncLen) != 0)) {
                WH_ERROR_PRINT(
                    "ML-KEM keygen-pub roundtrip ss mismatch level=%d\n",
                    levels[i]);
                ret = -1;
            }
        }

        if (refInited) {
            wc_MlKemKey_Free(refPub);
        }
        if (genInited) {
            wc_MlKemKey_Free(genPub);
        }
        if (!WH_KEYID_ISERASED(keyId)) {
            (void)wh_Client_KeyEvict(ctx, keyId);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-KEM CACHE-AND-EXPORT-PUBLIC SUCCESS\n");
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int whTestCrypto_MlKemExportPublicDma(whClientContext* ctx, int devId,
                                             WC_RNG* rng)
{
    int      ret      = 0;
    int      levels[3];
    int      levelCnt = 0;
    int      i;

    levelCnt = whTestCrypto_MlKemGetLevels(
        levels, (int)(sizeof(levels) / sizeof(levels[0])));

    for (i = 0; (ret == 0) && (i < levelCnt); i++) {
        whKeyId  keyId    = WH_KEYID_ERASED;
        MlKemKey pub[1]   = {0};
        MlKemKey cached[1] = {0};
        int      pubInited    = 0;
        int      cachedInited = 0;
        byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
        byte     ssEnc[WC_ML_KEM_SS_SZ];
        byte     ssDec[WC_ML_KEM_SS_SZ];
        word32   ctLen    = sizeof(ct);
        word32   ssEncLen = sizeof(ssEnc);
        word32   ssDecLen = sizeof(ssDec);

        ret = wh_Client_MlKemMakeCacheKey(
            ctx, levels[i], &keyId,
            WH_NVM_FLAGS_USAGE_DERIVE | WH_NVM_FLAGS_NONEXPORTABLE,
            0, NULL);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to make NONEXPORTABLE ML-KEM cached key (DMA) "
                "level=%d %d\n", levels[i], ret);
            break;
        }

        /* Full DMA export must be denied. */
        {
            byte     fullBuf[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
            uint16_t fullLen = sizeof(fullBuf);
            int denyRet = wh_Client_KeyExportDma(ctx, keyId, fullBuf, fullLen,
                                                 NULL, 0, &fullLen);
            if (denyRet != WH_ERROR_ACCESS) {
                WH_ERROR_PRINT(
                    "NONEXPORTABLE ML-KEM full DMA export was not denied "
                    "level=%d: %d\n", levels[i], denyRet);
                ret = -1;
            }
        }

        /* Public DMA export must succeed and yield a public-only key. */
        if (ret == 0) {
            ret = wc_MlKemKey_Init(pub, levels[i], NULL, devId);
            if (ret == 0) {
                pubInited = 1;
                ret = wh_Client_MlKemExportPublicKeyDma(ctx, keyId, pub,
                                                        0, NULL);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "wh_Client_MlKemExportPublicKeyDma failed level=%d "
                        "%d\n", levels[i], ret);
                }
                else if (((pub->flags & MLKEM_FLAG_PUB_SET) == 0) ||
                         ((pub->flags & MLKEM_FLAG_PRIV_SET) != 0)) {
                    WH_ERROR_PRINT(
                        "Exported ML-KEM key (DMA) flags wrong level=%d "
                        "flags=0x%x\n",
                        levels[i], (unsigned)pub->flags);
                    ret = -1;
                }
            }
        }

        /* Roundtrip: encapsulate locally with the DMA-exported public key,
         * decapsulate on the server-cached private key. */
        if (ret == 0) {
            ret = wc_MlKemKey_CipherTextSize(pub, &ctLen);
            if (ret == 0) {
                ret = wc_MlKemKey_SharedSecretSize(pub, &ssEncLen);
            }
            if (ret == 0) {
                ssDecLen = ssEncLen;
                ret      = wc_MlKemKey_Encapsulate(pub, ct, ssEnc, rng);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Local encapsulate against DMA-exported pub failed "
                        "level=%d %d\n", levels[i], ret);
                }
            }
        }
        if (ret == 0) {
            ret = wc_MlKemKey_Init(cached, levels[i], NULL, devId);
            if (ret == 0) {
                cachedInited = 1;
                ret          = wh_Client_MlKemSetKeyId(cached, keyId);
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemDecapsulate(ctx, cached, ct, ctLen, ssDec,
                                             &ssDecLen);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Server decapsulate of locally-encapsulated ct (DMA) "
                    "failed level=%d %d\n", levels[i], ret);
            }
            else if ((ssEncLen != ssDecLen) ||
                     (memcmp(ssEnc, ssDec, ssEncLen) != 0)) {
                WH_ERROR_PRINT(
                    "ML-KEM DMA export-public roundtrip ss mismatch "
                    "level=%d\n", levels[i]);
                ret = -1;
            }
        }

        /* Byte-identity check: DMA and non-DMA paths must produce the
         * same public bytes for the same cached key. */
        if (ret == 0) {
            byte     dmaBuf[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
            byte     nonDmaBuf[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
            uint16_t dmaSz    = sizeof(dmaBuf);
            uint16_t nonDmaSz = sizeof(nonDmaBuf);

            ret = wh_Client_KeyExportPublicDma(ctx, keyId, WH_KEY_ALGO_MLKEM,
                                               dmaBuf, dmaSz, NULL, 0, &dmaSz);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Generic ML-KEM DMA export failed for re-encode check "
                    "level=%d %d\n", levels[i], ret);
            }
            else {
                ret = wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_MLKEM,
                                                NULL, 0, nonDmaBuf, &nonDmaSz);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Non-DMA ML-KEM export failed for re-encode check "
                        "level=%d %d\n", levels[i], ret);
                }
                else if (dmaSz != nonDmaSz ||
                         memcmp(dmaBuf, nonDmaBuf, dmaSz) != 0) {
                    WH_ERROR_PRINT(
                        "ML-KEM DMA and non-DMA public bytes differ "
                        "level=%d (dmaSz=%u nonDmaSz=%u)\n",
                        levels[i], (unsigned)dmaSz, (unsigned)nonDmaSz);
                    ret = -1;
                }
            }
        }

        /* Negative: a too-small client buffer must yield WH_ERROR_NOSPACE. */
        if (ret == 0) {
            byte     tinyBuf[8];
            uint16_t tinySz = sizeof(tinyBuf);
            int      negRet = wh_Client_KeyExportPublicDma(
                ctx, keyId, WH_KEY_ALGO_MLKEM, tinyBuf, tinySz, NULL, 0,
                &tinySz);
            if (negRet != WH_ERROR_NOSPACE) {
                WH_ERROR_PRINT(
                    "Too-small DMA buffer did not return NOSPACE level=%d: "
                    "%d\n", levels[i], negRet);
                ret = -1;
            }
        }

        if (cachedInited) {
            wc_MlKemKey_Free(cached);
        }
        if (pubInited) {
            wc_MlKemKey_Free(pub);
        }
        if (!WH_KEYID_ISERASED(keyId)) {
            (void)wh_Client_KeyEvict(ctx, keyId);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-KEM EXPORT-PUBLIC DMA SUCCESS\n");
    }
    return ret;
}

/* DMA variant: one keygen call caches the private key and streams the public
 * key back through the client's DMA buffer. Verify it byte-matches
 * wh_Client_MlKemExportPublicKeyDma and that a KEM round-trips against the
 * cached private key. */
static int whTestCrypto_MlKemCacheKeyAndExportPublicDma(whClientContext* ctx,
                                                        int devId, WC_RNG* rng)
{
    int      ret      = 0;
    int      levels[3];
    int      levelCnt = 0;
    int      i;

    levelCnt = whTestCrypto_MlKemGetLevels(
        levels, (int)(sizeof(levels) / sizeof(levels[0])));

    for (i = 0; (ret == 0) && (i < levelCnt); i++) {
        whKeyId  keyId        = WH_KEYID_ERASED;
        MlKemKey genPub[1]    = {0};
        MlKemKey refPub[1]    = {0};
        int      genInited    = 0;
        int      refInited    = 0;
        byte     genRaw[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
        byte     refRaw[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
        word32   genRawSz     = 0;
        word32   refRawSz     = 0;
        byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
        byte     ssEnc[WC_ML_KEM_SS_SZ];
        byte     ssDec[WC_ML_KEM_SS_SZ];
        word32   ctLen    = sizeof(ct);
        word32   ssEncLen = sizeof(ssEnc);
        word32   ssDecLen = sizeof(ssDec);
        (void)devId;

        ret = wc_MlKemKey_Init(genPub, levels[i], NULL, INVALID_DEVID);
        if (ret == 0) {
            genInited = 1;
            ret       = wh_Client_MlKemMakeCacheKeyDma(
                ctx, levels[i], &keyId, WH_NVM_FLAGS_USAGE_DERIVE, 0, NULL,
                genPub);
            if (ret != 0) {
                WH_ERROR_PRINT("MlKemMakeCacheKeyDma failed level=%d %d\n",
                               levels[i], ret);
            }
        }

        /* Cross-check against a separate public DMA export of the same keyId. */
        if (ret == 0) {
            ret = wc_MlKemKey_Init(refPub, levels[i], NULL, INVALID_DEVID);
            if (ret == 0) {
                refInited = 1;
                ret = wh_Client_MlKemExportPublicKeyDma(ctx, keyId, refPub, 0,
                                                        NULL);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "wh_Client_MlKemExportPublicKeyDma failed level=%d %d\n",
                        levels[i], ret);
                }
            }
        }
        if (ret == 0) {
            ret = wc_MlKemKey_PublicKeySize(genPub, &genRawSz);
            if (ret == 0) {
                ret = wc_MlKemKey_EncodePublicKey(genPub, genRaw, genRawSz);
            }
            if (ret == 0) {
                ret = wc_MlKemKey_PublicKeySize(refPub, &refRawSz);
            }
            if (ret == 0) {
                ret = wc_MlKemKey_EncodePublicKey(refPub, refRaw, refRawSz);
            }
            if ((ret == 0) && ((genRawSz != refRawSz) ||
                               (memcmp(genRaw, refRaw, genRawSz) != 0))) {
                WH_ERROR_PRINT(
                    "keygen pubkey (DMA) mismatch vs export level=%d\n",
                    levels[i]);
                ret = -1;
            }
        }

        /* Roundtrip: encapsulate locally with the exported public key (refPub)
         * the client holds, decapsulate on the HSM using genPub directly as the
         * private-key handle (no separate key object). */
        if (ret == 0) {
            ret = wc_MlKemKey_CipherTextSize(refPub, &ctLen);
            if (ret == 0) {
                ret = wc_MlKemKey_SharedSecretSize(refPub, &ssEncLen);
            }
            if (ret == 0) {
                ssDecLen = ssEncLen;
                ret      = wc_MlKemKey_Encapsulate(refPub, ct, ssEnc, rng);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Encapsulate against keygen pub (DMA) failed level=%d "
                        "%d\n", levels[i], ret);
                }
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemDecapsulate(ctx, genPub, ct, ctLen, ssDec,
                                             &ssDecLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Server decapsulate (DMA) failed level=%d %d\n",
                               levels[i], ret);
            }
            else if ((ssEncLen != ssDecLen) ||
                     (memcmp(ssEnc, ssDec, ssEncLen) != 0)) {
                WH_ERROR_PRINT(
                    "ML-KEM DMA keygen-pub roundtrip ss mismatch level=%d\n",
                    levels[i]);
                ret = -1;
            }
        }

        if (refInited) {
            wc_MlKemKey_Free(refPub);
        }
        if (genInited) {
            wc_MlKemKey_Free(genPub);
        }
        if (!WH_KEYID_ISERASED(keyId)) {
            (void)wh_Client_KeyEvict(ctx, keyId);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-KEM CACHE-AND-EXPORT-PUBLIC DMA SUCCESS\n");
    }
    return ret;
}

static int whTestCrypto_MlKemDmaClient(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int      ret      = 0;
    int      levels[3];
    int      levelCnt = 0;
    int      i;
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ssEnc[WC_ML_KEM_SS_SZ];
    byte     ssDec[WC_ML_KEM_SS_SZ];
    byte     ssWrong[WC_ML_KEM_SS_SZ];
    byte     keyBuf1[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    byte     keyBuf2[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    word32   ctLen;
    word32   ssEncLen;
    word32   ssDecLen;
    word32   ssWrongLen;
    uint16_t keyBuf1Len;
    uint16_t keyBuf2Len;
    whKeyId  keyId;
    const uint8_t cacheLabel[] = "mlkem-dma-cache";

    (void)rng;

    levelCnt =
        whTestCrypto_MlKemGetLevels(levels, (int)(sizeof(levels) / sizeof(levels[0])));

    for (i = 0; (ret == 0) && (i < levelCnt); i++) {
        MlKemKey key[1];
        MlKemKey importedKey[1];
        MlKemKey wrongKey[1];
        int      keyInited      = 0;
        int      importedInited = 0;
        int      wrongInited    = 0;
        int      keyCached      = 0;

        ctLen      = sizeof(ct);
        ssEncLen   = sizeof(ssEnc);
        ssDecLen   = sizeof(ssDec);
        ssWrongLen = sizeof(ssWrong);
        keyBuf1Len = sizeof(keyBuf1);
        keyBuf2Len = sizeof(keyBuf2);
        keyId      = WH_KEYID_ERASED;

        memset(ct, 0, sizeof(ct));
        memset(ssEnc, 0, sizeof(ssEnc));
        memset(ssDec, 0, sizeof(ssDec));
        memset(ssWrong, 0, sizeof(ssWrong));
        memset(keyBuf1, 0, sizeof(keyBuf1));
        memset(keyBuf2, 0, sizeof(keyBuf2));

        ret = wc_MlKemKey_Init(key, levels[i], NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed init ML-KEM DMA key level=%d ret=%d\n",
                           levels[i], ret);
            break;
        }
        keyInited = 1;

        ret = wc_MlKemKey_Init(importedKey, levels[i], NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed init ML-KEM DMA imported key level=%d "
                           "ret=%d\n",
                           levels[i], ret);
        }
        else {
            importedInited = 1;
        }

        if (ret == 0) {
            ret = wc_MlKemKey_Init(wrongKey, levels[i], NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed init ML-KEM DMA wrong key level=%d "
                               "ret=%d\n",
                               levels[i], ret);
            }
            else {
                wrongInited = 1;
            }
        }

        if (ret == 0) {
            ret = wh_Client_MlKemMakeExportKeyDma(ctx, levels[i], key);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA keygen level=%d ret=%d\n",
                               levels[i], ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemMakeExportKeyDma(ctx, levels[i], wrongKey);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA wrong keygen level=%d ret=%d\n",
                               levels[i], ret);
            }
        }

        if (ret == 0) {
            ret = wh_Crypto_MlKemSerializeKey(key, keyBuf1Len, keyBuf1,
                                              &keyBuf1Len);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA serialize key level=%d "
                               "ret=%d\n",
                               levels[i], ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemImportKeyDma(
                ctx, key, &keyId, WH_NVM_FLAGS_NONE,
                (uint16_t)strlen((const char*)cacheLabel), (uint8_t*)cacheLabel);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA import key level=%d ret=%d\n",
                               levels[i], ret);
            }
            else {
                keyCached = 1;
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemExportKeyDma(
                ctx, keyId, importedKey,
                (uint16_t)strlen((const char*)cacheLabel), (uint8_t*)cacheLabel);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA export key level=%d ret=%d\n",
                               levels[i], ret);
            }
        }
        if (ret == 0) {
            ret = wh_Crypto_MlKemSerializeKey(importedKey, keyBuf2Len, keyBuf2,
                                              &keyBuf2Len);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA serialize imported key "
                               "level=%d ret=%d\n",
                               levels[i], ret);
            }
            else if ((keyBuf1Len != keyBuf2Len) ||
                     (memcmp(keyBuf1, keyBuf2, keyBuf1Len) != 0)) {
                WH_ERROR_PRINT("ML-KEM DMA imported key mismatch level=%d\n",
                               levels[i]);
                ret = -1;
            }
        }

        if (ret == 0) {
            ret = wh_Client_MlKemEncapsulateDma(ctx, key, ct, &ctLen, ssEnc,
                                                &ssEncLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA encapsulate level=%d ret=%d\n",
                               levels[i], ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemDecapsulateDma(ctx, key, ct, ctLen, ssDec,
                                                &ssDecLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA decapsulate level=%d ret=%d\n",
                               levels[i], ret);
            }
            else if ((ssEncLen != ssDecLen) ||
                     (memcmp(ssEnc, ssDec, ssEncLen) != 0)) {
                WH_ERROR_PRINT("ML-KEM DMA shared secret mismatch level=%d\n",
                               levels[i]);
                ret = -1;
            }
        }
        if (ret == 0) {
            ret = wh_Client_MlKemDecapsulateDma(ctx, wrongKey, ct, ctLen,
                                                ssWrong, &ssWrongLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA wrong-key decaps level=%d "
                               "ret=%d\n",
                               levels[i], ret);
            }
            else if ((ssWrongLen == ssEncLen) &&
                     (memcmp(ssWrong, ssEnc, ssEncLen) == 0)) {
                WH_ERROR_PRINT("ML-KEM DMA wrong-key decaps unexpectedly "
                               "matched level=%d\n",
                               levels[i]);
                ret = -1;
            }
        }

        /* Usage policy enforcement: key without derive should be denied */
        if (ret == 0) {
            MlKemKey  usageKey[1];
            whKeyId   usageKeyId     = WH_KEYID_ERASED;
            int       usageInited    = 0;
            int       usageKeyCached = 0;
            const uint8_t usageLabel[] = "mlkem-dma-nouse";

            ret = wh_Client_MlKemMakeCacheKey(
                ctx, levels[i], &usageKeyId, WH_NVM_FLAGS_NONE,
                (uint16_t)strlen((const char*)usageLabel),
                (uint8_t*)usageLabel);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed ML-KEM DMA cache key without derive "
                               "level=%d ret=%d\n",
                               levels[i], ret);
            }
            else {
                usageKeyCached = 1;
            }
            if (ret == 0) {
                ret = wc_MlKemKey_Init(usageKey, levels[i], NULL, devId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed init ML-KEM DMA usage key "
                                   "level=%d ret=%d\n",
                                   levels[i], ret);
                }
                else {
                    usageInited = 1;
                }
            }
            if (ret == 0) {
                ret = wh_Client_MlKemSetKeyId(usageKey, usageKeyId);
            }
            if (ret == 0) {
                word32 tmpCtLen = sizeof(ct);
                word32 tmpSsLen = sizeof(ssEnc);
                ret = wh_Client_MlKemEncapsulateDma(ctx, usageKey, ct,
                                                     &tmpCtLen, ssEnc,
                                                     &tmpSsLen);
                if (ret == WH_ERROR_USAGE) {
                    ret = 0; /* Expected */
                }
                else {
                    WH_ERROR_PRINT("Expected WH_ERROR_USAGE for ML-KEM DMA "
                                   "derive policy encaps level=%d got=%d\n",
                                   levels[i], ret);
                    ret = WH_ERROR_ABORTED;
                }
            }
            /* Negative test: DMA decapsulate with key lacking derive usage */
            if (ret == 0) {
                byte   dummyCt[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE] = {0};
                word32 dummySsLen = sizeof(ssEnc);
                ret = wh_Client_MlKemDecapsulateDma(
                    ctx, usageKey, dummyCt,
                    sizeof(dummyCt), ssEnc, &dummySsLen);
                if (ret == WH_ERROR_USAGE) {
                    ret = 0; /* Expected */
                }
                else {
                    WH_ERROR_PRINT("Expected WH_ERROR_USAGE for ML-KEM DMA "
                                   "derive policy decaps level=%d got=%d\n",
                                   levels[i], ret);
                    ret = WH_ERROR_ABORTED;
                }
            }
            if (usageKeyCached) {
                int evictRet = wh_Client_KeyEvict(ctx, usageKeyId);
                if ((evictRet != 0) && (ret == 0)) {
                    WH_ERROR_PRINT("Failed ML-KEM DMA usage key evict "
                                   "level=%d ret=%d\n",
                                   levels[i], evictRet);
                    ret = evictRet;
                }
            }
            if (usageInited) {
                wc_MlKemKey_Free(usageKey);
            }
        }

        if (keyCached) {
            int evictRet = wh_Client_KeyEvict(ctx, keyId);
            if ((evictRet != 0) && (ret == 0)) {
                WH_ERROR_PRINT("Failed ML-KEM DMA evict cached key level=%d "
                               "ret=%d\n",
                               levels[i], evictRet);
                ret = evictRet;
            }
        }
        if (wrongInited) {
            wc_MlKemKey_Free(wrongKey);
        }
        if (importedInited) {
            wc_MlKemKey_Free(importedKey);
        }
        if (keyInited) {
            wc_MlKemKey_Free(key);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("ML-KEM Client DMA API SUCCESS\n");
    }

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) &&    \
          !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
          !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) */
#endif /* WOLFSSL_HAVE_MLKEM */

#if defined(WOLFHSM_CFG_DMA) && \
    defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
/* L=1, H=5, W=8 keeps the signature ~1.3 KB and gives 2^5 = 32 signatures. */
#define WH_TEST_LMS_LEVELS     (1)
#define WH_TEST_LMS_HEIGHT     (5)
#define WH_TEST_LMS_WINTERNITZ (8)
/* Generous buffer that fits L1_H5_W8 (~1328) and any W<8 variant of the same
 * height (W=1 ~8688). Keeps off the stack so ASAN builds stay happy. */
static byte whTest_LmsSigBuf[8800];

static int whTestCrypto_LmsCryptoCb(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    int        ret           = 0;
    LmsKey     key[1];
    int        keyInited     = 0;
    word32     sigLen        = 0;
    word32     sigCap        = 0;
    const byte msg[]         = "wolfHSM LMS cryptocb test";
    word32     msgSz         = (word32)sizeof(msg) - 1;

    (void)rng;

    memset(whTest_LmsSigBuf, 0, sizeof(whTest_LmsSigBuf));

    ret = wc_LmsKey_Init(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wc_LmsKey_Init devId=0x%X ret=%d\n", devId, ret);
        return ret;
    }
    keyInited = 1;

    if (ret == 0) {
        ret = wc_LmsKey_SetParameters(key, WH_TEST_LMS_LEVELS,
                                      WH_TEST_LMS_HEIGHT,
                                      WH_TEST_LMS_WINTERNITZ);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed LMS SetParameters ret=%d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wc_LmsKey_GetSigLen(key, &sigCap);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed LMS GetSigLen ret=%d\n", ret);
        }
        else if (sigCap > sizeof(whTest_LmsSigBuf)) {
            WH_ERROR_PRINT("LMS sig buffer too small: need=%u have=%u\n",
                           (unsigned)sigCap,
                           (unsigned)sizeof(whTest_LmsSigBuf));
            ret = BUFFER_E;
        }
    }

    /* MakeKey via cryptocb: the server commits the key to NVM before
     * returning the public key over DMA. */
    if (ret == 0) {
        ret = wc_LmsKey_MakeKey(key, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed LMS MakeKey ret=%d\n", ret);
        }
    }

    /* wc_LmsKey_SigsLeft returns a boolean: nonzero = signatures available,
     * 0 = exhausted. Fresh key should report nonzero. */
    if (ret == 0) {
        if (wc_LmsKey_SigsLeft(key) == 0) {
            WH_ERROR_PRINT("LMS reported exhausted on fresh key\n");
            ret = -1;
        }
    }

    /* Durability: keygen must commit the key to NVM before returning the pub,
     * not defer it. Evict the volatile cache copy (as a power loss before the
     * first sign would) and confirm the key is still resident in NVM. */
    if (ret == 0) {
        whKeyId durId = WH_KEYID_ERASED;
        if ((wh_Client_LmsGetKeyId(key, &durId) == 0) &&
            !WH_KEYID_ISERASED(durId)) {
            ret = wh_Client_KeyEvict(ctx, durId);
            if (ret != 0) {
                WH_ERROR_PRINT("LMS durability evict failed: ret=%d\n", ret);
            }
            else {
                /* SigsLeft reloads the key from NVM; a negative return means
                 * keygen failed to commit it. A fresh key reports 1. */
                ret = wh_Client_LmsSigsLeftDma(ctx, key);
                if (ret < 0) {
                    WH_ERROR_PRINT("LMS key not durable after keygen: ret=%d\n",
                                   ret);
                }
                else {
                    ret = 0;
                }
            }
        }
    }

    /* EPHEMERAL is invalid for a stateful private keygen and must be rejected
     * locally with WH_ERROR_BADARGS (no server round-trip). */
    if (ret == 0) {
        int badRet = wh_Client_LmsMakeKeyDma(ctx, key, NULL,
                                             WH_NVM_FLAGS_EPHEMERAL, 0, NULL);
        if (badRet != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("LMS ephemeral keygen not rejected: ret=%d "
                           "(expected WH_ERROR_BADARGS)\n", badRet);
            ret = WH_ERROR_ABORTED;
        }
    }

    /* Direct DMA keygen with a label and a caller-visible keyId. The cryptocb
     * keygen above passes neither, so this drives the label-copy and keyId
     * write-back paths on both client and server. */
    if (ret == 0) {
        LmsKey  lblKey[1];
        int     lblInited = 0;
        whKeyId lblId     = WH_KEYID_ERASED;
        byte    label[]   = "wolfHSM LMS key";

        ret = wc_LmsKey_Init(lblKey, NULL, devId);
        if (ret == 0) {
            lblInited = 1;
            ret = wc_LmsKey_SetParameters(lblKey, WH_TEST_LMS_LEVELS,
                                          WH_TEST_LMS_HEIGHT,
                                          WH_TEST_LMS_WINTERNITZ);
        }
        if (ret == 0) {
            ret = wh_Client_LmsMakeKeyDma(ctx, lblKey, &lblId,
                                          WH_NVM_FLAGS_NONE,
                                          (uint16_t)(sizeof(label) - 1), label);
            if (ret != 0) {
                WH_ERROR_PRINT("LMS labeled keygen failed: ret=%d\n", ret);
            }
        }
        if ((ret == 0) && WH_KEYID_ISERASED(lblId)) {
            WH_ERROR_PRINT("LMS labeled keygen returned no keyId\n");
            ret = WH_ERROR_ABORTED;
        }
        /* Keygen is write-through, so erase (cache + NVM) to avoid leaking a
         * committed key. */
        if (!WH_KEYID_ISERASED(lblId)) {
            (void)wh_Client_KeyErase(ctx, lblId);
        }
        if (lblInited) {
            wc_LmsKey_Free(lblKey);
        }
    }

    /* Test that a client must not be able to set the server-only trusted-KEK
     * flag on its own stateful key */
    if (ret == 0) {
        LmsKey  kekKey[1];
        int     kekInited = 0;
        whKeyId kekId     = WH_KEYID_ERASED;

        ret = wc_LmsKey_Init(kekKey, NULL, devId);
        if (ret == 0) {
            kekInited = 1;
            ret       = wc_LmsKey_SetParameters(kekKey, WH_TEST_LMS_LEVELS,
                                                WH_TEST_LMS_HEIGHT,
                                                WH_TEST_LMS_WINTERNITZ);
        }
        if (ret == 0) {
            ret = wh_Client_LmsMakeKeyDma(
                ctx, kekKey, &kekId,
                WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("LMS trusted-flag keygen failed: ret=%d\n", ret);
            }
        }
        /* A surviving WH_NVM_FLAGS_TRUSTED would make this evict
         * WH_ERROR_ACCESS. */
        if ((ret == 0) && !WH_KEYID_ISERASED(kekId)) {
            ret = wh_Client_KeyEvict(ctx, kekId);
            if (ret != 0) {
                WH_ERROR_PRINT("LMS server-only trusted flag not stripped "
                               "(evict ret=%d)\n",
                               ret);
            }
            (void)wh_Client_KeyErase(ctx, kekId);
        }
        if (kekInited) {
            wc_LmsKey_Free(kekKey);
        }
    }

    /* Sign via cryptocb. */
    if (ret == 0) {
        sigLen = sigCap;
        ret = wc_LmsKey_Sign(key, whTest_LmsSigBuf, &sigLen, msg, (int)msgSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed LMS Sign ret=%d\n", ret);
        }
        else if (sigLen != sigCap) {
            WH_ERROR_PRINT("LMS Sign produced unexpected length=%u expected=%u\n",
                           (unsigned)sigLen, (unsigned)sigCap);
            ret = -1;
        }
    }

    /* Verify the signature via cryptocb. */
    if (ret == 0) {
        ret = wc_LmsKey_Verify(key, whTest_LmsSigBuf, sigLen, msg, (int)msgSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed LMS Verify ret=%d\n", ret);
        }
    }

    /* Tampered signature must fail to verify. */
    if (ret == 0) {
        whTest_LmsSigBuf[0] ^= 0xFF;
        ret = wc_LmsKey_Verify(key, whTest_LmsSigBuf, sigLen, msg, (int)msgSz);
        whTest_LmsSigBuf[0] ^= 0xFF;
        if (ret == 0) {
            WH_ERROR_PRINT("LMS Verify unexpectedly accepted tampered sig\n");
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    /* Wrong message must also fail to verify. */
    if (ret == 0) {
        const byte wrongMsg[] = "wolfHSM LMS cryptocb wrong";
        ret = wc_LmsKey_Verify(key, whTest_LmsSigBuf, sigLen, wrongMsg,
                               (int)(sizeof(wrongMsg) - 1));
        if (ret == 0) {
            WH_ERROR_PRINT("LMS Verify unexpectedly accepted wrong message\n");
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    /* H=5 means 32 sigs total; after one sign, the key is still not
     * exhausted. */
    if (ret == 0) {
        if (wc_LmsKey_SigsLeft(key) == 0) {
            WH_ERROR_PRINT("LMS reported exhausted after one sign\n");
            ret = -1;
        }
    }

    /* Verify the public key matches when read back */
    if (ret == 0) {
        whKeyId  pubId     = WH_KEYID_ERASED;
        word32   pubLen    = 0;
        uint8_t  pubBuf[128];
        uint16_t pubBufLen = (uint16_t)sizeof(pubBuf);
        if ((wh_Client_LmsGetKeyId(key, &pubId) == 0) &&
            !WH_KEYID_ISERASED(pubId) &&
            (wc_LmsKey_GetPubLen(key, &pubLen) == 0) &&
            (pubLen <= sizeof(pubBuf))) {
            int pubRet = wh_Client_KeyExportPublic(ctx, pubId, WH_KEY_ALGO_LMS,
                                                   NULL, 0, pubBuf, &pubBufLen);
            if (pubRet != WH_ERROR_OK) {
                WH_ERROR_PRINT("LMS export pub failed: ret=%d\n", pubRet);
                ret = pubRet;
            }
            else if (((word32)pubBufLen != pubLen) ||
                     (memcmp(pubBuf, key->pub, pubLen) != 0)) {
                WH_ERROR_PRINT("LMS export pub mismatch len=%u expected=%u\n",
                               (unsigned)pubBufLen, (unsigned)pubLen);
                ret = WH_ERROR_ABORTED;
            }
        }
    }

    /* Public-key import: provision a verify-only copy of this key's public
     * half under a new keyId, verify the signature made above against it, and
     * confirm signing with it is refused (no private state). */
    if (ret == 0) {
        LmsKey  pubKey[1];
        int     pubInited = 0;
        word32  pubLen    = 0;
        uint8_t pubRaw[128];
        whKeyId pubKeyId  = WH_KEYID_ERASED;
        int     vres      = 0;

        ret = wc_LmsKey_GetPubLen(key, &pubLen);
        if ((ret == 0) && (pubLen > sizeof(pubRaw))) {
            ret = BUFFER_E;
        }
        if (ret == 0) {
            ret = wc_LmsKey_ExportPubRaw(key, pubRaw, &pubLen);
        }
        if (ret == 0) {
            ret = wc_LmsKey_Init(pubKey, NULL, devId);
        }
        if (ret == 0) {
            pubInited = 1;
            ret = wc_LmsKey_SetParameters(pubKey, WH_TEST_LMS_LEVELS,
                                          WH_TEST_LMS_HEIGHT,
                                          WH_TEST_LMS_WINTERNITZ);
        }
        if (ret == 0) {
            ret = wc_LmsKey_ImportPubRaw(pubKey, pubRaw, pubLen);
        }
        /* EPHEMERAL keeps it cache-only for an easy cleanup; production would
         * pin with WH_NVM_FLAGS_NONMODIFIABLE and commit. */
        if (ret == 0) {
            ret = wh_Client_LmsImportPubKey(ctx, pubKey, &pubKeyId,
                                            WH_NVM_FLAGS_EPHEMERAL, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("LMS import pub failed: ret=%d\n", ret);
            }
        }
        if (ret == 0) {
            ret = wh_Client_LmsVerifyDma(ctx, whTest_LmsSigBuf, sigLen, msg,
                                         msgSz, &vres, pubKey);
            if ((ret == 0) && (vres != 1)) {
                WH_ERROR_PRINT("LMS verify with imported pub failed\n");
                ret = WH_ERROR_ABORTED;
            }
        }
        if (ret == 0) {
            word32 tmpSigLen = (word32)sizeof(whTest_LmsSigBuf);
            int    signRet =
                wh_Client_LmsSignDma(ctx, msg, msgSz, whTest_LmsSigBuf,
                                     &tmpSigLen, pubKey);
            if (signRet == 0) {
                WH_ERROR_PRINT("LMS sign with verify-only key unexpectedly "
                               "succeeded\n");
                ret = WH_ERROR_ABORTED;
            }
        }
        if (!WH_KEYID_ISERASED(pubKeyId)) {
            (void)wh_Client_KeyEvict(ctx, pubKeyId);
        }
        if (pubInited) {
            wc_LmsKey_Free(pubKey);
        }
    }

    /* The generic export API must refuse to return the private key state.
     * Keygen forces WH_NVM_FLAGS_NONEXPORTABLE, so export of the resident
     * key is denied with WH_ERROR_ACCESS. */
    if (ret == 0) {
        whKeyId  exportId = WH_KEYID_ERASED;
        uint8_t  expBuf[256];
        uint16_t expLen   = (uint16_t)sizeof(expBuf);
        if ((wh_Client_LmsGetKeyId(key, &exportId) == 0) &&
            !WH_KEYID_ISERASED(exportId)) {
            int expRet =
                wh_Client_KeyExport(ctx, exportId, NULL, 0, expBuf, &expLen);
            if (expRet != WH_ERROR_ACCESS) {
                WH_ERROR_PRINT("LMS export not blocked: ret=%d "
                               "(expected WH_ERROR_ACCESS)\n", expRet);
                ret = (expRet == 0) ? WH_ERROR_ABORTED : expRet;
            }
        }
    }

    /* Attempt to import an LMS key which must be rejected */
    if (ret == 0) {
        uint8_t  fakeBlob[64];
        uint32_t lmsMagic = 0x4C4D5301u; /* 'LMS\1', see wh_crypto.c */
        whKeyId  impId    = WH_KEYID_ERASED;
        int      impRet;
        memset(fakeBlob, 0, sizeof(fakeBlob));
        memcpy(fakeBlob, &lmsMagic, sizeof(lmsMagic));
        fakeBlob[6] = 1; /* privLen field nonzero: a private-bearing blob */
        impRet = wh_Client_KeyCache(ctx, 0, NULL, 0, fakeBlob,
                                    (uint16_t)sizeof(fakeBlob), &impId);
        if (impRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("LMS blob import not blocked: ret=%d "
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
        uint32_t lmsMagic = 0x4C4D5301u; /* 'LMS\1', see wh_crypto.c */
        int32_t  addRc    = 0;
        int      addRet;
        whNvmId  addId    = 0x1042; /* An arbitrary ID in the NVM range */
        memset(fakeBlob, 0, sizeof(fakeBlob));
        memcpy(fakeBlob, &lmsMagic, sizeof(lmsMagic));
        fakeBlob[6] = 1; /* privLen field nonzero: a private-bearing blob */
        addRet = wh_Client_NvmAddObject(ctx, addId, WH_NVM_ACCESS_ANY,
                                        WH_NVM_FLAGS_NONE, 0, NULL,
                                        (whNvmSize)sizeof(fakeBlob), fakeBlob,
                                        &addRc);
        if ((addRet != WH_ERROR_OK) || (addRc != WH_ERROR_ACCESS)) {
            WH_ERROR_PRINT("LMS blob NVM import not blocked: ret=%d rc=%d "
                           "(expected rc WH_ERROR_ACCESS)\n", addRet,
                           (int)addRc);
            ret = (addRc != 0) ? addRc : WH_ERROR_ABORTED;
        }
    }

    if (keyInited) {
        whKeyId evictId = WH_KEYID_ERASED;
        if ((wh_Client_LmsGetKeyId(key, &evictId) == 0) &&
            !WH_KEYID_ISERASED(evictId)) {
            int evictRet = wh_Client_KeyEvict(ctx, evictId);
            if ((evictRet != 0) && (ret == 0)) {
                WH_ERROR_PRINT("Failed LMS evict keyId=0x%X ret=%d\n",
                               (unsigned)evictId, evictRet);
                ret = evictRet;
            }
        }
        wc_LmsKey_Free(key);
    }

    if (ret == 0) {
        WH_TEST_PRINT("LMS CryptoCb DEVID=0x%X SUCCESS\n", devId);
    }

    return ret;
}
#endif /* WOLFHSM_CFG_DMA && WOLFSSL_HAVE_LMS && !WOLFSSL_LMS_VERIFY_ONLY */

#if defined(WOLFHSM_CFG_DMA) && \
    defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)
/* "XMSS-SHA2_10_256" is the smallest standardized XMSS parameter set
 * (height 10, 1024 signatures). pubLen=68, sigLen=2500. */
#define WH_TEST_XMSS_PARAM_STR "XMSS-SHA2_10_256"
static byte whTest_XmssSigBuf[2500];

static int whTestCrypto_XmssCryptoCb(whClientContext* ctx, int devId,
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

    /* Direct DMA keygen with a label and a caller-visible keyId. The cryptocb
     * keygen above passes neither, so this drives the label-copy and keyId
     * write-back paths on both client and server. */
    if (ret == 0) {
        XmssKey lblKey[1];
        int     lblInited = 0;
        whKeyId lblId     = WH_KEYID_ERASED;
        byte    label[]   = "wolfHSM XMSS key";

        ret = wc_XmssKey_Init(lblKey, NULL, devId);
        if (ret == 0) {
            lblInited = 1;
            ret = wc_XmssKey_SetParamStr(lblKey, WH_TEST_XMSS_PARAM_STR);
        }
        if (ret == 0) {
            ret = wh_Client_XmssMakeKeyDma(ctx, lblKey, &lblId,
                                           WH_NVM_FLAGS_NONE,
                                           (uint16_t)(sizeof(label) - 1), label);
            if (ret != 0) {
                WH_ERROR_PRINT("XMSS labeled keygen failed: ret=%d\n", ret);
            }
        }
        if ((ret == 0) && WH_KEYID_ISERASED(lblId)) {
            WH_ERROR_PRINT("XMSS labeled keygen returned no keyId\n");
            ret = WH_ERROR_ABORTED;
        }
        /* Keygen is write-through, so erase (cache + NVM) to avoid leaking a
         * committed key. */
        if (!WH_KEYID_ISERASED(lblId)) {
            (void)wh_Client_KeyErase(ctx, lblId);
        }
        if (lblInited) {
            wc_XmssKey_Free(lblKey);
        }
    }

    /* Test that keygen must strip a client-supplied server-only flags */
    if (ret == 0) {
        XmssKey kekKey[1];
        int     kekInited = 0;
        whKeyId kekId     = WH_KEYID_ERASED;

        ret = wc_XmssKey_Init(kekKey, NULL, devId);
        if (ret == 0) {
            kekInited = 1;
            ret       = wc_XmssKey_SetParamStr(kekKey, WH_TEST_XMSS_PARAM_STR);
        }
        if (ret == 0) {
            ret = wh_Client_XmssMakeKeyDma(
                ctx, kekKey, &kekId,
                WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("XMSS trusted-flag keygen failed: ret=%d\n",
                               ret);
            }
        }
        /* A surviving WH_NVM_FLAGS_TRUSTED would make this evict
         * WH_ERROR_ACCESS. */
        if ((ret == 0) && !WH_KEYID_ISERASED(kekId)) {
            ret = wh_Client_KeyEvict(ctx, kekId);
            if (ret != 0) {
                WH_ERROR_PRINT("XMSS server-only trusted flag not stripped "
                               "(evict ret=%d)\n",
                               ret);
            }
            (void)wh_Client_KeyErase(ctx, kekId);
        }
        if (kekInited) {
            wc_XmssKey_Free(kekKey);
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
#endif /* WOLFHSM_CFG_DMA && WOLFSSL_HAVE_XMSS && !WOLFSSL_XMSS_VERIFY_ONLY */

/* Test key usage policy enforcement for various crypto operations */
int whTest_CryptoKeyUsagePolicies(whClientContext* client, WC_RNG* rng)
{
    int      ret            = 0;
    uint8_t  plaintext[16]  = {0};
    uint8_t  ciphertext[16] = {0};
    uint8_t  key[32]        = {0};
    uint32_t keyLen         = sizeof(key);
    whKeyId  keyId          = WH_KEYID_ERASED;

    WH_TEST_PRINT("Testing Key Usage Policies...\n");

    /* Generate random test data */
    ret = wc_RNG_GenerateBlock(rng, plaintext, sizeof(plaintext));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate random data: %d\n", ret);
        return ret;
    }

    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate random key: %d\n", ret);
        return ret;
    }

#ifndef NO_AES
#ifdef HAVE_AES_CBC
    /* AES encrypt without ENCRYPT flag */
    WH_TEST_PRINT("  Testing AES CBC encrypt without ENCRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};

        /* Cache key WITHOUT encrypt flag */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"aes-no-enc", strlen("aes-no-enc"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            /* Initialize AES with HSM device ID */
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                /* Set the cached keyId (not raw key material) */
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    /* Set IV */
                    ret = wc_AesSetIV(aes, iv);
                    if (ret == 0) {
                        /* Try to encrypt - should fail with WH_ERROR_USAGE */
                        ret = wc_AesCbcEncrypt(aes, ciphertext, plaintext,
                                               sizeof(plaintext));
                        if (ret == WH_ERROR_USAGE) {
                            WH_TEST_PRINT("    PASS: Correctly denied encryption\n");
                            ret = 0; /* Test passed */
                        }
                        else {
                            WH_ERROR_PRINT(
                                "    FAIL: Expected WH_ERROR_USAGE, got %d\n",
                                ret);
                            ret = WH_ERROR_ABORTED;
                        }
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }

    /* AES decrypt without DECRYPT flag */
    WH_TEST_PRINT("  Testing AES CBC decrypt without DECRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        uint8_t decrypted[16]      = {0};
        uint8_t tempCipher[16]     = {0};

        /* First, create some ciphertext using a key with ENCRYPT flag */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"aes-enc-only",
                                   strlen("aes-enc-only"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesSetIV(aes, iv);
                    if (ret == 0) {
                        /* Encrypt to create ciphertext */
                        ret = wc_AesCbcEncrypt(aes, tempCipher, plaintext,
                                               sizeof(plaintext));
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }

        if (ret == 0) {
            /* Now cache same key WITHOUT decrypt flag */
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                  client,
                  WH_NVM_FLAGS_USAGE_ENCRYPT, /* Only ENCRYPT, no DECRYPT */
                  (uint8_t*)"aes-no-dec", strlen("aes-no-dec"), key, keyLen,
                  &keyId);
            if (ret == 0) {
                /* Initialize AES with HSM device ID */
                ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
                if (ret == 0) {
                    /* Set the cached keyId */
                    ret = wh_Client_AesSetKeyId(aes, keyId);
                    if (ret == 0) {
                        /* Set IV */
                        ret = wc_AesSetIV(aes, iv);
                        if (ret == 0) {
                            /* Try to decrypt - should fail with WH_ERROR_USAGE
                             */
                            ret = wc_AesCbcDecrypt(aes, decrypted, tempCipher,
                                                   sizeof(tempCipher));
                            if (ret == WH_ERROR_USAGE) {
                                WH_TEST_PRINT(
                                    "    PASS: Correctly denied decryption\n");
                                ret = 0; /* Test passed */
                            }
                            else {
                                WH_ERROR_PRINT("    FAIL: Expected "
                                               "WH_ERROR_USAGE, got %d\n",
                                               ret);
                                ret = WH_ERROR_ABORTED;
                            }
                        }
                    }
                    wc_AesFree(aes);
                }
                wh_Client_KeyEvict(client, keyId);
            }
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
    /* AES-CTR: encrypt without ENCRYPT flag */
    WH_TEST_PRINT("  Testing AES CTR encrypt without ENCRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        uint8_t ctrCipher[16]      = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"ctr-no-enc", strlen("ctr-no-enc"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesSetIV(aes, iv);
                }
                if (ret == 0) {
                    ret = wh_Client_AesCtr(client, aes, 1, plaintext,
                                           sizeof(plaintext), ctrCipher);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied encryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }

    /* AES-CTR: decrypt without DECRYPT flag */
    WH_TEST_PRINT("  Testing AES CTR decrypt without DECRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        uint8_t ctrOut[16]         = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"ctr-no-dec", strlen("ctr-no-dec"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesSetIV(aes, iv);
                }
                if (ret == 0) {
                    ret = wh_Client_AesCtr(client, aes, 0, ciphertext,
                                           sizeof(ciphertext), ctrOut);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied decryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
    /* AES-ECB: encrypt without ENCRYPT flag */
    WH_TEST_PRINT("  Testing AES ECB encrypt without ENCRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t ecbCipher[16] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"ecb-no-enc", strlen("ecb-no-enc"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesEcbEncrypt(aes, ecbCipher, plaintext,
                                           sizeof(plaintext));
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied encryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }

    /* AES-ECB: decrypt without DECRYPT flag */
    WH_TEST_PRINT("  Testing AES ECB decrypt without DECRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t ecbOut[16] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"ecb-no-dec", strlen("ecb-no-dec"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesEcbDecrypt(aes, ecbOut, ciphertext,
                                           sizeof(ciphertext));
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied decryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AESGCM
    /* AES-GCM: encrypt without ENCRYPT flag */
    WH_TEST_PRINT("  Testing AES GCM encrypt without ENCRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t gcmIv[12]     = {0};
        uint8_t gcmCipher[16] = {0};
        uint8_t gcmTag[16]    = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"gcm-no-enc", strlen("gcm-no-enc"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesGcmEncrypt(aes, gcmCipher, plaintext,
                                           sizeof(plaintext), gcmIv,
                                           sizeof(gcmIv), gcmTag, sizeof(gcmTag),
                                           NULL, 0);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied encryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }

    /* AES-GCM: decrypt without DECRYPT flag */
    WH_TEST_PRINT("  Testing AES GCM decrypt without DECRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t gcmIv[12]  = {0};
        uint8_t gcmOut[16] = {0};
        uint8_t gcmTag[16] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"gcm-no-dec", strlen("gcm-no-dec"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesGcmDecrypt(aes, gcmOut, ciphertext,
                                           sizeof(ciphertext), gcmIv,
                                           sizeof(gcmIv), gcmTag, sizeof(gcmTag),
                                           NULL, 0);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied decryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* HAVE_AESGCM */

#ifdef WOLFHSM_CFG_DMA
#ifdef WOLFSSL_AES_COUNTER
    /* AES-CTR DMA: encrypt without ENCRYPT flag */
    WH_TEST_PRINT("  Testing AES CTR DMA encrypt without ENCRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        uint8_t ctrCipher[16]      = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"dctr-no-enc",
                                   strlen("dctr-no-enc"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesSetIV(aes, iv);
                }
                if (ret == 0) {
                    ret = wh_Client_AesCtrDma(client, aes, 1, plaintext,
                                              sizeof(plaintext), ctrCipher);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied encryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }

    /* AES-CTR DMA: decrypt without DECRYPT flag */
    WH_TEST_PRINT("  Testing AES CTR DMA decrypt without DECRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        uint8_t ctrOut[16]         = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"dctr-no-dec",
                                   strlen("dctr-no-dec"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesSetIV(aes, iv);
                }
                if (ret == 0) {
                    ret = wh_Client_AesCtrDma(client, aes, 0, ciphertext,
                                              sizeof(ciphertext), ctrOut);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied decryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
    /* AES-ECB DMA: encrypt without ENCRYPT flag */
    WH_TEST_PRINT("  Testing AES ECB DMA encrypt without ENCRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t ecbCipher[16] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"decb-no-enc",
                                   strlen("decb-no-enc"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wh_Client_AesEcbDma(client, aes, 1, plaintext,
                                              sizeof(plaintext), ecbCipher);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied encryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }

    /* AES-ECB DMA: decrypt without DECRYPT flag */
    WH_TEST_PRINT("  Testing AES ECB DMA decrypt without DECRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t ecbOut[16] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"decb-no-dec",
                                   strlen("decb-no-dec"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wh_Client_AesEcbDma(client, aes, 0, ciphertext,
                                              sizeof(ciphertext), ecbOut);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied decryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
    /* AES-CBC DMA: encrypt without ENCRYPT flag */
    WH_TEST_PRINT("  Testing AES CBC DMA encrypt without ENCRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        uint8_t cbcCipher[16]      = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"dcbc-no-enc",
                                   strlen("dcbc-no-enc"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesSetIV(aes, iv);
                }
                if (ret == 0) {
                    ret = wh_Client_AesCbcDma(client, aes, 1, plaintext,
                                              sizeof(plaintext), cbcCipher);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied encryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }

    /* AES-CBC DMA: decrypt without DECRYPT flag */
    WH_TEST_PRINT("  Testing AES CBC DMA decrypt without DECRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        uint8_t cbcOut[16]         = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"dcbc-no-dec",
                                   strlen("dcbc-no-dec"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesSetIV(aes, iv);
                }
                if (ret == 0) {
                    ret = wh_Client_AesCbcDma(client, aes, 0, ciphertext,
                                              sizeof(ciphertext), cbcOut);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied decryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
    /* AES-GCM DMA: encrypt without ENCRYPT flag */
    WH_TEST_PRINT("  Testing AES GCM DMA encrypt without ENCRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t gcmIv[12]     = {0};
        uint8_t gcmCipher[16] = {0};
        uint8_t gcmTag[16]    = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"dgcm-no-enc",
                                   strlen("dgcm-no-enc"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wh_Client_AesGcmDma(client, aes, 1, plaintext,
                                              sizeof(plaintext), gcmIv,
                                              sizeof(gcmIv), NULL, 0,
                                              NULL, gcmTag, sizeof(gcmTag),
                                              gcmCipher);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied encryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }

    /* AES-GCM DMA: decrypt without DECRYPT flag */
    WH_TEST_PRINT("  Testing AES GCM DMA decrypt without DECRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t gcmIv[12]  = {0};
        uint8_t gcmOut[16] = {0};
        uint8_t gcmTag[16] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"dgcm-no-dec",
                                   strlen("dgcm-no-dec"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    /* dec_tag must be non-NULL for decrypt direction */
                    ret = wh_Client_AesGcmDma(client, aes, 0, ciphertext,
                                              sizeof(ciphertext), gcmIv,
                                              sizeof(gcmIv), NULL, 0,
                                              gcmTag, NULL, sizeof(gcmTag),
                                              gcmOut);
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied decryption\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* HAVE_AESGCM */
#endif /* WOLFHSM_CFG_DMA */

#endif /* !NO_AES */

#ifdef HAVE_ECC
#ifdef HAVE_ECC_SIGN
    /* ECDSA sign without SIGN flag */
    WH_TEST_PRINT("  Testing ECDSA sign without SIGN flag...\n");
    {
        ecc_key eccKey[1];
        uint8_t sig[ECC_MAX_SIG_SIZE]       = {0};
        word32  sigLen                      = sizeof(sig);
        uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};

        /* Generate key on server and cache it WITHOUT sign flag */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_EccMakeCacheKey(
              client, 32, ECC_SECP256R1, &keyId, WH_NVM_FLAGS_NONE,
              strlen("ecc-no-sign"), (uint8_t*)"ecc-no-sign");
        if (ret == 0) {
            /* Initialize ecc_key with HSM device ID and set curve */
            ret = wc_ecc_init_ex(eccKey, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wc_ecc_set_curve(eccKey, 32, ECC_SECP256R1);
                if (ret == 0) {
                    /* Associate the cached keyId with this ecc_key */
                    ret = wh_Client_EccSetKeyId(eccKey, keyId);
                    if (ret == 0) {
                        /* Generate a hash to sign */
                        ret = wc_RNG_GenerateBlock(rng, hash, sizeof(hash));
                        if (ret == 0) {
                            /* Try to sign - should fail with WH_ERROR_USAGE */
                            ret = wc_ecc_sign_hash(hash, sizeof(hash), sig,
                                                   &sigLen, rng, eccKey);
                            if (ret == WH_ERROR_USAGE) {
                                WH_TEST_PRINT("    PASS: Correctly denied signing\n");
                                ret = 0; /* Test passed */
                            }
                            else {
                                WH_ERROR_PRINT("    FAIL: Expected "
                                               "WH_ERROR_USAGE, got %d\n",
                                               ret);
                                ret = WH_ERROR_ABORTED;
                            }
                        }
                    }
                }
                wc_ecc_free(eccKey);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_DHE
    /* ECDH without DERIVE flag */
    WH_TEST_PRINT("  Testing ECDH without DERIVE flag...\n");
    {
        ecc_key privKey[1];
        ecc_key pubKey[1];
        uint8_t sharedSecret[ECC_MAXSIZE] = {0};
        word32  secretLen                 = sizeof(sharedSecret);

        /* Generate private key on server WITHOUT derive flag */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_EccMakeCacheKey(
              client, 32, ECC_SECP256R1, &keyId, WH_NVM_FLAGS_NONE,
              strlen("ecc-no-derive"), (uint8_t*)"ecc-no-derive");
        if (ret == 0) {
            /* Initialize private key with HSM device ID and set curve */
            ret = wc_ecc_init_ex(privKey, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wc_ecc_set_curve(privKey, 32, ECC_SECP256R1);
                if (ret == 0) {
                    /* Associate the cached keyId with private key */
                    ret = wh_Client_EccSetKeyId(privKey, keyId);
                }
                if (ret == 0) {
                    const byte qx[] = {
                        0xbb, 0x33, 0xac, 0x4c, 0x27, 0x50, 0x4a, 0xc6,
                        0x4a, 0xa5, 0x04, 0xc3, 0x3c, 0xde, 0x9f, 0x36,
                        0xdb, 0x72, 0x2d, 0xce, 0x94, 0xea, 0x2b, 0xfa,
                        0xcb, 0x20, 0x09, 0x39, 0x2c, 0x16, 0xe8, 0x61
                    };
                    const byte qy[] = {
                        0x02, 0xe9, 0xaf, 0x4d, 0xd3, 0x02, 0x93, 0x9a,
                        0x31, 0x5b, 0x97, 0x92, 0x21, 0x7f, 0xf0, 0xcf,
                        0x18, 0xda, 0x91, 0x11, 0x02, 0x34, 0x86, 0xe8,
                        0x20, 0x58, 0x33, 0x0b, 0x80, 0x34, 0x89, 0xd8
                    };
                    int curveId = ECC_SECP256R1;

                    /* Generate a public key locally for ECDH */
                    ret = wc_ecc_init_ex(pubKey, NULL, INVALID_DEVID);
                    if (ret == 0) {
                        /* Import public key */
                        ret = wc_ecc_import_unsigned(pubKey, qx, qy, NULL, curveId);
                        if (ret == 0) {
                            /* Try ECDH - should fail with WH_ERROR_USAGE */
                            ret = wc_ecc_shared_secret(
                                privKey, pubKey, sharedSecret, &secretLen);
                            if (ret == WH_ERROR_USAGE) {
                                WH_TEST_PRINT("    PASS: Correctly denied key "
                                       "derivation\n");
                                ret = 0; /* Test passed */
                            }
                            else {
                                WH_ERROR_PRINT("    FAIL: Expected "
                                               "WH_ERROR_USAGE, got %d\n",
                                               ret);
                                ret = WH_ERROR_ABORTED;
                            }
                        }
                        wc_ecc_free(pubKey);
                    }
                }
                wc_ecc_free(privKey);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* HAVE_ECC_DHE */
#endif /* HAVE_ECC */

#ifdef HAVE_HKDF
    /* HKDF without DERIVE flag */
    WH_TEST_PRINT("  Testing HKDF without DERIVE flag...\n");
    {
        uint8_t ikm[32]  = {0};
        whKeyId outKeyId = WH_KEYID_ERASED;

        ret = wc_RNG_GenerateBlock(rng, ikm, sizeof(ikm));
        if (ret == 0) {
            /* Cache IKM without DERIVE flag */
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                  client, WH_NVM_FLAGS_NONE, (uint8_t*)"hkdf-no-derive",
                  strlen("hkdf-no-derive"), ikm, sizeof(ikm), &keyId);
            if (ret == 0) {
                /* Try HKDF using cached key - should fail */
                ret = wh_Client_HkdfMakeCacheKey(
                    client, WC_SHA256, keyId, NULL, 0, /* Use cached key */
                    NULL, 0,                           /* salt */
                    NULL, 0,                           /* info */
                    &outKeyId,                         /* output key ID */
                    WH_NVM_FLAGS_EPHEMERAL, (uint8_t*)"hkdf-out",
                    strlen("hkdf-out"), 32); /* output size */
                if (ret == WH_ERROR_USAGE) {
                    WH_TEST_PRINT("    PASS: Correctly denied HKDF derivation\n");
                    ret = 0; /* Test passed */
                }
                else {
                    WH_ERROR_PRINT(
                        "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                    ret = WH_ERROR_ABORTED;
                }
                wh_Client_KeyEvict(client, keyId);
                if (!WH_KEYID_ISERASED(outKeyId)) {
                    wh_Client_KeyEvict(client, outKeyId);
                }
            }
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* HAVE_HKDF */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    /* CMAC Generate without SIGN flag */
    WH_TEST_PRINT("  Testing CMAC generate without SIGN flag...\n");
    {
        Cmac    cmac;
        whKeyId keyId = WH_KEYID_ERASED;
        uint8_t message[64];
        uint8_t tag[AES_BLOCK_SIZE];
        word32  tagLen = sizeof(tag);

        /* Generate random message */
        ret = wc_RNG_GenerateBlock(rng, message, sizeof(message));
        if (ret == 0) {
            /* Cache AES key without SIGN flag */
            ret = wh_Client_KeyCache(
                client, WH_NVM_FLAGS_NONE, (uint8_t*)"cmac-no-sign",
                strlen("cmac-no-sign"), key, AES_128_KEY_SIZE, &keyId);
        }

        if (ret == 0) {
            /* Initialize CMAC with HSM device ID */
            ret = wc_InitCmac_ex(&cmac, NULL, 0, WC_CMAC_AES, NULL, NULL,
                                 WH_CLIENT_DEVID(client));
            if (ret == 0) {
                /* Associate cached key */
                ret = wh_Client_CmacSetKeyId(&cmac, keyId);
                if (ret == 0) {
                    /* Try to generate CMAC - should fail */
                    ret = wc_AesCmacGenerate_ex(&cmac, tag, &tagLen, message,
                                                sizeof(message), NULL, 0, NULL,
                                                WH_CLIENT_DEVID(client));
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied CMAC generate\n");
                        ret = 0; /* Test passed */
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_CmacFree(&cmac);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }

    /* CMAC Verify without VERIFY flag */
    WH_TEST_PRINT("  Testing CMAC verify without VERIFY flag...\n");
    {
        Cmac    cmac;
        whKeyId keyId = WH_KEYID_ERASED;
        uint8_t message[64];
        uint8_t tag[AES_BLOCK_SIZE];
        word32  tagLen = sizeof(tag);

        /* Generate random message and tag */
        ret = wc_RNG_GenerateBlock(rng, message, sizeof(message));
        if (ret == 0) {
            ret = wc_RNG_GenerateBlock(rng, tag, sizeof(tag));
        }

        if (ret == 0) {
            /* Cache AES key without VERIFY flag */
            ret = wh_Client_KeyCache(
                client, WH_NVM_FLAGS_NONE, (uint8_t*)"cmac-no-verify",
                strlen("cmac-no-verify"), key, AES_128_KEY_SIZE, &keyId);
        }

        if (ret == 0) {
            /* Initialize CMAC with HSM device ID */
            ret = wc_InitCmac_ex(&cmac, NULL, 0, WC_CMAC_AES, NULL, NULL,
                                 WH_CLIENT_DEVID(client));
            if (ret == 0) {
                /* Associate cached key */
                ret = wh_Client_CmacSetKeyId(&cmac, keyId);
                if (ret == 0) {
                    /* Try to verify CMAC - should fail */
                    ret = wc_AesCmacVerify_ex(&cmac, tag, tagLen, message,
                                              sizeof(message), NULL, 0, NULL,
                                              WH_CLIENT_DEVID(client));
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT("    PASS: Correctly denied CMAC verify\n");
                        ret = 0; /* Test passed */
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_CmacFree(&cmac);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#ifdef WOLFHSM_CFG_KEYWRAP
    /* Key wrap without WRAP flag */
    WH_TEST_PRINT("  Testing key wrap without WRAP flag...\n");
    {
        uint8_t       kek[32]         = {0};
        uint8_t       dataKey[32]     = {0};
        uint8_t       wrappedKey[256] = {0};
        uint16_t      wrappedKeySz    = sizeof(wrappedKey);
        whKeyId       kekId           = WH_KEYID_ERASED;
        const whKeyId wrappedId       = 1;
        whNvmMetadata meta            = {0};

        ret = wc_RNG_GenerateBlock(rng, kek, sizeof(kek));
        if (ret == 0) {
            ret = wc_RNG_GenerateBlock(rng, dataKey, sizeof(dataKey));
        }

        if (ret == 0) {
            /* Cache KEK without WRAP flag */
            ret = wh_Client_KeyCache(
                client, WH_NVM_FLAGS_NONE, (uint8_t*)"kek-no-wrap",
                strlen("kek-no-wrap"), kek, sizeof(kek), &kekId);
            if (ret == 0) {
                /* Setup metadata for data key */
                meta.id = WH_CLIENT_KEYID_MAKE_WRAPPED_META(
                    client->comm->client_id, wrappedId);
                meta.flags = WH_NVM_FLAGS_NONE;
                meta.len   = sizeof(dataKey);

                /* Try to wrap - should fail */
                ret = wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, kekId,
                                        dataKey, sizeof(dataKey), &meta,
                                        wrappedKey, &wrappedKeySz);
                if (ret == WH_ERROR_USAGE) {
                    WH_TEST_PRINT("    PASS: Correctly denied key wrapping\n");
                    ret = 0; /* Test passed */
                }
                else {
                    WH_ERROR_PRINT(
                        "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                    ret = WH_ERROR_ABORTED;
                }
                wh_Client_KeyEvict(client, kekId);
            }
        }
    }
    if (ret != 0) {
        return ret;
    }
#endif /* WOLFHSM_CFG_KEYWRAP */

    WH_TEST_PRINT("Key Usage Policy Tests PASSED\n");
    return 0;
}

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS)
int _testRevocationTryAESEncrypt(whClientContext* client, whKeyId keyId,
                                 WC_RNG* rng, int* encryptRes)
{
    int     ret;
    Aes     aes[1];
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t plaintext[16];
    uint8_t ciphertext[16] = {0};
    /* generate random iv and plaintext */
    ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(rng, plaintext, sizeof(plaintext));
    }
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate AES revocation test inputs: %d\n",
                       ret);
        return ret;
    }
    /* try to encrypt with the given keyId */
    ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to init AES for revoked key test: %d\n", ret);
        return ret;
    }
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set AES keyId for revoked key test: %d\n",
                       ret);
        wc_AesFree(aes);
        return ret;
    }
    ret = wc_AesSetIV(aes, iv);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set AES IV for revoked key test: %d\n", ret);
        wc_AesFree(aes);
        return ret;
    }
    ret =
        wc_AesCbcEncrypt(aes, ciphertext, plaintext, (word32)sizeof(plaintext));
    wc_AesFree(aes);
    *encryptRes = ret;
    return WH_ERROR_OK;
}

int whTest_CryptoKeyRevocationAesCbc(whClientContext* client, WC_RNG* rng)
{
    int ret = 0;

    WH_TEST_PRINT("Testing Key Revocation...\n");

    {
        /* AES-CBC: revoked keys should be unusable and non-erasable */
        uint8_t       key[32]          = {0};
        const uint8_t label[]          = "revocation-aes-cbc";
        whKeyId       keyId            = WH_KEYID_ERASED;
        const int     expectedEraseErr = WH_ERROR_ACCESS;
        int           encryptRes       = 0;

        ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate AES revocation inputs: %d\n",
                           ret);
            return ret;
        }

        WH_TEST_PRINT("  AES-CBC key revoke flow...\n");

        ret =
            wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ANY, (uint8_t*)label,
                               sizeof(label), key, sizeof(key), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache AES key: %d\n", ret);
            return ret;
        }

        /* encrypt should work */
        ret = _testRevocationTryAESEncrypt(client, keyId, rng, &encryptRes);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to encrypt with unrevoked AES key: %d\n",
                           ret);
            (void)wh_Client_KeyEvict(client, keyId);
            return ret;
        }

        if (encryptRes != 0) {
            WH_ERROR_PRINT("Encrypt with unrevoked AES key failed: %d\n",
                           encryptRes);
            return encryptRes;
        }

        /* revoke a key in the cache */
        ret = wh_Client_KeyRevoke(client, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to revoke AES key: %d\n", ret);
            return ret;
        }

        /* now encrypt should fail */
        ret = _testRevocationTryAESEncrypt(client, keyId, rng, &encryptRes);
        if (ret != 0 || encryptRes != WH_ERROR_USAGE) {
            WH_ERROR_PRINT(
                "Encrypt with revoked AES key should fail (%d), got %d\n",
                WH_ERROR_USAGE, encryptRes);
            return WH_ERROR_ABORTED;
        }

        /* commit the key */
        ret = wh_Client_KeyCommit(client, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to commit revoked AES key: %d\n", ret);
            return ret;
        }

        /* keep failing */
        ret = _testRevocationTryAESEncrypt(client, keyId, rng, &encryptRes);
        if (ret != 0 || encryptRes != WH_ERROR_USAGE) {
            WH_ERROR_PRINT(
                "Encrypt with revoked AES key should fail (%d), got %d\n",
                WH_ERROR_USAGE, encryptRes);
            return WH_ERROR_ABORTED;
        }

        ret = wh_Client_KeyErase(client, keyId);
        if (ret != expectedEraseErr) {
            WH_ERROR_PRINT("Revoked key erase should fail (%d), got %d\n",
                           expectedEraseErr, ret);
            return WH_ERROR_ABORTED;
        }

        /* try a slightly different flow */
        keyId = WH_KEYID_ERASED;
        ret =
            wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ANY, (uint8_t*)label,
                               sizeof(label), key, sizeof(key), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache AES key (2nd time): %d\n", ret);
            return ret;
        }
        /* commit the key */
        ret = wh_Client_KeyCommit(client, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to commit AES key (2nd time): %d\n", ret);
            return ret;
        }
        /* try encrypt first */
        ret = _testRevocationTryAESEncrypt(client, keyId, rng, &encryptRes);
        if (ret != 0 || encryptRes != 0) {
            WH_ERROR_PRINT("Failed to encrypt with unrevoked AES key (2nd "
                           "time): %d\n",
                           ret);
            (void)wh_Client_KeyEvict(client, keyId);
            return ret != 0 ? ret : encryptRes;
        }
        /* evict the key */
        ret = wh_Client_KeyEvict(client, keyId);
        if (ret != 0 && ret != WH_ERROR_NOTFOUND) {
            WH_ERROR_PRINT("Failed to evict AES key (2nd time): %d\n", ret);
            return ret;
        }
        /* revoke with key in the NVM */
        ret = wh_Client_KeyRevoke(client, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to revoke AES key (2nd time): %d\n", ret);
            return ret;
        }
        /* this should still fail */
        ret = _testRevocationTryAESEncrypt(client, keyId, rng, &encryptRes);
        if (ret != 0 || encryptRes != WH_ERROR_USAGE) {
            WH_ERROR_PRINT(
                "Encrypt with revoked AES key should fail (%d), got %d\n",
                WH_ERROR_USAGE, encryptRes);
            (void)wh_Client_KeyEvict(client, keyId);
            return WH_ERROR_ABORTED;
        }


        WH_TEST_PRINT("  AES-CBC revocation enforcement: PASS\n");
    }

    return ret;
}
#endif /* !NO_AES && HAVE_AES_CBC && \
          WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS */

/* Negative tests: every cache-and-export keygen function must reject
 * WH_NVM_FLAGS_EPHEMERAL, a NULL inout_key_id, and a NULL pub with
 * WH_ERROR_BADARGS, before contacting the server. level is passed as 0 for the
 * PQC calls since the argument guards run before any level validation. */
static int whTest_CryptoMakeCacheKeyExportPublicArgs(whClientContext* ctx)
{
    int     ret   = 0;
    whKeyId keyId = WH_KEYID_ERASED;

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    {
        RsaKey rsa[1] = {0};
        if (wh_Client_RsaMakeCacheKeyAndExportPublic(
                ctx, 2048, WC_RSA_EXPONENT, &keyId, WH_NVM_FLAGS_EPHEMERAL, 0,
                NULL, rsa) != WH_ERROR_BADARGS ||
            wh_Client_RsaMakeCacheKeyAndExportPublic(
                NULL, 2048, WC_RSA_EXPONENT, &keyId, WH_NVM_FLAGS_NONE, 0, NULL,
                rsa) != WH_ERROR_BADARGS ||
            wh_Client_RsaMakeCacheKeyAndExportPublic(
                ctx, 2048, WC_RSA_EXPONENT, NULL, WH_NVM_FLAGS_NONE, 0, NULL,
                rsa) != WH_ERROR_BADARGS ||
            wh_Client_RsaMakeCacheKeyAndExportPublic(
                ctx, 2048, WC_RSA_EXPONENT, &keyId, WH_NVM_FLAGS_NONE, 0, NULL,
                NULL) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("RSA cache-export arg validation failed\n");
            ret = -1;
        }
    }
#endif
#ifdef HAVE_ECC
    if (ret == 0) {
        ecc_key ecc[1] = {0};
        if (wh_Client_EccMakeCacheKeyAndExportPublic(
                ctx, 32, ECC_SECP256R1, &keyId, WH_NVM_FLAGS_EPHEMERAL, 0, NULL,
                ecc) != WH_ERROR_BADARGS ||
            wh_Client_EccMakeCacheKeyAndExportPublic(
                NULL, 32, ECC_SECP256R1, &keyId, WH_NVM_FLAGS_NONE, 0, NULL,
                ecc) != WH_ERROR_BADARGS ||
            wh_Client_EccMakeCacheKeyAndExportPublic(
                ctx, 32, ECC_SECP256R1, NULL, WH_NVM_FLAGS_NONE, 0, NULL,
                ecc) != WH_ERROR_BADARGS ||
            wh_Client_EccMakeCacheKeyAndExportPublic(
                ctx, 32, ECC_SECP256R1, &keyId, WH_NVM_FLAGS_NONE, 0, NULL,
                NULL) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("ECC cache-export arg validation failed\n");
            ret = -1;
        }
    }
#endif
#ifdef HAVE_CURVE25519
    if (ret == 0) {
        curve25519_key cv[1] = {0};
        if (wh_Client_Curve25519MakeCacheKeyAndExportPublic(
                ctx, CURVE25519_KEYSIZE, &keyId, WH_NVM_FLAGS_EPHEMERAL, NULL, 0,
                cv) != WH_ERROR_BADARGS ||
            wh_Client_Curve25519MakeCacheKeyAndExportPublic(
                ctx, CURVE25519_KEYSIZE, NULL, WH_NVM_FLAGS_NONE, NULL, 0,
                cv) != WH_ERROR_BADARGS ||
            wh_Client_Curve25519MakeCacheKeyAndExportPublic(
                ctx, CURVE25519_KEYSIZE, &keyId, WH_NVM_FLAGS_NONE, NULL, 0,
                NULL) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Curve25519 cache-export arg validation failed\n");
            ret = -1;
        }
    }
#endif
#ifdef HAVE_ED25519
    if (ret == 0) {
        ed25519_key ed[1] = {0};
        if (wh_Client_Ed25519MakeCacheKeyAndExportPublic(
                ctx, &keyId, WH_NVM_FLAGS_EPHEMERAL, 0, NULL, ed) !=
                WH_ERROR_BADARGS ||
            wh_Client_Ed25519MakeCacheKeyAndExportPublic(
                ctx, NULL, WH_NVM_FLAGS_NONE, 0, NULL, ed) != WH_ERROR_BADARGS ||
            wh_Client_Ed25519MakeCacheKeyAndExportPublic(
                ctx, &keyId, WH_NVM_FLAGS_NONE, 0, NULL, NULL) !=
                WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Ed25519 cache-export arg validation failed\n");
            ret = -1;
        }
    }
#endif
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
    if (ret == 0) {
        wc_MlDsaKey mldsa[1] = {0};
        if (wh_Client_MlDsaMakeCacheKeyAndExportPublic(
                ctx, 0, 0, &keyId, WH_NVM_FLAGS_EPHEMERAL, 0, NULL, mldsa) !=
                WH_ERROR_BADARGS ||
            wh_Client_MlDsaMakeCacheKeyAndExportPublic(
                ctx, 0, 0, NULL, WH_NVM_FLAGS_NONE, 0, NULL, mldsa) !=
                WH_ERROR_BADARGS ||
            wh_Client_MlDsaMakeCacheKeyAndExportPublic(
                ctx, 0, 0, &keyId, WH_NVM_FLAGS_NONE, 0, NULL, NULL) !=
                WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("ML-DSA cache-export arg validation failed\n");
            ret = -1;
        }
#ifdef WOLFHSM_CFG_DMA
        if (ret == 0 &&
            (wh_Client_MlDsaMakeCacheKeyDma(
                 ctx, 0, &keyId, WH_NVM_FLAGS_EPHEMERAL, 0, NULL, mldsa) !=
                 WH_ERROR_BADARGS ||
             wh_Client_MlDsaMakeCacheKeyDma(
                 ctx, 0, NULL, WH_NVM_FLAGS_NONE, 0, NULL, mldsa) !=
                 WH_ERROR_BADARGS ||
             wh_Client_MlDsaMakeCacheKeyDma(
                 ctx, 0, &keyId, WH_NVM_FLAGS_NONE, 0, NULL, NULL) !=
                 WH_ERROR_BADARGS)) {
            WH_ERROR_PRINT("ML-DSA DMA cache-export arg validation failed\n");
            ret = -1;
        }
#endif /* WOLFHSM_CFG_DMA */
    }
#endif /* WOLFSSL_MLDSA_PUBLIC_KEY */
#ifdef WOLFSSL_HAVE_MLKEM
    if (ret == 0) {
        MlKemKey mlkem[1] = {0};
        if (wh_Client_MlKemMakeCacheKeyAndExportPublic(
                ctx, 0, &keyId, WH_NVM_FLAGS_EPHEMERAL, 0, NULL, mlkem) !=
                WH_ERROR_BADARGS ||
            wh_Client_MlKemMakeCacheKeyAndExportPublic(
                ctx, 0, NULL, WH_NVM_FLAGS_NONE, 0, NULL, mlkem) !=
                WH_ERROR_BADARGS ||
            wh_Client_MlKemMakeCacheKeyAndExportPublic(
                ctx, 0, &keyId, WH_NVM_FLAGS_NONE, 0, NULL, NULL) !=
                WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("ML-KEM cache-export arg validation failed\n");
            ret = -1;
        }
#ifdef WOLFHSM_CFG_DMA
        if (ret == 0 &&
            (wh_Client_MlKemMakeCacheKeyDma(
                 ctx, 0, &keyId, WH_NVM_FLAGS_EPHEMERAL, 0, NULL, mlkem) !=
                 WH_ERROR_BADARGS ||
             wh_Client_MlKemMakeCacheKeyDma(
                 ctx, 0, NULL, WH_NVM_FLAGS_NONE, 0, NULL, mlkem) !=
                 WH_ERROR_BADARGS ||
             wh_Client_MlKemMakeCacheKeyDma(
                 ctx, 0, &keyId, WH_NVM_FLAGS_NONE, 0, NULL, NULL) !=
                 WH_ERROR_BADARGS)) {
            WH_ERROR_PRINT("ML-KEM DMA cache-export arg validation failed\n");
            ret = -1;
        }
#endif /* WOLFHSM_CFG_DMA */
    }
#endif /* WOLFSSL_HAVE_MLKEM */

    if (ret == 0) {
        WH_TEST_PRINT("KEYGEN-EXPORT-PUBLIC ARG VALIDATION SUCCESS\n");
    }
    return ret;
}

/* WH_TEST_DMA_MODE_CNT (number of cryptoCb dispatch modes to exercise) is
 * provided by wh_test_common.h */

int whTest_CryptoClientConfig(whClientConfig* config)
{
    int i;
    int rngInited = 0;
    whClientContext client[1] = {0};
    int ret = 0;
    /* wolfcrypt */
    WC_RNG rng[1];

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));

    ret = wh_Client_CommInit(client, NULL, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to comm init:%d\n", ret);
    }

    if (ret == 0) {
#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
        int serverRc;

        /* Attempt log in as an admin user for the rest of the tests */
        WH_TEST_RETURN_ON_FAIL(wh_Client_AuthLogin(
            client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME, TEST_ADMIN_PIN,
            strlen(TEST_ADMIN_PIN), &serverRc, NULL));
#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION */
    }

#ifdef WOLFHSM_CFG_DEBUG_VERBOSE
    if (ret == 0) {
        (void)whTest_ShowNvmAvailable(client);
    }
#endif /* WOLFHSM_CFG_DEBUG_VERBOSE */

    /* Run RNG first, exercising each DMA dispatch mode (std and, when compiled,
     * DMA-preferred) on the single per-client devId before the remaining tests
     * settle on a default mode. */
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_TEST_DMA_MODE_CNT)) {
        int dmaMode = -1;
        /* Exercise RNG through both dispatch modes (std and, if compiled,
         * DMA-preferred) on the single per-client devId. */
        (void)wh_Client_SetDmaMode(client, i);
        /* Round-trip the dispatch mode through the getter (reports 0 in
         * non-DMA builds, where this loop only runs mode 0) */
        ret = wh_Client_GetDmaMode(client, &dmaMode);
        if ((ret == WH_ERROR_OK) && (dmaMode != i)) {
            WH_ERROR_PRINT("GetDmaMode returned %d after SetDmaMode(%d)\n",
                           dmaMode, i);
            ret = WH_ERROR_ABORTED;
        }
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoRng(client, WH_CLIENT_DEVID(client), rng);
        }
        if (ret == WH_ERROR_OK) {
            wc_FreeRng(rng);
            i++;
        }
    }

    /* Direct exercise of the async RNG primitives (does not go through the
     * wolfCrypt callback path, so DMA mode is not relevant). */
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoRngAsync(client);
    }
#ifdef WOLFHSM_CFG_DMA
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoRngDmaAsync(client);
    }
#endif /* WOLFHSM_CFG_DMA */

    /* The remaining once-run tests below historically used the non-DMA devId;
     * select the std (non-DMA) dispatch mode for them. Reinitialize the default
     * RNG used by the rest of the tests for random input generation. */
    if (ret == 0) {
        (void)wh_Client_SetDmaMode(client, 0);
        ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(client));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to reinitialize RNG %d\n", ret);
        }
        else {
            rngInited = 1;
        }
    }

    if (ret == 0) {
        /* Test Key Cache functions */
        ret = whTest_KeyCache(client, WH_CLIENT_DEVID(client), rng);
    }

    if (ret == 0) {
        /* Test server-side key generation from RNG */
        ret = whTest_KeyCacheRandom(client, WH_DEV_ID, rng);
    }

    if (ret == 0) {
        /* Test Non-Exportable Flag enforcement on keystore */
        ret =
            whTest_NonExportableKeystore(client, WH_CLIENT_DEVID(client), rng);
    }

    if (ret == 0) {
        /* Test Key Usage Policy enforcement */
        ret = whTest_CryptoKeyUsagePolicies(client, rng);
    }

#ifdef WOLFHSM_CFG_KEYWRAP
    if (ret == 0) {
        ret = whTest_Client_KeyWrap(client);
    }
    if (ret == 0) {
        ret = whTest_Client_DataWrap(client);
    }
#if defined(WOLFHSM_CFG_HWKEYSTORE) && defined(WOLFHSM_CFG_ENABLE_SERVER)
    /* Hardware-only KEK tests need the in-process test server, which binds
     * the test hardware keystore; external (client-only) servers may not */
    if (ret == 0) {
        ret = whTest_Client_HwKeystore(client);
    }
#endif
#endif

#ifndef NO_AES
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_TEST_DMA_MODE_CNT)) {
        (void)wh_Client_SetDmaMode(client, i);
        ret = whTestCrypto_Aes(client, WH_CLIENT_DEVID(client), rng);
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoAesAsync(client, WH_CLIENT_DEVID(client), rng);
        }
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoAesAsyncKat(client, WH_CLIENT_DEVID(client));
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    /* Dedicated async DMA tests drive the wh_Client_*Dma APIs directly; prefer
     * DMA so any wolfCrypt-routed operations also take the DMA path. */
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoAesDmaAsync(client, WH_CLIENT_DEVID(client), rng);
    }
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoAesDmaAsyncKat(client, WH_CLIENT_DEVID(client));
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* !NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_TEST_DMA_MODE_CNT)) {
        (void)wh_Client_SetDmaMode(client, i);
        ret = whTestCrypto_Cmac(client, WH_CLIENT_DEVID(client), rng);
        if (ret == WH_ERROR_OK) {
            ret = whTestCrypto_CmacAsync(client, WH_CLIENT_DEVID(client), rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == WH_ERROR_OK) {
        ret = whTestCrypto_CmacDmaAsync(client, WH_CLIENT_DEVID(client), rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

    /* Once-run public-key tests use the std (non-DMA) dispatch mode. */
    (void)wh_Client_SetDmaMode(client, 0);
    if (ret == 0) {
        ret = whTest_CryptoMakeCacheKeyExportPublicArgs(client);
    }

#ifndef NO_RSA
    if (ret == 0) {
        ret = whTest_CryptoRsa(client, WH_CLIENT_DEVID(client), rng);
    }
    if (ret == 0) {
        ret = whTest_CryptoRsaAsync(client, rng);
    }
#endif /* NO_RSA */

#ifdef HAVE_ECC
    (void)wh_Client_SetDmaMode(client, 0);
    if (ret == 0) {
        ret = whTest_CryptoEcc(client, WH_CLIENT_DEVID(client), rng);
    }
    if (ret == 0) {
        ret = whTest_CryptoEccCacheDuplicate(client);
    }
#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    if (ret == 0) {
        ret = whTest_CryptoEccCrossVerify(client, rng);
    }
    if (ret == 0) {
        ret = whTest_CryptoEccAsync(client, rng);
    }
#endif
#ifdef WOLFHSM_CFG_DMA
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == 0) {
        ret = whTest_CryptoEccExportPublicDma(client, WH_CLIENT_DEVID(client),
                                              rng);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "ECC export-public DMA test failed: %d\n", ret);
        }
    }
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
    if (ret != 0) {
        WH_ERROR_PRINT("Pre-Ed25519 tests ret=%d\n", ret);
        return ret;
    }
    (void)wh_Client_SetDmaMode(client, 0);
    if (ret == 0) {
        ret = whTest_CryptoEd25519Inline(client, WH_CLIENT_DEVID(client), rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 inline test failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret =
            whTest_CryptoEd25519ServerKey(client, WH_CLIENT_DEVID(client), rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 server key test failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = whTest_CryptoEd25519ExportPublic(client, WH_CLIENT_DEVID(client),
                                               rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 export-public test failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = whTest_CryptoEd25519CacheKeyAndExportPublic(
            client, WH_CLIENT_DEVID(client), rng);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Ed25519 cache-and-export-public test failed: %d\n", ret);
        }
    }
#ifdef WOLFHSM_CFG_DMA
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == 0) {
        ret = whTest_CryptoEd25519Dma(client, WH_CLIENT_DEVID(client), rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 DMA test failed: %d\n", ret);
        }
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_ED25519 */

#ifdef HAVE_CURVE25519
    /* test curve25519 (std/non-DMA dispatch mode) */
    (void)wh_Client_SetDmaMode(client, 0);
    if (ret == 0) {
        ret = whTest_CryptoCurve25519(client, WH_CLIENT_DEVID(client), rng);
    }
    if (ret == 0) {
        ret = whTest_CryptoCurve25519SharedSecretCacheKey(
            client, WH_CLIENT_DEVID(client), rng);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Curve25519 shared-secret cache-key test failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = whTest_CryptoCurve25519ExportPublic(client,
                                                  WH_CLIENT_DEVID(client), rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Curve25519 export-public test failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = whTest_CryptoCurve25519CacheKeyAndExportPublic(
            client, WH_CLIENT_DEVID(client), rng);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Curve25519 cache-and-export-public test failed: %d\n", ret);
        }
    }
#endif /* HAVE_CURVE25519 */

#ifndef NO_SHA256
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_TEST_DMA_MODE_CNT)) {
        (void)wh_Client_SetDmaMode(client, i);
        ret = whTest_CryptoSha256(client, WH_CLIENT_DEVID(client), rng);
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoSha256LargeInput(client, WH_CLIENT_DEVID(client),
                                                rng);
        }
        if (ret == WH_ERROR_OK) {
            ret =
                whTest_CryptoSha256Async(client, WH_CLIENT_DEVID(client), rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoSha256DmaAsync(client, WH_CLIENT_DEVID(client), rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA224
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_TEST_DMA_MODE_CNT)) {
        (void)wh_Client_SetDmaMode(client, i);
        ret = whTest_CryptoSha224(client, WH_CLIENT_DEVID(client), rng);
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoSha224LargeInput(client, WH_CLIENT_DEVID(client),
                                                rng);
        }
        if (ret == WH_ERROR_OK) {
            ret =
                whTest_CryptoSha224Async(client, WH_CLIENT_DEVID(client), rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoSha224DmaAsync(client, WH_CLIENT_DEVID(client), rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_TEST_DMA_MODE_CNT)) {
        (void)wh_Client_SetDmaMode(client, i);
        ret = whTest_CryptoSha384(client, WH_CLIENT_DEVID(client), rng);
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoSha384LargeInput(client, WH_CLIENT_DEVID(client),
                                                rng);
        }
        if (ret == WH_ERROR_OK) {
            ret =
                whTest_CryptoSha384Async(client, WH_CLIENT_DEVID(client), rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoSha384DmaAsync(client, WH_CLIENT_DEVID(client), rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_TEST_DMA_MODE_CNT)) {
        (void)wh_Client_SetDmaMode(client, i);
        ret = whTest_CryptoSha512(client, WH_CLIENT_DEVID(client), rng);
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoSha512LargeInput(client, WH_CLIENT_DEVID(client),
                                                rng);
        }
        if (ret == WH_ERROR_OK) {
            ret =
                whTest_CryptoSha512Async(client, WH_CLIENT_DEVID(client), rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoSha512DmaAsync(client, WH_CLIENT_DEVID(client), rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA512 */

#if defined(WOLFSSL_SHA3)
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_TEST_DMA_MODE_CNT)) {
        (void)wh_Client_SetDmaMode(client, i);
        ret = whTest_CryptoSha3(client, WH_CLIENT_DEVID(client), rng);
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoSha3Async(client, WH_CLIENT_DEVID(client), rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoSha3DmaAsync(client, WH_CLIENT_DEVID(client), rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA3 */

#ifdef HAVE_HKDF
    (void)wh_Client_SetDmaMode(client, 0);
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoHkdf(client, WH_CLIENT_DEVID(client), rng);
    }
#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
    (void)wh_Client_SetDmaMode(client, 0);
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoCmacKdf(client, WH_CLIENT_DEVID(client), rng);
    }
#endif /* HAVE_CMAC_KDF */

#ifdef WOLFSSL_HAVE_MLDSA

#if !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
    !defined(WOLFSSL_MLDSA_NO_SIGN) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_NO_ML_DSA_44)

    /* Exercise the ML-DSA client/server tests at every enabled security
     * level (44/65/87). */
    {
        const int mldsaLevels[] = {
#ifndef WOLFSSL_NO_ML_DSA_44
            WC_ML_DSA_44,
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
            WC_ML_DSA_65,
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
            WC_ML_DSA_87,
#endif
        };
        const int mldsaLevelCnt =
            (int)(sizeof(mldsaLevels) / sizeof(mldsaLevels[0]));
        int li;

        for (li = 0; (ret == 0) && (li < mldsaLevelCnt); li++) {
            int level = mldsaLevels[li];

            for (i = 0; (ret == WH_ERROR_OK) && (i < WH_TEST_DMA_MODE_CNT);
                 i++) {
#ifdef WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY
                /* Large-data DMA-only: exercise the DMA-preferred mode only */
                if (i != 1) {
                    continue;
                }
#endif /* WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY */
                (void)wh_Client_SetDmaMode(client, i);
                ret = whTestCrypto_MlDsaWolfCrypt(
                    client, WH_CLIENT_DEVID(client), rng, level);
            }

            (void)wh_Client_SetDmaMode(client, 0);
            if (ret == 0) {
                ret = whTestCrypto_MlDsaClient(client, WH_CLIENT_DEVID(client),
                                               rng, level);
            }

#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
            if (ret == 0) {
                ret = whTestCrypto_MlDsaExportPublic(
                    client, WH_CLIENT_DEVID(client), rng, level);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "ML-DSA export-public test failed (level %d): %d\n",
                        level, ret);
                }
            }
            if (ret == 0) {
                ret = whTestCrypto_MlDsaCacheKeyAndExportPublic(
                    client, WH_CLIENT_DEVID(client), rng, level);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "ML-DSA cache-and-export-public test failed "
                        "(level %d): %d\n",
                        level, ret);
                }
            }
#endif

#ifdef WOLFHSM_CFG_DMA
            (void)wh_Client_SetDmaMode(client, 1);
            if (ret == 0) {
                ret = whTestCrypto_MlDsaDmaClient(
                    client, WH_CLIENT_DEVID(client), rng, level);
            }
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
            if (ret == 0) {
                ret = whTestCrypto_MlDsaExportPublicDma(
                    client, WH_CLIENT_DEVID(client), rng, level);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "ML-DSA export-public DMA test failed (level %d): "
                        "%d\n",
                        level, ret);
                }
            }
            if (ret == 0) {
                ret = whTestCrypto_MlDsaCacheKeyAndExportPublicDma(
                    client, WH_CLIENT_DEVID(client), rng, level);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "ML-DSA cache-and-export-public DMA test failed "
                        "(level %d): %d\n",
                        level, ret);
                }
            }
#endif
#endif /* WOLFHSM_CFG_DMA*/
        }
    }
#endif /* !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
          !defined(WOLFSSL_MLDSA_NO_SIGN) && \
          !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) */

#if !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
    !defined(WOLFSSL_NO_ML_DSA_44) && \
    defined(WOLFHSM_CFG_DMA)
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == 0) {
        ret = whTestCrypto_MlDsaVerifyOnlyDma(client, WH_CLIENT_DEVID(client),
                                              rng);
    }
#endif /* !defined(WOLFSSL_MLDSA_NO_VERIFY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) && \
          defined(WOLFHSM_CFG_DMA) */

#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM
#if !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) &&    \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
    i = 0;
    while (ret == WH_ERROR_OK && i < WH_TEST_DMA_MODE_CNT) {
#ifdef WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY
        /* Large-data DMA-only: exercise the DMA-preferred mode only */
        if (i != 1) {
            i++;
            continue;
        }
#endif /* WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY */
        (void)wh_Client_SetDmaMode(client, i);
        ret = whTestCrypto_MlKemWolfCrypt(client, WH_CLIENT_DEVID(client), rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }

    (void)wh_Client_SetDmaMode(client, 0);
    if (ret == 0) {
        ret = whTestCrypto_MlKemClient(client, WH_CLIENT_DEVID(client), rng);
    }

    if (ret == 0) {
        ret = whTestCrypto_MlKemExportPublic(client, WH_CLIENT_DEVID(client),
                                             rng);
        if (ret != 0) {
            WH_ERROR_PRINT("ML-KEM export-public test failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = whTestCrypto_MlKemCacheKeyAndExportPublic(
            client, WH_CLIENT_DEVID(client), rng);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "ML-KEM cache-and-export-public test failed: %d\n", ret);
        }
    }

#ifdef WOLFHSM_CFG_DMA
    (void)wh_Client_SetDmaMode(client, 1);
    if (ret == 0) {
        ret = whTestCrypto_MlKemDmaClient(client, WH_CLIENT_DEVID(client), rng);
    }
    if (ret == 0) {
        ret = whTestCrypto_MlKemExportPublicDma(client, WH_CLIENT_DEVID(client),
                                                rng);
        if (ret != 0) {
            WH_ERROR_PRINT("ML-KEM export-public DMA test failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = whTestCrypto_MlKemCacheKeyAndExportPublicDma(
            client, WH_CLIENT_DEVID(client), rng);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "ML-KEM cache-and-export-public DMA test failed: %d\n", ret);
        }
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) &&    \
          !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
          !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) */
#endif /* WOLFSSL_HAVE_MLKEM */

#if defined(WOLFHSM_CFG_DMA) && \
    defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
    if (ret == 0) {
        ret = whTestCrypto_LmsCryptoCb(client, WH_DEV_ID_DMA, rng);
    }
#endif

#if defined(WOLFHSM_CFG_DMA) && \
    defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)
    if (ret == 0) {
        ret = whTestCrypto_XmssCryptoCb(client, WH_DEV_ID_DMA, rng);
    }
#endif

#ifdef WOLFHSM_CFG_DEBUG_VERBOSE
    if (ret == 0) {
        (void)whTest_ShowNvmAvailable(client);
    }
#endif /* WOLFHSM_CFG_DEBUG_VERBOSE */

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS)
    /* keep last, leaves artifact in the NVM layer */
    if (ret == 0) {
        /* The DMA-only groups above don't restore the dispatch mode; reset to
         * the std path so this test runs the same way in every config. */
        (void)wh_Client_SetDmaMode(client, 0);
        /* Test key revocation */
        ret = whTest_CryptoKeyRevocationAesCbc(client, rng);
    }
#endif

    /* Clean up used resources */
    if (rngInited) {
        (void)wc_FreeRng(rng);
    }
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);

    if (ret != 0) {
        WH_ERROR_PRINT("whTest_CryptoClientConfig returning error: %d\n", ret);
    }

    return ret;
}
#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#ifndef NO_WOLFHSM_CFG_TEST_CRYPTSVR_CFG
int whTest_CryptoServerConfig(whServerConfig* config)
{
    whServerContext server[1] = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int ret = 0;
#ifdef WOLFHSM_CFG_IS_TEST_SERVER
    int userChange = 0;
#endif

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }


    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, config));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));
    server->comm->client_id = WH_TEST_DEFAULT_CLIENT_ID;

    while(am_connected == WH_COMM_CONNECTED) {
#ifdef WOLFHSM_CFG_IS_TEST_SERVER
        while (serverDelay == 1) {
#ifdef WOLFHSM_CFG_TEST_POSIX
            sleep(1);
#endif
        }
#endif
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) &&
                (ret != WH_ERROR_OK)) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n",
                           ret);
            break;
        }
        wh_Server_GetConnected(server, &am_connected);

#ifdef WOLFHSM_CFG_IS_TEST_SERVER
        /* keep alive for 2 user changes */
        if (am_connected != WH_COMM_CONNECTED && userChange < 2) {
            if (userChange == 0)
                server->comm->client_id = ALT_CLIENT_ID;
            else if (userChange == 1)
                server->comm->client_id = WH_TEST_DEFAULT_CLIENT_ID;
            userChange++;
            am_connected = WH_COMM_CONNECTED;
            WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));
        }
#endif /* WOLFHSM_CFG_IS_TEST_SERVER */
    }

    if ((ret == 0) || (ret == WH_ERROR_NOTREADY)) {
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    } else {
        ret = wh_Server_Cleanup(server);
    }

    return ret;
}
#endif /* NO_WOLFHSM_CFG_TEST_CRYPTSVR_CFG */
#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    !defined(WOLFHSM_CFG_TEST_CLIENT_ONLY)
static void* _whClientTask(void *cf)
{
    int rc = whTest_CryptoClientConfig(cf);
    if (rc != 0) {
        WH_ERROR_PRINT("whTest_CryptoClientConfig returned %d\n", rc);
    }
    WH_TEST_ASSERT(0 == rc);
    return NULL;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_SERVER)
static void* _whServerTask(void* cf)
{
    WH_TEST_ASSERT(0 == whTest_CryptoServerConfig(cf));
    return NULL;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)


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


static int wh_ClientServer_MemThreadTest(whTestNvmBackendType nvmType)
{
    int     ret               = 0;
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
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};

#ifdef WOLFHSM_CFG_DMA
    /* In-process (shared address space) test: prefer DMA by default so the DMA
     * dispatch paths are exercised. The orchestrator toggles this per-group via
     * wh_Client_SetDmaMode() to exercise both the standard and DMA paths. Every
     * crypto/cert *Dma op is also routed through the bounce-pool callback so a
     * missing translation is rejected (see test/wh_test_dma.c); the
     * use-after-free class is covered by the single-thread harness. */
    whClientDmaConfig clientDmaConfig = {
        .cb        = whTestDma_BounceClientCb,
        .preferDma = 1,
    };
#endif
    whClientConfig c_conf[1] = {{
        .comm = cc_conf,
#ifdef WOLFHSM_CFG_DMA
        .dmaConfig = &clientDmaConfig,
#endif
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
    uint8_t memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1] = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE, /* 1MB  Flash */
        .sectorSize = FLASH_SECTOR_SIZE,  /* 128KB  Sector Size */
        .pageSize   = FLASH_PAGE_SIZE,           /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
        .memory     = memory,
    }};
    const whFlashCb  fcb[1]          = {WH_FLASH_RAMSIM_CB};

    whTestNvmBackendUnion nvm_setup;
    whNvmConfig           n_conf[1] = {0};
    whNvmContext nvm[1] = {{0}};

    WH_TEST_RETURN_ON_FAIL(
        whTest_NvmCfgBackend(nvmType, &nvm_setup, n_conf, fc_conf, fc, fcb));

    /* Crypto context */
    whServerCryptoContext crypto[1] = {0};

#ifdef WOLFHSM_CFG_DMA
    /* Server may only touch the bounce pool; this callback rejects an
     * untranslated client pointer. */
    whServerDmaConfig serverDmaConfig = {
        .cb = whTestDma_BounceServerCb,
    };
#endif
#if defined(WOLFHSM_CFG_HWKEYSTORE) && defined(WOLFHSM_CFG_KEYWRAP)
    /* Hardware keystore front-end backed by the test getKey callback. The
     * callback is defined in wh_test_keywrap.c, so only bind it when the
     * keywrap suite (its sole consumer) is compiled in */
    static const whHwKeystoreCb hwksCb        = WH_TEST_HWKEYSTORE_CB;
    whHwKeystoreContext         hwKeystore[1] = {{0}};
    whHwKeystoreConfig          hwksConf[1]   = {{
                   .cb      = &hwksCb,
                   .context = NULL,
    }};
#endif

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .devId       = INVALID_DEVID,
#ifdef WOLFHSM_CFG_DMA
        .dmaConfig   = &serverDmaConfig,
#endif
#if defined(WOLFHSM_CFG_HWKEYSTORE) && defined(WOLFHSM_CFG_KEYWRAP)
        .hwKeystore = hwKeystore,
#endif
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));
#if defined(WOLFHSM_CFG_HWKEYSTORE) && defined(WOLFHSM_CFG_KEYWRAP)
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(hwKeystore, hwksConf));
#endif

#ifdef WOLFHSM_CFG_DMA
    whTestDma_BounceReset();
#endif

    ret = wolfCrypt_Init();
    if (ret == 0) {
        ret = wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to initialize wolfCrypt rng: %d\n", ret);
        }
        else {
            _whClientServerThreadTest(c_conf, s_conf);
#ifdef WOLFHSM_CFG_DMA
            /* After the client thread joins, no mapping may be outstanding and
             * no POST may have hit a stale/unknown slot. */
            if (whTestDma_BounceOutstanding() != 0) {
                WH_ERROR_PRINT("wh_test bounce: %d DMA mapping(s) leaked "
                               "across the crypto suite\n",
                               whTestDma_BounceOutstanding());
                ret = WH_ERROR_ABORTED;
            }
            if (whTestDma_BounceStrayPosts() != 0) {
                WH_ERROR_PRINT("wh_test bounce: %d stray/double DMA POST(s) "
                               "across the crypto suite\n",
                               whTestDma_BounceStrayPosts());
                ret = WH_ERROR_ABORTED;
            }
#endif
        }
    }
    else {
        WH_ERROR_PRINT("Failed to initialize wolfCrypt: %d\n", ret);
    }

    wh_Nvm_Cleanup(nvm);
#if defined(WOLFHSM_CFG_HWKEYSTORE) && defined(WOLFHSM_CFG_KEYWRAP)
    (void)wh_HwKeystore_Cleanup(hwKeystore);
#endif
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    /* Propagate ret (was hard-coded WH_ERROR_OK): surfaces an init failure and
     * the DMA bounce leak check instead of silently passing. */
    return ret;
}
#endif /* WOLFHSM_CFG_TEST_POSIX */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
int whTest_Crypto(void)
{
    WH_TEST_PRINT("Testing crypto: (pthread) mem...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_ClientServer_MemThreadTest(WH_NVM_TEST_BACKEND_FLASH));

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    WH_TEST_PRINT("Testing crypto: (pthread) mem (flash log)...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_ClientServer_MemThreadTest(WH_NVM_TEST_BACKEND_FLASH_LOG));
#endif

    return 0;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
