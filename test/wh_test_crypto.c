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

#include "wh_test_common.h"

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
        ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
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
            ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
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
                        ret = wc_InitRsaKey_ex(rsaFull, NULL, WH_DEV_ID);
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

    if (ret == 0) {
        WH_TEST_PRINT("RSA SUCCESS\n");
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

        ret = wc_ecc_init_ex(bobKey, NULL, WH_DEV_ID);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_ecc_init_ex for export key %d\n", ret);
        }
        else {
            ret = wc_ecc_init_ex(aliceKey, NULL, WH_DEV_ID);
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
            ret = wc_ecc_init_ex(bobKey, NULL, WH_DEV_ID);
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
                    ret = wc_ecc_init_ex(aliceKey, NULL, WH_DEV_ID);
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
    uint8_t hash[TEST_ECC_KEYSIZE] = {0};
    uint8_t sig[ECC_MAX_SIG_SIZE]  = {0};
    word32  sigLen            = sizeof(sig);
    int     verified          = 0;
    byte    derBuf[ECC_BUFSIZE];
    uint16_t derSz            = sizeof(derBuf);
    (void)devId;

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
        ret = wc_ecc_init_ex(hsmKey, NULL, WH_DEV_ID);
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
    ret = wc_ecc_init_ex(hsmKey, NULL, WH_DEV_ID);
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
        ret = wc_ecc_init_ex(hsmKey, NULL, WH_DEV_ID);
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

    ret = wc_ecc_init_ex(hsmKey, NULL, WH_DEV_ID);
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
    ret = wc_ecc_init_ex(keyA, NULL, WH_DEV_ID);
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
        ret = wc_ecc_init_ex(keyB, NULL, WH_DEV_ID);
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

    if (ret == 0) {
        ret = wh_Client_Ed25519ImportKey(
            ctx, key, &signKeyId, WH_NVM_FLAGS_USAGE_SIGN, labelLen, label);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import Ed25519 key to server: %d\n", ret);
        }
        else {
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

    if (ret == 0) {
        if (outSignKeyId != NULL) {
            *outSignKeyId = signKeyId;
        }
        if (outVerifyKeyId != NULL) {
            *outVerifyKeyId = verifyKeyId;
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
        /* Corrupt signature to ensure verification fails */
        sig[0] ^= 0xFF;
        verified = 0;
        ret = wc_ed25519_verify_msg(sig, sigSz, msg, msgSz, &verified, pubKey);
        if (ret == 0 && verified == 1) {
            WH_ERROR_PRINT(
                "Modified Ed25519 signature unexpectedly verified\n");
            ret = -1;
        }
        else {
            ret = 0;
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
        sig[0] ^= 0xAA;
        verified = 0;
        ret      = wh_Client_Ed25519Verify(ctx, pubKey, sig, sigSz, msg,
                                           (uint32_t)sizeof(msg), (uint8_t)Ed25519,
                                           NULL, 0, &verified);
        if (ret == 0 && verified == 1) {
            WH_ERROR_PRINT("Modified server Ed25519 signature unexpectedly "
                           "verified\n");
            ret = -1;
        }
        else {
            ret = 0;
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
        ret = wc_ed25519_init_ex(hsmKey, NULL, WH_DEV_ID);
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
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#ifdef HAVE_DILITHIUM

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
    !defined(WOLFSSL_DILITHIUM_NO_SIGN) &&   \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && !defined(WOLFSSL_NO_ML_DSA_44)
static int whTestCrypto_MlDsaWolfCrypt(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    (void)ctx;

    int ret      = 0;
    int verified = 0;

    /* Test ML DSA key generation, signing and verification */
    MlDsaKey key;
    byte     msg[] = "Test message for ML DSA signing";
    byte     sig[DILITHIUM_ML_DSA_44_SIG_SIZE];
    word32   sigSz = sizeof(sig);

    /* Initialize key */
    ret = wc_MlDsaKey_Init(&key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML DSA key: %d\n", ret);
        return ret;
    }

    /* Set security level to 44-bit */
    ret = wc_MlDsaKey_SetParams(&key, WC_ML_DSA_44);
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
                                    WC_RNG* rng)
{
    (void)devId;
    (void)rng;

    int      ret = 0;
    MlDsaKey key[1];

    /* Initialize key */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML-DSA key: %d\n", ret);
        return ret;
    }

    /* Generate ephemeral key using non-DMA client API */
    if (ret == 0) {
        ret = wh_Client_MlDsaMakeExportKey(ctx, WC_ML_DSA_44, 0, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate ML-DSA key: %d\n", ret);
        }
    }

    /* Test basic sign/verify using the public API (no context) */
    if (ret == 0) {
        byte   msg[] = "Test message for non-DMA ML-DSA";
        byte   sig[DILITHIUM_MAX_SIG_SIZE];
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
        byte       sig[DILITHIUM_MAX_SIG_SIZE];
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

#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY) && \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && !defined(WOLFSSL_NO_ML_DSA_44)
static int whTestCrypto_MlDsaExportPublic(whClientContext* ctx, int devId,
                                          WC_RNG* rng)
{
    (void)rng;

    int      ret    = 0;
    whKeyId  keyId  = WH_KEYID_ERASED;
    MlDsaKey pub[1] = {0};
    /* Large enough to hold an ML-DSA key DER so the access-control assertion
     * doesn't get masked by a buffer-too-small failure. */
    uint8_t  denyBuf[DILITHIUM_MAX_BOTH_KEY_DER_SIZE];
    uint16_t denyLen = sizeof(denyBuf);
    (void)devId;

    /* MakeCacheKey at the smallest supported level, with NONEXPORTABLE. */
    ret = wh_Client_MlDsaMakeCacheKey(
        ctx, 0, WC_ML_DSA_44, &keyId,
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
            ret = wc_MlDsaKey_SetParams(pub, WC_ML_DSA_44);
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
#endif /* WOLFSSL_DILITHIUM_PUBLIC_KEY && ML_DSA_44 available */

#ifdef WOLFHSM_CFG_DMA
static int whTestCrypto_MlDsaDmaClient(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    (void)rng;

    int      ret = 0;
    MlDsaKey key[1];
    MlDsaKey imported_key[1];
    whKeyId  keyId       = WH_KEYID_ERASED;
    uint8_t  label[]     = "ML-DSA Test Key";
    int      keyImported = 0;

    /* Buffers for comparing serialized keys */
    byte   key_der1[DILITHIUM_MAX_PRV_KEY_SIZE];
    byte   key_der2[DILITHIUM_MAX_PRV_KEY_SIZE];
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
        ret = wh_Client_MlDsaMakeExportKeyDma(ctx, WC_ML_DSA_44, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate ML-DSA key using DMA: %d\n",
                           ret);
        }
    }

    /* Serialize the generated key for comparison */
    if (ret == 0) {
        ret = wc_Dilithium_PrivateKeyToDer(key, key_der1, key_der1_len);
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
            wc_Dilithium_PrivateKeyToDer(imported_key, key_der2, key_der2_len);
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
        byte   sig[DILITHIUM_MAX_SIG_SIZE];
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
        byte   sig[DILITHIUM_MAX_SIG_SIZE];
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

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
static int whTestCrypto_MlDsaExportPublicDma(whClientContext* ctx, int devId,
                                             WC_RNG* rng)
{
    (void)rng;
    (void)devId;

    int      ret    = 0;
    whKeyId  keyId  = WH_KEYID_ERASED;
    MlDsaKey pub[1] = {0};
    uint8_t  denyBuf[1];
    uint16_t denyLen = sizeof(denyBuf);

    /* Cache an ML-DSA-44 keypair NONEXPORTABLE on the HSM. */
    ret = wh_Client_MlDsaMakeCacheKey(
        ctx, 0, WC_ML_DSA_44, &keyId,
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
        byte fullBuf[DILITHIUM_MAX_BOTH_KEY_DER_SIZE];
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
            ret = wc_MlDsaKey_SetParams(pub, WC_ML_DSA_44);
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
        byte     dmaDer[DILITHIUM_MAX_PUB_KEY_DER_SIZE];
        byte     nonDmaDer[DILITHIUM_MAX_PUB_KEY_DER_SIZE];
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
#endif /* WOLFSSL_DILITHIUM_PUBLIC_KEY */

#endif /* WOLFHSM_CFG_DMA */
#endif /* !defined(WOLFSSL_DILITHIUM_NO_VERIFY) &&   \
          !defined(WOLFSSL_DILITHIUM_NO_SIGN) &&     \
          !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) */

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
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

    int      ret;
    MlDsaKey key[1];
    whNvmId  keyId    = WH_KEYID_ERASED;
    int      evictKey = 0;

    /* Initialize keys */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML-DSA key: %d\n", ret);
        return ret;
    }
    else {
        ret = wc_dilithium_set_level(key, WC_ML_DSA_44);
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
    /* Import the key into wolfHSM via the wolfCrypt structure */
    if (ret == 0) {
        if (devId == WH_DEV_ID_DMA) {
            ret = wh_Client_MlDsaImportKeyDma(ctx, key, &keyId, 0, 0, NULL);
        }
        else {
            ret = wh_Client_MlDsaImportKey(ctx, key, &keyId, 0, 0, NULL);
        }
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
#endif /* !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) && \
          defined(WOLFHSM_CFG_DMA) */


#endif /* HAVE_DILITHIUM */

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
            ret = wc_AesInit(aes, NULL, WH_DEV_ID);
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
    if (ret != 0)
        return ret;

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
            ret = wc_AesInit(aes, NULL, WH_DEV_ID);
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
                ret = wc_AesInit(aes, NULL, WH_DEV_ID);
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
    if (ret != 0)
        return ret;
#endif /* HAVE_AES_CBC */
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
            ret = wc_ecc_init_ex(eccKey, NULL, WH_DEV_ID);
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
    if (ret != 0)
        return ret;
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
            ret = wc_ecc_init_ex(privKey, NULL, WH_DEV_ID);
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
    if (ret != 0)
        return ret;
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
    if (ret != 0)
        return ret;
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
                                 WH_DEV_ID);
            if (ret == 0) {
                /* Associate cached key */
                ret = wh_Client_CmacSetKeyId(&cmac, keyId);
                if (ret == 0) {
                    /* Try to generate CMAC - should fail */
                    ret = wc_AesCmacGenerate_ex(&cmac, tag, &tagLen, message,
                                                sizeof(message), NULL, 0, NULL,
                                                WH_DEV_ID);
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
    if (ret != 0)
        return ret;

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
                                 WH_DEV_ID);
            if (ret == 0) {
                /* Associate cached key */
                ret = wh_Client_CmacSetKeyId(&cmac, keyId);
                if (ret == 0) {
                    /* Try to verify CMAC - should fail */
                    ret = wc_AesCmacVerify_ex(&cmac, tag, tagLen, message,
                                              sizeof(message), NULL, 0, NULL,
                                              WH_DEV_ID);
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
    if (ret != 0)
        return ret;
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
    if (ret != 0)
        return ret;
#endif /* WOLFHSM_CFG_KEYWRAP */

    WH_TEST_PRINT("Key Usage Policy Tests PASSED\n");
    return 0;
}

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS)
int _testRevocationTryAESEncrypt(whKeyId keyId, WC_RNG* rng, int* encryptRes)
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
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
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
        ret = _testRevocationTryAESEncrypt(keyId, rng, &encryptRes);
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
        ret = _testRevocationTryAESEncrypt(keyId, rng, &encryptRes);
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
        ret = _testRevocationTryAESEncrypt(keyId, rng, &encryptRes);
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
        ret = _testRevocationTryAESEncrypt(keyId, rng, &encryptRes);
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
        ret = _testRevocationTryAESEncrypt(keyId, rng, &encryptRes);
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

    /* First crypto test should be of RNG so we can iterate over and test all
     * devIds before choosing one to run the rest of the tests on */
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoRng(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            wc_FreeRng(rng);
            i++;
        }
    }

    /* Direct exercise of the async RNG primitives (does not go through the
     * wolfCrypt callback path, so devId is not relevant). */
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoRngAsync(client);
    }
#ifdef WOLFHSM_CFG_DMA
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoRngDmaAsync(client);
    }
#endif /* WOLFHSM_CFG_DMA */

    /* Now that we have tested all RNG devIds, reinitialize the default RNG
     * devId (non-DMA) that will be used by the remainder of the tests for
     * random input generation */
    if (ret == 0) {
        ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to reinitialize RNG %d\n", ret);
        }
        else {
            rngInited = 1;
        }
    }

    if (ret == 0) {
        /* Test Key Cache functions */
        ret = whTest_KeyCache(client, WH_DEV_ID, rng);
    }

    if (ret == 0) {
        /* Test Non-Exportable Flag enforcement on keystore */
        ret = whTest_NonExportableKeystore(client, WH_DEV_ID, rng);
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
#endif

#ifndef NO_AES
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTestCrypto_Aes(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#endif /* !NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTestCrypto_Cmac(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#ifndef NO_RSA
    if (ret == 0) {
        ret = whTest_CryptoRsa(client, WH_DEV_ID, rng);
    }
#endif /* NO_RSA */

#ifdef HAVE_ECC
    if (ret == 0) {
        ret = whTest_CryptoEcc(client, WH_DEV_ID, rng);
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
    if (ret == 0) {
        ret = whTest_CryptoEccExportPublicDma(client, WH_DEV_ID_DMA, rng);
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
    if (ret == 0) {
        ret = whTest_CryptoEd25519Inline(client, WH_DEV_ID, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 inline test failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = whTest_CryptoEd25519ServerKey(client, WH_DEV_ID, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 server key test failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = whTest_CryptoEd25519ExportPublic(client, WH_DEV_ID, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 export-public test failed: %d\n", ret);
        }
    }
#ifdef WOLFHSM_CFG_DMA
    if (ret == 0) {
        ret = whTest_CryptoEd25519Dma(client, WH_DEV_ID_DMA, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 DMA test failed: %d\n", ret);
        }
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_ED25519 */

#ifdef HAVE_CURVE25519
    /* test curve25519 */
    if (ret == 0) {
        ret = whTest_CryptoCurve25519(client, WH_DEV_ID, rng);
    }
    if (ret == 0) {
        ret = whTest_CryptoCurve25519ExportPublic(client, WH_DEV_ID, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Curve25519 export-public test failed: %d\n", ret);
        }
    }
#endif /* HAVE_CURVE25519 */

#ifndef NO_SHA256
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoSha256(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            ret =
                whTest_CryptoSha256LargeInput(client, WH_DEV_IDS_ARRAY[i], rng);
        }
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoSha256Async(client, WH_DEV_IDS_ARRAY[i], rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoSha256DmaAsync(client, WH_DEV_ID_DMA, rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA224
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoSha224(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            ret =
                whTest_CryptoSha224LargeInput(client, WH_DEV_IDS_ARRAY[i], rng);
        }
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoSha224Async(client, WH_DEV_IDS_ARRAY[i], rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoSha224DmaAsync(client, WH_DEV_ID_DMA, rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoSha384(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            ret =
                whTest_CryptoSha384LargeInput(client, WH_DEV_IDS_ARRAY[i], rng);
        }
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoSha384Async(client, WH_DEV_IDS_ARRAY[i], rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoSha384DmaAsync(client, WH_DEV_ID_DMA, rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoSha512(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            ret =
                whTest_CryptoSha512LargeInput(client, WH_DEV_IDS_ARRAY[i], rng);
        }
        if (ret == WH_ERROR_OK) {
            ret = whTest_CryptoSha512Async(client, WH_DEV_IDS_ARRAY[i], rng);
        }
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#ifdef WOLFHSM_CFG_DMA
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoSha512DmaAsync(client, WH_DEV_ID_DMA, rng);
    }
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA512 */

#ifdef HAVE_HKDF
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoHkdf(client, WH_DEV_ID, rng);
    }
#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoCmacKdf(client, WH_DEV_ID, rng);
    }
#endif /* HAVE_CMAC_KDF */

#ifdef HAVE_DILITHIUM

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
    !defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_NO_ML_DSA_44)

    i = 0;
    while (ret == WH_ERROR_OK && i < WH_NUM_DEVIDS) {
#ifdef WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY
        if (WH_DEV_IDS_ARRAY[i] != WH_DEV_ID_DMA) {
            i++;
            continue;
        }
#endif /* WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY */
        ret = whTestCrypto_MlDsaWolfCrypt(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }

    if (ret == 0) {
        ret = whTestCrypto_MlDsaClient(client, WH_DEV_ID, rng);
    }

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
    if (ret == 0) {
        ret = whTestCrypto_MlDsaExportPublic(client, WH_DEV_ID, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("ML-DSA export-public test failed: %d\n", ret);
        }
    }
#endif

#ifdef WOLFHSM_CFG_DMA
    if (ret == 0) {
        ret = whTestCrypto_MlDsaDmaClient(client, WH_DEV_ID_DMA, rng);
    }
#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
    if (ret == 0) {
        ret = whTestCrypto_MlDsaExportPublicDma(client, WH_DEV_ID_DMA, rng);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "ML-DSA export-public DMA test failed: %d\n", ret);
        }
    }
#endif
#endif /* WOLFHSM_CFG_DMA*/
#endif /* !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
          !defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
          !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) */

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
    !defined(WOLFSSL_NO_ML_DSA_44) && \
    defined(WOLFHSM_CFG_DMA)
    if (ret == 0) {
        ret = whTestCrypto_MlDsaVerifyOnlyDma(client, WH_DEV_ID_DMA, rng);
    }
#endif /* !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) && \
          defined(WOLFHSM_CFG_DMA) */

#endif /* HAVE_DILITHIUM */

#ifdef WOLFHSM_CFG_DEBUG_VERBOSE
    if (ret == 0) {
        (void)whTest_ShowNvmAvailable(client);
    }
#endif /* WOLFHSM_CFG_DEBUG_VERBOSE */

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS)
    /* keep last, leaves artifact in the NVM layer */
    if (ret == 0) {
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
    whClientDmaConfig clientDmaConfig = {0};
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


    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .devId       = INVALID_DEVID,
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    ret = wolfCrypt_Init();
    if (ret == 0) {
        ret = wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to initialize wolfCrypt rng: %d\n", ret);
        }
        else {
            _whClientServerThreadTest(c_conf, s_conf);
        }
    }
    else {
        WH_ERROR_PRINT("Failed to initialize wolfCrypt: %d\n", ret);
    }

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
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
