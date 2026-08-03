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
 * test/wh_test_she.c
 *
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_server_keystore.h"
#endif

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_she.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_she.h"
#endif

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#endif

#include "wolfhsm/wh_transport_mem.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_she_crypto.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client_she.h"
#endif

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include "wh_test_common.h"
#include "wh_test_keywrap_util.h"
#include "wh_test_she_no_nvm.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <unistd.h> /* For sleep */
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

enum {
    REQ_SIZE    = 32,
    RESP_SIZE   = 64,
    BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                  WOLFHSM_CFG_COMM_DATA_LEN,
};

#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */
#define FLASH_SECTOR_SIZE (128 * 1024) /* 128KB */
#define FLASH_PAGE_SIZE (8) /* 8B */

#ifndef TEST_ADMIN_USERNAME
#define TEST_ADMIN_USERNAME "admin"
#endif
#ifndef TEST_ADMIN_PIN
#define TEST_ADMIN_PIN "1234"
#endif

#if defined(WOLFHSM_CFG_KEYWRAP) && defined(HAVE_AESGCM)
/* Id of the trusted KEK the server task provisions for the SHE<->keywrap
 * interop tests. Defined here so both the client section and the server task
 * can use it. */
#define WH_SHE_INTEROP_KEK_ID 0x20
#endif /* WOLFHSM_CFG_KEYWRAP && HAVE_AESGCM */

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
/* Helper function to destroy a SHE key so the unit tests don't
 * leak NVM objects across invocations. Necessary, as SHE doesn't expose a
 * destroy key API since SHE keys are supposed to be fixed hardware keys */
static int _destroySheKey(whClientContext* client, whNvmId clientSheKeyId)
{
    int rc = 0;
    int32_t serverRc = 0;

    whNvmId id = WH_SHE_MAKE_KEYID(client->comm->client_id, clientSheKeyId);

    rc = wh_Client_NvmDestroyObjects(client, 1, &id, &serverRc);
    if (rc == WH_ERROR_OK) {
        rc = serverRc;
    }

    return rc;
}

int whTest_SheClientConfig(whClientConfig* config)
{
    int ret = 0;
    WC_RNG rng[1];
    Cmac cmac[1];
    whClientContext client[1] = {0};
    uint8_t key[16] = {0};
    uint32_t keySz = sizeof(key);
    uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t plainText[64];
    uint8_t cipherText[64];
    uint8_t finalText[64];
    /* secretKey and prngSeed are taken from SHE test vectors */
    uint8_t sheUid[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t secretKey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab,
        0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t prngSeed[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
        0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t zeros[WH_SHE_BOOT_MAC_PREFIX_LEN] = {0};
    uint8_t bootloader[512];
    uint8_t bootMacDigest[16] = {0};
    uint8_t vectorMasterEcuKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint32_t digestSz = sizeof(bootMacDigest);
    uint32_t bootloaderSz = sizeof(bootloader);
    uint8_t vectorMessageOne[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41};
    uint8_t vectorMessageTwo[] = {0x2b, 0x11, 0x1e, 0x2d, 0x93, 0xf4, 0x86,
        0x56, 0x6b, 0xcb, 0xba, 0x1d, 0x7f, 0x7a, 0x97, 0x97, 0xc9, 0x46, 0x43,
        0xb0, 0x50, 0xfc, 0x5d, 0x4d, 0x7d, 0xe1, 0x4c, 0xff, 0x68, 0x22, 0x03,
        0xc3};
    uint8_t vectorMessageThree[] = {0xb9, 0xd7, 0x45, 0xe5, 0xac, 0xe7, 0xd4,
        0x18, 0x60, 0xbc, 0x63, 0xc2, 0xb9, 0xf5, 0xbb, 0x46};
    uint8_t vectorMessageFour[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41, 0xb4, 0x72, 0xe8,
        0xd8, 0x72, 0x7d, 0x70, 0xd5, 0x72, 0x95, 0xe7, 0x48, 0x49, 0xa2, 0x79,
        0x17};
    uint8_t vectorMessageFive[] = {0x82, 0x0d, 0x8d, 0x95, 0xdc, 0x11, 0xb4,
        0x66, 0x88, 0x78, 0x16, 0x0c, 0xb2, 0xa4, 0xe2, 0x3e};
    uint8_t vectorRawKey[] = {0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t outMessageFour[sizeof(vectorMessageFour)];
    uint8_t outMessageFive[sizeof(vectorMessageFive)];
    uint8_t entropy[] = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e,
        0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    uint8_t sreg;
    uint8_t messageOne[WH_SHE_M1_SZ];
    uint8_t messageTwo[WH_SHE_M2_SZ];
    uint8_t messageThree[WH_SHE_M3_SZ];
    uint8_t messageFour[WH_SHE_M4_SZ];
    uint8_t messageFive[WH_SHE_M5_SZ];
    uint32_t outClientId = 0;
    uint32_t outServerId = 0;
    const uint32_t SHE_TEST_VECTOR_KEY_ID = 4;

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInit(client, &outClientId, &outServerId));

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    /* Attempt log in as an admin user for the rest of the tests */
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthLogin(
        client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME, TEST_ADMIN_PIN,
        strlen(TEST_ADMIN_PIN), &ret, NULL));
#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION */

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

        WH_TEST_DEBUG_PRINT("PRE-SHE TEST: NvmGetAvailable:%d, server_rc:%d avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects,
               (int)reclaim_size, (int)reclaim_objects);
    }

    /* generate a new cmac key */
    if ((ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(client))) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RNG_GenerateBlock(rng, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit;
    }
    /* generate a fake bootloader */
    if ((ret = wc_RNG_GenerateBlock(rng, bootloader, sizeof(bootloader))) != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit;
    }
    /* Done generating test data, free RNG */
    wc_FreeRng(rng);
    /* cmac 0..0 | size | bootloader */
    if ((ret = wc_InitCmac(cmac, key, sizeof(key), WC_CMAC_AES, NULL)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitCmac %d\n", ret);
        goto exit;
    }
    if ((ret = wc_CmacUpdate(cmac, zeros, sizeof(zeros))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }
    if ((ret = wc_CmacUpdate(cmac, (uint8_t*)&bootloaderSz, sizeof(bootloaderSz))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }
    if ((ret = wc_CmacUpdate(cmac, bootloader, sizeof(bootloader))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }
    digestSz = AES_BLOCK_SIZE;
    if ((ret = wc_CmacFinal(cmac, bootMacDigest, (word32*)&digestSz)) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }
    /* store cmac key */
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_BOOT_MAC_KEY_ID, 0, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    /* store cmac digest */
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_BOOT_MAC, 0, bootMacDigest, sizeof(bootMacDigest))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    /* set the she uid */
    if ((ret = wh_Client_SheSetUid(client, sheUid, sizeof(sheUid))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheSetUid %d\n", ret);
        goto exit;
    }
    /* verify bootloader */
    if ((ret = wh_Client_SheSecureBoot(client, bootloader, bootloaderSz)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheSecureBoot %d\n", ret);
        goto exit;
    }
    /* get status */
    if ((ret = wh_Client_SheGetStatus(client, &sreg)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGetStatus %d\n", ret);
        goto exit;
    }
    /* verify bootOk, bootFinished and secureBoot */
    if ((sreg & WH_SHE_SREG_BOOT_OK) == 0 ||
        (sreg & WH_SHE_SREG_BOOT_FINISHED) == 0 ||
        (sreg & WH_SHE_SREG_SECURE_BOOT) == 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("Failed to secureBoot with SHE CMAC\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE secure boot SUCCESS\n");
    /* load the secret key using pre program */
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_SECRET_KEY_ID, 0, secretKey, sizeof(secretKey))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    /* load the prng seed using pre program */
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_PRNG_SEED_ID, 0, prngSeed, sizeof(prngSeed))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    /* load the vector master ecu key */
    if ((ret = wh_She_GenerateLoadableKey(WH_SHE_MASTER_ECU_KEY_ID, WH_SHE_SECRET_KEY_ID, 1, 0, sheUid, vectorMasterEcuKey, secretKey, messageOne, messageTwo, messageThree, messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGenerateLoadableKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheLoadKey(client, messageOne, messageTwo, messageThree, outMessageFour, outMessageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadKey %d\n", ret);
        goto exit;
    }
    /* verify that our helper function output matches the vector */
    if ((ret = wh_She_GenerateLoadableKey(SHE_TEST_VECTOR_KEY_ID, WH_SHE_MASTER_ECU_KEY_ID, 1, 0, sheUid, vectorRawKey, vectorMasterEcuKey, messageOne, messageTwo, messageThree, messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGenerateLoadableKey %d\n", ret);
        goto exit;
    }
    if (memcmp(messageOne, vectorMessageOne, sizeof(vectorMessageOne)) != 0 ||
        memcmp(messageTwo, vectorMessageTwo, sizeof(vectorMessageTwo)) != 0 ||
        memcmp(messageThree, vectorMessageThree, sizeof(vectorMessageThree)) != 0 ||
        memcmp(messageFour, vectorMessageFour, sizeof(vectorMessageFour)) != 0 ||
        memcmp(messageFive, vectorMessageFive, sizeof(vectorMessageFive)) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("Failed to generate a loadable key to match the vector\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE wh_SheGenerateLoadableKey SUCCESS\n");
    /* test CMD_LOAD_KEY with test vector */
    if ((ret = wh_Client_SheLoadKey(client, vectorMessageOne, vectorMessageTwo, vectorMessageThree, outMessageFour, outMessageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadKey %d\n", ret);
        goto exit;
    }
    if (memcmp(outMessageFour, vectorMessageFour, sizeof(vectorMessageFour))
        != 0 || memcmp(outMessageFive, vectorMessageFive,
        sizeof(vectorMessageFive)) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("wh_Client_SheLoadKey FAILED TO MATCH\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE LOAD KEY SUCCESS\n");

    /* _LoadKey UID handling: a non-matching UID must be rejected, an
     * all-zero UID must be rejected unless the stored target key has
     * WH_SHE_FLAG_WILDCARD set. Use wh_She_GenerateLoadableKey with the
     * authKey bytes so M3 is valid and the server reaches the UID
     * check instead of failing earlier on CMAC verification. */
    {
        uint8_t badUid[WH_SHE_UID_SZ];
        uint8_t zeroUid[WH_SHE_UID_SZ] = {0};
        const uint32_t SHE_WILDCARD_KEY_ID = 5;

        memset(badUid, 0xAA, sizeof(badUid));

        /* Wrong UID targeting an existing key slot. Server must reject
         * with WH_SHE_ERC_KEY_UPDATE_ERROR. */
        if ((ret = wh_She_GenerateLoadableKey(SHE_TEST_VECTOR_KEY_ID,
                WH_SHE_MASTER_ECU_KEY_ID, 2, 0, badUid, vectorRawKey,
                vectorMasterEcuKey, messageOne, messageTwo,
                messageThree, messageFour, messageFive)) != 0) {
            WH_ERROR_PRINT("Failed to generate bad-UID M1/M2/M3 %d\n",
                           ret);
            goto exit;
        }
        ret = wh_Client_SheLoadKey(client, messageOne, messageTwo,
                messageThree, outMessageFour, outMessageFive);
        if (ret != WH_SHE_ERC_KEY_UPDATE_ERROR) {
            WH_ERROR_PRINT("SHE LOAD KEY bad UID: expected "
                           "KEY_UPDATE_ERROR, got %d\n", ret);
            ret = WH_ERROR_ABORTED;
            goto exit;
        }

        /* Zero UID targeting an unused slot (stored flags == 0, so
         * WH_SHE_FLAG_WILDCARD is clear). Server must reject. */
        if ((ret = wh_She_GenerateLoadableKey(SHE_WILDCARD_KEY_ID,
                WH_SHE_MASTER_ECU_KEY_ID, 1, 0, zeroUid, vectorRawKey,
                vectorMasterEcuKey, messageOne, messageTwo,
                messageThree, messageFour, messageFive)) != 0) {
            WH_ERROR_PRINT("Failed to generate zero-UID no-wildcard "
                           "M1/M2/M3 %d\n", ret);
            goto exit;
        }
        ret = wh_Client_SheLoadKey(client, messageOne, messageTwo,
                messageThree, outMessageFour, outMessageFive);
        if (ret != WH_SHE_ERC_KEY_UPDATE_ERROR) {
            WH_ERROR_PRINT("SHE LOAD KEY zero UID without wildcard: "
                           "expected KEY_UPDATE_ERROR, got %d\n", ret);
            ret = WH_ERROR_ABORTED;
            goto exit;
        }

        /* Preload the target slot with WH_SHE_FLAG_WILDCARD and count
         * 0 via ShePreProgramKey, which writes the meta label directly
         * (wh_She_GenerateLoadableKey cannot encode flags > 4 bits due
         * to the M2 layout overlap between flags and count). Then
         * re-load the slot with an all-zero UID; the server must
         * accept it because the stored flags contain WILDCARD. */
        if ((ret = wh_Client_ShePreProgramKey(client,
                SHE_WILDCARD_KEY_ID, WH_SHE_FLAG_WILDCARD, vectorRawKey,
                sizeof(vectorRawKey))) != 0) {
            WH_ERROR_PRINT("Failed to preload wildcard key %d\n", ret);
            goto exit;
        }
        if ((ret = wh_She_GenerateLoadableKey(SHE_WILDCARD_KEY_ID,
                WH_SHE_MASTER_ECU_KEY_ID, 1, 0, zeroUid, vectorRawKey,
                vectorMasterEcuKey, messageOne, messageTwo,
                messageThree, messageFour, messageFive)) != 0) {
            WH_ERROR_PRINT("Failed to generate zero-UID wildcard "
                           "M1/M2/M3 %d\n", ret);
            goto exit;
        }
        if ((ret = wh_Client_SheLoadKey(client, messageOne, messageTwo,
                messageThree, outMessageFour, outMessageFive)) != 0) {
            WH_ERROR_PRINT("SHE LOAD KEY zero UID with wildcard: "
                           "expected success, got %d\n", ret);
            goto exit;
        }

        if ((ret = _destroySheKey(client, SHE_WILDCARD_KEY_ID)) != 0) {
            WH_ERROR_PRINT("Failed to _destroySheKey wildcard slot, "
                           "ret=%d\n", ret);
            goto exit;
        }
        WH_TEST_PRINT("SHE LOAD KEY UID checks SUCCESS\n");
    }

    if ((ret = wh_Client_SheInitRnd(client)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheInitRnd %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheRnd(client, key, &keySz)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheInitRnd %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheExtendSeed(client, entropy, sizeof(entropy))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheExtendSeed %d\n", ret);
        goto exit;
    }
    WH_TEST_PRINT("SHE RND SUCCESS\n");
    if ((ret = wh_Client_SheLoadPlainKey(client, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadPlainKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheEncEcb(client, WH_SHE_RAM_KEY_ID, plainText, cipherText, sizeof(plainText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheEncEcb %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheExportRamKey(client, messageOne, messageTwo, messageThree, messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheExportRamKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheLoadKey(client, messageOne, messageTwo, messageThree, messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheDecEcb(client, WH_SHE_RAM_KEY_ID, cipherText, finalText, sizeof(cipherText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheEncEcb %d\n", ret);
        goto exit;
    }
    if (memcmp(finalText, plainText, sizeof(plainText)) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("SHE ECB FAILED TO MATCH\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE ECB SUCCESS\n");
    if ((ret = wh_Client_SheEncCbc(client, WH_SHE_RAM_KEY_ID, iv, sizeof(iv), plainText, cipherText, sizeof(plainText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheEncCbc %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheDecCbc(client, WH_SHE_RAM_KEY_ID, iv, sizeof(iv), cipherText, finalText, sizeof(cipherText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheDecCbc %d\n", ret);
        goto exit;
    }
    if (memcmp(finalText, plainText, sizeof(plainText)) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("SHE CBC FAILED TO MATCH\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE CBC SUCCESS\n");
    if ((ret = wh_Client_SheGenerateMac(client, WH_SHE_RAM_KEY_ID, plainText, sizeof(plainText), cipherText, sizeof(cipherText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGenerateMac %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheVerifyMac(client, WH_SHE_RAM_KEY_ID, plainText, sizeof(plainText), cipherText, sizeof(cipherText), &sreg)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheVerifyMac %d\n", ret);
        goto exit;
    }
    if (sreg != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("SHE CMAC FAILED TO VERIFY\n");
        goto exit;
    }

    /* Needs the trusted KEK the server task provisions in NVM, so this only
     * runs in the in-process (client+server) build, guarded the same way as
     * whTest_SheClientConfigBoundarySecureBoot below. */
#if defined(WOLFHSM_CFG_KEYWRAP) && defined(HAVE_AESGCM) && \
    defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
    /* SHE <-> keywrap interop: wrap-export a SHE key, prime an unused SHE slot
     * via unwrap-and-cache and use it, and verify the SHE counter rollback
     * guard on unwrap-and-cache. */
    {
        /* The client cannot read or set the trusted KEK; it only names it */
        whKeyId       kekId = WH_SHE_INTEROP_KEK_ID;
        uint8_t       blob[128];
        uint16_t      blobSz;
        uint16_t      expSz = (uint16_t)(WH_KEYWRAP_AES_GCM_HEADER_SIZE +
                                    sizeof(whNvmMetadata) + WH_SHE_KEY_SZ);
        const whNvmId SHE_PRIME_SLOT = 6;
        const whNvmId SHE_CTR_SLOT   = 7;
        uint8_t       sheKey[WH_SHE_KEY_SZ];
        uint8_t       ecbIn[WH_SHE_KEY_SZ];
        uint8_t       ecbOut[WH_SHE_KEY_SZ];
        uint8_t       ecbBack[WH_SHE_KEY_SZ];
        uint16_t      outId    = 0;
        int32_t       serverRc = 0;
        uint8_t       ctrLabel[WH_NVM_LABEL_LEN];

        /* Wrap-export the cached RAM key (slot 14) by id; the blob must keep
         * TYPE=SHE and be the expected size. */
        blobSz = sizeof(blob);
        ret    = wh_Client_KeyWrapExport(client, WC_CIPHER_AES_GCM,
                                         WH_SHE_RAM_KEY_ID, WH_KEYTYPE_SHE, kekId,
                                         blob, &blobSz);
        if (ret != 0 || blobSz != expSz) {
            WH_ERROR_PRINT("SHE wrap-export failed ret=%d sz=%u exp=%u\n", ret,
                           blobSz, expSz);
            ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
            goto exit;
        }

        /* SECRET_KEY has ID field == 0; it must still wrap-export like any
         * other SHE slot. */
        blobSz = sizeof(blob);
        ret    = wh_Client_KeyWrapExport(client, WC_CIPHER_AES_GCM,
                                         WH_SHE_SECRET_KEY_ID, WH_KEYTYPE_SHE,
                                         kekId, blob, &blobSz);
        if (ret != 0 || blobSz != expSz) {
            WH_ERROR_PRINT(
                "SHE slot-0 wrap-export failed ret=%d sz=%u exp=%u\n", ret,
                blobSz, expSz);
            ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
            goto exit;
        }

        /* Domain separation: a wrap-export blob must not open via DataUnwrap,
         * and a data-wrap blob must not unwrap-and-cache as a key.
         * blob/blobSz still hold the slot-0 SHE wrap-export. */
        {
            uint8_t  leak[sizeof(whNvmMetadata) + WH_SHE_KEY_SZ];
            uint32_t leakSz = sizeof(leak);
            uint8_t  dataBlob[128];
            uint32_t dataBlobSz = sizeof(dataBlob);
            uint16_t injectId   = 0;

            /* A key blob must fail to decrypt as data */
            ret = wh_Client_DataUnwrap(client, WC_CIPHER_AES_GCM, kekId, blob,
                                       blobSz, leak, &leakSz);
            if (ret == WH_ERROR_OK) {
                WH_ERROR_PRINT("SHE interop: DataUnwrap of a wrap-export blob "
                               "must fail but it succeeded\n");
                ret = WH_ERROR_ABORTED;
                goto exit;
            }

            /* DataWrap accepts the trusted KEK, but the resulting data blob
             * must fail to cache as a key */
            memset(leak, 0x33, sizeof(leak));
            ret = wh_Client_DataWrap(client, WC_CIPHER_AES_GCM, kekId, leak,
                                     sizeof(leak), dataBlob, &dataBlobSz);
            if (ret != WH_ERROR_OK) {
                WH_ERROR_PRINT("SHE interop: DataWrap under trusted KEK failed "
                               "%d\n",
                               ret);
                goto exit;
            }
            ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                                              dataBlob, (uint16_t)dataBlobSz,
                                              &injectId);
            if (ret == WH_ERROR_OK) {
                WH_ERROR_PRINT("SHE interop: unwrap-and-cache of a data-wrap "
                               "blob must fail but it succeeded\n");
                ret = WH_ERROR_ABORTED;
                goto exit;
            }
            ret = 0;
        }

        /* KeyUnwrapAndExport must refuse a SHE blob (only TYPE=WRAPPED is
         * allowed) with ABORTED and return no key bytes. */
        {
            whNvmMetadata leakMeta;
            uint8_t       leakKey[WH_SHE_KEY_SZ];
            uint8_t       sentinel[WH_SHE_KEY_SZ];
            uint16_t      leakKeySz = sizeof(leakKey);

            memset(sentinel, 0xa5, sizeof(sentinel));
            memset(leakKey, 0xa5, sizeof(leakKey));
            memset(&leakMeta, 0, sizeof(leakMeta));
            ret = wh_Client_KeyUnwrapAndExport(client, WC_CIPHER_AES_GCM, kekId,
                                               blob, blobSz, &leakMeta, leakKey,
                                               &leakKeySz);
            if (ret != WH_ERROR_ABORTED) {
                WH_ERROR_PRINT("SHE interop: unwrap-and-export of a SHE "
                               "wrap-export blob expected ABORTED, got %d\n",
                               ret);
                ret = (ret == 0) ? WH_ERROR_ABORTED : ret;
                goto exit;
            }
            if (memcmp(leakKey, sentinel, sizeof(leakKey)) != 0) {
                WH_ERROR_PRINT("SHE interop: unwrap-and-export refused the "
                               "blob but wrote key bytes\n");
                ret = WH_ERROR_ABORTED;
                goto exit;
            }
            ret = 0;
        }

        /* Prime an unused SHE slot via unwrap-and-cache, then use it. */
        memset(sheKey, 0x5a, sizeof(sheKey));
        blobSz = sizeof(blob);
        ret    = whTest_BuildSheKeyBlob(
            whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
            WH_SHE_MAKE_KEYID(client->comm->client_id, SHE_PRIME_SLOT), 1, 0,
            sheKey, blob, &blobSz);
        if (ret != 0) {
            WH_ERROR_PRINT("SHE interop: build prime blob failed %d\n", ret);
            goto exit;
        }
        ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                                          blob, blobSz, &outId);
        if (ret != 0) {
            WH_ERROR_PRINT("SHE unwrap-and-cache failed %d\n", ret);
            goto exit;
        }
        /* Returned id is the slot number, with the global flag set when SHE
         * slots are global */
        if ((outId & WH_KEYID_MASK) != SHE_PRIME_SLOT) {
            WH_ERROR_PRINT("SHE unwrap-and-cache returned wrong slot 0x%x\n",
                           (unsigned)outId);
            ret = WH_ERROR_ABORTED;
            goto exit;
        }
#ifdef WOLFHSM_CFG_SHE_GLOBAL_KEYS
        if ((outId & WH_KEYID_CLIENT_GLOBAL_FLAG) == 0) {
            WH_ERROR_PRINT("SHE unwrap-and-cache missing global flag 0x%x\n",
                           (unsigned)outId);
            ret = WH_ERROR_ABORTED;
            goto exit;
        }
#endif
        memset(ecbIn, 0x11, sizeof(ecbIn));
        ret = wh_Client_SheEncEcb(client, SHE_PRIME_SLOT, ecbIn, ecbOut,
                                  sizeof(ecbIn));
        if (ret == 0) {
            ret = wh_Client_SheDecEcb(client, SHE_PRIME_SLOT, ecbOut, ecbBack,
                                      sizeof(ecbOut));
        }
        if (ret != 0 || memcmp(ecbIn, ecbBack, sizeof(ecbIn)) != 0) {
            WH_ERROR_PRINT("SHE primed-key ECB round trip failed %d\n", ret);
            ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
            goto exit;
        }

        /* Counter guard on the SHE unwrap-and-cache path: seed an NVM SHE
         * slot with counter=5, then check a lower-counter prime is rejected
         * and an equal-counter prime is accepted. */
        wh_She_Meta2Label(5, 0, ctrLabel);
        ret = wh_Client_NvmAddObject(
            client, WH_SHE_MAKE_KEYID(client->comm->client_id, SHE_CTR_SLOT), 0,
            0, sizeof(ctrLabel), ctrLabel, sizeof(sheKey), sheKey, &serverRc);
        if (ret == 0) {
            ret = serverRc;
        }
        if (ret != 0) {
            WH_ERROR_PRINT("SHE interop: seed counter slot failed %d\n", ret);
            goto exit;
        }
        /* lower counter -> rejected */
        blobSz = sizeof(blob);
        ret    = whTest_BuildSheKeyBlob(
            whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
            WH_SHE_MAKE_KEYID(client->comm->client_id, SHE_CTR_SLOT), 3, 0,
            sheKey, blob, &blobSz);
        if (ret != 0) {
            goto exit;
        }
        ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                                          blob, blobSz, &outId);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("SHE counter rollback expected ACCESS, got %d\n",
                           ret);
            ret = WH_ERROR_ABORTED;
            goto exit;
        }

        /* equal counter -> accepted */
        blobSz = sizeof(blob);
        ret    = whTest_BuildSheKeyBlob(
            whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
            WH_SHE_MAKE_KEYID(client->comm->client_id, SHE_CTR_SLOT), 5, 0,
            sheKey, blob, &blobSz);
        if (ret != 0) {
            goto exit;
        }
        ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                                          blob, blobSz, &outId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("SHE counter equal expected OK, got %d\n", ret);
            ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
            goto exit;
        }

#ifndef WOLFHSM_CFG_SHE_GLOBAL_KEYS
        /* A blob carrying a global-namespace SHE id (minted by a global-SHE
         * build) must be refused, since no SHE command on this build reads
         * the global id and caching it would pin the slot with an unreachable
         * key. */
        blobSz = sizeof(blob);
        ret    = whTest_BuildSheKeyBlob(
            whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
            WH_MAKE_KEYID(WH_KEYTYPE_SHE, WH_KEYUSER_GLOBAL, SHE_PRIME_SLOT), 1,
            0, sheKey, blob, &blobSz);
        if (ret != 0) {
            goto exit;
        }
        ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                                          blob, blobSz, &outId);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("SHE global-id blob expected ACCESS, got %d\n", ret);
            ret = WH_ERROR_ABORTED;
            goto exit;
        }
#endif /* !WOLFHSM_CFG_SHE_GLOBAL_KEYS */

        /* LoadKey update of a slot that is primed in cache and committed in
         * NVM: M4/M5 and later crypto must use the new key, not the stale
         * cached copy. */
        {
            uint8_t newSheKey[WH_SHE_KEY_SZ];
            Aes     ecbAes[1];

            memset(newSheKey, 0xc3, sizeof(newSheKey));
            /* counter 6 > the primed and stored counter of 5 */
            if ((ret = wh_She_GenerateLoadableKey(
                     SHE_CTR_SLOT, WH_SHE_MASTER_ECU_KEY_ID, 6, 0, sheUid,
                     newSheKey, vectorMasterEcuKey, messageOne, messageTwo,
                     messageThree, messageFour, messageFive)) != 0) {
                WH_ERROR_PRINT("Failed to generate update M1-M5 %d\n", ret);
                goto exit;
            }
            if ((ret = wh_Client_SheLoadKey(client, messageOne, messageTwo,
                                            messageThree, outMessageFour,
                                            outMessageFive)) != 0) {
                WH_ERROR_PRINT("SHE LOAD KEY over primed slot failed %d\n",
                               ret);
                goto exit;
            }
            if (memcmp(outMessageFour, messageFour, WH_SHE_M4_SZ) != 0 ||
                memcmp(outMessageFive, messageFive, WH_SHE_M5_SZ) != 0) {
                WH_ERROR_PRINT("SHE LOAD KEY over primed slot returned M4/M5 "
                               "from a stale key\n");
                ret = WH_ERROR_ABORTED;
                goto exit;
            }
            /* server-side ECB must match software AES under the new key */
            memset(ecbIn, 0x22, sizeof(ecbIn));
            if ((ret = wh_Client_SheEncEcb(client, SHE_CTR_SLOT, ecbIn, ecbOut,
                                           sizeof(ecbIn))) != 0) {
                WH_ERROR_PRINT("SHE ECB after update failed %d\n", ret);
                goto exit;
            }
            ret = wc_AesInit(ecbAes, NULL, INVALID_DEVID);
            if (ret == 0) {
                ret = wc_AesSetKey(ecbAes, newSheKey, WH_SHE_KEY_SZ, NULL,
                                   AES_ENCRYPTION);
                if (ret == 0) {
                    ret = wc_AesEncryptDirect(ecbAes, ecbBack, ecbIn);
                }
                wc_AesFree(ecbAes);
            }
            if (ret != 0) {
                WH_ERROR_PRINT("software AES for ECB check failed %d\n", ret);
                goto exit;
            }
            if (memcmp(ecbOut, ecbBack, AES_BLOCK_SIZE) != 0) {
                WH_ERROR_PRINT("SHE ECB after update used a stale key\n");
                ret = WH_ERROR_ABORTED;
                goto exit;
            }
        }

#ifdef WOLFHSM_CFG_SHE_GLOBAL_KEYS
        /* A blob minted by a per-client build carries USER=client_id; unwrap
         * must move it to the global namespace where SHE commands look. */
        {
            const whNvmId SHE_LEGACY_SLOT = 8;

            blobSz = sizeof(blob);
            ret    = whTest_BuildSheKeyBlob(
                whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
                WH_MAKE_KEYID(WH_KEYTYPE_SHE, client->comm->client_id,
                                 SHE_LEGACY_SLOT),
                1, 0, sheKey, blob, &blobSz);
            if (ret != 0) {
                WH_ERROR_PRINT("SHE interop: build legacy blob failed %d\n",
                               ret);
                goto exit;
            }
            ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                                              blob, blobSz, &outId);
            if (ret != 0) {
                WH_ERROR_PRINT("SHE legacy-blob unwrap failed %d\n", ret);
                goto exit;
            }
            if ((outId & WH_KEYID_CLIENT_GLOBAL_FLAG) == 0 ||
                (outId & WH_KEYID_MASK) != SHE_LEGACY_SLOT) {
                WH_ERROR_PRINT("SHE legacy blob not normalized to global "
                               "(outId 0x%x)\n",
                               (unsigned)outId);
                ret = WH_ERROR_ABORTED;
                goto exit;
            }
            memset(ecbIn, 0x33, sizeof(ecbIn));
            ret = wh_Client_SheEncEcb(client, SHE_LEGACY_SLOT, ecbIn, ecbOut,
                                      sizeof(ecbIn));
            if (ret == 0) {
                ret = wh_Client_SheDecEcb(client, SHE_LEGACY_SLOT, ecbOut,
                                          ecbBack, sizeof(ecbOut));
            }
            if (ret != 0 || memcmp(ecbIn, ecbBack, sizeof(ecbIn)) != 0) {
                WH_ERROR_PRINT("SHE legacy-slot ECB round trip failed %d\n",
                               ret);
                ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
                goto exit;
            }
        }
#endif /* WOLFHSM_CFG_SHE_GLOBAL_KEYS */

        /* cleanup: destroy the NVM counter slot. The client must not be able
         * to evict the server-owned KEK. */
        (void)_destroySheKey(client, SHE_CTR_SLOT);
        ret = wh_Client_KeyEvict(client, kekId);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("SHE interop: KEK evict expected ACCESS, got %d\n",
                           ret);
            ret = (ret == 0) ? WH_ERROR_ABORTED : ret;
            goto exit;
        }
        ret = 0;

        WH_TEST_PRINT("SHE <-> keywrap interop SUCCESS\n");
    }
#endif /* WOLFHSM_CFG_KEYWRAP && HAVE_AESGCM && WOLFHSM_CFG_TEST_POSIX &&
          WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */

    /* destroy "pre-programmed" keys so we don't leak NVM */
    if ((ret = _destroySheKey(client, WH_SHE_BOOT_MAC_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, WH_SHE_BOOT_MAC)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, WH_SHE_SECRET_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, WH_SHE_PRNG_SEED_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, WH_SHE_MASTER_ECU_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, SHE_TEST_VECTOR_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    WH_TEST_PRINT("SHE CMAC SUCCESS\n");

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

        WH_TEST_DEBUG_PRINT("POST-SHE TEST: NvmGetAvailable:%d, server_rc:%d avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects,
               (int)reclaim_size, (int)reclaim_objects);
    }


exit:
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

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
static int whTest_SheClientConfigBoundarySecureBoot(whClientConfig* config)
{
    int             ret = 0;
    WC_RNG          rng[1];
    Cmac            cmac[1];
    whClientContext client[1]                         = {0};
    uint8_t         key[16]                           = {0};
    uint8_t         zeros[WH_SHE_BOOT_MAC_PREFIX_LEN] = {0};
    uint8_t         sheUid[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t         bootMacDigest[16] = {0};
    uint8_t         sreg              = 0;
    uint8_t         bootloaderBoundary[WOLFHSM_CFG_COMM_DATA_LEN -
                               sizeof(whMessageShe_SecureBootUpdateRequest)];
    uint32_t        digestSz = sizeof(bootMacDigest);
    uint32_t        bootloaderSz;
    uint32_t        serverCommDataLen = WOLFHSM_CFG_COMM_DATA_LEN;
    uint32_t        maxBoundaryUpdateChunk =
        WOLFHSM_CFG_COMM_DATA_LEN -
        sizeof(whMessageShe_SecureBootUpdateRequest);
    uint32_t outClientId = 0;
    uint32_t outServerId = 0;

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInit(client, &outClientId, &outServerId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInfo(
        client, NULL, NULL, &serverCommDataLen, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL));

    if (serverCommDataLen <= sizeof(whMessageShe_SecureBootUpdateRequest)) {
        WH_ERROR_PRINT("Invalid server cfg_comm_data_len %u\n",
                       (unsigned int)serverCommDataLen);
        ret = WH_ERROR_ABORTED;
        goto exit_boundary;
    }
    if (serverCommDataLen < WOLFHSM_CFG_COMM_DATA_LEN) {
        maxBoundaryUpdateChunk =
            serverCommDataLen - sizeof(whMessageShe_SecureBootUpdateRequest);
    }

    bootloaderSz = maxBoundaryUpdateChunk;

    if ((ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(client))) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        goto exit_boundary;
    }
    if ((ret = wc_RNG_GenerateBlock(rng, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit_boundary;
    }
    if ((ret = wc_RNG_GenerateBlock(rng, bootloaderBoundary,
                                    maxBoundaryUpdateChunk)) != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit_boundary;
    }
    wc_FreeRng(rng);

    if ((ret = wc_InitCmac(cmac, key, sizeof(key), WC_CMAC_AES, NULL)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitCmac %d\n", ret);
        goto exit_boundary;
    }
    if ((ret = wc_CmacUpdate(cmac, zeros, sizeof(zeros))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit_boundary;
    }
    if ((ret = wc_CmacUpdate(cmac, (uint8_t*)&bootloaderSz,
                             sizeof(bootloaderSz))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit_boundary;
    }
    if ((ret = wc_CmacUpdate(cmac, bootloaderBoundary, bootloaderSz)) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit_boundary;
    }
    digestSz = AES_BLOCK_SIZE;
    if ((ret = wc_CmacFinal(cmac, bootMacDigest, (word32*)&digestSz)) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacFinal %d\n", ret);
        goto exit_boundary;
    }

    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_BOOT_MAC_KEY_ID, 0,
                                          key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit_boundary;
    }
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_BOOT_MAC, 0,
                                          bootMacDigest,
                                          sizeof(bootMacDigest))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit_boundary;
    }
    if ((ret = wh_Client_SheSetUid(client, sheUid, sizeof(sheUid))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheSetUid %d\n", ret);
        goto exit_boundary;
    }
    if ((ret = wh_Client_SheSecureBoot(client, bootloaderBoundary,
                                       bootloaderSz)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheSecureBoot boundary %d\n", ret);
        goto exit_boundary;
    }
    if ((ret = wh_Client_SheGetStatus(client, &sreg)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGetStatus %d\n", ret);
        goto exit_boundary;
    }
    if ((sreg & WH_SHE_SREG_BOOT_OK) == 0 ||
        (sreg & WH_SHE_SREG_BOOT_FINISHED) == 0 ||
        (sreg & WH_SHE_SREG_SECURE_BOOT) == 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("Failed secureBoot boundary with SHE CMAC\n");
        goto exit_boundary;
    }
    WH_TEST_PRINT("SHE secure boot boundary SUCCESS\n");

    if ((ret = _destroySheKey(client, WH_SHE_BOOT_MAC_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit_boundary;
    }
    if ((ret = _destroySheKey(client, WH_SHE_BOOT_MAC)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit_boundary;
    }

exit_boundary:
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
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
/* Test that a key with WH_SHE_FLAG_WRITE_PROTECT cannot be overwritten
 * via SHE LoadKey, and that ERC_WRITE_PROTECTED is returned */
static int whTest_SheWriteProtect(whClientConfig* config)
{
    int             ret = 0;
    WC_RNG          rng[1];
    Cmac            cmac[1];
    whClientContext  client[1] = {0};
    uint8_t sheUid[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x01};
    uint8_t secretKey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
                           0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                           0x4f, 0x3c};
    uint8_t rawKey[] = {0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
                        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
                        0x01, 0x00};
    uint8_t zeros[WH_SHE_BOOT_MAC_PREFIX_LEN] = {0};
    uint8_t bootMacKey[WH_SHE_KEY_SZ] = {0};
    uint8_t bootloader[512];
    uint8_t bootMacDigest[WH_SHE_KEY_SZ] = {0};
    uint32_t digestSz = sizeof(bootMacDigest);
    uint32_t bootloaderSz = sizeof(bootloader);
    uint8_t messageOne[WH_SHE_M1_SZ];
    uint8_t messageTwo[WH_SHE_M2_SZ];
    uint8_t messageThree[WH_SHE_M3_SZ];
    uint8_t messageFour[WH_SHE_M4_SZ];
    uint8_t messageFive[WH_SHE_M5_SZ];
    uint32_t outClientId = 0;
    uint32_t outServerId = 0;
    const uint32_t WP_TEST_KEY_ID = 4;

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_Init(client, config));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInit(client, &outClientId, &outServerId));

    /* generate boot MAC key and fake bootloader */
    if ((ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(client))) != 0) {
        WH_ERROR_PRINT(
            "Failed to wc_InitRng_ex %d\n", ret);
        goto exit_wp;
    }
    if ((ret = wc_RNG_GenerateBlock(
             rng, bootMacKey, sizeof(bootMacKey))) != 0) {
        WH_ERROR_PRINT(
            "Failed to wc_RNG_GenerateBlock %d\n", ret);
        wc_FreeRng(rng);
        goto exit_wp;
    }
    if ((ret = wc_RNG_GenerateBlock(
             rng, bootloader, sizeof(bootloader))) != 0) {
        WH_ERROR_PRINT(
            "Failed to wc_RNG_GenerateBlock %d\n", ret);
        wc_FreeRng(rng);
        goto exit_wp;
    }
    wc_FreeRng(rng);

    /* compute boot MAC digest: CMAC(0..0 | size | bootloader) */
    if ((ret = wc_InitCmac(cmac, bootMacKey,
             sizeof(bootMacKey), WC_CMAC_AES, NULL)) != 0) {
        WH_ERROR_PRINT(
            "Failed to wc_InitCmac %d\n", ret);
        goto exit_wp;
    }
    if ((ret = wc_CmacUpdate(
             cmac, zeros, sizeof(zeros))) != 0) {
        WH_ERROR_PRINT(
            "Failed to wc_CmacUpdate %d\n", ret);
        goto exit_wp;
    }
    if ((ret = wc_CmacUpdate(cmac,
             (uint8_t*)&bootloaderSz,
             sizeof(bootloaderSz))) != 0) {
        WH_ERROR_PRINT(
            "Failed to wc_CmacUpdate %d\n", ret);
        goto exit_wp;
    }
    if ((ret = wc_CmacUpdate(
             cmac, bootloader, sizeof(bootloader))) != 0) {
        WH_ERROR_PRINT(
            "Failed to wc_CmacUpdate %d\n", ret);
        goto exit_wp;
    }
    digestSz = AES_BLOCK_SIZE;
    if ((ret = wc_CmacFinal(cmac, bootMacDigest,
             (word32*)&digestSz)) != 0) {
        WH_ERROR_PRINT(
            "Failed to wc_CmacFinal %d\n", ret);
        goto exit_wp;
    }

    /* pre-program boot MAC key and digest for secure boot */
    if ((ret = wh_Client_ShePreProgramKey(
             client, WH_SHE_BOOT_MAC_KEY_ID, 0,
             bootMacKey, sizeof(bootMacKey))) != 0) {
        WH_ERROR_PRINT(
            "Failed to pre-program boot MAC key %d\n", ret);
        goto exit_wp;
    }
    if ((ret = wh_Client_ShePreProgramKey(
             client, WH_SHE_BOOT_MAC, 0,
             bootMacDigest, sizeof(bootMacDigest))) != 0) {
        WH_ERROR_PRINT(
            "Failed to pre-program boot MAC digest %d\n",
            ret);
        goto exit_wp;
    }

    /* set the SHE UID */
    if ((ret = wh_Client_SheSetUid(
             client, sheUid, sizeof(sheUid))) != 0) {
        WH_ERROR_PRINT(
            "Failed to wh_Client_SheSetUid %d\n", ret);
        goto exit_wp;
    }

    /* secure boot must succeed before SHE LoadKey is allowed */
    if ((ret = wh_Client_SheSecureBoot(
             client, bootloader, bootloaderSz)) != 0) {
        WH_ERROR_PRINT(
            "Failed to wh_Client_SheSecureBoot %d\n", ret);
        goto exit_wp;
    }

    /* pre-program the secret key as auth key */
    if ((ret = wh_Client_ShePreProgramKey(
             client, WH_SHE_SECRET_KEY_ID, 0,
             secretKey, sizeof(secretKey))) != 0) {
        WH_ERROR_PRINT(
            "Failed to pre-program secret key %d\n", ret);
        goto exit_wp;
    }

    /* pre-program the target key WITH write protect flag */
    if ((ret = wh_Client_ShePreProgramKey(
             client, WP_TEST_KEY_ID,
             WH_SHE_FLAG_WRITE_PROTECT,
             rawKey, sizeof(rawKey))) != 0) {
        WH_ERROR_PRINT(
            "Failed to pre-program write-protected key %d\n",
            ret);
        goto exit_wp;
    }

    /* generate loadable key messages for the protected slot */
    if ((ret = wh_She_GenerateLoadableKey(
             WP_TEST_KEY_ID, WH_SHE_SECRET_KEY_ID,
             1, 0, sheUid, rawKey, secretKey,
             messageOne, messageTwo, messageThree,
             messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT(
            "Failed to generate loadable key %d\n", ret);
        goto exit_wp;
    }

    /* attempt to load key into the write-protected slot */
    ret = wh_Client_SheLoadKey(client, messageOne, messageTwo,
                               messageThree, messageFour,
                               messageFive);
    if (ret != WH_SHE_ERC_WRITE_PROTECTED) {
        WH_ERROR_PRINT(
            "Expected WH_SHE_ERC_WRITE_PROTECTED, got %d\n",
            ret);
        ret = WH_ERROR_ABORTED;
        goto exit_wp;
    }

    /* load succeeded (returned the expected error) */
    ret = 0;
    WH_TEST_PRINT("SHE write protect test SUCCESS\n");

    /* destroy test keys to prevent NVM leaks */
    if ((ret = _destroySheKey(
             client, WH_SHE_BOOT_MAC_KEY_ID)) != 0) {
        WH_ERROR_PRINT(
            "Failed to _destroySheKey, ret=%d\n", ret);
        goto exit_wp;
    }
    if ((ret = _destroySheKey(
             client, WH_SHE_BOOT_MAC)) != 0) {
        WH_ERROR_PRINT(
            "Failed to _destroySheKey, ret=%d\n", ret);
        goto exit_wp;
    }
    if ((ret = _destroySheKey(
             client, WH_SHE_SECRET_KEY_ID)) != 0) {
        WH_ERROR_PRINT(
            "Failed to _destroySheKey, ret=%d\n", ret);
        goto exit_wp;
    }
    if ((ret = _destroySheKey(client, WP_TEST_KEY_ID)) != 0) {
        WH_ERROR_PRINT(
            "Failed to _destroySheKey, ret=%d\n", ret);
        goto exit_wp;
    }

exit_wp:
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommClose(client));

    if (ret == 0) {
        WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));
    }
    else {
        wh_Client_Cleanup(client);
    }

    return ret;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#if defined(WOLFHSM_CFG_KEYWRAP) && defined(HAVE_AESGCM)
/* Provision the trusted keywrap KEK in NVM with WH_NVM_FLAGS_TRUSTED, the way
 * whnvmtool would on a real device. Clients can never set that flag. */
static int _ProvisionSheServerKek(whServerContext* server)
{
    whNvmMetadata meta = {0};

    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID,
                                WH_SHE_INTEROP_KEK_ID);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP |
                 WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_NONMODIFIABLE;
    meta.len = (whNvmSize)sizeof(whTest_KeywrapKek);
    memcpy(meta.label, "SHE interop KEK", sizeof("SHE interop KEK"));

    return wh_Nvm_AddObject(server->nvm, &meta, meta.len, whTest_KeywrapKek);
}
#endif /* WOLFHSM_CFG_KEYWRAP && HAVE_AESGCM */

int whTest_SheServerConfig(whServerConfig* config)
{
    whServerContext server[1] = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int ret = 0;

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, config));
#if defined(WOLFHSM_CFG_KEYWRAP) && defined(HAVE_AESGCM)
    /* Provision the trusted KEK before the server accepts requests */
    WH_TEST_RETURN_ON_FAIL(_ProvisionSheServerKek(server));
#endif
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));

    while(am_connected == WH_COMM_CONNECTED) {
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) &&
                (ret != WH_ERROR_OK)) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            break;
        }
        wh_Server_GetConnected(server, &am_connected);
    }
    if ((ret == 0) || (ret == WH_ERROR_NOTREADY)){
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    } else {
        ret = wh_Server_Cleanup(server);
    }

    return ret;
}
#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    !defined(WOLFHSM_CFG_TEST_CLIENT_ONLY)
typedef int (*whTestSheClientFn)(whClientConfig* config);

typedef struct {
    whClientConfig*   clientConfig;
    whTestSheClientFn clientFn;
} whTestSheClientTaskCtx;

static void* _whClientTask(void* cf)
{
    whTestSheClientTaskCtx* ctx = (whTestSheClientTaskCtx*)cf;
    WH_TEST_ASSERT(0 == ctx->clientFn(ctx->clientConfig));
    return NULL;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          !defined(WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP) */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_SERVER)
static void* _whServerTask(void* cf)
{
    WH_TEST_ASSERT(0 == whTest_SheServerConfig(cf));
    return NULL;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
static void _whClientServerThreadTest(whClientConfig*   c_conf,
                                      whServerConfig*   s_conf,
                                      whTestSheClientFn clientFn)
{
    pthread_t cthread = {0};
    pthread_t sthread = {0};
    whTestSheClientTaskCtx cTaskCtx = {
        .clientConfig = c_conf,
        .clientFn     = clientFn,
    };

    void* retval;
    int rc = 0;

    rc = pthread_create(&sthread, NULL, _whServerTask, s_conf);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whClientTask, &cTaskCtx);
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

static int wh_ClientServer_MemThreadTest(whTestSheClientFn clientFn)
{
    uint8_t req[BUFFER_SIZE] = {0};
    uint8_t resp[BUFFER_SIZE] = {0};

    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
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
    whClientConfig c_conf[1] = {{
       .comm = cc_conf,
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
        .size       = FLASH_RAM_SIZE,     /* 1MB  Flash */
        .sectorSize = FLASH_SECTOR_SIZE,  /* 128KB  Sector Size */
        .pageSize   = FLASH_PAGE_SIZE,    /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
        .memory     = memory,
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
    whServerCryptoContext crypto[1] = {0};

    whServerSheContext she[1];
    memset(she, 0, sizeof(she));

    whServerConfig                  s_conf[1] = {{
       .comm_config = cs_conf,
       .nvm = nvm,
       .crypto = crypto,
       .she = she,
       .devId = INVALID_DEVID,
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));

    _whClientServerThreadTest(c_conf, s_conf, clientFn);

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_ENABLE_SERVER)
static int wh_She_TestMasterEcuKeyFallback(void)
{
    int             ret                   = 0;
    whServerContext server[1]             = {0};
    whNvmMetadata   outMeta[1]            = {0};
    uint8_t         keyBuf[WH_SHE_KEY_SZ] = {0};
    uint32_t        keySz                 = sizeof(keyBuf);
    uint8_t         zeros[WH_SHE_KEY_SZ]  = {0};
    whKeyId         masterEcuKeyId;

    /* Transport (not used, but required for server init) */
    uint8_t                     reqBuf[BUFFER_SIZE]  = {0};
    uint8_t                     respBuf[BUFFER_SIZE] = {0};
    whTransportMemConfig        tmcf[1]              = {{
                            .req       = (whTransportMemCsr*)reqBuf,
                            .req_size  = sizeof(reqBuf),
                            .resp      = (whTransportMemCsr*)respBuf,
                            .resp_size = sizeof(respBuf),
    }};
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    /* RamSim Flash state and configuration */
    uint8_t          memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]                  = {0};
    whFlashRamsimCfg fc_conf[1]             = {{
                    .size       = FLASH_RAM_SIZE,
                    .sectorSize = FLASH_SECTOR_SIZE,
                    .pageSize   = FLASH_PAGE_SIZE,
                    .erasedByte = ~(uint8_t)0,
                    .memory     = memory,
    }};
    const whFlashCb  fcb[1]                 = {WH_FLASH_RAMSIM_CB};

    /* NVM */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};
    whNvmConfig       n_conf[1]  = {{
               .cb      = nfcb,
               .context = nfc,
               .config  = nf_conf,
    }};
    whNvmContext      nvm[1]     = {{0}};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {0};

    whServerSheContext she[1];
    memset(she, 0, sizeof(she));

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .she         = she,
        .devId       = INVALID_DEVID,
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, s_conf->devId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, WH_COMM_CONNECTED));

    masterEcuKeyId =
        WH_SHE_MAKE_KEYID(server->comm->client_id, WH_SHE_MASTER_ECU_KEY_ID);

    /* Fill keyBuf with non-zero to ensure it gets overwritten */
    memset(keyBuf, 0xFF, sizeof(keyBuf));

    /* Read master ECU key when it has never been provisioned */
    ret = wh_Server_KeystoreReadKey(server, masterEcuKeyId, outMeta, keyBuf,
                                    &keySz);

    WH_TEST_ASSERT_RETURN(ret == 0);
    WH_TEST_ASSERT_RETURN(keySz == WH_SHE_KEY_SZ);
    WH_TEST_ASSERT_RETURN(memcmp(keyBuf, zeros, WH_SHE_KEY_SZ) == 0);
    WH_TEST_ASSERT_RETURN(outMeta->len == WH_SHE_KEY_SZ);
    WH_TEST_ASSERT_RETURN(outMeta->id == masterEcuKeyId);

    WH_TEST_PRINT("SHE master ECU key fallback metadata test SUCCESS\n");

    wh_Server_Cleanup(server);
    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return 0;
}
#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_ENABLE_SERVER)
/* Values from the wh_server_she.c internal WH_SHE_SB_STATE enum */
#define TEST_SHE_SB_STATE_INIT 0
#define TEST_SHE_SB_STATE_SUCCESS 3

/**
 * Test that SHE server handlers correctly reject requests with invalid
 * req_size while still producing an action-specific response packet.
 * Each handler is called directly via wh_Server_HandleSheRequest()
 * with a realistic but incorrectly sized request packet.
 */
static int wh_She_TestReqSizeChecking(void)
{
    int             ret = 0;
    whServerContext server[1] = {0};
    uint16_t        req_size = 0;
    uint16_t        resp_size = 0;

    /* Buffers for request and response packets */
    uint8_t req_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t resp_packet[WOLFHSM_CFG_COMM_DATA_LEN];

    /* Transport (not used, but required for server init) */
    uint8_t                     reqBuf[BUFFER_SIZE]  = {0};
    uint8_t                     respBuf[BUFFER_SIZE] = {0};
    whTransportMemConfig        tmcf[1]              = {{
                            .req       = (whTransportMemCsr*)reqBuf,
                            .req_size  = sizeof(reqBuf),
                            .resp      = (whTransportMemCsr*)respBuf,
                            .resp_size = sizeof(respBuf),
    }};
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    /* RamSim Flash state and configuration.
     * memory[] is static to avoid 1MB stack allocation. */
    static uint8_t   memory[FLASH_RAM_SIZE];
    whFlashRamsimCtx fc[1]                  = {0};
    whFlashRamsimCfg fc_conf[1]             = {{0}};
    const whFlashCb  fcb[1]                 = {WH_FLASH_RAMSIM_CB};

    /* NVM */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};
    whNvmConfig       n_conf[1]  = {{
               .cb      = nfcb,
               .context = nfc,
               .config  = nf_conf,
    }};
    whNvmContext      nvm[1]     = {{0}};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {0};

    whServerSheContext she[1];

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .she         = she,
        .devId       = INVALID_DEVID,
    }};

    memset(she, 0, sizeof(she));
    memset(memory, 0, sizeof(memory));

    fc_conf->size       = FLASH_RAM_SIZE;
    fc_conf->sectorSize = FLASH_SECTOR_SIZE;
    fc_conf->pageSize   = FLASH_PAGE_SIZE;
    fc_conf->erasedByte = ~(uint8_t)0;
    fc_conf->memory     = memory;

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, s_conf->devId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, WH_COMM_CONNECTED));

    /*
     * Set SHE state so _ReportInvalidSheState allows requests through.
     * WH_SHE_SET_UID always passes the state gate, but most other handlers
     * require uidSet=1 and sbState=WH_SHE_SB_SUCCESS.
     */
    server->she->uidSet  = 1;
    server->she->sbState = TEST_SHE_SB_STATE_SUCCESS;

    /*
     * Test 1: WH_SHE_SET_UID with truncated request.
     * Populate a valid UID in the packet, but pass req_size one byte short.
     */
    {
        whMessageShe_SetUidRequest* req =
            (whMessageShe_SetUidRequest*)req_packet;
        whMessageShe_SetUidResponse* setUidResp =
            (whMessageShe_SetUidResponse*)resp_packet;
        memset(setUidResp, 0, sizeof(*setUidResp));
        memset(req->uid, 0xAA, WH_SHE_UID_SZ);
        req_size = sizeof(whMessageShe_SetUidRequest) - 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_SET_UID, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*setUidResp));
        WH_TEST_ASSERT_RETURN(setUidResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 2: WH_SHE_SECURE_BOOT_INIT with truncated request.
     * Set a valid bootloader size, but pass req_size one byte short.
     */
    {
        whMessageShe_SecureBootInitRequest* req =
            (whMessageShe_SecureBootInitRequest*)req_packet;
        whMessageShe_SecureBootInitResponse* secureBootInitResp =
            (whMessageShe_SecureBootInitResponse*)resp_packet;
        /* Need sbState=WH_SHE_SB_INIT for this handler to not return
         * ERC_SEQUENCE_ERROR, but since we're testing the size check which
         * happens first, we just need to pass the state gate. The state gate
         * allows SECURE_BOOT_INIT through regardless of sbState. */
        memset(secureBootInitResp, 0, sizeof(*secureBootInitResp));
        req->sz = 256;
        req_size = sizeof(whMessageShe_SecureBootInitRequest) - 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_SECURE_BOOT_INIT, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*secureBootInitResp));
        WH_TEST_ASSERT_RETURN(secureBootInitResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /* Secure boot failure resets sbState to SB_INIT, restore it */
    server->she->sbState = TEST_SHE_SB_STATE_SUCCESS;

    /*
     * Test 3: WH_SHE_SECURE_BOOT_UPDATE with truncated fixed header.
     * Set a valid chunk size but pass req_size smaller than the header.
     */
    {
        whMessageShe_SecureBootUpdateRequest* req =
            (whMessageShe_SecureBootUpdateRequest*)req_packet;
        whMessageShe_SecureBootUpdateResponse* secureBootUpdateResp =
            (whMessageShe_SecureBootUpdateResponse*)resp_packet;
        memset(secureBootUpdateResp, 0, sizeof(*secureBootUpdateResp));
        req->sz = 64;
        req_size = sizeof(whMessageShe_SecureBootUpdateRequest) - 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_SECURE_BOOT_UPDATE, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*secureBootUpdateResp));
        WH_TEST_ASSERT_RETURN(secureBootUpdateResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /* Secure boot failure resets sbState to SB_INIT, restore it */
    server->she->sbState = TEST_SHE_SB_STATE_SUCCESS;

    /*
     * Test 4: WH_SHE_SECURE_BOOT_FINISH expects no request body.
     * Send a nonzero req_size to trigger the check.
     */
    {
        whMessageShe_SecureBootFinishResponse* secureBootFinishResp =
            (whMessageShe_SecureBootFinishResponse*)resp_packet;
        memset(secureBootFinishResp, 0, sizeof(*secureBootFinishResp));
        req_size = 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_SECURE_BOOT_FINISH, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*secureBootFinishResp));
        WH_TEST_ASSERT_RETURN(secureBootFinishResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /* Secure boot failure resets sbState to SB_INIT, restore it */
    server->she->sbState = TEST_SHE_SB_STATE_SUCCESS;

    /*
     * Test 5: WH_SHE_LOAD_KEY with truncated request.
     * Fill M1/M2/M3 with nonzero data, pass req_size one byte short.
     * NOTE: _LoadKey maps the malformed request to an action-specific response.
     * Verify the request still completes with a response packet instead of
     * failing the transport path.
     */
    {
        whMessageShe_LoadKeyRequest* req =
            (whMessageShe_LoadKeyRequest*)req_packet;
        whMessageShe_LoadKeyResponse* loadKeyResp =
            (whMessageShe_LoadKeyResponse*)resp_packet;
        memset(loadKeyResp, 0, sizeof(*loadKeyResp));
        memset(req->messageOne, 0x11, WH_SHE_M1_SZ);
        memset(req->messageTwo, 0x22, WH_SHE_M2_SZ);
        memset(req->messageThree, 0x33, WH_SHE_M3_SZ);
        req_size = sizeof(whMessageShe_LoadKeyRequest) - 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_LOAD_KEY, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*loadKeyResp));
        WH_TEST_ASSERT_RETURN(loadKeyResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 6: WH_SHE_LOAD_PLAIN_KEY with truncated request.
     * Fill a valid key, pass req_size one byte short.
     */
    {
        whMessageShe_LoadPlainKeyRequest* req =
            (whMessageShe_LoadPlainKeyRequest*)req_packet;
        whMessageShe_LoadPlainKeyResponse* loadPlainKeyResp =
            (whMessageShe_LoadPlainKeyResponse*)resp_packet;
        memset(loadPlainKeyResp, 0, sizeof(*loadPlainKeyResp));
        memset(req->key, 0xBB, WH_SHE_KEY_SZ);
        req_size = sizeof(whMessageShe_LoadPlainKeyRequest) - 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_LOAD_PLAIN_KEY, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*loadPlainKeyResp));
        WH_TEST_ASSERT_RETURN(loadPlainKeyResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 7: WH_SHE_EXPORT_RAM_KEY expects no request body.
     * Send a nonzero req_size to trigger the check.
     */
    {
        whMessageShe_ExportRamKeyResponse* exportRamKeyResp =
            (whMessageShe_ExportRamKeyResponse*)resp_packet;
        memset(exportRamKeyResp, 0, sizeof(*exportRamKeyResp));
        req_size = 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_EXPORT_RAM_KEY, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*exportRamKeyResp));
        WH_TEST_ASSERT_RETURN(exportRamKeyResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 8: WH_SHE_INIT_RND expects no request body.
     * Send a nonzero req_size to trigger the check.
     */
    {
        whMessageShe_InitRngResponse* initRngResp =
            (whMessageShe_InitRngResponse*)resp_packet;
        memset(initRngResp, 0, sizeof(*initRngResp));
        req_size = 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_INIT_RND, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*initRngResp));
        WH_TEST_ASSERT_RETURN(initRngResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 9: WH_SHE_RND expects no request body.
     * Send a nonzero req_size to trigger the check.
     */
    {
        whMessageShe_RndResponse* rndResp =
            (whMessageShe_RndResponse*)resp_packet;
        memset(rndResp, 0, sizeof(*rndResp));
        req_size = 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_RND, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*rndResp));
        WH_TEST_ASSERT_RETURN(rndResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 10: WH_SHE_EXTEND_SEED with truncated request.
     * Fill valid entropy data, pass req_size one byte short.
     */
    {
        whMessageShe_ExtendSeedRequest* req =
            (whMessageShe_ExtendSeedRequest*)req_packet;
        whMessageShe_ExtendSeedResponse* extendSeedResp =
            (whMessageShe_ExtendSeedResponse*)resp_packet;
        memset(extendSeedResp, 0, sizeof(*extendSeedResp));
        memset(req->entropy, 0xCC, WH_SHE_KEY_SZ);
        req_size = sizeof(whMessageShe_ExtendSeedRequest) - 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_EXTEND_SEED, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*extendSeedResp));
        WH_TEST_ASSERT_RETURN(extendSeedResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 11: WH_SHE_ENC_ECB with valid header but truncated payload.
     * Set sz to 16 (one AES block) but only include the header, no data.
     */
    {
        whMessageShe_EncEcbRequest* req =
            (whMessageShe_EncEcbRequest*)req_packet;
        whMessageShe_EncEcbResponse* encEcbResp =
            (whMessageShe_EncEcbResponse*)resp_packet;
        memset(encEcbResp, 0, sizeof(*encEcbResp));
        req->sz    = 16;
        req->keyId = WH_SHE_RAM_KEY_ID;
        req_size = sizeof(whMessageShe_EncEcbRequest);
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_ENC_ECB, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*encEcbResp));
        WH_TEST_ASSERT_RETURN(encEcbResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 12: WH_SHE_ENC_ECB with truncated header.
     * Pass req_size one byte short of the header struct.
     */
    {
        whMessageShe_EncEcbRequest* req =
            (whMessageShe_EncEcbRequest*)req_packet;
        whMessageShe_EncEcbResponse* encEcbResp =
            (whMessageShe_EncEcbResponse*)resp_packet;
        memset(encEcbResp, 0, sizeof(*encEcbResp));
        req->sz    = 16;
        req->keyId = WH_SHE_RAM_KEY_ID;
        req_size = sizeof(whMessageShe_EncEcbRequest) - 1;
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_ENC_ECB, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*encEcbResp));
        WH_TEST_ASSERT_RETURN(encEcbResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 13: WH_SHE_ENC_CBC with valid header but truncated payload.
     * Set sz to 16 (one AES block), fill a valid IV, but only include the
     * header with no cipher data following it.
     */
    {
        whMessageShe_EncCbcRequest* req =
            (whMessageShe_EncCbcRequest*)req_packet;
        whMessageShe_EncCbcResponse* encCbcResp =
            (whMessageShe_EncCbcResponse*)resp_packet;
        memset(encCbcResp, 0, sizeof(*encCbcResp));
        req->sz    = 16;
        req->keyId = WH_SHE_RAM_KEY_ID;
        memset(req->iv, 0xDD, WH_SHE_KEY_SZ);
        req_size = sizeof(whMessageShe_EncCbcRequest);
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_ENC_CBC, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*encCbcResp));
        WH_TEST_ASSERT_RETURN(encCbcResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 14: WH_SHE_DEC_ECB with valid header but truncated payload.
     */
    {
        whMessageShe_DecEcbRequest* req =
            (whMessageShe_DecEcbRequest*)req_packet;
        whMessageShe_DecEcbResponse* decEcbResp =
            (whMessageShe_DecEcbResponse*)resp_packet;
        memset(decEcbResp, 0, sizeof(*decEcbResp));
        req->sz    = 16;
        req->keyId = WH_SHE_RAM_KEY_ID;
        req_size = sizeof(whMessageShe_DecEcbRequest);
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_DEC_ECB, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*decEcbResp));
        WH_TEST_ASSERT_RETURN(decEcbResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 15: WH_SHE_DEC_CBC with valid header but truncated payload.
     */
    {
        whMessageShe_DecCbcRequest* req =
            (whMessageShe_DecCbcRequest*)req_packet;
        whMessageShe_DecCbcResponse* decCbcResp =
            (whMessageShe_DecCbcResponse*)resp_packet;
        memset(decCbcResp, 0, sizeof(*decCbcResp));
        req->sz    = 16;
        req->keyId = WH_SHE_RAM_KEY_ID;
        memset(req->iv, 0xEE, WH_SHE_KEY_SZ);
        req_size = sizeof(whMessageShe_DecCbcRequest);
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_DEC_CBC, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*decCbcResp));
        WH_TEST_ASSERT_RETURN(decCbcResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 16: WH_SHE_GEN_MAC with valid header but truncated payload.
     * Set sz to 16 bytes of message data, but only pass the header.
     */
    {
        whMessageShe_GenMacRequest* req =
            (whMessageShe_GenMacRequest*)req_packet;
        whMessageShe_GenMacResponse* genMacResp =
            (whMessageShe_GenMacResponse*)resp_packet;
        memset(genMacResp, 0, sizeof(*genMacResp));
        req->keyId = WH_SHE_RAM_KEY_ID;
        req->sz    = 16;
        req_size = sizeof(whMessageShe_GenMacRequest);
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_GEN_MAC, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*genMacResp));
        WH_TEST_ASSERT_RETURN(genMacResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    /*
     * Test 17: WH_SHE_VERIFY_MAC with valid header but truncated payload.
     * Set messageLen=16 and macLen=16 but only pass the header.
     */
    {
        whMessageShe_VerifyMacRequest* req =
            (whMessageShe_VerifyMacRequest*)req_packet;
        whMessageShe_VerifyMacResponse* verifyMacResp =
            (whMessageShe_VerifyMacResponse*)resp_packet;
        memset(verifyMacResp, 0, sizeof(*verifyMacResp));
        req->keyId     = WH_SHE_RAM_KEY_ID;
        req->messageLen = 16;
        req->macLen     = 16;
        req_size = sizeof(whMessageShe_VerifyMacRequest);
        ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE,
                  WH_SHE_VERIFY_MAC, req_size,
                  req_packet, &resp_size, resp_packet);
        WH_TEST_ASSERT_RETURN(ret == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(*verifyMacResp));
        WH_TEST_ASSERT_RETURN(verifyMacResp->rc != WH_SHE_ERC_NO_ERROR);
    }

    WH_TEST_PRINT("SHE req_size checking test SUCCESS\n");

    wh_Server_Cleanup(server);
    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return 0;
}

/* Send one SHE action through the server and return its response rc. */
static int32_t wh_She_SheActionRc(whServerContext* server, uint16_t action,
                                  const void* req_packet, uint16_t req_size,
                                  void* resp_packet)
{
    uint16_t resp_size = 0;
    int      ret;

    *((int32_t*)resp_packet) = WH_SHE_ERC_NO_ERROR;
    ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE, action,
                                     req_size, req_packet, &resp_size,
                                     resp_packet);
    if (ret != 0 || resp_size < sizeof(int32_t)) {
        return WH_SHE_ERC_GENERAL_ERROR;
    }
    return *((const int32_t*)resp_packet);
}

/* Test that the SHE state gate rejects protected commands before the SHE
 * state machine is initialized. */
static int wh_She_TestStateGate(void)
{
    int             ret = 0;
    uint32_t        i;
    int32_t         rc;
    whServerContext server[1] = {0};

    /* Buffers for request and response packets */
    uint8_t req_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t resp_packet[WOLFHSM_CFG_COMM_DATA_LEN];

    /* Protected actions that must not run before the state machine is up.
     * req_size is the valid size for each, so a deleted gate would let the
     * handler proceed rather than fail on size alone. */
    const struct {
        uint16_t action;
        uint16_t req_size;
    } protectedActions[] = {
        {WH_SHE_LOAD_PLAIN_KEY, sizeof(whMessageShe_LoadPlainKeyRequest)},
        {WH_SHE_INIT_RND, 0},
        {WH_SHE_ENC_ECB, sizeof(whMessageShe_EncEcbRequest)},
    };
    const uint32_t protectedCount =
        sizeof(protectedActions) / sizeof(protectedActions[0]);

    /* Transport (not used, but required for server init) */
    uint8_t                     reqBuf[BUFFER_SIZE]  = {0};
    uint8_t                     respBuf[BUFFER_SIZE] = {0};
    whTransportMemConfig        tmcf[1]              = {{
                            .req       = (whTransportMemCsr*)reqBuf,
                            .req_size  = sizeof(reqBuf),
                            .resp      = (whTransportMemCsr*)respBuf,
                            .resp_size = sizeof(respBuf),
    }};
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 125,
    }};

    /* RamSim Flash state and configuration.
     * memory[] is static to avoid 1MB stack allocation. */
    static uint8_t   memory[FLASH_RAM_SIZE];
    whFlashRamsimCtx fc[1]                  = {0};
    whFlashRamsimCfg fc_conf[1]             = {{0}};
    const whFlashCb  fcb[1]                 = {WH_FLASH_RAMSIM_CB};

    /* NVM */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};
    whNvmConfig       n_conf[1]  = {{
               .cb      = nfcb,
               .context = nfc,
               .config  = nf_conf,
    }};
    whNvmContext      nvm[1]     = {{0}};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {0};

    whServerSheContext she[1];

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .she         = she,
        .devId       = INVALID_DEVID,
    }};

    memset(she, 0, sizeof(she));
    memset(memory, 0, sizeof(memory));
    memset(req_packet, 0, sizeof(req_packet));

    fc_conf->size       = FLASH_RAM_SIZE;
    fc_conf->sectorSize = FLASH_SECTOR_SIZE;
    fc_conf->pageSize   = FLASH_PAGE_SIZE;
    fc_conf->erasedByte = ~(uint8_t)0;
    fc_conf->memory     = memory;

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, s_conf->devId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, WH_COMM_CONNECTED));

    /* she is zeroed: uidSet == 0, sbState == WH_SHE_SB_INIT. */

    /*
     * Phase 1: before UID setup. Protected commands must be rejected with
     * WH_SHE_ERC_SEQUENCE_ERROR, while GET_STATUS is allowed (per SHE spec).
     */
    for (i = 0; i < protectedCount; i++) {
        rc = wh_She_SheActionRc(server, protectedActions[i].action, req_packet,
                                protectedActions[i].req_size, resp_packet);
        WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_SEQUENCE_ERROR);
    }
    /* Secure boot itself also needs the UID set first. */
    rc = wh_She_SheActionRc(server, WH_SHE_SECURE_BOOT_INIT, req_packet,
                            sizeof(whMessageShe_SecureBootInitRequest),
                            resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_SEQUENCE_ERROR);
    /* GET_STATUS is callable at any time, even before UID setup. */
    rc = wh_She_SheActionRc(server, WH_SHE_GET_STATUS, req_packet, 0,
                            resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_NO_ERROR);
    /* Rejected commands left no state behind. */
    WH_TEST_ASSERT_RETURN(server->she->uidSet == 0);
    WH_TEST_ASSERT_RETURN(server->she->rndInited == 0);

    /* SET_UID passes the gate and provisions the UID. */
    {
        whMessageShe_SetUidRequest* uidReq =
            (whMessageShe_SetUidRequest*)req_packet;
        memset(uidReq, 0, sizeof(*uidReq));
        memset(uidReq->uid, 0x5A, WH_SHE_UID_SZ);
        rc = wh_She_SheActionRc(server, WH_SHE_SET_UID, req_packet,
                                sizeof(*uidReq), resp_packet);
        WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_NO_ERROR);
        WH_TEST_ASSERT_RETURN(server->she->uidSet == 1);
    }
    memset(req_packet, 0, sizeof(req_packet));

    /*
     * Phase 2: UID set but secure boot not yet successful. Isolates the
     * secure-boot requirement from the UID check above.
     */
    server->she->sbState = TEST_SHE_SB_STATE_INIT;
    for (i = 0; i < protectedCount; i++) {
        rc = wh_She_SheActionRc(server, protectedActions[i].action, req_packet,
                                protectedActions[i].req_size, resp_packet);
        WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_SEQUENCE_ERROR);
    }
    rc = wh_She_SheActionRc(server, WH_SHE_GET_STATUS, req_packet, 0,
                            resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_NO_ERROR);
    WH_TEST_ASSERT_RETURN(server->she->rndInited == 0);

    /*
     * Phase 3: UID set and secure boot successful. The gate must let a
     * protected command reach its handler, proving it does not over-block.
     * Keys are not provisioned here, so INIT_RND still fails inside the
     * handler, but with a key error rather than a gate sequence error.
     */
    server->she->sbState = TEST_SHE_SB_STATE_SUCCESS;
    rc = wh_She_SheActionRc(server, WH_SHE_INIT_RND, req_packet, 0,
                            resp_packet);
    WH_TEST_ASSERT_RETURN(rc != WH_SHE_ERC_SEQUENCE_ERROR);

    WH_TEST_PRINT("SHE state gate test SUCCESS\n");

    wh_Server_Cleanup(server);
    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return ret;
}
#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)

#if defined(WOLFHSM_CFG_KEYWRAP) && defined(HAVE_AESGCM)
/*
 * SHE <-> keywrap reboot interop, run across two server sessions to model a
 * power cycle. Each wh_ClientServer_MemThreadTest() call builds a fresh server
 * and NVM; the client carries only the wrapped blob across the "reset".
 *
 *   Session 1 (provision): secure boot, load a target key, capture its ECB
 *     ciphertext, wrap-export it by id, save the blob.
 *   Session 2 (restore): secure boot, unwrap-and-cache the saved blob, ECB
 *     ciphertext must match session 1.
 *
 * The KEK is the trusted key the server task provisions in NVM in both
 * sessions; the client never uploads it.
 */

/* Shared inputs that must match across the two sessions. */
static uint8_t s_interopUid[WH_SHE_UID_SZ]   = {0x00, 0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t s_interopPlain[WH_SHE_KEY_SZ] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
/* Carried from the provision session to the restore session. */
static uint8_t  s_interopBlob[256];
static uint16_t s_interopBlobSz;
static uint8_t  s_interopCipher[WH_SHE_KEY_SZ];

#define WH_SHE_INTEROP_TARGET_SLOT 4

/* Establish secure-boot state so SHE key operations are permitted. Both
 * sessions must do this (a fresh server starts un-booted). */
static int _SheInteropSecureBoot(whClientContext* client)
{
    int      ret;
    Cmac     cmac[1];
    uint8_t  bootMacKey[WH_SHE_KEY_SZ] = {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6,
                                          0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c,
                                          0x6d, 0x7e, 0x8f, 0x90};
    uint8_t  bootloader[64];
    uint32_t bootloaderSz                      = sizeof(bootloader);
    uint8_t  zeros[WH_SHE_BOOT_MAC_PREFIX_LEN] = {0};
    uint8_t  digest[WH_SHE_KEY_SZ]             = {0};
    uint32_t digestSz                          = sizeof(digest);
    uint8_t  sreg                              = 0;

    memset(bootloader, 0xB7, sizeof(bootloader));

    /* boot MAC digest = CMAC_bootMacKey(zeros || size || bootloader) */
    if ((ret = wc_InitCmac(cmac, bootMacKey, sizeof(bootMacKey), WC_CMAC_AES,
                           NULL)) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, zeros, sizeof(zeros))) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, (uint8_t*)&bootloaderSz,
                             sizeof(bootloaderSz))) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, bootloader, sizeof(bootloader))) != 0) {
        return ret;
    }
    digestSz = AES_BLOCK_SIZE;
    if ((ret = wc_CmacFinal(cmac, digest, (word32*)&digestSz)) != 0) {
        return ret;
    }

    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_BOOT_MAC_KEY_ID, 0,
                                          bootMacKey, sizeof(bootMacKey))) !=
        0) {
        return ret;
    }
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_BOOT_MAC, 0, digest,
                                          sizeof(digest))) != 0) {
        return ret;
    }
    if ((ret = wh_Client_SheSetUid(client, s_interopUid,
                                   sizeof(s_interopUid))) != 0) {
        return ret;
    }
    if ((ret = wh_Client_SheSecureBoot(client, bootloader, bootloaderSz)) !=
        0) {
        return ret;
    }
    if ((ret = wh_Client_SheGetStatus(client, &sreg)) != 0) {
        return ret;
    }
    if ((sreg & WH_SHE_SREG_BOOT_OK) == 0 ||
        (sreg & WH_SHE_SREG_BOOT_FINISHED) == 0 ||
        (sreg & WH_SHE_SREG_SECURE_BOOT) == 0) {
        return WH_ERROR_ABORTED;
    }
    return 0;
}

static int _SheInteropProvision(whClientConfig* config)
{
    int             ret;
    whClientContext client[1]            = {0};
    uint32_t        outClientId          = 0;
    uint32_t        outServerId          = 0;
    uint8_t  secretKey[WH_SHE_KEY_SZ]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                            0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                            0x09, 0xcf, 0x4f, 0x3c};
    uint8_t  masterEcuKey[WH_SHE_KEY_SZ] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                            0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t  targetKey[WH_SHE_KEY_SZ]    = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x23,
                                            0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                            0xfe, 0xdc, 0xba, 0x98};
    uint8_t  m1[WH_SHE_M1_SZ];
    uint8_t  m2[WH_SHE_M2_SZ];
    uint8_t  m3[WH_SHE_M3_SZ];
    uint8_t  m4[WH_SHE_M4_SZ];
    uint8_t  m5[WH_SHE_M5_SZ];
    uint8_t  o4[WH_SHE_M4_SZ];
    uint8_t  o5[WH_SHE_M5_SZ];
    uint16_t blobSz = sizeof(s_interopBlob);

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInit(client, &outClientId, &outServerId));
#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthLogin(
        client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME, TEST_ADMIN_PIN,
        strlen(TEST_ADMIN_PIN), &ret, NULL));
#endif

    ret = _SheInteropSecureBoot(client);
    if (ret != 0) {
        WH_ERROR_PRINT("interop provision: secure boot failed %d\n", ret);
        goto exit;
    }

    /* Provision the secret key, then load the master ECU key (auth=secret) and
     * the target key (auth=master ECU) using offline-generated M1/M2/M3. */
    ret = wh_Client_ShePreProgramKey(client, WH_SHE_SECRET_KEY_ID, 0, secretKey,
                                     sizeof(secretKey));
    if (ret != 0) {
        goto exit;
    }
    ret = wh_She_GenerateLoadableKey(
        WH_SHE_MASTER_ECU_KEY_ID, WH_SHE_SECRET_KEY_ID, 1, 0, s_interopUid,
        masterEcuKey, secretKey, m1, m2, m3, m4, m5);
    if (ret != 0) {
        goto exit;
    }
    ret = wh_Client_SheLoadKey(client, m1, m2, m3, o4, o5);
    if (ret != 0) {
        WH_ERROR_PRINT("interop provision: load master ECU failed %d\n", ret);
        goto exit;
    }
    ret = wh_She_GenerateLoadableKey(
        WH_SHE_INTEROP_TARGET_SLOT, WH_SHE_MASTER_ECU_KEY_ID, 1, 0,
        s_interopUid, targetKey, masterEcuKey, m1, m2, m3, m4, m5);
    if (ret != 0) {
        goto exit;
    }
    ret = wh_Client_SheLoadKey(client, m1, m2, m3, o4, o5);
    if (ret != 0) {
        WH_ERROR_PRINT(
            "interop provision: load target via M1/M2/M3 failed %d\n", ret);
        goto exit;
    }

    /* Capture the target key's ECB output for cross-session comparison. */
    ret =
        wh_Client_SheEncEcb(client, WH_SHE_INTEROP_TARGET_SLOT, s_interopPlain,
                            s_interopCipher, sizeof(s_interopPlain));
    if (ret != 0) {
        goto exit;
    }

    /* Wrap-export the target key by id under the server's trusted KEK. */
    ret = wh_Client_KeyWrapExport(
        client, WC_CIPHER_AES_GCM, WH_SHE_INTEROP_TARGET_SLOT, WH_KEYTYPE_SHE,
        WH_SHE_INTEROP_KEK_ID, s_interopBlob, &blobSz);
    if (ret != 0) {
        WH_ERROR_PRINT("interop provision: wrap-export failed %d\n", ret);
        goto exit;
    }
    s_interopBlobSz = blobSz;

exit:
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);
    return ret;
}

static int _SheInteropRestore(whClientConfig* config)
{
    int             ret;
    whClientContext client[1]             = {0};
    uint32_t        outClientId           = 0;
    uint32_t        outServerId           = 0;
    uint8_t         cipher[WH_SHE_KEY_SZ] = {0};
    uint16_t        outId                 = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInit(client, &outClientId, &outServerId));
#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthLogin(
        client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME, TEST_ADMIN_PIN,
        strlen(TEST_ADMIN_PIN), &ret, NULL));
#endif

    /* Fresh boot: re-establish secure-boot state. This server's NVM holds
     * only the trusted KEK, not the target SHE key. */
    ret = _SheInteropSecureBoot(client);
    if (ret != 0) {
        WH_ERROR_PRINT("interop restore: secure boot failed %d\n", ret);
        goto exit;
    }

    /* Prime the SHE key purely from the client-held wrapped blob. */
    ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM,
                                      WH_SHE_INTEROP_KEK_ID, s_interopBlob,
                                      s_interopBlobSz, &outId);
    if (ret != 0) {
        WH_ERROR_PRINT("interop restore: unwrap-and-cache failed %d\n", ret);
        goto exit;
    }

    /* Use the restored key via the SHE API; it must reproduce the provision
     * session's ciphertext, proving the exact key round-tripped. */
    ret = wh_Client_SheEncEcb(client, WH_SHE_INTEROP_TARGET_SLOT,
                              s_interopPlain, cipher, sizeof(s_interopPlain));
    if (ret != 0) {
        WH_ERROR_PRINT("interop restore: SheEncEcb failed %d\n", ret);
        goto exit;
    }
    if (memcmp(cipher, s_interopCipher, sizeof(cipher)) != 0) {
        WH_ERROR_PRINT("interop restore: restored key does not match\n");
        ret = WH_ERROR_ABORTED;
        goto exit;
    }
    WH_TEST_PRINT("SHE wrapped-key reboot interop SUCCESS\n");

exit:
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);
    return ret;
}

/* Drive the two sessions back-to-back. Each MemThreadTest call uses a fresh
 * server + NVM, modeling the power cycle between provision and restore. */
static int wh_She_TestWrappedInterop(void)
{
    int ret;

    s_interopBlobSz = 0;
    memset(s_interopBlob, 0, sizeof(s_interopBlob));
    memset(s_interopCipher, 0, sizeof(s_interopCipher));

    ret = wh_ClientServer_MemThreadTest(_SheInteropProvision);
    if (ret != 0) {
        return ret;
    }
    return wh_ClientServer_MemThreadTest(_SheInteropRestore);
}
#endif /* WOLFHSM_CFG_KEYWRAP && HAVE_AESGCM */

int whTest_She(void)
{
    WH_TEST_PRINT("Testing SHE: master ECU key fallback...\n");
    WH_TEST_RETURN_ON_FAIL(wh_She_TestMasterEcuKeyFallback());

    WH_TEST_PRINT("Testing SHE: req_size checking...\n");
    WH_TEST_RETURN_ON_FAIL(wh_She_TestReqSizeChecking());
    WH_TEST_PRINT("Testing SHE: state gate...\n");
    WH_TEST_RETURN_ON_FAIL(wh_She_TestStateGate());
    WH_TEST_PRINT("Testing SHE: (pthread) mem core flow...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_ClientServer_MemThreadTest(whTest_SheClientConfig));
    WH_TEST_PRINT("Testing SHE: (pthread) mem boundary secure boot...\n");
    WH_TEST_RETURN_ON_FAIL(wh_ClientServer_MemThreadTest(
        whTest_SheClientConfigBoundarySecureBoot));
    WH_TEST_PRINT("Testing SHE: (pthread) mem write protect...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_ClientServer_MemThreadTest(whTest_SheWriteProtect));
#if defined(WOLFHSM_CFG_KEYWRAP) && defined(HAVE_AESGCM)
    WH_TEST_PRINT("Testing SHE: (pthread) wrapped-key reboot interop...\n");
    WH_TEST_RETURN_ON_FAIL(wh_She_TestWrappedInterop());
    WH_TEST_PRINT("Testing SHE: (pthread) NVM-less wrapped-key flow...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_SheNoNvm());
#endif
    return 0;
}
#endif

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
#endif /* WOLFHSM_CFG_SHE_EXTENSION */
