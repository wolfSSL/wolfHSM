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
 * test-refactor/client-server/wh_test_she.c
 *
 * Client-side SHE flow. SHE UID and secure-boot state is one-shot
 * per server lifetime, so the whole sequence runs as a single test
 * against one connected client: one SetUid and one secure boot
 * (sized to the comm-buffer boundary), then the load-key vectors,
 * UID handling, RND, ECB/CBC/MAC round-trips, and a write-protect
 * rejection, which only require that UID is set and secure boot has
 * completed.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_SHE_EXTENSION) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_she.h"
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_she_crypto.h"
#include "wolfhsm/wh_message_she.h"

#include "wh_test_common.h"

#ifndef TEST_ADMIN_USERNAME
#define TEST_ADMIN_USERNAME "admin"
#endif
#ifndef TEST_ADMIN_PIN
#define TEST_ADMIN_PIN "1234"
#endif


/* Destroy a SHE key so the unit tests don't leak NVM objects across
 * invocations. Necessary, as SHE doesn't expose a destroy key API since
 * SHE keys are supposed to be fixed hardware keys. */
static int _destroySheKey(whClientContext* client, whNvmId clientSheKeyId)
{
    int     rc       = 0;
    int32_t serverRc = 0;
    whNvmId id        = WH_MAKE_KEYID(WH_KEYTYPE_SHE, client->comm->client_id,
                                      clientSheKeyId);

    rc = wh_Client_NvmDestroyObjects(client, 1, &id, &serverRc);
    if (rc == WH_ERROR_OK) {
        rc = serverRc;
    }

    return rc;
}


/*
 * Full SHE flow against a freshly connected client. SetUid and secure
 * boot are one-shot per server lifetime, so they run once up front; the
 * remaining checks (load-key vectors, UID handling, RND, ECB/CBC/MAC,
 * write protect) only need UID set and secure boot complete.
 */
int whTest_She(whClientContext* client)
{
    int      ret = 0;
    WC_RNG   rng[1];
    Cmac     cmac[1];
    /* key doubles as the boot MAC key (secure boot) and later the RND
     * output that gets loaded as the RAM plain key. */
    uint8_t  key[16] = {0};
    uint32_t keySz   = sizeof(key);
    uint8_t  iv[]    = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t  plainText[64];
    uint8_t  cipherText[64];
    uint8_t  finalText[64];
    /* secretKey and prngSeed are taken from SHE test vectors */
    uint8_t  sheUid[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t  secretKey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t  prngSeed[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                           0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t  zeros[WH_SHE_BOOT_MAC_PREFIX_LEN] = {0};
    /* Bootloader sized to the comm-buffer boundary so the single secure
     * boot exercises the secure-boot update path at the maximum chunk. */
    uint8_t  bootloader[WOLFHSM_CFG_COMM_DATA_LEN -
                        sizeof(whMessageShe_SecureBootUpdateRequest)];
    uint8_t  bootMacDigest[16] = {0};
    uint8_t  vectorMasterEcuKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                       0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                       0x0c, 0x0d, 0x0e, 0x0f};
    uint32_t digestSz     = sizeof(bootMacDigest);
    uint32_t bootloaderSz;
    uint32_t serverCommDataLen = WOLFHSM_CFG_COMM_DATA_LEN;
    uint32_t maxBoundaryUpdateChunk =
        WOLFHSM_CFG_COMM_DATA_LEN -
        sizeof(whMessageShe_SecureBootUpdateRequest);
    uint8_t  vectorMessageOne[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41};
    uint8_t  vectorMessageTwo[] = {0x2b, 0x11, 0x1e, 0x2d, 0x93, 0xf4, 0x86,
        0x56, 0x6b, 0xcb, 0xba, 0x1d, 0x7f, 0x7a, 0x97, 0x97, 0xc9, 0x46, 0x43,
        0xb0, 0x50, 0xfc, 0x5d, 0x4d, 0x7d, 0xe1, 0x4c, 0xff, 0x68, 0x22, 0x03,
        0xc3};
    uint8_t  vectorMessageThree[] = {0xb9, 0xd7, 0x45, 0xe5, 0xac, 0xe7, 0xd4,
        0x18, 0x60, 0xbc, 0x63, 0xc2, 0xb9, 0xf5, 0xbb, 0x46};
    uint8_t  vectorMessageFour[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41, 0xb4, 0x72, 0xe8,
        0xd8, 0x72, 0x7d, 0x70, 0xd5, 0x72, 0x95, 0xe7, 0x48, 0x49, 0xa2, 0x79,
        0x17};
    uint8_t  vectorMessageFive[] = {0x82, 0x0d, 0x8d, 0x95, 0xdc, 0x11, 0xb4,
        0x66, 0x88, 0x78, 0x16, 0x0c, 0xb2, 0xa4, 0xe2, 0x3e};
    uint8_t  vectorRawKey[] = {0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t  outMessageFour[sizeof(vectorMessageFour)];
    uint8_t  outMessageFive[sizeof(vectorMessageFive)];
    uint8_t  entropy[] = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e,
        0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    uint8_t  sreg;
    uint8_t  messageOne[WH_SHE_M1_SZ];
    uint8_t  messageTwo[WH_SHE_M2_SZ];
    uint8_t  messageThree[WH_SHE_M3_SZ];
    uint8_t  messageFour[WH_SHE_M4_SZ];
    uint8_t  messageFive[WH_SHE_M5_SZ];
    uint8_t  sheChallenge[WH_SHE_KEY_SZ] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t  sheGetIdUid[WH_SHE_UID_SZ];
    uint8_t  sheGetIdMac[WH_SHE_KEY_SZ];
    uint8_t  expectedGetIdMac[WH_SHE_KEY_SZ];
    uint8_t  getIdMacInput[WH_SHE_KEY_SZ + WH_SHE_UID_SZ + 1];
    word32   expectedGetIdMacSz = sizeof(expectedGetIdMac);
    const uint32_t SHE_TEST_VECTOR_KEY_ID = 4;
    const uint32_t SHE_WP_KEY_ID          = 6;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    /* Log in as an admin user for the rest of the test */
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthLogin(
        client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME, TEST_ADMIN_PIN,
        strlen(TEST_ADMIN_PIN), &ret, NULL));
#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION */

    /* === SetUid + boundary-sized secure boot (one-shot per server) === */

    /* Size the bootloader to the server's comm-buffer boundary so the
     * single secure boot drives a maximum-sized secure-boot update. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInfo(
        client, NULL, NULL, &serverCommDataLen, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL));
    if (serverCommDataLen <= sizeof(whMessageShe_SecureBootUpdateRequest)) {
        WH_ERROR_PRINT("Invalid server cfg_comm_data_len %u\n",
                       (unsigned int)serverCommDataLen);
        return WH_ERROR_ABORTED;
    }
    if (serverCommDataLen < WOLFHSM_CFG_COMM_DATA_LEN) {
        maxBoundaryUpdateChunk =
            serverCommDataLen - sizeof(whMessageShe_SecureBootUpdateRequest);
    }
    bootloaderSz = maxBoundaryUpdateChunk;

    /* generate the boot MAC key and a fake bootloader */
    if ((ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RNG_GenerateBlock(rng, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        wc_FreeRng(rng);
        goto exit;
    }
    if ((ret = wc_RNG_GenerateBlock(rng, bootloader,
                                    maxBoundaryUpdateChunk)) != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        wc_FreeRng(rng);
        goto exit;
    }
    /* Done generating test data, free RNG */
    wc_FreeRng(rng);

    /* boot MAC digest: CMAC(0..0 | size | bootloader) */
    if ((ret = wc_InitCmac(cmac, key, sizeof(key), WC_CMAC_AES, NULL)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitCmac %d\n", ret);
        goto exit;
    }
    if ((ret = wc_CmacUpdate(cmac, zeros, sizeof(zeros))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }
    if ((ret = wc_CmacUpdate(cmac, (uint8_t*)&bootloaderSz,
                             sizeof(bootloaderSz))) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }
    if ((ret = wc_CmacUpdate(cmac, bootloader, bootloaderSz)) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }
    digestSz = AES_BLOCK_SIZE;
    if ((ret = wc_CmacFinal(cmac, bootMacDigest, (word32*)&digestSz)) != 0) {
        WH_ERROR_PRINT("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }
    /* store the boot MAC key and digest */
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_BOOT_MAC_KEY_ID, 0,
                                          key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_BOOT_MAC, 0,
                                          bootMacDigest,
                                          sizeof(bootMacDigest))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    /* set the she uid */
    if ((ret = wh_Client_SheSetUid(client, sheUid, sizeof(sheUid))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheSetUid %d\n", ret);
        goto exit;
    }
    /* verify bootloader at the comm-buffer boundary */
    if ((ret = wh_Client_SheSecureBoot(client, bootloader, bootloaderSz)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheSecureBoot %d\n", ret);
        goto exit;
    }
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

    /* === Loadable keys and test vectors === */

    /* load the secret key and prng seed using pre program */
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_SECRET_KEY_ID, 0,
                                          secretKey, sizeof(secretKey))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_ShePreProgramKey(client, WH_SHE_PRNG_SEED_ID, 0,
                                          prngSeed, sizeof(prngSeed))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    /* load the vector master ecu key */
    if ((ret = wh_She_GenerateLoadableKey(WH_SHE_MASTER_ECU_KEY_ID,
            WH_SHE_SECRET_KEY_ID, 1, 0, sheUid, vectorMasterEcuKey, secretKey,
            messageOne, messageTwo, messageThree, messageFour,
            messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_She_GenerateLoadableKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheLoadKey(client, messageOne, messageTwo,
            messageThree, outMessageFour, outMessageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadKey %d\n", ret);
        goto exit;
    }
    /* verify that our helper function output matches the vector */
    if ((ret = wh_She_GenerateLoadableKey(SHE_TEST_VECTOR_KEY_ID,
            WH_SHE_MASTER_ECU_KEY_ID, 1, 0, sheUid, vectorRawKey,
            vectorMasterEcuKey, messageOne, messageTwo, messageThree,
            messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_She_GenerateLoadableKey %d\n", ret);
        goto exit;
    }
    if (memcmp(messageOne, vectorMessageOne, sizeof(vectorMessageOne)) != 0 ||
        memcmp(messageTwo, vectorMessageTwo, sizeof(vectorMessageTwo)) != 0 ||
        memcmp(messageThree, vectorMessageThree,
               sizeof(vectorMessageThree)) != 0 ||
        memcmp(messageFour, vectorMessageFour, sizeof(vectorMessageFour)) != 0 ||
        memcmp(messageFive, vectorMessageFive, sizeof(vectorMessageFive)) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("Failed to generate a loadable key to match the "
                       "vector\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE wh_SheGenerateLoadableKey SUCCESS\n");
    /* test CMD_LOAD_KEY with test vector */
    if ((ret = wh_Client_SheLoadKey(client, vectorMessageOne, vectorMessageTwo,
            vectorMessageThree, outMessageFour, outMessageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadKey %d\n", ret);
        goto exit;
    }
    if (memcmp(outMessageFour, vectorMessageFour, sizeof(vectorMessageFour))
            != 0 ||
        memcmp(outMessageFive, vectorMessageFive,
               sizeof(vectorMessageFive)) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("wh_Client_SheLoadKey FAILED TO MATCH\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE LOAD KEY SUCCESS\n");

    /* === GET_ID identity + MAC verification === */

    /* CMD_GET_ID: read the module identity and verify the identity MAC. The
     * MASTER_ECU_KEY (slot 1) was loaded above with vectorMasterEcuKey, so we
     * can recompute the expected CMAC over challenge || uid || sreg. */
    if ((ret = wh_Client_SheGetId(client, sheChallenge, sizeof(sheChallenge),
             sheGetIdUid, &sreg, sheGetIdMac)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGetId %d\n", ret);
        goto exit;
    }
    if (memcmp(sheGetIdUid, sheUid, WH_SHE_UID_SZ) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("SHE GET_ID returned an unexpected UID\n");
        goto exit;
    }
    /* expected MAC = CMAC(MASTER_ECU_KEY, challenge || uid || sreg) */
    memcpy(getIdMacInput, sheChallenge, WH_SHE_KEY_SZ);
    memcpy(getIdMacInput + WH_SHE_KEY_SZ, sheGetIdUid, WH_SHE_UID_SZ);
    getIdMacInput[WH_SHE_KEY_SZ + WH_SHE_UID_SZ] = sreg;
    expectedGetIdMacSz = sizeof(expectedGetIdMac);
    if ((ret = wc_AesCmacGenerate(expectedGetIdMac, &expectedGetIdMacSz,
             getIdMacInput, sizeof(getIdMacInput), vectorMasterEcuKey,
             sizeof(vectorMasterEcuKey))) != 0) {
        WH_ERROR_PRINT("Failed to compute expected GET_ID MAC %d\n", ret);
        goto exit;
    }
    if (memcmp(sheGetIdMac, expectedGetIdMac, WH_SHE_KEY_SZ) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("SHE GET_ID MAC mismatch\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE GET ID SUCCESS\n");

    /* === LoadKey UID handling === */

    /* A non-matching UID must be rejected, an all-zero UID must be
     * rejected unless the stored target key has WH_SHE_FLAG_WILDCARD set.
     * Use wh_She_GenerateLoadableKey with the authKey bytes so M3 is valid
     * and the server reaches the UID check instead of failing earlier on
     * CMAC verification. */
    {
        uint8_t        badUid[WH_SHE_UID_SZ];
        uint8_t        zeroUid[WH_SHE_UID_SZ] = {0};
        const uint32_t SHE_WILDCARD_KEY_ID    = 5;

        memset(badUid, 0xAA, sizeof(badUid));

        /* Wrong UID targeting an existing key slot. Server must reject
         * with WH_SHE_ERC_KEY_UPDATE_ERROR. */
        if ((ret = wh_She_GenerateLoadableKey(SHE_TEST_VECTOR_KEY_ID,
                WH_SHE_MASTER_ECU_KEY_ID, 2, 0, badUid, vectorRawKey,
                vectorMasterEcuKey, messageOne, messageTwo, messageThree,
                messageFour, messageFive)) != 0) {
            WH_ERROR_PRINT("Failed to generate bad-UID M1/M2/M3 %d\n", ret);
            goto exit;
        }
        ret = wh_Client_SheLoadKey(client, messageOne, messageTwo, messageThree,
                outMessageFour, outMessageFive);
        if (ret != WH_SHE_ERC_KEY_UPDATE_ERROR) {
            WH_ERROR_PRINT("SHE LOAD KEY bad UID: expected KEY_UPDATE_ERROR, "
                           "got %d\n", ret);
            ret = WH_ERROR_ABORTED;
            goto exit;
        }

        /* Zero UID targeting an unused slot (stored flags == 0, so
         * WH_SHE_FLAG_WILDCARD is clear). Server must reject. */
        if ((ret = wh_She_GenerateLoadableKey(SHE_WILDCARD_KEY_ID,
                WH_SHE_MASTER_ECU_KEY_ID, 1, 0, zeroUid, vectorRawKey,
                vectorMasterEcuKey, messageOne, messageTwo, messageThree,
                messageFour, messageFive)) != 0) {
            WH_ERROR_PRINT("Failed to generate zero-UID no-wildcard "
                           "M1/M2/M3 %d\n", ret);
            goto exit;
        }
        ret = wh_Client_SheLoadKey(client, messageOne, messageTwo, messageThree,
                outMessageFour, outMessageFive);
        if (ret != WH_SHE_ERC_KEY_UPDATE_ERROR) {
            WH_ERROR_PRINT("SHE LOAD KEY zero UID without wildcard: expected "
                           "KEY_UPDATE_ERROR, got %d\n", ret);
            ret = WH_ERROR_ABORTED;
            goto exit;
        }

        /* Preload the target slot with WH_SHE_FLAG_WILDCARD and count
         * 0 via ShePreProgramKey, which writes the meta label directly
         * (wh_She_GenerateLoadableKey cannot encode flags > 4 bits due
         * to the M2 layout overlap between flags and count). Then
         * re-load the slot with an all-zero UID; the server must
         * accept it because the stored flags contain WILDCARD. */
        if ((ret = wh_Client_ShePreProgramKey(client, SHE_WILDCARD_KEY_ID,
                WH_SHE_FLAG_WILDCARD, vectorRawKey, sizeof(vectorRawKey)))
                != 0) {
            WH_ERROR_PRINT("Failed to preload wildcard key %d\n", ret);
            goto exit;
        }
        if ((ret = wh_She_GenerateLoadableKey(SHE_WILDCARD_KEY_ID,
                WH_SHE_MASTER_ECU_KEY_ID, 1, 0, zeroUid, vectorRawKey,
                vectorMasterEcuKey, messageOne, messageTwo, messageThree,
                messageFour, messageFive)) != 0) {
            WH_ERROR_PRINT("Failed to generate zero-UID wildcard "
                           "M1/M2/M3 %d\n", ret);
            goto exit;
        }
        if ((ret = wh_Client_SheLoadKey(client, messageOne, messageTwo,
                messageThree, outMessageFour, outMessageFive)) != 0) {
            WH_ERROR_PRINT("SHE LOAD KEY zero UID with wildcard: expected "
                           "success, got %d\n", ret);
            goto exit;
        }

        if ((ret = _destroySheKey(client, SHE_WILDCARD_KEY_ID)) != 0) {
            WH_ERROR_PRINT("Failed to _destroySheKey wildcard slot, ret=%d\n",
                           ret);
            goto exit;
        }
        WH_TEST_PRINT("SHE LOAD KEY UID checks SUCCESS\n");
    }

    /* === RND === */

    if ((ret = wh_Client_SheInitRnd(client)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheInitRnd %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheRnd(client, key, &keySz)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheRnd %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheExtendSeed(client, entropy, sizeof(entropy))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheExtendSeed %d\n", ret);
        goto exit;
    }
    WH_TEST_PRINT("SHE RND SUCCESS\n");

    /* === RAM key ECB/CBC/MAC round-trips === */

    if ((ret = wh_Client_SheLoadPlainKey(client, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadPlainKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheEncEcb(client, WH_SHE_RAM_KEY_ID, plainText,
            cipherText, sizeof(plainText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheEncEcb %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheExportRamKey(client, messageOne, messageTwo,
            messageThree, messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheExportRamKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheLoadKey(client, messageOne, messageTwo,
            messageThree, messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheDecEcb(client, WH_SHE_RAM_KEY_ID, cipherText,
            finalText, sizeof(cipherText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheDecEcb %d\n", ret);
        goto exit;
    }
    if (memcmp(finalText, plainText, sizeof(plainText)) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("SHE ECB FAILED TO MATCH\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE ECB SUCCESS\n");
    if ((ret = wh_Client_SheEncCbc(client, WH_SHE_RAM_KEY_ID, iv, sizeof(iv),
            plainText, cipherText, sizeof(plainText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheEncCbc %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheDecCbc(client, WH_SHE_RAM_KEY_ID, iv, sizeof(iv),
            cipherText, finalText, sizeof(cipherText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheDecCbc %d\n", ret);
        goto exit;
    }
    if (memcmp(finalText, plainText, sizeof(plainText)) != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("SHE CBC FAILED TO MATCH\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE CBC SUCCESS\n");
    if ((ret = wh_Client_SheGenerateMac(client, WH_SHE_RAM_KEY_ID, plainText,
            sizeof(plainText), cipherText, sizeof(cipherText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGenerateMac %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheVerifyMac(client, WH_SHE_RAM_KEY_ID, plainText,
            sizeof(plainText), cipherText, sizeof(cipherText), &sreg)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheVerifyMac %d\n", ret);
        goto exit;
    }
    if (sreg != 0) {
        ret = WH_ERROR_ABORTED;
        WH_ERROR_PRINT("SHE CMAC FAILED TO VERIFY\n");
        goto exit;
    }
    WH_TEST_PRINT("SHE CMAC SUCCESS\n");

    /* === Write protect === */

    /* A key pre-programmed with WH_SHE_FLAG_WRITE_PROTECT cannot be
     * overwritten via SHE LoadKey; the server must return
     * WH_SHE_ERC_WRITE_PROTECTED. Reuses the secret key (auth) and the
     * secure boot established above; uses a clean slot of its own. */
    if ((ret = wh_Client_ShePreProgramKey(client, SHE_WP_KEY_ID,
                                          WH_SHE_FLAG_WRITE_PROTECT,
                                          vectorRawKey,
                                          sizeof(vectorRawKey))) != 0) {
        WH_ERROR_PRINT("Failed to pre-program write-protected key %d\n", ret);
        goto exit;
    }
    if ((ret = wh_She_GenerateLoadableKey(SHE_WP_KEY_ID, WH_SHE_SECRET_KEY_ID,
            1, 0, sheUid, vectorRawKey, secretKey, messageOne, messageTwo,
            messageThree, messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to generate loadable key %d\n", ret);
        goto exit;
    }
    ret = wh_Client_SheLoadKey(client, messageOne, messageTwo, messageThree,
                               messageFour, messageFive);
    if (ret != WH_SHE_ERC_WRITE_PROTECTED) {
        WH_ERROR_PRINT("Expected WH_SHE_ERC_WRITE_PROTECTED, got %d\n", ret);
        ret = WH_ERROR_ABORTED;
        goto exit;
    }
    ret = 0;
    WH_TEST_PRINT("SHE write protect SUCCESS\n");

    /* === Cleanup: destroy provisioned keys so we don't leak NVM === */

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
    if ((ret = _destroySheKey(client, SHE_WP_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }

exit:
    return ret;
}

#endif /* WOLFHSM_CFG_SHE_EXTENSION && !WOLFHSM_CFG_NO_CRYPTO && \
          WOLFHSM_CFG_ENABLE_CLIENT */
