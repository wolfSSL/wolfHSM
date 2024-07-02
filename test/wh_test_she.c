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

#if defined(WH_CONFIG)
#include "wh_config.h"
#endif

#ifdef WOLFHSM_SHE_EXTENSION
#ifndef WOLFHSM_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_she.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_common.h"

#include "wh_test_common.h"

#if defined(WH_CFG_TEST_POSIX)
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

/* Helper function to destroy a SHE key so the unit tests don't
 * leak NVM objects across invocations. Necessary, as SHE doesn't expose a
 * destroy key API since SHE keys are supposed to be fixed hardware keys */
static int _destroySheKey(whClientContext* client, whNvmId clientSheKeyId)
{
    int rc = 0;
    int32_t serverRc = 0;

    whNvmId id = MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_SHE, client->comm->client_id, clientSheKeyId);

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
    uint8_t zeros[WOLFHSM_SHE_BOOT_MAC_PREFIX_LEN] = {0};
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
    uint8_t messageOne[WOLFHSM_SHE_M1_SZ];
    uint8_t messageTwo[WOLFHSM_SHE_M2_SZ];
    uint8_t messageThree[WOLFHSM_SHE_M3_SZ];
    uint8_t messageFour[WOLFHSM_SHE_M4_SZ];
    uint8_t messageFive[WOLFHSM_SHE_M5_SZ];
    uint32_t outClientId = 0;
    uint32_t outServerId = 0;
    const uint32_t SHE_TEST_VECTOR_KEY_ID = 4;

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInit(client, &outClientId, &outServerId));

#ifdef WH_CFG_TEST_VERBOSE
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

        printf("PRE-SHE TEST: NvmGetAvailable:%d, server_rc:%d avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects,
               (int)reclaim_size, (int)reclaim_objects);
    }
#endif /* WH_CFG_TEST_VERBOSE */

    /* generate a new cmac key */
    if ((ret = wc_InitRng_ex(rng, NULL, WOLFHSM_DEV_ID)) != 0) {
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
    if ((ret = wh_Client_ShePreProgramKey(client, WOLFHSM_SHE_BOOT_MAC_KEY_ID, 0, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    /* store cmac digest */
    if ((ret = wh_Client_ShePreProgramKey(client, WOLFHSM_SHE_BOOT_MAC, 0, bootMacDigest, sizeof(bootMacDigest))) != 0) {
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
    if ((sreg & WOLFHSM_SHE_SREG_BOOT_OK) == 0 ||
        (sreg & WOLFHSM_SHE_SREG_BOOT_FINISHED) == 0 ||
        (sreg & WOLFHSM_SHE_SREG_SECURE_BOOT) == 0) {
        WH_ERROR_PRINT("Failed to secureBoot with SHE CMAC\n");
        goto exit;
    }
    printf("SHE secure boot SUCCESS\n");
    /* load the secret key using pre progam */
    if ((ret = wh_Client_ShePreProgramKey(client, WOLFHSM_SHE_SECRET_KEY_ID, 0, secretKey, sizeof(secretKey))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    /* load the prng seed using pre program */
    if ((ret = wh_Client_ShePreProgramKey(client, WOLFHSM_SHE_PRNG_SEED_ID, 0, prngSeed, sizeof(prngSeed))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_ShePreProgramKey %d\n", ret);
        goto exit;
    }
    /* load the vector master ecu key */
    if ((ret = wh_SheGenerateLoadableKey(WOLFHSM_SHE_MASTER_ECU_KEY_ID, WOLFHSM_SHE_SECRET_KEY_ID, 1, 0, sheUid, vectorMasterEcuKey, secretKey, messageOne, messageTwo, messageThree, messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGenerateLoadableKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheLoadKey(client, messageOne, messageTwo, messageThree, outMessageFour, outMessageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadKey %d\n", ret);
        goto exit;
    }
    /* verify that our helper function output matches the vector */
    if ((ret = wh_SheGenerateLoadableKey(SHE_TEST_VECTOR_KEY_ID, WOLFHSM_SHE_MASTER_ECU_KEY_ID, 1, 0, sheUid, vectorRawKey, vectorMasterEcuKey, messageOne, messageTwo, messageThree, messageFour, messageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGenerateLoadableKey %d\n", ret);
        goto exit;
    }
    if (memcmp(messageOne, vectorMessageOne, sizeof(vectorMessageOne)) != 0 ||
        memcmp(messageTwo, vectorMessageTwo, sizeof(vectorMessageTwo)) != 0 ||
        memcmp(messageThree, vectorMessageThree, sizeof(vectorMessageThree)) != 0 ||
        memcmp(messageFour, vectorMessageFour, sizeof(vectorMessageFour)) != 0 ||
        memcmp(messageFive, vectorMessageFive, sizeof(vectorMessageFive)) != 0) {
        WH_ERROR_PRINT("Failed to generate a loadable key to match the vector\n");
        goto exit;
    }
    printf("SHE wh_SheGenerateLoadableKey SUCCESS\n");
    /* test CMD_LOAD_KEY with test vector */
    if ((ret = wh_Client_SheLoadKey(client, vectorMessageOne, vectorMessageTwo, vectorMessageThree, outMessageFour, outMessageFive)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadKey %d\n", ret);
        goto exit;
    }
    if (memcmp(outMessageFour, vectorMessageFour, sizeof(vectorMessageFour))
        != 0 || memcmp(outMessageFive, vectorMessageFive,
        sizeof(vectorMessageFive)) != 0) {
        WH_ERROR_PRINT("wh_Client_SheLoadKey FAILED TO MATCH\n");
        goto exit;
    }
    printf("SHE LOAD KEY SUCCESS\n");
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
    printf("SHE RND SUCCESS\n");
    if ((ret = wh_Client_SheLoadPlainKey(client, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheLoadPlainKey %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheEncEcb(client, WOLFHSM_SHE_RAM_KEY_ID, plainText, cipherText, sizeof(plainText))) != 0) {
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
    if ((ret = wh_Client_SheDecEcb(client, WOLFHSM_SHE_RAM_KEY_ID, cipherText, finalText, sizeof(cipherText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheEncEcb %d\n", ret);
        goto exit;
    }
    if (memcmp(finalText, plainText, sizeof(plainText)) != 0) {
        WH_ERROR_PRINT("SHE ECB FAILED TO MATCH\n");
        goto exit;
    }
    printf("SHE ECB SUCCESS\n");
    if ((ret = wh_Client_SheEncCbc(client, WOLFHSM_SHE_RAM_KEY_ID, iv, sizeof(iv), plainText, cipherText, sizeof(plainText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheEncEcb %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheDecCbc(client, WOLFHSM_SHE_RAM_KEY_ID, iv, sizeof(iv), cipherText, finalText, sizeof(cipherText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheEncEcb %d\n", ret);
        goto exit;
    }
    if (memcmp(finalText, plainText, sizeof(plainText)) != 0) {
        WH_ERROR_PRINT("SHE CBC FAILED TO MATCH\n");
        goto exit;
    }
    printf("SHE CBC SUCCESS\n");
    if ((ret = wh_Client_SheGenerateMac(client, WOLFHSM_SHE_RAM_KEY_ID, plainText, sizeof(plainText), cipherText, sizeof(cipherText))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheGenerateMac %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_SheVerifyMac(client, WOLFHSM_SHE_RAM_KEY_ID, plainText, sizeof(plainText), cipherText, sizeof(cipherText), &sreg)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SheVerifyMac %d\n", ret);
        goto exit;
    }
    if (sreg != 0) {
        WH_ERROR_PRINT("SHE CMAC FAILED TO VERIFY\n");
        goto exit;
    }

    /* destroy "pre-programmed" keys so we don't leak NVM */
    if ((ret = _destroySheKey(client, WOLFHSM_SHE_BOOT_MAC_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, WOLFHSM_SHE_BOOT_MAC)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, WOLFHSM_SHE_SECRET_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, WOLFHSM_SHE_PRNG_SEED_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, WOLFHSM_SHE_MASTER_ECU_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    if ((ret = _destroySheKey(client, SHE_TEST_VECTOR_KEY_ID)) != 0) {
        WH_ERROR_PRINT("Failed to _destroySheKey, ret=%d\n", ret);
        goto exit;
    }
    printf("SHE CMAC SUCCESS\n");

#ifdef WH_CFG_TEST_VERBOSE
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

        printf("POST-SHE TEST: NvmGetAvailable:%d, server_rc:%d avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects,
               (int)reclaim_size, (int)reclaim_objects);
    }
#endif /* WH_CFG_TEST_VERBOSE */


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

int whTest_SheServerConfig(whServerConfig* config)
{
    whServerContext server[1] = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int ret = 0;

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, config));
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

#if defined(WH_CFG_TEST_POSIX)
static void* _whClientTask(void *cf)
{
    WH_TEST_ASSERT(0 == whTest_SheClientConfig(cf));
    return NULL;
}

static void* _whServerTask(void* cf)
{
    WH_TEST_ASSERT(0 == whTest_SheServerConfig(cf));
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
                 .client_id         = 1,
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
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));

    _whClientServerThreadTest(c_conf, s_conf);

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}
#endif /* WH_CFG_TEST_POSIX */


int whTest_She(void)
{
#if defined(WH_CFG_TEST_POSIX)
    printf("Testing SHE: (pthread) mem...\n");
    WH_TEST_RETURN_ON_FAIL(wh_ClientServer_MemThreadTest());
#endif
    return 0;
}

#endif /* !WOLFHSM_NO_CRYPTO */
#endif /* WOLFHSM_SHE_EXTENSION */
