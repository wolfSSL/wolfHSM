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
 * test-refactor/server/wh_test_she_server.c
 *
 * Server-side SHE test suite. Exercises internal server SHE
 * behavior through direct server API calls against the shared
 * server context: the master ECU key metadata fallback and the
 * per-action request-size validation in the SHE handlers.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_SHE_EXTENSION) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_she.h"
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_she.h"
#include "wolfhsm/wh_comm.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Value of WH_SHE_SB_SUCCESS from the wh_server_she.c internal enum.
 * Mirrored here since the enum is private to that translation unit. */
#define TEST_SHE_SB_STATE_SUCCESS 3


/*
 * Reading the master ECU key when it has never been provisioned must
 * succeed and return an all-zero key with correctly populated metadata.
 */
int whTest_SheMasterEcuKeyFallback(whServerContext* server)
{
    int           ret;
    whNvmMetadata outMeta[1]            = {0};
    uint8_t       keyBuf[WH_SHE_KEY_SZ] = {0};
    uint32_t      keySz                 = sizeof(keyBuf);
    uint8_t       zeros[WH_SHE_KEY_SZ]  = {0};
    whKeyId       masterEcuKeyId;

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    masterEcuKeyId = WH_MAKE_KEYID(WH_KEYTYPE_SHE, server->comm->client_id,
                                   WH_SHE_MASTER_ECU_KEY_ID);

    /* Fill keyBuf with non-zero to ensure it gets overwritten */
    memset(keyBuf, 0xFF, sizeof(keyBuf));

    ret = wh_Server_KeystoreReadKey(server, masterEcuKeyId, outMeta, keyBuf,
                                    &keySz);

    WH_TEST_ASSERT_RETURN(ret == 0);
    WH_TEST_ASSERT_RETURN(keySz == WH_SHE_KEY_SZ);
    WH_TEST_ASSERT_RETURN(memcmp(keyBuf, zeros, WH_SHE_KEY_SZ) == 0);
    WH_TEST_ASSERT_RETURN(outMeta->len == WH_SHE_KEY_SZ);
    WH_TEST_ASSERT_RETURN(outMeta->id == masterEcuKeyId);

    WH_TEST_PRINT("SHE master ECU key fallback metadata test SUCCESS\n");

    return 0;
}


/*
 * Test that SHE server handlers reject requests with an invalid
 * req_size while still producing an action-specific response packet.
 * Each handler is called directly via wh_Server_HandleSheRequest()
 * with a realistic but incorrectly sized request packet.
 */
int whTest_SheReqSizeChecking(whServerContext* server)
{
    int      ret       = 0;
    uint16_t req_size  = 0;
    uint16_t resp_size = 0;

    /* Buffers for request and response packets */
    uint8_t req_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t resp_packet[WOLFHSM_CFG_COMM_DATA_LEN];

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

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
        /* The state gate allows SECURE_BOOT_INIT through regardless of
         * sbState; we are testing the size check which happens first. */
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
     * _LoadKey maps the malformed request to an action-specific response;
     * verify the request still completes with a response packet instead
     * of failing the transport path.
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
        req->keyId      = WH_SHE_RAM_KEY_ID;
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

    /* Restore a clean SHE context so the poked uidSet/sbState don't
     * leak into the live request loop the server enters next. */
    memset(server->she, 0, sizeof(*server->she));

    WH_TEST_PRINT("SHE req_size checking test SUCCESS\n");

    return 0;
}

#endif /* WOLFHSM_CFG_SHE_EXTENSION && !WOLFHSM_CFG_NO_CRYPTO */
