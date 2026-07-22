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
 * test-refactor/misc/wh_test_she_keywrap.c
 *
 * SHE <-> keywrap interop, ported from the interop additions in
 * test/wh_test_she.c. Lives in the misc group because it requires a server
 * whose NVM is provisioned with a trusted keywrap KEK (WH_NVM_FLAGS_TRUSTED,
 * the way whnvmtool would provision it), which the port's shared server does
 * not guarantee: this test spins up its own client/server pair over the mem
 * transport and pumps the server inline between the split (non-blocking)
 * client request/response calls, so no threading is needed. The secure-boot
 * protocol only has a blocking client API, so its INIT / UPDATE / FINISH
 * messages are driven directly with the split comm primitives.
 *
 *   _SheKeywrapInterop - wrap-export a SHE key by id (including the slot-0
 *                        SECRET_KEY), key-wrap vs data-wrap AES-GCM domain
 *                        separation, priming an unused SHE slot via
 *                        unwrap-and-cache, the SHE counter rollback guard
 *                        (reject lower, allow equal), LoadKey updating a slot
 *                        that is primed in cache and committed in NVM, and
 *                        the KEK being immune to client evict
 *   _SheInteropProvision / _SheInteropRestore - end-to-end reboot interop
 *                        across two server sessions with fresh server + NVM
 *                        each: provision loads a key via M1-M5 and
 *                        wrap-exports it; after the "reset" the restore
 *                        session rebuilds it purely from the client-held blob
 *                        and must reproduce the provision ciphertext
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_SHE_EXTENSION) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_KEYWRAP) && defined(WOLFHSM_CFG_ENABLE_CLIENT) &&    \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(NO_AES) &&                \
    defined(HAVE_AESGCM)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_she.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_she.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_she.h"
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_she_crypto.h"

#include "wh_test_common.h"
#include "wh_test_keywrap_util.h"
#include "wh_test_list.h"

enum {
    BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                  WOLFHSM_CFG_COMM_DATA_LEN,
};

#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (128 * 1024)
#define FLASH_PAGE_SIZE 8

/* Id of the trusted KEK the test setup provisions in NVM */
#define WH_SHE_INTEROP_KEK_ID 0x20

static const uint8_t s_uid[WH_SHE_UID_SZ] = {0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x01};

static const uint8_t s_secretKey[WH_SHE_KEY_SZ] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t s_masterEcuKey[WH_SHE_KEY_SZ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t s_bootMacKey[WH_SHE_KEY_SZ] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90};
static const uint8_t s_ramKey[WH_SHE_KEY_SZ] = {
    0xca, 0xfe, 0xf0, 0x0d, 0x10, 0x32, 0x54, 0x76,
    0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89};

/* Reboot-interop state carried from the provision session to the restore
 * session. The client holds only the wrapped blob across the "reset" (the
 * no-NVM premise). */
#define WH_SHE_INTEROP_TARGET_SLOT 4
static const uint8_t s_interopPlain[WH_SHE_KEY_SZ] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
static const uint8_t s_targetKey[WH_SHE_KEY_SZ] = {
    0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98};
static uint8_t  s_interopBlob[256];
static uint16_t s_interopBlobSz;
static uint8_t  s_interopCipher[WH_SHE_KEY_SZ];

/* Self-contained client/server pair over the mem transport with an
 * NVM-provisioned trusted KEK. The server is pumped inline
 * (wh_Server_HandleRequestMessage) between each split client
 * request/response pair. */
typedef struct {
    whServerContext       server[1];
    whClientContext       client[1];
    whNvmContext          nvm[1];
    whServerCryptoContext crypto[1];
    whServerSheContext    she[1];
    /* Transport */
    uint8_t                     reqBuf[BUFFER_SIZE];
    uint8_t                     respBuf[BUFFER_SIZE];
    whTransportMemConfig        tmcf[1];
    whTransportServerCb         tscb[1];
    whTransportMemServerContext tmsc[1];
    whCommServerConfig          cs_conf[1];
    whTransportClientCb         tccb[1];
    whTransportMemClientContext tmcc[1];
    whCommClientConfig          cc_conf[1];
    whClientConfig              c_conf[1];
    /* Flash / NVM */
    whFlashRamsimCtx  fc[1];
    whFlashRamsimCfg  fc_conf[1];
    whFlashCb         fcb[1];
    whNvmFlashConfig  nf_conf[1];
    whNvmFlashContext nfc[1];
    whNvmCb           nfcb[1];
    whNvmConfig       n_conf[1];
    whServerConfig    s_conf[1];
} TestCtx;

/* Static to keep the misc group's stack footprint small */
static TestCtx _testCtx;
static uint8_t _flashMemory[FLASH_RAM_SIZE];

/* Provision the trusted keywrap KEK in NVM with WH_NVM_FLAGS_TRUSTED, the way
 * whnvmtool would on a real device. Clients can never set that flag. */
static int _ProvisionNvmKek(whNvmContext* nvm)
{
    whNvmMetadata meta = {0};

    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID,
                                WH_SHE_INTEROP_KEK_ID);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP |
                 WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_NONMODIFIABLE;
    meta.len = (whNvmSize)sizeof(whTest_KeywrapKek);
    memcpy(meta.label, "SHE interop KEK", sizeof("SHE interop KEK"));

    return wh_Nvm_AddObject(nvm, &meta, meta.len, whTest_KeywrapKek);
}

/* Fresh server + fresh (empty) NVM every call: the reboot interop relies on
 * this modeling a real power cycle between sessions. */
static int _SetupClientServer(TestCtx* t)
{
    uint32_t client_id = 0;
    uint32_t server_id = 0;

    memset(t, 0, sizeof(*t));
    memset(_flashMemory, 0, sizeof(_flashMemory));

    /* Transport */
    t->tmcf[0] = (whTransportMemConfig){
        .req       = (whTransportMemCsr*)t->reqBuf,
        .req_size  = sizeof(t->reqBuf),
        .resp      = (whTransportMemCsr*)t->respBuf,
        .resp_size = sizeof(t->respBuf),
    };
    t->tscb[0]    = (whTransportServerCb)WH_TRANSPORT_MEM_SERVER_CB;
    t->cs_conf[0] = (whCommServerConfig){
        .transport_cb      = t->tscb,
        .transport_context = (void*)t->tmsc,
        .transport_config  = (void*)t->tmcf,
        .server_id         = 124,
    };
    t->tccb[0]    = (whTransportClientCb)WH_TRANSPORT_MEM_CLIENT_CB;
    t->cc_conf[0] = (whCommClientConfig){
        .transport_cb      = t->tccb,
        .transport_context = (void*)t->tmcc,
        .transport_config  = (void*)t->tmcf,
        .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    };
    t->c_conf[0] = (whClientConfig){
        .comm = t->cc_conf,
    };

    /* Flash / NVM */
    t->fc_conf[0] = (whFlashRamsimCfg){
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_SECTOR_SIZE,
        .pageSize   = FLASH_PAGE_SIZE,
        .erasedByte = ~(uint8_t)0,
        .memory     = _flashMemory,
    };
    t->fcb[0]     = (whFlashCb)WH_FLASH_RAMSIM_CB;
    t->nf_conf[0] = (whNvmFlashConfig){
        .cb      = t->fcb,
        .context = t->fc,
        .config  = t->fc_conf,
    };
    t->nfcb[0]   = (whNvmCb)WH_NVM_FLASH_CB;
    t->n_conf[0] = (whNvmConfig){
        .cb      = t->nfcb,
        .context = t->nfc,
        .config  = t->nf_conf,
    };

    /* Server config */
    t->s_conf[0] = (whServerConfig){
        .comm_config = t->cs_conf,
        .nvm         = t->nvm,
        .crypto      = t->crypto,
        .she         = t->she,
        .devId       = INVALID_DEVID,
    };

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(t->nvm, t->n_conf));
    /* Trusted keywrap KEK is provisioned before the server accepts requests */
    WH_TEST_RETURN_ON_FAIL(_ProvisionNvmKek(t->nvm));
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(t->crypto->rng, NULL, INVALID_DEVID));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(t->server, t->s_conf));
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_SetConnected(t->server, WH_COMM_CONNECTED));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(t->client, t->c_conf));

    /* Comm init so the server learns the client id */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(t->client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInitResponse(t->client, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(client_id == t->client->comm->client_id);

    return WH_ERROR_OK;
}

static void _CleanupClientServer(TestCtx* t)
{
    (void)wh_Client_Cleanup(t->client);
    (void)wh_Server_Cleanup(t->server);
    (void)wh_Nvm_Cleanup(t->nvm);
    (void)wc_FreeRng(t->crypto->rng);
    (void)wolfCrypt_Cleanup();
}

/* boot MAC digest = CMAC_bootMacKey(zeros || size || bootloader) */
static int _ComputeBootMac(const uint8_t* bootloader, uint32_t bootloaderSz,
                           const uint8_t* bootMacKey, uint8_t* digestOut)
{
    int     ret;
    Cmac    cmac[1];
    uint8_t zeros[WH_SHE_BOOT_MAC_PREFIX_LEN] = {0};
    word32  digestSz                          = WH_SHE_KEY_SZ;

    if ((ret = wc_InitCmac(cmac, bootMacKey, WH_SHE_KEY_SZ, WC_CMAC_AES,
                           NULL)) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, zeros, sizeof(zeros))) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, (const uint8_t*)&bootloaderSz,
                             sizeof(bootloaderSz))) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, bootloader, bootloaderSz)) != 0) {
        return ret;
    }
    digestSz = AES_BLOCK_SIZE;
    return wc_CmacFinal(cmac, digestOut, &digestSz);
}

/* Sequential wrappers: send the request, pump the server once, then collect
 * the response */

static int _NvmAddObject(TestCtx* t, whNvmId id, whNvmAccess access,
                         whNvmFlags flags, whNvmSize labelLen, uint8_t* label,
                         whNvmSize len, const uint8_t* data)
{
    int32_t rc = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectRequest(
        t->client, id, access, flags, labelLen, label, len, data));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectResponse(t->client, &rc));
    return (int)rc;
}

/* Pre-program a SHE key: an NVM object at the SHE key id with a zero-counter
 * SHE label (split-API equivalent of wh_Client_ShePreProgramKey) */
static int _ShePreProgramKey(TestCtx* t, whNvmId keyId, uint32_t sheFlags,
                             const uint8_t* key, whNvmSize keySz)
{
    uint8_t label[WH_NVM_LABEL_LEN] = {0};

    wh_She_Meta2Label(0, sheFlags, label);
    return _NvmAddObject(
        t, WH_MAKE_KEYID(WH_KEYTYPE_SHE, t->client->comm->client_id, keyId), 0,
        0, sizeof(label), label, keySz, key);
}

static int _KeyWrapExport(TestCtx* t, whKeyId keyId, uint16_t keyType,
                          whKeyId kekId, uint8_t* wrappedOut,
                          uint16_t* wrappedSz)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapExportRequest(
        t->client, WC_CIPHER_AES_GCM, keyId, keyType, kekId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyWrapExportResponse(t->client, WC_CIPHER_AES_GCM,
                                           wrappedOut, wrappedSz);
}

static int _KeyUnwrapAndCache(TestCtx* t, whKeyId kekId, uint8_t* wrappedIn,
                              uint16_t wrappedSz, uint16_t* keyIdOut)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndCacheRequest(
        t->client, WC_CIPHER_AES_GCM, kekId, wrappedIn, wrappedSz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyUnwrapAndCacheResponse(t->client, WC_CIPHER_AES_GCM,
                                               keyIdOut);
}

static int _KeyUnwrapAndExport(TestCtx* t, whKeyId kekId, uint8_t* wrappedIn,
                               uint16_t wrappedSz, whNvmMetadata* metaOut,
                               uint8_t* keyOut, uint16_t* keySz)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportRequest(
        t->client, WC_CIPHER_AES_GCM, kekId, wrappedIn, wrappedSz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyUnwrapAndExportResponse(t->client, WC_CIPHER_AES_GCM,
                                                metaOut, keyOut, keySz);
}

static int _KeyEvict(TestCtx* t, uint16_t keyId)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(t->client, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyEvictResponse(t->client);
}

static int _DataWrap(TestCtx* t, whKeyId kekId, uint8_t* dataIn,
                     uint32_t dataSz, uint8_t* wrappedOut, uint32_t* wrappedSz)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_DataWrapRequest(
        t->client, WC_CIPHER_AES_GCM, kekId, dataIn, dataSz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_DataWrapResponse(t->client, WC_CIPHER_AES_GCM, wrappedOut,
                                      wrappedSz);
}

static int _DataUnwrap(TestCtx* t, whKeyId kekId, uint8_t* wrappedIn,
                       uint32_t wrappedSz, uint8_t* dataOut, uint32_t* dataSz)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_DataUnwrapRequest(
        t->client, WC_CIPHER_AES_GCM, kekId, wrappedIn, wrappedSz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_DataUnwrapResponse(t->client, WC_CIPHER_AES_GCM, dataOut,
                                        dataSz);
}

static int _SheSetUid(TestCtx* t, uint8_t* uid, uint32_t uidSz)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheSetUidRequest(t->client, uid, uidSz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheSetUidResponse(t->client);
}

static int _SheGetStatus(TestCtx* t, uint8_t* sreg)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheGetStatusRequest(t->client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheGetStatusResponse(t->client, sreg);
}

static int _SheLoadKey(TestCtx* t, uint8_t* m1, uint8_t* m2, uint8_t* m3,
                       uint8_t* m4, uint8_t* m5)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheLoadKeyRequest(t->client, m1, m2, m3));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheLoadKeyResponse(t->client, m4, m5);
}

static int _SheLoadPlainKey(TestCtx* t, uint8_t* key, uint32_t keySz)
{
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SheLoadPlainKeyRequest(t->client, key, keySz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheLoadPlainKeyResponse(t->client);
}

static int _SheEncEcb(TestCtx* t, uint8_t keyId, uint8_t* in, uint8_t* out,
                      uint32_t sz)
{
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SheEncEcbRequest(t->client, keyId, in, sz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheEncEcbResponse(t->client, out, sz);
}

static int _SheDecEcb(TestCtx* t, uint8_t keyId, uint8_t* in, uint8_t* out,
                      uint32_t sz)
{
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SheDecEcbRequest(t->client, keyId, in, sz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheDecEcbResponse(t->client, out, sz);
}

/* The secure-boot protocol (INIT / UPDATE / FINISH) only has a blocking
 * client API, so drive the messages directly and pump the server between
 * each step. The bootloaders used here fit one UPDATE chunk. */
static int _SheSecureBoot(TestCtx* t, uint8_t* bootloader,
                          uint32_t bootloaderLen)
{
    int      ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* respBuf;

    whMessageShe_SecureBootInitRequest*    initReq;
    whMessageShe_SecureBootUpdateRequest*  updateReq;
    whMessageShe_SecureBootInitResponse*   initResp;
    whMessageShe_SecureBootUpdateResponse* updateResp;
    whMessageShe_SecureBootFinishResponse* finishResp;

    if (bootloaderLen >
        (uint32_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                   sizeof(whMessageShe_SecureBootUpdateRequest))) {
        return WH_ERROR_BADARGS;
    }

    respBuf = (uint8_t*)wh_CommClient_GetDataPtr(t->client->comm);

    /* INIT: announce the bootloader size */
    initReq = (whMessageShe_SecureBootInitRequest*)wh_CommClient_GetDataPtr(
        t->client->comm);
    initReq->sz = bootloaderLen;
    WH_TEST_RETURN_ON_FAIL(wh_Client_SendRequest(
        t->client, WH_MESSAGE_GROUP_SHE, WH_SHE_SECURE_BOOT_INIT,
        sizeof(*initReq), (uint8_t*)initReq));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    ret = wh_Client_RecvResponse(t->client, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, respBuf);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    initResp = (whMessageShe_SecureBootInitResponse*)respBuf;
    if (initResp->rc != WH_SHE_ERC_NO_ERROR) {
        return initResp->rc;
    }

    /* UPDATE: feed the bootloader (single chunk) */
    updateReq = (whMessageShe_SecureBootUpdateRequest*)wh_CommClient_GetDataPtr(
        t->client->comm);
    updateReq->sz = bootloaderLen;
    memcpy((uint8_t*)(updateReq + 1), bootloader, bootloaderLen);
    WH_TEST_RETURN_ON_FAIL(wh_Client_SendRequest(
        t->client, WH_MESSAGE_GROUP_SHE, WH_SHE_SECURE_BOOT_UPDATE,
        (uint16_t)(sizeof(*updateReq) + bootloaderLen), (uint8_t*)updateReq));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    ret = wh_Client_RecvResponse(t->client, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, respBuf);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    updateResp = (whMessageShe_SecureBootUpdateResponse*)respBuf;
    if (updateResp->rc != WH_SHE_ERC_NO_ERROR) {
        return updateResp->rc;
    }

    /* FINISH: verify the boot MAC */
    WH_TEST_RETURN_ON_FAIL(wh_Client_SendRequest(
        t->client, WH_MESSAGE_GROUP_SHE, WH_SHE_SECURE_BOOT_FINISH, 0, NULL));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    ret = wh_Client_RecvResponse(t->client, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, respBuf);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    finishResp = (whMessageShe_SecureBootFinishResponse*)respBuf;
    return finishResp->rc;
}

/* Establish secure-boot state so SHE key operations are permitted (a fresh
 * server starts un-booted): pre-program the boot MAC key and the expected
 * bootloader CMAC, set the UID, then run the secure-boot protocol. */
static int _SheEstablishSecureBoot(TestCtx* t)
{
    int      ret;
    uint8_t  bootloader[64];
    uint32_t bootloaderSz          = sizeof(bootloader);
    uint8_t  digest[WH_SHE_KEY_SZ] = {0};
    uint8_t  sreg                  = 0;

    memset(bootloader, 0xB7, sizeof(bootloader));

    ret = _ComputeBootMac(bootloader, bootloaderSz, s_bootMacKey, digest);
    if (ret != 0) {
        return ret;
    }

    ret = _ShePreProgramKey(t, WH_SHE_BOOT_MAC_KEY_ID, 0, s_bootMacKey,
                            WH_SHE_KEY_SZ);
    if (ret != 0) {
        return ret;
    }
    ret = _ShePreProgramKey(t, WH_SHE_BOOT_MAC, 0, digest, sizeof(digest));
    if (ret != 0) {
        return ret;
    }
    ret = _SheSetUid(t, (uint8_t*)s_uid, sizeof(s_uid));
    if (ret != 0) {
        return ret;
    }
    ret = _SheSecureBoot(t, bootloader, bootloaderSz);
    if (ret != 0) {
        return ret;
    }
    ret = _SheGetStatus(t, &sreg);
    if (ret != 0) {
        return ret;
    }
    if ((sreg & WH_SHE_SREG_BOOT_OK) == 0 ||
        (sreg & WH_SHE_SREG_BOOT_FINISHED) == 0 ||
        (sreg & WH_SHE_SREG_SECURE_BOOT) == 0) {
        return WH_ERROR_ABORTED;
    }
    return 0;
}

/* SHE <-> keywrap interop: wrap-export a SHE key, prime an unused SHE slot
 * via unwrap-and-cache and use it, and verify the SHE counter rollback guard
 * on unwrap-and-cache. */
static int _SheKeywrapInterop(TestCtx* t)
{
    int ret;

    /* The client cannot read or set the trusted KEK; it only names it */
    whKeyId       kekId = WH_SHE_INTEROP_KEK_ID;
    uint8_t       blob[128];
    uint16_t      blobSz;
    uint16_t      expSz          = (uint16_t)(WH_KEYWRAP_AES_GCM_HEADER_SIZE +
                                sizeof(whNvmMetadata) + WH_SHE_KEY_SZ);
    const whNvmId SHE_PRIME_SLOT = 6;
    const whNvmId SHE_CTR_SLOT   = 7;
    uint8_t       sheKey[WH_SHE_KEY_SZ];
    uint8_t       ecbIn[WH_SHE_KEY_SZ];
    uint8_t       ecbOut[WH_SHE_KEY_SZ];
    uint8_t       ecbBack[WH_SHE_KEY_SZ];
    uint16_t      outId = 0;
    uint8_t       ctrLabel[WH_NVM_LABEL_LEN];
    uint8_t       m1[WH_SHE_M1_SZ];
    uint8_t       m2[WH_SHE_M2_SZ];
    uint8_t       m3[WH_SHE_M3_SZ];
    uint8_t       m4[WH_SHE_M4_SZ];
    uint8_t       m5[WH_SHE_M5_SZ];
    uint8_t       o4[WH_SHE_M4_SZ];
    uint8_t       o5[WH_SHE_M5_SZ];

    ret = _SheEstablishSecureBoot(t);
    if (ret != 0) {
        WH_ERROR_PRINT("SHE interop: secure boot failed %d\n", ret);
        return ret;
    }

    /* Pre-program the keys the interop uses: SECRET_KEY (slot 0), the master
     * ECU key to authorize the LoadKey update, and the RAM key (slot 14). */
    ret = _ShePreProgramKey(t, WH_SHE_SECRET_KEY_ID, 0, s_secretKey,
                            WH_SHE_KEY_SZ);
    if (ret != 0) {
        WH_ERROR_PRINT("SHE interop: pre-program SECRET_KEY failed %d\n", ret);
        return ret;
    }
    ret = _ShePreProgramKey(t, WH_SHE_MASTER_ECU_KEY_ID, 0, s_masterEcuKey,
                            WH_SHE_KEY_SZ);
    if (ret != 0) {
        WH_ERROR_PRINT("SHE interop: pre-program MASTER_ECU failed %d\n", ret);
        return ret;
    }
    ret = _SheLoadPlainKey(t, (uint8_t*)s_ramKey, WH_SHE_KEY_SZ);
    if (ret != 0) {
        WH_ERROR_PRINT("SHE interop: LoadPlainKey failed %d\n", ret);
        return ret;
    }

    /* Wrap-export the cached RAM key (slot 14) by id; the blob must keep
     * TYPE=SHE and be the expected size. */
    blobSz = sizeof(blob);
    ret    = _KeyWrapExport(t, WH_SHE_RAM_KEY_ID, WH_KEYTYPE_SHE, kekId, blob,
                            &blobSz);
    if (ret != 0 || blobSz != expSz) {
        WH_ERROR_PRINT("SHE wrap-export failed ret=%d sz=%u exp=%u\n", ret,
                       blobSz, expSz);
        return (ret != 0) ? ret : WH_ERROR_ABORTED;
    }

    /* SECRET_KEY has ID field == 0; it must still wrap-export like any other
     * SHE slot. */
    blobSz = sizeof(blob);
    ret = _KeyWrapExport(t, WH_SHE_SECRET_KEY_ID, WH_KEYTYPE_SHE, kekId, blob,
                         &blobSz);
    if (ret != 0 || blobSz != expSz) {
        WH_ERROR_PRINT("SHE slot-0 wrap-export failed ret=%d sz=%u exp=%u\n",
                       ret, blobSz, expSz);
        return (ret != 0) ? ret : WH_ERROR_ABORTED;
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
        ret = _DataUnwrap(t, kekId, blob, blobSz, leak, &leakSz);
        if (ret == WH_ERROR_OK) {
            WH_ERROR_PRINT("SHE interop: DataUnwrap of a wrap-export blob "
                           "must fail but it succeeded\n");
            return WH_ERROR_ABORTED;
        }

        /* DataWrap accepts the trusted KEK, but the resulting data blob must
         * fail to cache as a key */
        memset(leak, 0x33, sizeof(leak));
        ret = _DataWrap(t, kekId, leak, sizeof(leak), dataBlob, &dataBlobSz);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("SHE interop: DataWrap under trusted KEK failed "
                           "%d\n",
                           ret);
            return ret;
        }
        ret = _KeyUnwrapAndCache(t, kekId, dataBlob, (uint16_t)dataBlobSz,
                                 &injectId);
        if (ret == WH_ERROR_OK) {
            WH_ERROR_PRINT("SHE interop: unwrap-and-cache of a data-wrap "
                           "blob must fail but it succeeded\n");
            return WH_ERROR_ABORTED;
        }
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
        ret = _KeyUnwrapAndExport(t, kekId, blob, blobSz, &leakMeta, leakKey,
                                  &leakKeySz);
        if (ret != WH_ERROR_ABORTED) {
            WH_ERROR_PRINT("SHE interop: unwrap-and-export of a SHE "
                           "wrap-export blob expected ABORTED, got %d\n",
                           ret);
            return (ret == 0) ? WH_ERROR_ABORTED : ret;
        }
        if (memcmp(leakKey, sentinel, sizeof(leakKey)) != 0) {
            WH_ERROR_PRINT("SHE interop: unwrap-and-export refused the "
                           "blob but wrote key bytes\n");
            return WH_ERROR_ABORTED;
        }
    }

    /* Prime an unused SHE slot via unwrap-and-cache, then use it. */
    memset(sheKey, 0x5a, sizeof(sheKey));
    blobSz = sizeof(blob);
    ret = whTest_BuildSheKeyBlob(whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
                                 WH_MAKE_KEYID(WH_KEYTYPE_SHE,
                                               t->client->comm->client_id,
                                               SHE_PRIME_SLOT),
                                 1, 0, sheKey, blob, &blobSz);
    if (ret != 0) {
        WH_ERROR_PRINT("SHE interop: build prime blob failed %d\n", ret);
        return ret;
    }
    ret = _KeyUnwrapAndCache(t, kekId, blob, blobSz, &outId);
    if (ret != 0) {
        WH_ERROR_PRINT("SHE unwrap-and-cache failed %d\n", ret);
        return ret;
    }
    memset(ecbIn, 0x11, sizeof(ecbIn));
    ret = _SheEncEcb(t, SHE_PRIME_SLOT, ecbIn, ecbOut, sizeof(ecbIn));
    if (ret == 0) {
        ret = _SheDecEcb(t, SHE_PRIME_SLOT, ecbOut, ecbBack, sizeof(ecbOut));
    }
    if (ret != 0 || memcmp(ecbIn, ecbBack, sizeof(ecbIn)) != 0) {
        WH_ERROR_PRINT("SHE primed-key ECB round trip failed %d\n", ret);
        return (ret != 0) ? ret : WH_ERROR_ABORTED;
    }

    /* Counter guard on the SHE unwrap-and-cache path: seed an NVM SHE slot
     * with counter=5, then check a lower-counter prime is rejected and an
     * equal-counter prime is accepted. */
    wh_She_Meta2Label(5, 0, ctrLabel);
    ret = _NvmAddObject(
        t,
        WH_MAKE_KEYID(WH_KEYTYPE_SHE, t->client->comm->client_id, SHE_CTR_SLOT),
        0, 0, sizeof(ctrLabel), ctrLabel, sizeof(sheKey), sheKey);
    if (ret != 0) {
        WH_ERROR_PRINT("SHE interop: seed counter slot failed %d\n", ret);
        return ret;
    }
    /* lower counter -> rejected */
    blobSz = sizeof(blob);
    ret    = whTest_BuildSheKeyBlob(
        whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
        WH_MAKE_KEYID(WH_KEYTYPE_SHE, t->client->comm->client_id, SHE_CTR_SLOT),
        3, 0, sheKey, blob, &blobSz);
    if (ret != 0) {
        return ret;
    }
    ret = _KeyUnwrapAndCache(t, kekId, blob, blobSz, &outId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("SHE counter rollback expected ACCESS, got %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    /* equal counter -> accepted */
    blobSz = sizeof(blob);
    ret    = whTest_BuildSheKeyBlob(
        whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
        WH_MAKE_KEYID(WH_KEYTYPE_SHE, t->client->comm->client_id, SHE_CTR_SLOT),
        5, 0, sheKey, blob, &blobSz);
    if (ret != 0) {
        return ret;
    }
    ret = _KeyUnwrapAndCache(t, kekId, blob, blobSz, &outId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("SHE counter equal expected OK, got %d\n", ret);
        return (ret != 0) ? ret : WH_ERROR_ABORTED;
    }

    /* LoadKey update of a slot that is primed in cache and committed in NVM:
     * M4/M5 and later crypto must use the new key, not the stale cached
     * copy. */
    {
        uint8_t newSheKey[WH_SHE_KEY_SZ];
        Aes     ecbAes[1];

        memset(newSheKey, 0xc3, sizeof(newSheKey));
        /* counter 6 > the primed and stored counter of 5 */
        ret = wh_She_GenerateLoadableKey(
            SHE_CTR_SLOT, WH_SHE_MASTER_ECU_KEY_ID, 6, 0, (uint8_t*)s_uid,
            newSheKey, (uint8_t*)s_masterEcuKey, m1, m2, m3, m4, m5);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate update M1-M5 %d\n", ret);
            return ret;
        }
        ret = _SheLoadKey(t, m1, m2, m3, o4, o5);
        if (ret != 0) {
            WH_ERROR_PRINT("SHE LOAD KEY over primed slot failed %d\n", ret);
            return ret;
        }
        if (memcmp(o4, m4, WH_SHE_M4_SZ) != 0 ||
            memcmp(o5, m5, WH_SHE_M5_SZ) != 0) {
            WH_ERROR_PRINT("SHE LOAD KEY over primed slot returned M4/M5 "
                           "from a stale key\n");
            return WH_ERROR_ABORTED;
        }
        /* server-side ECB must match software AES under the new key */
        memset(ecbIn, 0x22, sizeof(ecbIn));
        ret = _SheEncEcb(t, SHE_CTR_SLOT, ecbIn, ecbOut, sizeof(ecbIn));
        if (ret != 0) {
            WH_ERROR_PRINT("SHE ECB after update failed %d\n", ret);
            return ret;
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
            return ret;
        }
        if (memcmp(ecbOut, ecbBack, AES_BLOCK_SIZE) != 0) {
            WH_ERROR_PRINT("SHE ECB after update used a stale key\n");
            return WH_ERROR_ABORTED;
        }
    }

    /* The client must not be able to evict the server-owned KEK. The
     * fixture's NVM is torn down with the test, so no further cleanup. */
    ret = _KeyEvict(t, kekId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("SHE interop: KEK evict expected ACCESS, got %d\n", ret);
        return (ret == 0) ? WH_ERROR_ABORTED : ret;
    }

    WH_TEST_PRINT("SHE <-> keywrap interop SUCCESS\n");
    return 0;
}

/*
 * SHE <-> keywrap reboot interop, run across two server sessions to model a
 * power cycle. Each session gets a fresh server and NVM from
 * _SetupClientServer; the client carries only the wrapped blob across the
 * "reset".
 *
 *   Session 1 (provision): secure boot, load a target key, capture its ECB
 *     ciphertext, wrap-export it by id, save the blob.
 *   Session 2 (restore): secure boot, unwrap-and-cache the saved blob, ECB
 *     ciphertext must match session 1.
 *
 * The KEK is the trusted key the setup provisions in NVM in both sessions;
 * the client never uploads it.
 */
static int _SheInteropProvision(TestCtx* t)
{
    int      ret;
    uint8_t  m1[WH_SHE_M1_SZ];
    uint8_t  m2[WH_SHE_M2_SZ];
    uint8_t  m3[WH_SHE_M3_SZ];
    uint8_t  m4[WH_SHE_M4_SZ];
    uint8_t  m5[WH_SHE_M5_SZ];
    uint8_t  o4[WH_SHE_M4_SZ];
    uint8_t  o5[WH_SHE_M5_SZ];
    uint16_t blobSz = sizeof(s_interopBlob);

    ret = _SheEstablishSecureBoot(t);
    if (ret != 0) {
        WH_ERROR_PRINT("interop provision: secure boot failed %d\n", ret);
        return ret;
    }

    /* Provision the secret key, then load the master ECU key (auth=secret)
     * and the target key (auth=master ECU) using offline-generated M1/M2/M3.
     */
    ret = _ShePreProgramKey(t, WH_SHE_SECRET_KEY_ID, 0, s_secretKey,
                            WH_SHE_KEY_SZ);
    if (ret != 0) {
        return ret;
    }
    ret = wh_She_GenerateLoadableKey(
        WH_SHE_MASTER_ECU_KEY_ID, WH_SHE_SECRET_KEY_ID, 1, 0, (uint8_t*)s_uid,
        (uint8_t*)s_masterEcuKey, (uint8_t*)s_secretKey, m1, m2, m3, m4, m5);
    if (ret != 0) {
        return ret;
    }
    ret = _SheLoadKey(t, m1, m2, m3, o4, o5);
    if (ret != 0) {
        WH_ERROR_PRINT("interop provision: load master ECU failed %d\n", ret);
        return ret;
    }
    ret = wh_She_GenerateLoadableKey(
        WH_SHE_INTEROP_TARGET_SLOT, WH_SHE_MASTER_ECU_KEY_ID, 1, 0,
        (uint8_t*)s_uid, (uint8_t*)s_targetKey, (uint8_t*)s_masterEcuKey, m1,
        m2, m3, m4, m5);
    if (ret != 0) {
        return ret;
    }
    ret = _SheLoadKey(t, m1, m2, m3, o4, o5);
    if (ret != 0) {
        WH_ERROR_PRINT("interop provision: load target via M1/M2/M3 failed "
                       "%d\n",
                       ret);
        return ret;
    }

    /* Capture the target key's ECB output for cross-session comparison. */
    ret = _SheEncEcb(t, WH_SHE_INTEROP_TARGET_SLOT, (uint8_t*)s_interopPlain,
                     s_interopCipher, sizeof(s_interopPlain));
    if (ret != 0) {
        return ret;
    }

    /* Wrap-export the target key by id under the server's trusted KEK. */
    ret = _KeyWrapExport(t, WH_SHE_INTEROP_TARGET_SLOT, WH_KEYTYPE_SHE,
                         WH_SHE_INTEROP_KEK_ID, s_interopBlob, &blobSz);
    if (ret != 0) {
        WH_ERROR_PRINT("interop provision: wrap-export failed %d\n", ret);
        return ret;
    }
    s_interopBlobSz = blobSz;

    return 0;
}

static int _SheInteropRestore(TestCtx* t)
{
    int      ret;
    uint8_t  cipher[WH_SHE_KEY_SZ] = {0};
    uint16_t outId                 = 0;

    /* Fresh boot: re-establish secure-boot state. The target SHE key is NOT
     * in NVM (this server's NVM is fresh); the trusted KEK was provisioned in
     * NVM by the setup, so the client just names it. */
    ret = _SheEstablishSecureBoot(t);
    if (ret != 0) {
        WH_ERROR_PRINT("interop restore: secure boot failed %d\n", ret);
        return ret;
    }

    /* Prime the SHE key purely from the client-held wrapped blob. */
    ret = _KeyUnwrapAndCache(t, WH_SHE_INTEROP_KEK_ID, s_interopBlob,
                             s_interopBlobSz, &outId);
    if (ret != 0) {
        WH_ERROR_PRINT("interop restore: unwrap-and-cache failed %d\n", ret);
        return ret;
    }

    /* Use the restored key via the SHE API; it must reproduce the provision
     * session's ciphertext, proving the exact key round-tripped. */
    ret = _SheEncEcb(t, WH_SHE_INTEROP_TARGET_SLOT, (uint8_t*)s_interopPlain,
                     cipher, sizeof(s_interopPlain));
    if (ret != 0) {
        WH_ERROR_PRINT("interop restore: SheEncEcb failed %d\n", ret);
        return ret;
    }
    if (memcmp(cipher, s_interopCipher, sizeof(cipher)) != 0) {
        WH_ERROR_PRINT("interop restore: restored key does not match\n");
        return WH_ERROR_ABORTED;
    }
    WH_TEST_PRINT("SHE wrapped-key reboot interop SUCCESS\n");

    return 0;
}

int whTest_SheKeywrapInterop(void* ctx)
{
    int      ret;
    TestCtx* t = &_testCtx;

    (void)ctx;

    /* Interop under a single server lifetime */
    WH_TEST_RETURN_ON_FAIL(_SetupClientServer(t));
    ret = _SheKeywrapInterop(t);
    _CleanupClientServer(t);
    if (ret != 0) {
        return ret;
    }

    /* Reboot interop: two sessions back-to-back, each with a fresh server +
     * NVM, modeling the power cycle between provision and restore. */
    s_interopBlobSz = 0;
    memset(s_interopBlob, 0, sizeof(s_interopBlob));
    memset(s_interopCipher, 0, sizeof(s_interopCipher));

    WH_TEST_RETURN_ON_FAIL(_SetupClientServer(t));
    ret = _SheInteropProvision(t);
    _CleanupClientServer(t);
    if (ret != 0) {
        return ret;
    }

    WH_TEST_RETURN_ON_FAIL(_SetupClientServer(t));
    ret = _SheInteropRestore(t);
    _CleanupClientServer(t);

    return ret;
}

#endif /* WOLFHSM_CFG_SHE_EXTENSION && !WOLFHSM_CFG_NO_CRYPTO && \
          WOLFHSM_CFG_KEYWRAP && WOLFHSM_CFG_ENABLE_CLIENT &&    \
          WOLFHSM_CFG_ENABLE_SERVER && !NO_AES && HAVE_AESGCM */
