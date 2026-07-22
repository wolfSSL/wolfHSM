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
 * test-refactor/misc/wh_test_she_no_nvm.c
 *
 * NVM-less SHE test, ported from test/wh_test_she_no_nvm.c. Lives in the misc
 * group because it requires a server with a NULL NVM context
 * (whServerConfig.nvm == NULL), which the port's shared server cannot provide:
 * this test spins up its own client/server pair over the mem transport and
 * pumps the server inline between the split (non-blocking) client
 * request/response calls, so no threading is needed.
 *
 * A client provisions every SHE key it needs purely from client-held AES-GCM
 * wrapped blobs: the server boots with a trusted KEK in its volatile cache,
 * the client wraps the plaintext SHE keys into blobs under the same known KEK
 * bytes, then primes them into the server's key cache on demand via
 * unwrap-and-cache. The client then drives the client-facing SHE surface
 * (secure boot, LoadKey, LoadPlainKey, ECB/CBC, CMAC, ExportRamKey, and the
 * PRNG) to prove it all works without any NVM backing.
 *
 * The secure-boot protocol only has a blocking client API, so the INIT /
 * UPDATE / FINISH messages are driven directly here with the split comm
 * primitives.
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
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_she.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_she.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
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

/* Test KEK cache id (intrinsic in production; provisioned by the server task
 * here). */
#define SHE_NONVM_KEK_ID 0x20
/* SHE slot provisioned via unwrap-and-cache and used directly. */
#define SHE_NONVM_WORKING_SLOT 4
/* SHE slot loaded through the SheLoadKey protocol (cache path). */
#define SHE_NONVM_USER_SLOT 5
/* Wrapped-blob size for one 16-byte SHE key (matches the server's KEK). */
#define SHE_NONVM_BLOB_SZ \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(whNvmMetadata) + WH_SHE_KEY_SZ)

/* ---- Hardcoded plaintext test material ---------------------------------- */

/* Test KEK bytes: whTest_KeywrapKek (wh_test_keywrap_util.h). In production the
 * KEK is intrinsic; the server task provisions it in its cache the way boot
 * code would. */

static const uint8_t s_uid[WH_SHE_UID_SZ] = {0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x01};

/* Reused from the SHE test vectors. */
static const uint8_t s_secretKey[WH_SHE_KEY_SZ] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t s_masterEcuKey[WH_SHE_KEY_SZ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t s_bootMacKey[WH_SHE_KEY_SZ] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90};
static const uint8_t s_workingKey[WH_SHE_KEY_SZ] = {
    0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98};
static const uint8_t s_userKey[WH_SHE_KEY_SZ] = {
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
static const uint8_t s_prngSeed[WH_SHE_KEY_SZ] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
static const uint8_t s_entropy[WH_SHE_KEY_SZ] = {
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};

/* A SHE key the test holds as a client-side wrapped blob, plus its plaintext
 * and SHE label fields. */
typedef struct {
    whKeyId  slot;    /* SHE slot id (WH_SHE_*_ID) */
    uint32_t counter; /* SHE label counter */
    uint32_t flags;   /* SHE label flags */
    uint8_t  plain[WH_SHE_KEY_SZ];
    uint8_t  blob[SHE_NONVM_BLOB_SZ];
    uint16_t blobSz;
} SheNoNvmKey;

/* Self-contained client/server pair over the mem transport. The server is
 * pumped inline (wh_Server_HandleRequestMessage) between each split client
 * request/response pair. The whole point of this fixture: the server has NO
 * NVM backing (config.nvm == NULL). */
typedef struct {
    whServerContext       server[1];
    whClientContext       client[1];
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
    whServerConfig              s_conf[1];
} TestCtx;

/* Static to keep the misc group's stack footprint small */
static TestCtx _testCtx;

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

/* Provision the trusted KEK directly in the server cache, the way boot code
 * would on an NVM-less device. It carries WH_NVM_FLAGS_TRUSTED -- a flag the
 * request handlers strip from every client path, so only server-internal
 * provisioning like this can set it. That makes it the trusted KEK that
 * unwrap-and-cache requires. committed=0 keeps it pinned for the life of the
 * (NVM-less) server. The id matches what the client names: plain
 * SHE_NONVM_KEK_ID translated against WH_TEST_DEFAULT_CLIENT_ID. */
static int _ProvisionServerKek(whServerContext* server)
{
    whNvmMetadata meta = {0};

    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID,
                                SHE_NONVM_KEK_ID);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP |
                 WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_NONMODIFIABLE;
    meta.len = (whNvmSize)sizeof(whTest_KeywrapKek);
    memcpy(meta.label, "SHE no-nvm KEK", sizeof("SHE no-nvm KEK"));

    return wh_Server_KeystoreCacheKey(server, &meta,
                                      (uint8_t*)whTest_KeywrapKek);
}

static int _SetupClientServer(TestCtx* t)
{
    uint32_t client_id = 0;
    uint32_t server_id = 0;

    memset(t, 0, sizeof(*t));

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

    /* Server config -- the whole point of this test: NO NVM backing */
    t->s_conf[0] = (whServerConfig){
        .comm_config = t->cs_conf,
        .nvm         = NULL,
        .crypto      = t->crypto,
        .she         = t->she,
        .devId       = INVALID_DEVID,
    };

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(t->crypto->rng, NULL, INVALID_DEVID));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(t->server, t->s_conf));
    /* Boot-time KEK provisioning happens before the server accepts requests */
    WH_TEST_RETURN_ON_FAIL(_ProvisionServerKek(t->server));
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
    (void)wc_FreeRng(t->crypto->rng);
    (void)wolfCrypt_Cleanup();
}

/* Sequential wrappers: send the request, pump the server once, then collect
 * the response */

static int _KeyUnwrapAndCache(TestCtx* t, whKeyId kekId, uint8_t* wrappedIn,
                              uint16_t wrappedSz, uint16_t* keyIdOut)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndCacheRequest(
        t->client, WC_CIPHER_AES_GCM, kekId, wrappedIn, wrappedSz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyUnwrapAndCacheResponse(t->client, WC_CIPHER_AES_GCM,
                                               keyIdOut);
}

static int _KeyExport(TestCtx* t, uint16_t keyId, uint8_t* label,
                      uint16_t labelSz, uint8_t* keyOut, uint16_t* keySz)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(t->client, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyExportResponse(t->client, label, labelSz, keyOut,
                                       keySz);
}

static int _KeyEvict(TestCtx* t, uint16_t keyId)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(t->client, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyEvictResponse(t->client);
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

static int _SheExportRamKey(TestCtx* t, uint8_t* m1, uint8_t* m2, uint8_t* m3,
                            uint8_t* m4, uint8_t* m5)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheExportRamKeyRequest(t->client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheExportRamKeyResponse(t->client, m1, m2, m3, m4, m5);
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

static int _SheEncCbc(TestCtx* t, uint8_t keyId, uint8_t* iv, uint32_t ivSz,
                      uint8_t* in, uint8_t* out, uint32_t sz)
{
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SheEncCbcRequest(t->client, keyId, iv, ivSz, in, sz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheEncCbcResponse(t->client, out, sz);
}

static int _SheDecCbc(TestCtx* t, uint8_t keyId, uint8_t* iv, uint32_t ivSz,
                      uint8_t* in, uint8_t* out, uint32_t sz)
{
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SheDecCbcRequest(t->client, keyId, iv, ivSz, in, sz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheDecCbcResponse(t->client, out, sz);
}

static int _SheGenerateMac(TestCtx* t, uint8_t keyId, uint8_t* in,
                           uint32_t inSz, uint8_t* out, uint32_t outSz)
{
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SheGenerateMacRequest(t->client, keyId, in, inSz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheGenerateMacResponse(t->client, out, outSz);
}

static int _SheVerifyMac(TestCtx* t, uint8_t keyId, uint8_t* message,
                         uint32_t messageLen, uint8_t* mac, uint32_t macLen,
                         uint8_t* outStatus)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheVerifyMacRequest(
        t->client, keyId, message, messageLen, mac, macLen));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheVerifyMacResponse(t->client, outStatus);
}

static int _SheInitRnd(TestCtx* t)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheInitRndRequest(t->client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheInitRndResponse(t->client);
}

static int _SheRnd(TestCtx* t, uint8_t* out, uint32_t* outSz)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheRndRequest(t->client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheRndResponse(t->client, out, outSz);
}

static int _SheExtendSeed(TestCtx* t, uint8_t* entropy, uint32_t entropySz)
{
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SheExtendSeedRequest(t->client, entropy, entropySz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_SheExtendSeedResponse(t->client);
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

/* Wrap every SHE key the test uses into a client-held blob, under the trusted
 * KEK that boot code provisioned in the server cache (_ProvisionServerKek).
 * Unwrap-and-cache requires a trusted KEK (WH_NVM_FLAGS_TRUSTED), which a
 * client can never set, so the client cannot upload the KEK; it only names it
 * by id and wraps under the same known bytes. */
static int _WrapSheKeys(TestCtx* t, SheNoNvmKey* keys, int n)
{
    int ret;
    int i;

    for (i = 0; i < n; i++) {
        keys[i].blobSz = (uint16_t)sizeof(keys[i].blob);
        ret            = whTest_BuildSheKeyBlob(
            whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
            WH_MAKE_KEYID(WH_KEYTYPE_SHE, t->client->comm->client_id,
                                     keys[i].slot),
            keys[i].counter, keys[i].flags, keys[i].plain, keys[i].blob,
            &keys[i].blobSz);
        if (ret != 0) {
            WH_ERROR_PRINT("no-nvm: wrap SHE slot %u failed %d\n",
                           (unsigned)keys[i].slot, ret);
            return ret;
        }
    }

    return 0;
}

/* Unwrap and cache every SHE key blob so the keys are resident in the
 * server's volatile cache, ready for the SHE API to use. */
static int _UnwrapAndCacheSheKeys(TestCtx* t, SheNoNvmKey* keys, int n,
                                  whKeyId kekId)
{
    int      ret;
    int      i;
    uint16_t outId;

    for (i = 0; i < n; i++) {
        outId = 0;
        ret =
            _KeyUnwrapAndCache(t, kekId, keys[i].blob, keys[i].blobSz, &outId);
        if (ret != 0) {
            WH_ERROR_PRINT("no-nvm: unwrap-and-cache SHE slot %u failed %d\n",
                           (unsigned)keys[i].slot, ret);
            return ret;
        }
    }

    return 0;
}

static int _SheNoNvmFlow(TestCtx* t)
{
    int     ret;
    whKeyId kekId = SHE_NONVM_KEK_ID;

    uint8_t  bootloader[64];
    uint32_t bootloaderSz = sizeof(bootloader);
    uint8_t  sreg         = 0;

    uint8_t m1[WH_SHE_M1_SZ];
    uint8_t m2[WH_SHE_M2_SZ];
    uint8_t m3[WH_SHE_M3_SZ];
    uint8_t m4[WH_SHE_M4_SZ];
    uint8_t m5[WH_SHE_M5_SZ];
    uint8_t o4[WH_SHE_M4_SZ];
    uint8_t o5[WH_SHE_M5_SZ];

    uint8_t plain[WH_SHE_KEY_SZ];
    uint8_t cipher[WH_SHE_KEY_SZ];
    uint8_t back[WH_SHE_KEY_SZ];
    uint8_t mac[WH_SHE_KEY_SZ];
    uint8_t iv[WH_SHE_KEY_SZ] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                 0x0c, 0x0d, 0x0e, 0x0f};

    /* SHE keys provisioned purely from client-held wrapped blobs:
     *   SECRET_KEY     - auth for ExportRamKey and PRNG derivation
     *   MASTER_ECU_KEY - auth for the user-slot LoadKey below
     *   BOOT_MAC_KEY   - secure-boot CMAC key
     *   BOOT_MAC       - expected bootloader CMAC (computed below)
     *   working slot   - used directly via the SHE cipher API
     *   PRNG_SEED      - seed state for InitRnd/ExtendSeed
     * SECRET_KEY is SHE slot 0; priming it via unwrap-and-cache relies on the
     * keystore exempting SHE keys from the "id 0 == unassigned" check. */
    SheNoNvmKey keys[6];

    /* Build the key table. Plaintext is hardcoded; BOOT_MAC is the CMAC of
     * the (fixed) bootloader so secure boot will accept it. */
    memset(bootloader, 0xB7, sizeof(bootloader));
    memset(keys, 0, sizeof(keys));

    keys[0].slot    = WH_SHE_SECRET_KEY_ID;
    keys[0].counter = 1;
    memcpy(keys[0].plain, s_secretKey, WH_SHE_KEY_SZ);

    keys[1].slot    = WH_SHE_MASTER_ECU_KEY_ID;
    keys[1].counter = 1;
    memcpy(keys[1].plain, s_masterEcuKey, WH_SHE_KEY_SZ);

    keys[2].slot    = WH_SHE_BOOT_MAC_KEY_ID;
    keys[2].counter = 1;
    memcpy(keys[2].plain, s_bootMacKey, WH_SHE_KEY_SZ);

    keys[3].slot    = WH_SHE_BOOT_MAC;
    keys[3].counter = 1;
    ret =
        _ComputeBootMac(bootloader, bootloaderSz, s_bootMacKey, keys[3].plain);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: compute BOOT_MAC failed %d\n", ret);
        return ret;
    }

    keys[4].slot    = SHE_NONVM_WORKING_SLOT;
    keys[4].counter = 1;
    memcpy(keys[4].plain, s_workingKey, WH_SHE_KEY_SZ);

    keys[5].slot    = WH_SHE_PRNG_SEED_ID;
    keys[5].counter = 1;
    memcpy(keys[5].plain, s_prngSeed, WH_SHE_KEY_SZ);

    /* wrap every SHE key into a client-held blob */
    ret = _WrapSheKeys(t, keys, 6);
    if (ret != 0) {
        return ret;
    }

    /* prime them into the NULL-NVM server's volatile cache */
    ret = _UnwrapAndCacheSheKeys(t, keys, 6, kekId);
    if (ret != 0) {
        return ret;
    }
    WH_TEST_PRINT("SHE no-nvm: unwrap-and-cache provisioning SUCCESS\n");

    /* Secure boot using the cached BOOT_MAC_KEY + BOOT_MAC. */
    ret = _SheSetUid(t, (uint8_t*)s_uid, sizeof(s_uid));
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheSetUid failed %d\n", ret);
        return ret;
    }
    ret = _SheSecureBoot(t, bootloader, bootloaderSz);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheSecureBoot failed %d\n", ret);
        return ret;
    }
    ret = _SheGetStatus(t, &sreg);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheGetStatus failed %d\n", ret);
        return ret;
    }
    if ((sreg & WH_SHE_SREG_BOOT_OK) == 0 ||
        (sreg & WH_SHE_SREG_BOOT_FINISHED) == 0 ||
        (sreg & WH_SHE_SREG_SECURE_BOOT) == 0) {
        WH_ERROR_PRINT("no-nvm: secure boot status 0x%02x\n", sreg);
        return WH_ERROR_ABORTED;
    }
    WH_TEST_PRINT("SHE no-nvm: secure boot SUCCESS\n");

    /* LoadKey cache path: load a user key (auth = master ECU key, primed via
     * unwrap-and-cache above). The loaded key lands in the cache because the
     * server has no NVM (src/wh_server_she.c LOAD_KEY nvm==NULL guard). */
    ret = wh_She_GenerateLoadableKey(
        SHE_NONVM_USER_SLOT, WH_SHE_MASTER_ECU_KEY_ID, 1, 0, (uint8_t*)s_uid,
        (uint8_t*)s_userKey, (uint8_t*)s_masterEcuKey, m1, m2, m3, m4, m5);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: generate user-slot M1/M2/M3 failed %d\n", ret);
        return ret;
    }
    ret = _SheLoadKey(t, m1, m2, m3, o4, o5);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: LoadKey user slot failed %d\n", ret);
        return ret;
    }
    WH_TEST_PRINT("SHE no-nvm: LoadKey (cache path) SUCCESS\n");

    /* ECB round trip on the LoadKey-provisioned user slot. */
    memset(plain, 0x11, sizeof(plain));
    ret = _SheEncEcb(t, SHE_NONVM_USER_SLOT, plain, cipher, sizeof(plain));
    if (ret == 0) {
        ret = _SheDecEcb(t, SHE_NONVM_USER_SLOT, cipher, back, sizeof(cipher));
    }
    if (ret != 0 || memcmp(plain, back, sizeof(plain)) != 0) {
        WH_ERROR_PRINT("no-nvm: user-slot ECB round trip failed %d\n", ret);
        return (ret != 0) ? ret : WH_ERROR_ABORTED;
    }

    /* ECB round trip on the unwrap-and-cache-provisioned working slot. */
    memset(plain, 0x22, sizeof(plain));
    ret = _SheEncEcb(t, SHE_NONVM_WORKING_SLOT, plain, cipher, sizeof(plain));
    if (ret == 0) {
        ret =
            _SheDecEcb(t, SHE_NONVM_WORKING_SLOT, cipher, back, sizeof(cipher));
    }
    if (ret != 0 || memcmp(plain, back, sizeof(plain)) != 0) {
        WH_ERROR_PRINT("no-nvm: working-slot ECB round trip failed %d\n", ret);
        return (ret != 0) ? ret : WH_ERROR_ABORTED;
    }
    WH_TEST_PRINT("SHE no-nvm: ECB round trips SUCCESS\n");

    /* RAM key: plain load, ECB, then export + re-import round trip. The
     * exported M1..M5 authenticate with SECRET_KEY (slot 0); re-importing
     * reproduces the same RAM key, so decrypting the earlier ciphertext must
     * round-trip back to the plaintext. */
    ret = _SheLoadPlainKey(t, (uint8_t*)s_workingKey, WH_SHE_KEY_SZ);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheLoadPlainKey failed %d\n", ret);
        return ret;
    }
    memset(plain, 0x33, sizeof(plain));
    ret = _SheEncEcb(t, WH_SHE_RAM_KEY_ID, plain, cipher, sizeof(plain));
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: RAM EncEcb failed %d\n", ret);
        return ret;
    }
    ret = _SheExportRamKey(t, m1, m2, m3, m4, m5);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheExportRamKey failed %d\n", ret);
        return ret;
    }
    ret = _SheLoadKey(t, m1, m2, m3, o4, o5);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: re-import exported RAM key failed %d\n", ret);
        return ret;
    }
    ret = _SheDecEcb(t, WH_SHE_RAM_KEY_ID, cipher, back, sizeof(cipher));
    if (ret != 0 || memcmp(plain, back, sizeof(plain)) != 0) {
        WH_ERROR_PRINT("no-nvm: RAM ECB export round trip failed %d\n", ret);
        return (ret != 0) ? ret : WH_ERROR_ABORTED;
    }
    WH_TEST_PRINT("SHE no-nvm: ExportRamKey round trip SUCCESS\n");

    memset(plain, 0x44, sizeof(plain));
    ret = _SheEncCbc(t, WH_SHE_RAM_KEY_ID, iv, sizeof(iv), plain, cipher,
                     sizeof(plain));
    if (ret == 0) {
        ret = _SheDecCbc(t, WH_SHE_RAM_KEY_ID, iv, sizeof(iv), cipher, back,
                         sizeof(cipher));
    }
    if (ret != 0 || memcmp(plain, back, sizeof(plain)) != 0) {
        WH_ERROR_PRINT("no-nvm: RAM CBC round trip failed %d\n", ret);
        return (ret != 0) ? ret : WH_ERROR_ABORTED;
    }

    ret = _SheGenerateMac(t, WH_SHE_RAM_KEY_ID, plain, sizeof(plain), mac,
                          sizeof(mac));
    if (ret == 0) {
        ret = _SheVerifyMac(t, WH_SHE_RAM_KEY_ID, plain, sizeof(plain), mac,
                            sizeof(mac), &sreg);
    }
    if (ret != 0 || sreg != 0) {
        WH_ERROR_PRINT("no-nvm: RAM CMAC failed ret=%d status=%d\n", ret, sreg);
        return (ret != 0) ? ret : WH_ERROR_ABORTED;
    }
    WH_TEST_PRINT("SHE no-nvm: RAM key ECB/CBC/CMAC SUCCESS\n");

    /* PRNG: init from SECRET_KEY + PRNG_SEED, draw a block, then extend the
     * seed. InitRnd/ExtendSeed cache the updated PRNG seed since there is no
     * NVM to persist it to. */
    {
        uint8_t  rnd[WH_SHE_KEY_SZ];
        uint32_t rndSz = sizeof(rnd);

        ret = _SheInitRnd(t);
        if (ret == 0) {
            ret = _SheRnd(t, rnd, &rndSz);
        }
        if (ret == 0) {
            ret = _SheExtendSeed(t, (uint8_t*)s_entropy, sizeof(s_entropy));
        }
        if (ret != 0) {
            WH_ERROR_PRINT("no-nvm: PRNG init/rnd/extend failed %d\n", ret);
            return ret;
        }
    }
    WH_TEST_PRINT("SHE no-nvm: PRNG (init/rnd/extend) SUCCESS\n");

    /* The boot-provisioned KEK is a WH_NVM_FLAGS_TRUSTED key: the client
     * must be able neither to read it nor to evict it. */
    {
        uint8_t  kbuf[sizeof(whTest_KeywrapKek)];
        uint16_t kbufSz = (uint16_t)sizeof(kbuf);
        uint8_t  klabel[WH_NVM_LABEL_LEN];

        ret = _KeyExport(t, kekId, klabel, sizeof(klabel), kbuf, &kbufSz);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("no-nvm: KEK export expected ACCESS, got %d\n", ret);
            return (ret == 0) ? WH_ERROR_ABORTED : ret;
        }
        ret = _KeyEvict(t, kekId);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("no-nvm: KEK evict expected ACCESS, got %d\n", ret);
            return (ret == 0) ? WH_ERROR_ABORTED : ret;
        }
    }
    WH_TEST_PRINT("SHE no-nvm: KEK unreadable and immutable SUCCESS\n");
    WH_TEST_PRINT("SHE no-nvm flow SUCCESS\n");

    return WH_ERROR_OK;
}

int whTest_SheNoNvm(void* ctx)
{
    int      ret;
    TestCtx* t = &_testCtx;

    (void)ctx;

    WH_TEST_RETURN_ON_FAIL(_SetupClientServer(t));

    ret = _SheNoNvmFlow(t);

    _CleanupClientServer(t);

    return ret;
}

#endif /* WOLFHSM_CFG_SHE_EXTENSION && !WOLFHSM_CFG_NO_CRYPTO && \
          WOLFHSM_CFG_KEYWRAP && WOLFHSM_CFG_ENABLE_CLIENT &&    \
          WOLFHSM_CFG_ENABLE_SERVER && !NO_AES && HAVE_AESGCM */
