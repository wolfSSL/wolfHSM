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
 * test-refactor/misc/wh_test_portkey.c
 *
 * End-to-end coverage of port keys (WH_KEYTYPE_PORT) as key wrap KEKs. Lives
 * in the misc group because it needs a server with known port keys,
 * which the port's shared server does not guarantee: this test spins up its
 * own client/server pair over the mem transport and pumps the server inline
 * between the split (non-blocking) client request/response calls, so no
 * threading is needed. A mock wolfCrypt device holds one AES-256 KEK, which
 * the port registers as port key WH_TEST_PORTKEK_ID, and runs AES-GCM with
 * it when the server passes the key by reference. It also exports a by-value
 * KEK.
 *
 *   _whTest_PortKeyKeyWrap         - key wrap / unwrap-export /
 *                                    unwrap-and-cache with the port KEK;
 *                                    wrapped+port key flag precedence;
 *                                    unregistered-id and wrong-KEK negative
 *                                    paths
 *   _whTest_PortKeyWrappedKeyNoNvm - an unwrapped key is cache-only, so
 *                                    commit and erase must reject a wrapped
 *                                    key id while eviction still works
 *   _whTest_PortKeyKeyWrapExport   - wrap-export a server-held key by id
 *                                    (never presenting plaintext) under the
 *                                    port KEK, round-trip it, and enforce
 *                                    NONEXPORTABLE
 *   _whTest_PortKeyUnwrappedKeyUse - a key unwrapped and cached with the
 *                                    port KEK runs AES-GCM through its
 *                                    wrapped key id, beside a local key with
 *                                    the same number
 *   _whTest_PortKeyDataWrap        - data wrap/unwrap roundtrip with the
 *                                    port KEK, over several AES blocks
 *   _whTest_PortKeyRejections      - keystore operations on a port key id
 *                                    must fail with WH_ERROR_ACCESS
 *   _whTest_PortKeyKekPolicy       - a port key without WRAP usage, or
 *                                    another client's, is refused as a KEK
 *   _whTest_PortKeyUnbound         - a port KEK fails with NOTFOUND on a
 *                                    server with no port keys bound
 *   _whTest_PortKeyByValueKek      - a by-value KEK, whose bytes the port
 *                                    exports, in every wrap operation, and
 *                                    with no crypto device
 *
 * AES and CMAC with port keys, and client-loaded keys as KEKs, are covered
 * in misc/wh_test_portkey_crypto.c.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) &&                                    \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_KEYWRAP) && defined(WOLFHSM_CFG_PORTKEY) &&          \
    !defined(NO_AES) && defined(HAVE_AESGCM)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_portkey.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_server.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define BUFFER_SIZE 4096
#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (128 * 1024)
#define FLASH_PAGE_SIZE 8

/* Id and size of the mock device's KEK, which the port registers */
#define WH_TEST_PORTKEK_ID 3
#define WH_TEST_PORTKEK_SIZE 32

#define WH_TEST_AES_KEYSIZE 32
#define WH_TEST_WRAPPED_KEYID 20
#define WH_TEST_WRAPEXPORT_KEYID 21
#define WH_TEST_WRAPEXPORT_NE_KEYID 22
#define WH_TEST_WRAPPED_KEYSIZE                             \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + WH_TEST_AES_KEYSIZE + \
     sizeof(whNvmMetadata))

static const uint8_t _portKekMaterial[WH_TEST_PORTKEK_SIZE] = {
    0x9a, 0x4e, 0x21, 0xc7, 0x5d, 0x10, 0xfb, 0x33, 0x6f, 0x82, 0xd4,
    0x59, 0xee, 0x07, 0xb1, 0x2c, 0x48, 0x95, 0x3a, 0xc6, 0x71, 0x0d,
    0xb8, 0xe5, 0x12, 0x6a, 0xf9, 0x84, 0x2f, 0xd0, 0x5b, 0xa7};

/* wolfCrypt device of the mock hardware */
#define WH_TEST_PORT_DEVID 0x4D4B454B

/* Port keys _whTest_PortKeyKekPolicy registers: one without WRAP usage,
 * and one that belongs to another client */
#define WH_TEST_PORT_NOWRAP_ID (WH_TEST_PORTKEK_ID + 2)
#define WH_TEST_PORT_OTHER_ID (WH_TEST_PORTKEK_ID + 3)

/* A by-value KEK, whose bytes the port exports, and the keystore key
 * _whTest_PortKeyByValueKek wraps with it */
#define WH_TEST_BYVALUE_KEK_ID (WH_TEST_PORTKEK_ID + 4)
#define WH_TEST_BYVALUE_SRC_KEYID 23

static const uint8_t _byValueKekMaterial[WH_TEST_PORTKEK_SIZE] = {
    0x5d, 0x0e, 0xa3, 0x71, 0xc8, 0x2f, 0x94, 0x16, 0xeb, 0x38, 0x7a,
    0xd1, 0x05, 0xb6, 0x4c, 0x99, 0x23, 0xf0, 0x6e, 0x8a, 0x17, 0xc2,
    0x5b, 0x30, 0xad, 0x74, 0xe9, 0x02, 0x86, 0x3f, 0xd5, 0x61};

/* AES-GCM operations the mock device ran with the KEK */
static int _portKekOps;

/* Times the port exported the by-value KEK */
static int _byValueKekReads;

/* Export the by-value KEK's bytes */
static int _MockExport(wc_CryptoInfo* info)
{
    byte*   out   = info->keystore.op.exportPlain.key;
    word32* outSz = info->keystore.op.exportPlain.keySz;

    if ((info->keystore.type != WC_KEYSTORE_EXPORT_PLAIN) ||
        (wh_PortKey_KeyRefToId(info->keystore.op.exportPlain.keyRef,
                               info->keystore.op.exportPlain.keyRefSz) !=
         WH_TEST_BYVALUE_KEK_ID)) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (out == NULL) {
        /* Size query */
        *outSz = sizeof(_byValueKekMaterial);
        return 0;
    }
    if (*outSz < sizeof(_byValueKekMaterial)) {
        return BUFFER_E;
    }
    memcpy(out, _byValueKekMaterial, sizeof(_byValueKekMaterial));
    *outSz = sizeof(_byValueKekMaterial);
    _byValueKekReads++;
    return 0;
}

/* Runs AES-GCM with the KEK when the server passes it by reference, and
 * exports the by-value KEK. Software keys are left to wolfCrypt */
static int _MockCryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    Aes* aes;
    Aes  sw[1];
    int  ret;

    (void)devId;
    (void)ctx;

    if (info->algo_type == WC_ALGO_TYPE_KEYSTORE) {
        return _MockExport(info);
    }
    if ((info->algo_type != WC_ALGO_TYPE_CIPHER) ||
        (info->cipher.type != WC_CIPHER_AES_GCM)) {
        return CRYPTOCB_UNAVAILABLE;
    }
    aes = (info->cipher.enc != 0) ? info->cipher.aesgcm_enc.aes
                                  : info->cipher.aesgcm_dec.aes;
    if (aes->idLen == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* No other port key holds a KEK */
    if (wh_PortKey_KeyRefToId(aes->id, (uint32_t)aes->idLen) !=
        WH_TEST_PORTKEK_ID) {
        return WC_HW_E;
    }

    ret = wc_AesInit(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(sw, _portKekMaterial, sizeof(_portKekMaterial));
        if ((ret == 0) && (info->cipher.enc != 0)) {
            wc_CryptoCb_AesAuthEnc* e = &info->cipher.aesgcm_enc;
            ret = wc_AesGcmEncrypt(sw, e->out, e->in, e->sz, e->iv, e->ivSz,
                                   e->authTag, e->authTagSz, e->authIn,
                                   e->authInSz);
        }
        else if (ret == 0) {
            wc_CryptoCb_AesAuthDec* d = &info->cipher.aesgcm_dec;
            ret = wc_AesGcmDecrypt(sw, d->out, d->in, d->sz, d->iv, d->ivSz,
                                   d->authTag, d->authTagSz, d->authIn,
                                   d->authInSz);
        }
        wc_AesFree(sw);
    }
    if (ret == 0) {
        _portKekOps++;
    }
    return ret;
}

/* Self-contained client/server pair over the mem transport. The server is
 * pumped inline (wh_Server_HandleRequestMessage) between each split client
 * request/response pair */
typedef struct {
    whServerContext  server[1];
    whClientContext  client[1];
    whNvmContext     nvm[1];
    whPortKeyContext portKey[1];
#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext crypto[1];
#endif
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
    /* Port keys */
    whPortKeyConfig pks_conf[1];
    whServerConfig  s_conf[1];
} TestCtx;

/* Static to keep the misc group's stack footprint small */
static TestCtx _testCtx;
static uint8_t _flashMemory[FLASH_RAM_SIZE];

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
#ifndef WOLFHSM_CFG_NO_CRYPTO
        .crypto = t->crypto,
        .devId  = WH_TEST_PORT_DEVID,
#endif
        .portKey = t->portKey,
    };

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(t->nvm, t->n_conf));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Init(t->portKey, t->pks_conf));
    /* The port's KEK, shared by all clients */
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        t->portKey,
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, WH_TEST_PORTKEK_ID),
        WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE,
        WH_PORTKEY_ACCESS_BY_REF));
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(
        wc_CryptoCb_RegisterDevice(WH_TEST_PORT_DEVID, _MockCryptoCb, NULL));
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
    (void)wh_PortKey_Cleanup(t->portKey);
    (void)wc_FreeRng(t->crypto->rng);
    wc_CryptoCb_UnRegisterDevice(WH_TEST_PORT_DEVID);
    (void)wolfCrypt_Cleanup();
}

/* Sequential wrappers: send the request, pump the server once, then collect
 * the response. The server handler reports operation errors in the response
 * rc, which the client response call returns */

static int _KeyWrap(TestCtx* t, whKeyId kekId, uint8_t* keyIn, uint16_t keySz,
                    whNvmMetadata* meta, uint8_t* wrappedOut,
                    uint16_t* wrappedSz)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(
        t->client, WC_CIPHER_AES_GCM, kekId, keyIn, keySz, meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyWrapResponse(t->client, WC_CIPHER_AES_GCM, wrappedOut,
                                     wrappedSz);
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

static int _KeyUnwrapAndCache(TestCtx* t, whKeyId kekId, uint8_t* wrappedIn,
                              uint16_t wrappedSz, uint16_t* keyIdOut)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndCacheRequest(
        t->client, WC_CIPHER_AES_GCM, kekId, wrappedIn, wrappedSz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyUnwrapAndCacheResponse(t->client, WC_CIPHER_AES_GCM,
                                               keyIdOut);
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

static int _KeyCache(TestCtx* t, uint32_t flags, uint8_t* label,
                     uint16_t labelSz, uint8_t* keyIn, uint16_t keySz,
                     uint16_t* keyIdInOut)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        t->client, flags, label, labelSz, keyIn, keySz, *keyIdInOut));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyCacheResponse(t->client, keyIdInOut);
}

static int _KeyEvict(TestCtx* t, uint16_t keyId)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(t->client, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyEvictResponse(t->client);
}

static int _KeyExport(TestCtx* t, uint16_t keyId, uint8_t* label,
                      uint16_t labelSz, uint8_t* keyOut, uint16_t* keySz)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(t->client, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyExportResponse(t->client, label, labelSz, keyOut,
                                       keySz);
}

static int _KeyCommit(TestCtx* t, uint16_t keyId)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommitRequest(t->client, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyCommitResponse(t->client);
}

static int _KeyErase(TestCtx* t, uint16_t keyId)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEraseRequest(t->client, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyEraseResponse(t->client);
}

static int _KeyRevoke(TestCtx* t, uint16_t keyId)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyRevokeRequest(t->client, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    return wh_Client_KeyRevokeResponse(t->client);
}

/* AES-GCM with the key aes names. tag is the output when encrypting and the
 * input when decrypting */
static int _AesGcm(TestCtx* t, Aes* aes, int enc, const uint8_t* in,
                   uint32_t sz, const uint8_t* iv, uint32_t ivSz,
                   const uint8_t* aad, uint32_t aadSz, uint8_t* tag,
                   uint32_t tagSz, uint8_t* out)
{
    uint32_t outSz = 0;
    int      ret;

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_AesGcmRequest(t->client, aes, enc, in, sz, iv, ivSz, aad,
                                aadSz, (enc != 0) ? NULL : tag, tagSz));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    ret = wh_Client_AesGcmResponse(t->client, aes, out, sz, &outSz,
                                   (enc != 0) ? tag : NULL, tagSz);
    if ((ret == WH_ERROR_OK) && (outSz != sz)) {
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}

static int _whTest_PortKeyKeyWrap(TestCtx* t)
{
    int           ret;
    whKeyId       portKekId = WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORTKEK_ID);
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       tmpPlainKey[WH_TEST_AES_KEYSIZE];
    uint16_t      tmpPlainKeySz = sizeof(tmpPlainKey);
    uint8_t       wrappedKey[WH_TEST_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz   = sizeof(wrappedKey);
    uint16_t      unwrappedKeyId = WH_KEYID_ERASED;
    whNvmMetadata metadata       = {0};
    whNvmMetadata tmpMetadata    = {0};
    int           ops            = _portKekOps;
    size_t        i;

    metadata.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(t->client->comm->client_id,
                                                     WH_TEST_WRAPPED_KEYID);
    metadata.len = WH_TEST_AES_KEYSIZE;
    metadata.flags = WH_NVM_FLAGS_USAGE_ANY;
    memcpy(metadata.label, "port KEK wrapped key",
           sizeof("port KEK wrapped key"));

    /* Fixed pattern; distinct from the KEK material */
    for (i = 0; i < sizeof(plainKey); i++) {
        plainKey[i] = (uint8_t)(0xA0 ^ i);
    }

    /* Wrap a key using the port KEK */
    ret = _KeyWrap(t, portKekId, plainKey, sizeof(plainKey), &metadata,
                   wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to KeyWrap with port KEK %d\n", ret);
        return ret;
    }

    /* Unwrap and export with the port KEK, check the roundtrip */
    ret = _KeyUnwrapAndExport(t, portKekId, wrappedKey, wrappedKeySz,
                              &tmpMetadata, tmpPlainKey, &tmpPlainKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to KeyUnwrapAndExport with port KEK %d\n", ret);
        return ret;
    }

    /* The mock device ran both operations with the KEK, by reference */
    WH_TEST_ASSERT_RETURN(_portKekOps == ops + 2);

    if (memcmp(plainKey, tmpPlainKey, sizeof(plainKey)) != 0) {
        WH_ERROR_PRINT("port KEK wrap/unwrap key failed to match\n");
        return WH_ERROR_ABORTED;
    }

    if (memcmp(&metadata, &tmpMetadata, sizeof(metadata)) != 0) {
        WH_ERROR_PRINT("port KEK wrap/unwrap metadata failed to match\n");
        return WH_ERROR_ABORTED;
    }

    /* Unwrap-and-cache with the port KEK: the wrapped payload is an
     * ordinary key and may enter the cache; only the KEK itself is
     * held by the port */
    ret = _KeyUnwrapAndCache(t, portKekId, wrappedKey, wrappedKeySz,
                             &unwrappedKeyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to KeyUnwrapAndCache with port KEK %d\n", ret);
        return ret;
    }
    WH_TEST_RETURN_ON_FAIL(_KeyEvict(t, unwrappedKeyId));

    /* A KEK id with both the wrapped and port key flags is a port key
     * (the port key flag takes precedence) */
    wrappedKeySz = sizeof(wrappedKey);
    ret = _KeyWrap(t, portKekId | WH_KEYID_CLIENT_WRAPPED_FLAG, plainKey,
                   sizeof(plainKey), &metadata, wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to KeyWrap with wrapped+port KEK %d\n", ret);
        return ret;
    }

    /* Unwrapping a port-KEK-wrapped blob with a different, cached KEK
     * must fail authentication, proving distinct key material was used */
    {
        uint16_t cachedKekId = WH_KEYID_ERASED;
        uint8_t  cachedKek[WH_TEST_PORTKEK_SIZE];
        uint8_t  kekLabel[] = "cached-kek";

        for (i = 0; i < sizeof(cachedKek); i++) {
            cachedKek[i] = (uint8_t)(0x5C ^ i);
        }

        WH_TEST_RETURN_ON_FAIL(_KeyCache(
            t, WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_WRAP, kekLabel,
            sizeof(kekLabel), cachedKek, sizeof(cachedKek), &cachedKekId));

        tmpPlainKeySz = sizeof(tmpPlainKey);
        ret = _KeyUnwrapAndExport(t, cachedKekId, wrappedKey, wrappedKeySz,
                                  &tmpMetadata, tmpPlainKey, &tmpPlainKeySz);
        WH_TEST_RETURN_ON_FAIL(_KeyEvict(t, cachedKekId));
        if (ret == WH_ERROR_OK) {
            WH_ERROR_PRINT("Unwrap with wrong KEK unexpectedly succeeded\n");
            return WH_ERROR_ABORTED;
        }
    }

    /* A port key the server has no record of must fail */
    wrappedKeySz = sizeof(wrappedKey);
    ret =
        _KeyWrap(t, WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORTKEK_ID + 1), plainKey,
                 sizeof(plainKey), &metadata, wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("KeyWrap with unregistered port KEK expected NOTFOUND, "
                       "got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

/* An unwrapped key is cache-only and must never reach NVM, so that it cannot
 * shadow a protected NVM entry. Commit and erase must reject a wrapped key id
 * while eviction still works. Uses the port KEK, since unwrap-and-cache
 * requires a trusted KEK. */
static int _whTest_PortKeyWrappedKeyNoNvm(TestCtx* t)
{
    int           ret;
    whKeyId       portKekId = WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORTKEK_ID);
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       wrappedKey[WH_TEST_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    uint16_t      cachedKeyId  = WH_KEYID_ERASED;
    whNvmMetadata metadata     = {0};
    size_t        i;

    metadata.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(t->client->comm->client_id,
                                                     WH_TEST_WRAPPED_KEYID);
    metadata.len = WH_TEST_AES_KEYSIZE;
    metadata.flags = WH_NVM_FLAGS_USAGE_ANY;
    memcpy(metadata.label, "NoNvm wrapped key", sizeof("NoNvm wrapped key"));

    for (i = 0; i < sizeof(plainKey); i++) {
        plainKey[i] = (uint8_t)(0x3B ^ i);
    }

    WH_TEST_RETURN_ON_FAIL(_KeyWrap(t, portKekId, plainKey, sizeof(plainKey),
                                    &metadata, wrappedKey, &wrappedKeySz));

    WH_TEST_RETURN_ON_FAIL(_KeyUnwrapAndCache(t, portKekId, wrappedKey,
                                              wrappedKeySz, &cachedKeyId));

    /* Commit must refuse to persist a wrapped key to NVM */
    ret = _KeyCommit(t, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId));
    if (ret != WH_ERROR_ABORTED) {
        WH_ERROR_PRINT("KeyCommit of wrapped key expected ABORTED, got %d\n",
                       ret);
        (void)_KeyEvict(t, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId));
        return WH_ERROR_ABORTED;
    }

    /* Erase must likewise refuse a wrapped key */
    ret = _KeyErase(t, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId));
    if (ret != WH_ERROR_ABORTED) {
        WH_ERROR_PRINT("KeyErase of wrapped key expected ABORTED, got %d\n",
                       ret);
        (void)_KeyEvict(t, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId));
        return WH_ERROR_ABORTED;
    }

    /* Cache-only eviction must still succeed */
    WH_TEST_RETURN_ON_FAIL(
        _KeyEvict(t, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId)));

    return WH_ERROR_OK;
}

/* Exercises wh_Client_KeyWrapExport: wrap a key the server already holds (by
 * id, never presenting plaintext), round-trip it through unwrap-and-cache,
 * confirm the cached and exported material match the source, and confirm
 * NONEXPORTABLE is honored. Wrap-export requires a trusted KEK; the port
 * KEK qualifies. */
static int _whTest_PortKeyKeyWrapExport(TestCtx* t)
{
    int           ret;
    whKeyId       portKekId = WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORTKEK_ID);
    uint8_t       srcKey[WH_TEST_AES_KEYSIZE];
    uint16_t      srcKeyId                = WH_TEST_WRAPEXPORT_KEYID;
    uint8_t       label[WH_NVM_LABEL_LEN] = "WrapExport Src";
    uint8_t       wrappedKey[WH_TEST_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    uint16_t      wrappedKeyId = WH_KEYID_ERASED;
    uint8_t       tmpKey[WH_TEST_AES_KEYSIZE];
    uint16_t      tmpKeySz = sizeof(tmpKey);
    uint8_t       tmpLabel[WH_NVM_LABEL_LEN];
    whNvmMetadata tmpMeta = {0};
    size_t        i;

    /* Cache a source crypto key (exportable, full usage); distinct pattern */
    for (i = 0; i < sizeof(srcKey); i++) {
        srcKey[i] = (uint8_t)(0x3D ^ i);
    }
    WH_TEST_RETURN_ON_FAIL(_KeyCache(t, WH_NVM_FLAGS_USAGE_ANY, label,
                                     sizeof(label), srcKey, sizeof(srcKey),
                                     &srcKeyId));

    /* Wrap-and-export the cached key by id; the client never sees plaintext */
    ret = _KeyWrapExport(t, srcKeyId, WH_KEYTYPE_CRYPTO, portKekId, wrappedKey,
                         &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to KeyWrapExport with port KEK %d\n", ret);
        return ret;
    }

    /* Round-trip: unwrap-and-cache the blob (comes back as a wrapped key) */
    ret = _KeyUnwrapAndCache(t, portKekId, wrappedKey, wrappedKeySz,
                             &wrappedKeyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to unwrap-and-cache wrap-exported key %d\n",
                       ret);
        return ret;
    }

    /* The cached round-tripped key must hold the source material */
    ret = _KeyExport(t, WH_CLIENT_KEYID_MAKE_WRAPPED(wrappedKeyId), tmpLabel,
                     sizeof(tmpLabel), tmpKey, &tmpKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to export round-tripped key %d\n", ret);
        return ret;
    }
    if (tmpKeySz != sizeof(srcKey) ||
        memcmp(tmpKey, srcKey, sizeof(srcKey)) != 0) {
        WH_ERROR_PRINT("wrap-export round-trip material mismatch\n");
        return WH_ERROR_ABORTED;
    }

    /* The exported material must match the original, and the embedded id must
     * have been normalized to the wrapped-key namespace */
    tmpKeySz = sizeof(tmpKey);
    ret = _KeyUnwrapAndExport(t, portKekId, wrappedKey, wrappedKeySz, &tmpMeta,
                              tmpKey, &tmpKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to unwrap-and-export wrap-exported key %d\n",
                       ret);
        return ret;
    }
    if (tmpKeySz != sizeof(srcKey) ||
        memcmp(tmpKey, srcKey, sizeof(srcKey)) != 0) {
        WH_ERROR_PRINT("wrap-export key material mismatch\n");
        return WH_ERROR_ABORTED;
    }
    if (WH_KEYID_TYPE(tmpMeta.id) != WH_KEYTYPE_WRAPPED) {
        WH_ERROR_PRINT("wrap-export did not normalize to wrapped type\n");
        return WH_ERROR_ABORTED;
    }

    WH_TEST_RETURN_ON_FAIL(
        _KeyEvict(t, WH_CLIENT_KEYID_MAKE_WRAPPED(wrappedKeyId)));
    WH_TEST_RETURN_ON_FAIL(_KeyEvict(t, srcKeyId));

    /* A NONEXPORTABLE key must be refused by wrap-export */
    {
        uint16_t neKeyId                   = WH_TEST_WRAPEXPORT_NE_KEYID;
        uint8_t  neLabel[WH_NVM_LABEL_LEN] = "WrapExport NoExp";
        uint16_t neWrappedSz               = sizeof(wrappedKey);

        WH_TEST_RETURN_ON_FAIL(_KeyCache(
            t, WH_NVM_FLAGS_USAGE_ANY | WH_NVM_FLAGS_NONEXPORTABLE, neLabel,
            sizeof(neLabel), srcKey, sizeof(srcKey), &neKeyId));
        ret = _KeyWrapExport(t, neKeyId, WH_KEYTYPE_CRYPTO, portKekId,
                             wrappedKey, &neWrappedSz);
        WH_TEST_RETURN_ON_FAIL(_KeyEvict(t, neKeyId));
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT(
                "wrap-export of nonexportable key expected ACCESS, got %d\n",
                ret);
            return WH_ERROR_ABORTED;
        }
    }

    return WH_ERROR_OK;
}

/* A key unwrapped and cached with the port KEK runs AES-GCM through its
 * wrapped key id, beside a local key with the same number */
static int _whTest_PortKeyUnwrappedKeyUse(TestCtx* t)
{
    whKeyId       portKekId = WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORTKEK_ID);
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       localKey[WH_TEST_AES_KEYSIZE] = {0};
    uint8_t       localLabel[WH_NVM_LABEL_LEN]  = "same number";
    uint8_t       label[WH_NVM_LABEL_LEN];
    uint8_t       tmpKey[WH_TEST_AES_KEYSIZE];
    uint16_t      tmpKeySz = sizeof(tmpKey);
    uint8_t       wrappedKey[WH_TEST_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    uint16_t      cachedKeyId  = WH_KEYID_ERASED;
    uint16_t      localKeyId   = WH_TEST_WRAPPED_KEYID;
    whNvmMetadata metadata     = {0};
    const uint8_t plain[]      = "AES-GCM with an unwrapped key";
    const uint8_t aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef};
    uint8_t       iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t       cipher[sizeof(plain)];
    uint8_t       expCipher[sizeof(plain)];
    uint8_t       decrypted[sizeof(plain)];
    uint8_t       tag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t       expTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    Aes           aes[1];
    int           ret;
    size_t        i;

    metadata.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(t->client->comm->client_id,
                                                     WH_TEST_WRAPPED_KEYID);
    metadata.len = WH_TEST_AES_KEYSIZE;
    metadata.flags = WH_NVM_FLAGS_USAGE_ANY;
    for (i = 0; i < sizeof(plainKey); i++) {
        plainKey[i] = (uint8_t)(0x6E ^ i);
    }
    for (i = 0; i < sizeof(iv); i++) {
        iv[i] = (uint8_t)(0x90 + i);
    }

    /* What the unwrapped key must give, in software */
    WH_TEST_RETURN_ON_FAIL(wc_AesInit(aes, NULL, INVALID_DEVID));
    ret = wc_AesGcmSetKey(aes, plainKey, sizeof(plainKey));
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(aes, expCipher, plain, sizeof(plain), iv,
                               sizeof(iv), expTag, sizeof(expTag), aad,
                               sizeof(aad));
    }
    wc_AesFree(aes);
    WH_TEST_RETURN_ON_FAIL(ret);

    WH_TEST_RETURN_ON_FAIL(_KeyWrap(t, portKekId, plainKey, sizeof(plainKey),
                                    &metadata, wrappedKey, &wrappedKeySz));
    WH_TEST_RETURN_ON_FAIL(_KeyUnwrapAndCache(t, portKekId, wrappedKey,
                                              wrappedKeySz, &cachedKeyId));

    /* A local key with the same number is a separate key */
    WH_TEST_RETURN_ON_FAIL(_KeyCache(t, WH_NVM_FLAGS_USAGE_ANY, localLabel,
                                     sizeof(localLabel), localKey,
                                     sizeof(localKey), &localKeyId));
    WH_TEST_ASSERT_RETURN(localKeyId == WH_TEST_WRAPPED_KEYID);

    /* AES-GCM through the wrapped key id runs with the unwrapped key */
    WH_TEST_RETURN_ON_FAIL(wc_AesInit(aes, NULL, INVALID_DEVID));
    ret = wh_Client_AesSetKeyId(aes, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId));
    if (ret == WH_ERROR_OK) {
        ret = _AesGcm(t, aes, 1, plain, sizeof(plain), iv, sizeof(iv), aad,
                      sizeof(aad), tag, sizeof(tag), cipher);
    }
    if (ret == WH_ERROR_OK) {
        ret = _AesGcm(t, aes, 0, cipher, sizeof(cipher), iv, sizeof(iv), aad,
                      sizeof(aad), tag, sizeof(tag), decrypted);
    }
    wc_AesFree(aes);
    WH_TEST_RETURN_ON_FAIL(ret);
    WH_TEST_ASSERT_RETURN((memcmp(cipher, expCipher, sizeof(cipher)) == 0) &&
                          (memcmp(tag, expTag, sizeof(tag)) == 0) &&
                          (memcmp(decrypted, plain, sizeof(plain)) == 0));

    /* and the local key keeps its own bytes */
    WH_TEST_RETURN_ON_FAIL(
        _KeyExport(t, localKeyId, label, sizeof(label), tmpKey, &tmpKeySz));
    WH_TEST_ASSERT_RETURN((tmpKeySz == sizeof(localKey)) &&
                          (memcmp(tmpKey, localKey, sizeof(localKey)) == 0));

    WH_TEST_RETURN_ON_FAIL(_KeyEvict(t, localKeyId));
    return _KeyEvict(t, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId));
}

static int _whTest_PortKeyDataWrap(TestCtx* t)
{
    int     ret;
    whKeyId portKekId = WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORTKEK_ID);
    uint8_t data[] =
        "Example data spanning several AES blocks to catch overlap bugs!";
    uint8_t  unwrappedData[sizeof(data)] = {0};
    uint32_t unwrappedDataSz             = sizeof(unwrappedData);
    uint8_t  wrappedData[sizeof(data) + WH_KEYWRAP_AES_GCM_HEADER_SIZE] = {0};
    uint32_t wrappedDataSz = sizeof(wrappedData);

    ret = _DataWrap(t, portKekId, data, sizeof(data), wrappedData,
                    &wrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to DataWrap with port KEK %d\n", ret);
        return ret;
    }

    ret = _DataUnwrap(t, portKekId, wrappedData, sizeof(wrappedData),
                      unwrappedData, &unwrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to DataUnwrap with port KEK %d\n", ret);
        return ret;
    }

    if (memcmp(data, unwrappedData, sizeof(data)) != 0) {
        WH_ERROR_PRINT("port KEK unwrapped data failed to match input data\n");
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

/* Port keys must be rejected by every keystore operation. Key wrap and
 * the crypto handlers use them through the port key front end instead */
static int _whTest_PortKeyRejections(TestCtx* t)
{
    int      ret;
    whKeyId  portKeyId = WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORTKEK_ID);
    uint8_t  buf[WH_TEST_PORTKEK_SIZE] = {0};
    uint16_t bufSz                     = sizeof(buf);
    uint8_t  label[WH_NVM_LABEL_LEN]   = "portkey reject";
    uint16_t cacheKeyId                = portKeyId;

    /* Caching key material under a port key id must be rejected */
    ret = _KeyCache(t, WH_NVM_FLAGS_NONE, label, sizeof(label), buf,
                    sizeof(buf), &cacheKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyCache of port key id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

#ifdef WOLFHSM_CFG_DMA
    /* The DMA cache path must reject port key ids as well */
    cacheKeyId = portKeyId;
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheDmaRequest(
        t->client, WH_NVM_FLAGS_NONE, label, sizeof(label), buf, sizeof(buf),
        cacheKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    ret = wh_Client_KeyCacheDmaResponse(t->client, &cacheKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyCacheDma of port key id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }
#endif

    /* Exporting a port key must be rejected */
    ret = _KeyExport(t, portKeyId, label, sizeof(label), buf, &bufSz);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyExport of port key id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    /* Commit/evict/erase/revoke of a port key must be rejected */
    ret = _KeyCommit(t, portKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyCommit of port key id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    ret = _KeyEvict(t, portKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyEvict of port key id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    ret = _KeyErase(t, portKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyErase of port key id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    ret = _KeyRevoke(t, portKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyRevoke of port key id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

/* A KEK must allow WRAP usage and belong to the caller or be shared, the same
 * policy the server applies to every other use of a port key */
static int _whTest_PortKeyKekPolicy(TestCtx* t)
{
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE] = {0};
    uint8_t       wrappedKey[WH_TEST_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    uint8_t       data[]       = "Example data!";
    uint8_t       wrappedData[sizeof(data) + WH_KEYWRAP_AES_GCM_HEADER_SIZE];
    uint32_t      wrappedDataSz = sizeof(wrappedData);
    whNvmMetadata metadata      = {0};
    uint16_t      otherUser     = (uint16_t)(t->client->comm->client_id + 1);

    metadata.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(t->client->comm->client_id,
                                                     WH_TEST_WRAPPED_KEYID);
    metadata.len = WH_TEST_AES_KEYSIZE;
    metadata.flags = WH_NVM_FLAGS_USAGE_ANY;

    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        t->portKey,
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL,
                      WH_TEST_PORT_NOWRAP_ID),
        WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
        WH_TEST_PORTKEK_SIZE, WH_PORTKEY_ACCESS_BY_REF));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        t->portKey,
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, otherUser, WH_TEST_PORT_OTHER_ID),
        WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE,
        WH_PORTKEY_ACCESS_BY_REF));

    /* No WRAP usage */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_USAGE ==
        _KeyWrap(t, WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORT_NOWRAP_ID), plainKey,
                 sizeof(plainKey), &metadata, wrappedKey, &wrappedKeySz));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_USAGE ==
        _DataWrap(t, WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORT_NOWRAP_ID), data,
                  sizeof(data), wrappedData, &wrappedDataSz));

    /* Another client's key */
    wrappedKeySz = sizeof(wrappedKey);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ACCESS ==
        _KeyWrap(t, WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORT_OTHER_ID), plainKey,
                 sizeof(plainKey), &metadata, wrappedKey, &wrappedKeySz));

    return WH_ERROR_OK;
}

/* A port KEK requested against a server that has no port keys
 * bound (PORTKEY compiled in, whServerConfig.portKey left NULL) must fail
 * cleanly with NOTFOUND from the keywrap KEK resolver. Simulate the unbound
 * configuration by detaching the server's port keys for the duration of the
 * checks, then restore it for teardown */
static int _whTest_PortKeyUnbound(TestCtx* t)
{
    int           ret;
    whKeyId       portKekId = WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORTKEK_ID);
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE] = {0};
    uint8_t       wrappedKey[WH_TEST_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    uint8_t       data[]       = "Example data!";
    uint8_t       wrappedData[sizeof(data) + WH_KEYWRAP_AES_GCM_HEADER_SIZE];
    uint32_t      wrappedDataSz = sizeof(wrappedData);
    whNvmMetadata metadata      = {0};
    whPortKeyContext* saved     = t->server->portKey;

    metadata.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(t->client->comm->client_id,
                                                     WH_TEST_WRAPPED_KEYID);
    metadata.len = WH_TEST_AES_KEYSIZE;
    metadata.flags = WH_NVM_FLAGS_USAGE_ANY;

    /* Detach the port keys to mimic a server without them bound */
    t->server->portKey = NULL;

    /* KeyWrap (usage-enforcing KEK path) must report NOTFOUND */
    ret = _KeyWrap(t, portKekId, plainKey, sizeof(plainKey), &metadata,
                   wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_NOTFOUND) {
        t->server->portKey = saved;
        WH_ERROR_PRINT("KeyWrap with port KEK and no bound keystore expected "
                       "NOTFOUND, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    /* DataWrap (non-enforcing KEK path) must report NOTFOUND as well */
    ret = _DataWrap(t, portKekId, data, sizeof(data), wrappedData,
                    &wrappedDataSz);
    if (ret != WH_ERROR_NOTFOUND) {
        t->server->portKey = saved;
        WH_ERROR_PRINT("DataWrap with port KEK and no bound keystore expected "
                       "NOTFOUND, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    /* Restore the keystore for teardown */
    t->server->portKey = saved;

    return WH_ERROR_OK;
}

/* A by-value KEK: the server wraps with the bytes the port exports, so the
 * mock device never runs the wrap. It is trusted. With no crypto device, it
 * fails like a KEK used by reference */
static int _whTest_PortKeyByValueKek(TestCtx* t)
{
    whKeyId       kekId    = WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_BYVALUE_KEK_ID);
    whKeyId       refKekId = WH_CLIENT_KEYID_MAKE_PORT(WH_TEST_PORTKEK_ID);
    uint8_t       srcKey[WH_TEST_AES_KEYSIZE];
    uint16_t      srcKeyId                = WH_TEST_BYVALUE_SRC_KEYID;
    uint8_t       label[WH_NVM_LABEL_LEN] = "By-value KEK Src";
    uint8_t       wrappedKey[WH_TEST_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    uint16_t      wrappedKeyId = WH_KEYID_ERASED;
    uint8_t       tmpKey[WH_TEST_AES_KEYSIZE];
    uint16_t      tmpKeySz = sizeof(tmpKey);
    uint8_t       tmpLabel[WH_NVM_LABEL_LEN];
    uint8_t       data[] = "Example data!";
    uint8_t       wrappedData[sizeof(data) + WH_KEYWRAP_AES_GCM_HEADER_SIZE];
    uint32_t      wrappedDataSz = sizeof(wrappedData);
    uint8_t       dataOut[sizeof(data)];
    uint32_t      dataOutSz = sizeof(dataOut);
    whNvmMetadata metadata  = {0};
    whNvmMetadata tmpMeta   = {0};
    int           ops       = _portKekOps;
    int           reads     = _byValueKekReads;
    int           devId;
    int           ret;
    int           refRet;
    size_t        i;

    for (i = 0; i < sizeof(srcKey); i++) {
        srcKey[i] = (uint8_t)(0x5C ^ i);
    }
    metadata.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(t->client->comm->client_id,
                                                     WH_TEST_WRAPPED_KEYID);
    metadata.len = WH_TEST_AES_KEYSIZE;
    metadata.flags = WH_NVM_FLAGS_USAGE_ANY;

    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        t->portKey,
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL,
                      WH_TEST_BYVALUE_KEK_ID),
        WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE,
        WH_PORTKEY_ACCESS_BY_VALUE));

    /* Wrap, then unwrap-and-export */
    WH_TEST_RETURN_ON_FAIL(_KeyWrap(t, kekId, srcKey, sizeof(srcKey), &metadata,
                                    wrappedKey, &wrappedKeySz));
    WH_TEST_RETURN_ON_FAIL(_KeyUnwrapAndExport(
        t, kekId, wrappedKey, wrappedKeySz, &tmpMeta, tmpKey, &tmpKeySz));
    WH_TEST_ASSERT_RETURN((tmpKeySz == sizeof(srcKey)) &&
                          (memcmp(tmpKey, srcKey, sizeof(srcKey)) == 0));

    /* The KEK the device holds can't open the blob */
    tmpKeySz = sizeof(tmpKey);
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK !=
                          _KeyUnwrapAndExport(t, refKekId, wrappedKey,
                                              wrappedKeySz, &tmpMeta, tmpKey,
                                              &tmpKeySz));

    /* It is trusted: wrap-export a server-held key, then cache it back */
    WH_TEST_RETURN_ON_FAIL(_KeyCache(t, WH_NVM_FLAGS_USAGE_ANY, label,
                                     sizeof(label), srcKey, sizeof(srcKey),
                                     &srcKeyId));
    wrappedKeySz = sizeof(wrappedKey);
    WH_TEST_RETURN_ON_FAIL(_KeyWrapExport(t, srcKeyId, WH_KEYTYPE_CRYPTO, kekId,
                                          wrappedKey, &wrappedKeySz));
    WH_TEST_RETURN_ON_FAIL(
        _KeyUnwrapAndCache(t, kekId, wrappedKey, wrappedKeySz, &wrappedKeyId));
    tmpKeySz = sizeof(tmpKey);
    WH_TEST_RETURN_ON_FAIL(
        _KeyExport(t, WH_CLIENT_KEYID_MAKE_WRAPPED(wrappedKeyId), tmpLabel,
                   sizeof(tmpLabel), tmpKey, &tmpKeySz));
    WH_TEST_ASSERT_RETURN((tmpKeySz == sizeof(srcKey)) &&
                          (memcmp(tmpKey, srcKey, sizeof(srcKey)) == 0));
    WH_TEST_RETURN_ON_FAIL(
        _KeyEvict(t, WH_CLIENT_KEYID_MAKE_WRAPPED(wrappedKeyId)));
    WH_TEST_RETURN_ON_FAIL(_KeyEvict(t, srcKeyId));

    /* Data wrap round trip */
    WH_TEST_RETURN_ON_FAIL(
        _DataWrap(t, kekId, data, sizeof(data), wrappedData, &wrappedDataSz));
    WH_TEST_RETURN_ON_FAIL(
        _DataUnwrap(t, kekId, wrappedData, wrappedDataSz, dataOut, &dataOutSz));
    WH_TEST_ASSERT_RETURN((dataOutSz == sizeof(data)) &&
                          (memcmp(dataOut, data, sizeof(data)) == 0));

    /* The port exported the bytes for each of the 6 operations, and the
     * device ran none of them */
    WH_TEST_ASSERT_RETURN(_byValueKekReads == reads + 6);
    WH_TEST_ASSERT_RETURN(_portKekOps == ops);

    /* With no crypto device, the port can't export the by-value KEK or run
     * the other one */
    devId            = t->server->devId;
    t->server->devId = INVALID_DEVID;
    wrappedKeySz     = sizeof(wrappedKey);
    ret = _KeyWrap(t, kekId, srcKey, sizeof(srcKey), &metadata, wrappedKey,
                   &wrappedKeySz);
    wrappedKeySz     = sizeof(wrappedKey);
    refRet           = _KeyWrap(t, refKekId, srcKey, sizeof(srcKey), &metadata,
                                wrappedKey, &wrappedKeySz);
    t->server->devId = devId;
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_NOTFOUND);
    WH_TEST_ASSERT_RETURN(refRet == WH_ERROR_NOTFOUND);

    return WH_ERROR_OK;
}

int whTest_PortKey(void* ctx)
{
    int      ret;
    TestCtx* t = &_testCtx;

    (void)ctx;

    WH_TEST_RETURN_ON_FAIL(_SetupClientServer(t));

    ret = _whTest_PortKeyKeyWrap(t);
    if (ret == WH_ERROR_OK) {
        ret = _whTest_PortKeyWrappedKeyNoNvm(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_PortKeyKeyWrapExport(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_PortKeyUnwrappedKeyUse(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_PortKeyDataWrap(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_PortKeyRejections(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_PortKeyKekPolicy(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_PortKeyUnbound(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_PortKeyByValueKek(t);
    }

    _CleanupClientServer(t);

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER && \
          !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_KEYWRAP &&          \
          WOLFHSM_CFG_PORTKEY && !NO_AES && HAVE_AESGCM */
