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
 * test-refactor/misc/wh_test_hwkeystore.c
 *
 * End-to-end hardware-only key (WH_KEYTYPE_HW) coverage. Lives in the
 * misc group because it requires a server with a known hardware keystore
 * backend bound, which the port's shared server does not guarantee: this
 * test spins up its own client/server pair over the mem transport, binds an
 * emulated hardware keystore serving a single AES-256 KEK, and pumps the
 * server inline between the split (non-blocking) client request/response
 * calls so no threading is needed.
 *
 *   _whTest_HwKeystoreKeyWrap    - key wrap / unwrap-export / unwrap-and-cache
 *                                  with a hardware-only KEK; wrapped+hwonly
 *                                  flag precedence; unserved-id and wrong-KEK
 *                                  negative paths
 *   _whTest_HwKeystoreDataWrap   - data wrap/unwrap roundtrip with a
 *                                  hardware-only KEK
 *   _whTest_HwKeystoreRejections - keystore operations on a hardware-only id
 *                                  must fail with WH_ERROR_ACCESS
 *
 * Crypto key use of a hardware-only id (rejected at the keystore freshen
 * choke point) is covered server-side in server/wh_test_hwkeystore_server.c,
 * since the blocking wolfCrypt callback cannot be pumped single-threaded.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) &&                                    \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_KEYWRAP) && defined(WOLFHSM_CFG_HWKEYSTORE) &&       \
    !defined(NO_AES) && defined(HAVE_AESGCM)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_hwkeystore.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define BUFFER_SIZE 4096
#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (128 * 1024)
#define FLASH_PAGE_SIZE 8

/* Id and material of the only KEK served by the emulated hardware keystore */
#define WH_TEST_HWKEK_ID 3
#define WH_TEST_HWKEK_SIZE 32

#define WH_TEST_AES_KEYSIZE 32
#define WH_TEST_WRAPPED_KEYID 20
#define WH_TEST_WRAPPED_KEYSIZE                             \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + WH_TEST_AES_KEYSIZE + \
     sizeof(whNvmMetadata))

static const uint8_t _hwKekMaterial[WH_TEST_HWKEK_SIZE] = {
    0x9a, 0x4e, 0x21, 0xc7, 0x5d, 0x10, 0xfb, 0x33, 0x6f, 0x82, 0xd4,
    0x59, 0xee, 0x07, 0xb1, 0x2c, 0x48, 0x95, 0x3a, 0xc6, 0x71, 0x0d,
    0xb8, 0xe5, 0x12, 0x6a, 0xf9, 0x84, 0x2f, 0xd0, 0x5b, 0xa7};

static int _HwKeystoreGetKey(void* context, whKeyId keyId, uint8_t* out,
                             uint16_t* inout_len)
{
    (void)context;

    /* Only hardware-only keyIds should ever reach a hardware keystore */
    if (WH_KEYID_TYPE(keyId) != WH_KEYTYPE_HW) {
        return WH_ERROR_ACCESS;
    }

    /* Serve only the known test KEK id, refuse everything else */
    if (WH_KEYID_ID(keyId) != WH_TEST_HWKEK_ID) {
        return WH_ERROR_NOTFOUND;
    }

    if ((out == NULL) || (inout_len == NULL) ||
        (*inout_len < sizeof(_hwKekMaterial))) {
        return WH_ERROR_BUFFER_SIZE;
    }

    memcpy(out, _hwKekMaterial, sizeof(_hwKekMaterial));
    *inout_len = sizeof(_hwKekMaterial);
    return WH_ERROR_OK;
}

/* clang-format off */
static const whHwKeystoreCb _hwKeystoreCb = {
    .Init    = NULL,
    .Cleanup = NULL,
    .GetKey  = _HwKeystoreGetKey,
};
/* clang-format on */

/* Self-contained client/server pair over the mem transport. The server is
 * pumped inline (wh_Server_HandleRequestMessage) between each split client
 * request/response pair */
typedef struct {
    whServerContext     server[1];
    whClientContext     client[1];
    whNvmContext        nvm[1];
    whHwKeystoreContext hwKeystore[1];
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
    /* Hardware keystore */
    whHwKeystoreConfig hwks_conf[1];
    whServerConfig     s_conf[1];
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

    /* Hardware keystore front-end backed by the test getKey callback */
    t->hwks_conf[0] = (whHwKeystoreConfig){
        .cb      = &_hwKeystoreCb,
        .context = NULL,
    };

    /* Server config */
    t->s_conf[0] = (whServerConfig){
        .comm_config = t->cs_conf,
        .nvm         = t->nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
        .crypto = t->crypto,
        .devId  = INVALID_DEVID,
#endif
        .hwKeystore = t->hwKeystore,
    };

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(t->nvm, t->n_conf));
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(t->hwKeystore, t->hwks_conf));
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
    (void)wh_HwKeystore_Cleanup(t->hwKeystore);
    (void)wc_FreeRng(t->crypto->rng);
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

static int _whTest_HwKeystoreKeyWrap(TestCtx* t)
{
    int           ret;
    whKeyId       hwKekId = WH_CLIENT_KEYID_MAKE_HW(WH_TEST_HWKEK_ID);
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       tmpPlainKey[WH_TEST_AES_KEYSIZE];
    uint16_t      tmpPlainKeySz = sizeof(tmpPlainKey);
    uint8_t       wrappedKey[WH_TEST_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz   = sizeof(wrappedKey);
    uint16_t      unwrappedKeyId = WH_KEYID_ERASED;
    whNvmMetadata metadata       = {0};
    whNvmMetadata tmpMetadata    = {0};
    size_t        i;

    metadata.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(t->client->comm->client_id,
                                                     WH_TEST_WRAPPED_KEYID);
    metadata.len = WH_TEST_AES_KEYSIZE;
    metadata.flags = WH_NVM_FLAGS_USAGE_ANY;
    memcpy(metadata.label, "HW KEK wrapped key", sizeof("HW KEK wrapped key"));

    /* Fixed pattern; distinct from the KEK material */
    for (i = 0; i < sizeof(plainKey); i++) {
        plainKey[i] = (uint8_t)(0xA0 ^ i);
    }

    /* Wrap a key using the hardware-only KEK */
    ret = _KeyWrap(t, hwKekId, plainKey, sizeof(plainKey), &metadata,
                   wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to KeyWrap with HW KEK %d\n", ret);
        return ret;
    }

    /* Unwrap and export with the hardware-only KEK, check the roundtrip */
    ret = _KeyUnwrapAndExport(t, hwKekId, wrappedKey, wrappedKeySz,
                              &tmpMetadata, tmpPlainKey, &tmpPlainKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to KeyUnwrapAndExport with HW KEK %d\n", ret);
        return ret;
    }

    if (memcmp(plainKey, tmpPlainKey, sizeof(plainKey)) != 0) {
        WH_ERROR_PRINT("HW KEK wrap/unwrap key failed to match\n");
        return WH_ERROR_ABORTED;
    }

    if (memcmp(&metadata, &tmpMetadata, sizeof(metadata)) != 0) {
        WH_ERROR_PRINT("HW KEK wrap/unwrap metadata failed to match\n");
        return WH_ERROR_ABORTED;
    }

    /* Unwrap-and-cache with the hardware-only KEK: the wrapped payload is an
     * ordinary key and may enter the cache; only the KEK itself is
     * hardware-resident */
    ret = _KeyUnwrapAndCache(t, hwKekId, wrappedKey, wrappedKeySz,
                             &unwrappedKeyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to KeyUnwrapAndCache with HW KEK %d\n", ret);
        return ret;
    }
    WH_TEST_RETURN_ON_FAIL(_KeyEvict(t, unwrappedKeyId));

    /* A wrapped+hardware-only KEK id must behave as hardware-only (the
     * hardware-only flag takes precedence) */
    wrappedKeySz = sizeof(wrappedKey);
    ret          = _KeyWrap(t, hwKekId | WH_KEYID_CLIENT_WRAPPED_FLAG, plainKey,
                            sizeof(plainKey), &metadata, wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to KeyWrap with wrapped+HW KEK %d\n", ret);
        return ret;
    }

    /* Unwrapping a hardware-KEK-wrapped blob with a different, cached KEK
     * must fail authentication, proving distinct key material was used */
    {
        uint16_t cachedKekId = WH_KEYID_ERASED;
        uint8_t  cachedKek[WH_TEST_HWKEK_SIZE];
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

    /* A hardware KEK id the backend does not serve must fail */
    wrappedKeySz = sizeof(wrappedKey);
    ret = _KeyWrap(t, WH_CLIENT_KEYID_MAKE_HW(WH_TEST_HWKEK_ID + 1), plainKey,
                   sizeof(plainKey), &metadata, wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("KeyWrap with unserved HW KEK expected NOTFOUND, "
                       "got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

static int _whTest_HwKeystoreDataWrap(TestCtx* t)
{
    int      ret;
    whKeyId  hwKekId = WH_CLIENT_KEYID_MAKE_HW(WH_TEST_HWKEK_ID);
    uint8_t  data[]  = "Example data!";
    uint8_t  unwrappedData[sizeof(data)] = {0};
    uint32_t unwrappedDataSz             = sizeof(unwrappedData);
    uint8_t  wrappedData[sizeof(data) + WH_KEYWRAP_AES_GCM_HEADER_SIZE] = {0};
    uint32_t wrappedDataSz = sizeof(wrappedData);

    ret =
        _DataWrap(t, hwKekId, data, sizeof(data), wrappedData, &wrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to DataWrap with HW KEK %d\n", ret);
        return ret;
    }

    ret = _DataUnwrap(t, hwKekId, wrappedData, sizeof(wrappedData),
                      unwrappedData, &unwrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to DataUnwrap with HW KEK %d\n", ret);
        return ret;
    }

    if (memcmp(data, unwrappedData, sizeof(data)) != 0) {
        WH_ERROR_PRINT("HW KEK unwrapped data failed to match input data\n");
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

/* Hardware-only keys must be rejected by every keystore operation; only the
 * keywrap KEK paths may resolve them. Crypto key use is rejected at the same
 * keystore choke points, covered in server/wh_test_hwkeystore_server.c */
static int _whTest_HwKeystoreRejections(TestCtx* t)
{
    int      ret;
    whKeyId  hwKeyId = WH_CLIENT_KEYID_MAKE_HW(WH_TEST_HWKEK_ID);
    uint8_t  buf[WH_TEST_HWKEK_SIZE] = {0};
    uint16_t bufSz                   = sizeof(buf);
    uint8_t  label[WH_NVM_LABEL_LEN] = "hwonly reject";
    uint16_t cacheKeyId              = hwKeyId;

    /* Caching key material under a hardware-only id must be rejected */
    ret = _KeyCache(t, WH_NVM_FLAGS_NONE, label, sizeof(label), buf,
                    sizeof(buf), &cacheKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyCache of HW-only id expected ACCESS, got %d\n", ret);
        return WH_ERROR_ABORTED;
    }

#ifdef WOLFHSM_CFG_DMA
    /* The DMA cache path must reject hardware-only ids as well */
    cacheKeyId = hwKeyId;
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheDmaRequest(
        t->client, WH_NVM_FLAGS_NONE, label, sizeof(label), buf, sizeof(buf),
        cacheKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    ret = wh_Client_KeyCacheDmaResponse(t->client, &cacheKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyCacheDma of HW-only id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }
#endif

    /* Exporting a hardware-only key must be rejected */
    ret = _KeyExport(t, hwKeyId, label, sizeof(label), buf, &bufSz);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyExport of HW-only id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    /* Commit/evict/erase/revoke of a hardware-only key must be rejected */
    ret = _KeyCommit(t, hwKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyCommit of HW-only id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    ret = _KeyEvict(t, hwKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyEvict of HW-only id expected ACCESS, got %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    ret = _KeyErase(t, hwKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyErase of HW-only id expected ACCESS, got %d\n", ret);
        return WH_ERROR_ABORTED;
    }

    ret = _KeyRevoke(t, hwKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyRevoke of HW-only id expected ACCESS, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

/* A hardware-only KEK requested against a server that has no hardware keystore
 * bound (HWKEYSTORE compiled in, whServerConfig.hwKeystore left NULL) must fail
 * cleanly with NOTFOUND from the keywrap KEK resolver. Simulate the unbound
 * configuration by detaching the server's keystore for the duration of the
 * checks, then restore it for teardown */
static int _whTest_HwKeystoreUnbound(TestCtx* t)
{
    int           ret;
    whKeyId       hwKekId = WH_CLIENT_KEYID_MAKE_HW(WH_TEST_HWKEK_ID);
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE] = {0};
    uint8_t       wrappedKey[WH_TEST_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    uint8_t       data[]       = "Example data!";
    uint8_t       wrappedData[sizeof(data) + WH_KEYWRAP_AES_GCM_HEADER_SIZE];
    uint32_t      wrappedDataSz = sizeof(wrappedData);
    whNvmMetadata metadata      = {0};
    whHwKeystoreContext* saved  = t->server->hwKeystore;

    metadata.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(t->client->comm->client_id,
                                                     WH_TEST_WRAPPED_KEYID);
    metadata.len = WH_TEST_AES_KEYSIZE;
    metadata.flags = WH_NVM_FLAGS_USAGE_ANY;

    /* Detach the hardware keystore to mimic a server without one bound */
    t->server->hwKeystore = NULL;

    /* KeyWrap (usage-enforcing KEK path) must report NOTFOUND */
    ret = _KeyWrap(t, hwKekId, plainKey, sizeof(plainKey), &metadata,
                   wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_NOTFOUND) {
        t->server->hwKeystore = saved;
        WH_ERROR_PRINT("KeyWrap with HW KEK and no bound keystore expected "
                       "NOTFOUND, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    /* DataWrap (non-enforcing KEK path) must report NOTFOUND as well */
    ret =
        _DataWrap(t, hwKekId, data, sizeof(data), wrappedData, &wrappedDataSz);
    if (ret != WH_ERROR_NOTFOUND) {
        t->server->hwKeystore = saved;
        WH_ERROR_PRINT("DataWrap with HW KEK and no bound keystore expected "
                       "NOTFOUND, got %d\n",
                       ret);
        return WH_ERROR_ABORTED;
    }

    /* Restore the keystore for teardown */
    t->server->hwKeystore = saved;

    return WH_ERROR_OK;
}

int whTest_HwKeystore(void* ctx)
{
    int      ret;
    TestCtx* t = &_testCtx;

    (void)ctx;

    WH_TEST_RETURN_ON_FAIL(_SetupClientServer(t));

    ret = _whTest_HwKeystoreKeyWrap(t);
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeystoreDataWrap(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeystoreRejections(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeystoreUnbound(t);
    }

    _CleanupClientServer(t);

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER && \
          !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_KEYWRAP &&          \
          WOLFHSM_CFG_HWKEYSTORE && !NO_AES && HAVE_AESGCM */
