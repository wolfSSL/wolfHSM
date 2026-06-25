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

#include <assert.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"

#include "wh_test_common.h"
#include "wh_test.h"

/* Individual unit test drivers */
#include "wh_test_comm.h"
#include "wh_test_flash_ramsim.h"
#include "wh_test_nvm_flash.h"
#include "wh_test_crypto.h"
#include "wh_test_she.h"
#include "wh_test_clientserver.h"
#include "wh_test_keywrap.h"
#include "wh_test_multiclient.h"
#include "wh_test_log.h"
#include "wh_test_lock.h"
#include "wh_test_posix_threadsafe_stress.h"
#include "wh_test_crypto_affinity.h"
#include "wh_test_timeout.h"
#include "wh_test_dma.h"
#include "wh_test_keystore_reqsize.h"
#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
#include "wh_test_auth.h"
#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION */

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER)
#include "wh_test_cert.h"
#endif

#if defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)
#include "wh_test_wolfcrypt_test.h"
#endif

#if defined(WOLFHSM_CFG_SERVER_IMG_MGR)
#include "wh_test_server_img_mgr.h"
#endif

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT)
#include "port/posix/posix_transport_tcp.h"
#if defined(WOLFHSM_CFG_TEST_CLIENT_ONLY) && defined(WOLFHSM_CFG_TLS)
#include "port/posix/posix_transport_tls.h"
#endif /* WOLFHSM_CFG_TEST_CLIENT_ONLY && WOLFHSM_CFG_TLS */
#endif

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

/* ===========================================================================
 * Key-material remanence regression tests (#5473/#5474/#6030/#5476).
 *
 * Each test runs a real client/server operation and then asserts that no copy
 * of the secret key bytes is left behind in the long-lived/shared buffers it
 * passed through. These guard against a future deletion of the
 * wh_Utils_ForceZero / wh_Utils_memset_flush calls (such a deletion does not
 * change any functional behaviour, so only a test like this would catch it).
 * =========================================================================== */
#if defined(WOLFHSM_CFG_TEST_POSIX)

#include <stdint.h>
#include <pthread.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#endif

#if defined(WOLFHSM_CFG_KEYWRAP) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(HAVE_AESGCM)
#include "wolfhsm/wh_client_crypto.h"
#endif

#if defined(WOLFHSM_CFG_DMA) && defined(WOLFSSL_STATIC_MEMORY)
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfhsm/wh_dma.h"
#include "port/posix/posix_transport_shm.h"
#endif

#define REM_CLIENT_ID 1
#define REM_KEKID     10
#define REM_AES_KEYSZ 32

#define REM_FLASH_RAM_SIZE    (1024 * 1024)
#define REM_FLASH_SECTOR_SIZE (128 * 1024)
#define REM_FLASH_PAGE_SIZE   (8)

enum {
    REM_BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                      WOLFHSM_CFG_COMM_DATA_LEN,
};

/* server thread plumbing */
static volatile int g_remServerRun = 1;

static void* remServerTask(void* arg)
{
    whServerContext* server = (whServerContext*)arg;
    int              ret;

    while (g_remServerRun) {
        ret = wh_Server_HandleRequestMessage(server);
        if (ret != WH_ERROR_NOTREADY && ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("[remanence server] HandleRequestMessage %d\n", ret);
            break;
        }
    }
    return NULL;
}

/* Return non-zero (and print) if needle is found anywhere in hay. */
static int remContains(const uint8_t* hay, size_t haySz, const uint8_t* needle,
                       size_t needleSz)
{
    size_t i;
    if (haySz < needleSz) {
        return 0;
    }
    for (i = 0; i + needleSz <= haySz; i++) {
        if (memcmp(hay + i, needle, needleSz) == 0) {
            return 1;
        }
    }
    return 0;
}

/* #5473: importing (caching) a key must not leave the imported key bytes in the
 * client comm buffer or in the shared transport request buffer. */
static int remTest_KeyCacheImport(whClientContext* client, const uint8_t* reqBuf,
                                  size_t reqBufSz)
{
    whKeyId        keyId                   = WH_KEYID_ERASED;
    uint8_t        label[WH_NVM_LABEL_LEN] = "rem-import";
    uint8_t        key[REM_AES_KEYSZ];
    const uint8_t* commData;
    int            i;

    for (i = 0; i < REM_AES_KEYSZ; i++) {
        key[i] = (uint8_t)(0xC5 ^ i);
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE, label,
                                              sizeof(label), key, sizeof(key),
                                              &keyId));

    commData = wh_CommClient_GetDataPtr(client->comm);
    if (remContains(commData, WOLFHSM_CFG_COMM_DATA_LEN, key, sizeof(key))) {
        WH_ERROR_PRINT("#5473: imported key left in client comm buffer\n");
        return WH_TEST_FAIL;
    }
    if (remContains(reqBuf, reqBufSz, key, sizeof(key))) {
        WH_ERROR_PRINT("#5473: imported key left in shared request buffer\n");
        return WH_TEST_FAIL;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, keyId));
    return WH_ERROR_OK;
}

/* #5474: exporting a cached key must not leave the exported key bytes in the
 * client comm buffer after copy-out. */
static int remTest_KeyExport(whClientContext* client)
{
    whKeyId        keyId                      = WH_KEYID_ERASED;
    uint8_t        label[WH_NVM_LABEL_LEN]    = "rem-export";
    uint8_t        key[REM_AES_KEYSZ];
    uint8_t        outKey[REM_AES_KEYSZ]      = {0};
    uint16_t       outSz                      = sizeof(outKey);
    uint8_t        outLabel[WH_NVM_LABEL_LEN] = {0};
    const uint8_t* commData;
    int            i;

    for (i = 0; i < REM_AES_KEYSZ; i++) {
        key[i] = (uint8_t)(0x74 ^ i);
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE, label,
                                              sizeof(label), key, sizeof(key),
                                              &keyId));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExport(client, keyId, outLabel,
                                               sizeof(outLabel), outKey,
                                               &outSz));

    /* sanity: we actually got the key back */
    if (outSz != REM_AES_KEYSZ || memcmp(outKey, key, REM_AES_KEYSZ) != 0) {
        WH_ERROR_PRINT("#5474: export did not return the expected key\n");
        return WH_TEST_FAIL;
    }

    commData = wh_CommClient_GetDataPtr(client->comm);
    if (remContains(commData, WOLFHSM_CFG_COMM_DATA_LEN, key, sizeof(key))) {
        WH_ERROR_PRINT("#5474: exported key left in client comm buffer\n");
        return WH_TEST_FAIL;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, keyId));
    return WH_ERROR_OK;
}

#if defined(WOLFHSM_CFG_KEYWRAP) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(HAVE_AESGCM)
/* #6030: unwrap-and-export must not leave the recovered plaintext key in the
 * client comm buffer after copy-out. */
static int remTest_KeyUnwrapAndExport(whClientContext* client)
{
    whKeyId       kekId                      = REM_KEKID;
    uint8_t       keklabel[WH_NVM_LABEL_LEN] = "rem-kek";
    const uint8_t kek[REM_AES_KEYSZ]         = {
        0x03, 0x03, 0x0d, 0xd9, 0xeb, 0x18, 0x17, 0x2e, 0x06, 0x6e, 0x19,
        0xce, 0x98, 0x44, 0x54, 0x0d, 0x78, 0xa0, 0xbe, 0xe7, 0x35, 0x43,
        0x40, 0xa4, 0x22, 0x8a, 0xd1, 0x0e, 0xa3, 0x63, 0x1c, 0x0b};
    uint8_t       plainKey[REM_AES_KEYSZ];
    uint8_t       wrapped[WH_KEYWRAP_AES_GCM_HEADER_SIZE + REM_AES_KEYSZ +
                          sizeof(whNvmMetadata)];
    uint16_t       wrappedSz = sizeof(wrapped);
    whNvmMetadata  meta      = {0};
    whNvmMetadata  outMeta   = {0};
    uint8_t        outKey[REM_AES_KEYSZ] = {0};
    uint16_t       outKeySz  = sizeof(outKey);
    const uint8_t* commData;
    int            i;

    for (i = 0; i < REM_AES_KEYSZ; i++) {
        plainKey[i] = (uint8_t)(0x60 ^ i);
    }
    meta.id    = WH_CLIENT_KEYID_MAKE_WRAPPED_META(REM_CLIENT_ID, 20);
    meta.len   = REM_AES_KEYSZ;
    meta.flags = WH_NVM_FLAGS_USAGE_ANY;
    memcpy(meta.label, "rem-wrapme", sizeof("rem-wrapme"));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCache(
        client, WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_WRAP, keklabel,
        sizeof(keklabel), (uint8_t*)kek, sizeof(kek), &kekId));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM,
                                             REM_KEKID, plainKey,
                                             sizeof(plainKey), &meta, wrapped,
                                             &wrappedSz));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExport(
        client, WC_CIPHER_AES_GCM, REM_KEKID, wrapped, wrappedSz, &outMeta,
        outKey, &outKeySz));

    if (outKeySz != REM_AES_KEYSZ ||
        memcmp(outKey, plainKey, REM_AES_KEYSZ) != 0) {
        WH_ERROR_PRINT("#6030: unwrap+export did not return the expected key\n");
        return WH_TEST_FAIL;
    }

    commData = wh_CommClient_GetDataPtr(client->comm);
    if (remContains(commData, WOLFHSM_CFG_COMM_DATA_LEN, plainKey,
                    sizeof(plainKey))) {
        WH_ERROR_PRINT("#6030: recovered key left in client comm buffer\n");
        return WH_TEST_FAIL;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, REM_KEKID));
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_KEYWRAP && !NO_CRYPTO && HAVE_AESGCM */

#if defined(WOLFHSM_CFG_DMA) && defined(WOLFSSL_STATIC_MEMORY)
/* #5476: the POSIX shm DMA bounce buffer must be zeroized before it is freed
 * back to the shared static-memory DMA heap. Exercises the callback directly. */
static int remTest_DmaBounce(void)
{
    static uint8_t     dmaRegion[8000] __attribute__((aligned(16)));
    const word32       sizeList[1] = {128};
    const word32       distList[1] = {16};
    WOLFSSL_HEAP_HINT* hint        = NULL;
    int                ret;
    int                i;
    uint8_t            secret[REM_AES_KEYSZ];
    void*              xformed = NULL;
    whDmaFlags         flags   = {0};
    uint8_t*           slot;

    posixTransportShmContext shmCtx;
    whClientContext          client;

    for (i = 0; i < REM_AES_KEYSZ; i++) {
        secret[i] = (uint8_t)(0xA0 + i);
    }
    memset(dmaRegion, 0, sizeof(dmaRegion));
    memset(&shmCtx, 0, sizeof(shmCtx));
    memset(&client, 0, sizeof(client));

    ret = wc_LoadStaticMemory_ex(&hint, 1, sizeList, distList, dmaRegion,
                                 (word32)sizeof(dmaRegion), 0, 0);
    if (ret != 0) {
        WH_ERROR_PRINT("#5476: wc_LoadStaticMemory_ex %d\n", ret);
        return WH_TEST_FAIL;
    }

    shmCtx.dma                     = dmaRegion;
    shmCtx.dma_size                = sizeof(dmaRegion);
    shmCtx.heap                    = (void*)hint;
    client.comm->transport_context = (void*)&shmCtx;

    /* READ path: client input copied into a bounce buffer, then freed. */
    ret = posixTransportShm_ClientStaticMemDmaCallback(
        &client, (uintptr_t)secret, &xformed, REM_AES_KEYSZ,
        WH_DMA_OPER_CLIENT_READ_PRE, flags);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("#5476: READ_PRE %d\n", ret);
        return WH_TEST_FAIL;
    }
    slot = dmaRegion + (uintptr_t)xformed;
    ret  = posixTransportShm_ClientStaticMemDmaCallback(
        &client, (uintptr_t)secret, &xformed, REM_AES_KEYSZ,
        WH_DMA_OPER_CLIENT_READ_POST, flags);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("#5476: READ_POST %d\n", ret);
        return WH_TEST_FAIL;
    }
    if (remContains(slot, REM_AES_KEYSZ, secret, REM_AES_KEYSZ)) {
        WH_ERROR_PRINT("#5476: client input left in freed DMA bounce buffer\n");
        return WH_TEST_FAIL;
    }

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA && WOLFSSL_STATIC_MEMORY */

static int whTest_Remanence(void)
{
    int ret = WH_ERROR_OK;

    /* shared transport buffers (we scan req[] for #5473) */
    static uint8_t       req[REM_BUFFER_SIZE];
    static uint8_t       resp[REM_BUFFER_SIZE];
    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
    }};

    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = REM_CLIENT_ID,
    }};
    whClientConfig  c_conf[1] = {{.comm = cc_conf}};
    whClientContext client[1] = {0};

    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    static uint8_t   memory[REM_FLASH_RAM_SIZE];
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = REM_FLASH_RAM_SIZE,
        .sectorSize = REM_FLASH_SECTOR_SIZE,
        .pageSize   = REM_FLASH_PAGE_SIZE,
        .erasedByte = ~(uint8_t)0,
        .memory     = memory,
    }};
    const whFlashCb   fcb[1]      = {WH_FLASH_RAMSIM_CB};
    whNvmFlashConfig  nvmFlashCfg = {.cb = fcb, .context = fc, .config = fc_conf};
    whNvmFlashContext nvmFlashCtx = {0};
    whNvmCb           nfcb[1]     = {WH_NVM_FLASH_CB};
    whNvmConfig       n_conf[1]   = {{.cb      = nfcb,
                                      .context = &nvmFlashCtx,
                                      .config  = &nvmFlashCfg}};
    whNvmContext      nvm[1]      = {{0}};

#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext crypto[1] = {0};
#endif
    whServerConfig  s_conf[1] = {{
         .comm_config = cs_conf,
         .nvm         = nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
         .crypto = crypto,
         .devId  = INVALID_DEVID,
#endif
    }};
    whServerContext server[1] = {0};
    pthread_t       sthread;

    memset(memory, 0, sizeof(memory));
    memset(req, 0, sizeof(req));
    memset(resp, 0, sizeof(resp));

    WH_TEST_PRINT("Testing key-material remanence (#5473/#5474/#6030/#5476)\n");

#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));
#endif
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, WH_COMM_CONNECTED));
    server->comm->client_id = REM_CLIENT_ID;

    g_remServerRun = 1;
    if (pthread_create(&sthread, NULL, remServerTask, server) != 0) {
        WH_ERROR_PRINT("remanence: pthread_create failed\n");
        ret = WH_ERROR_ABORTED;
        goto out_server;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));
    ret = wh_Client_CommInit(client, NULL, NULL);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("remanence: CommInit %d\n", ret);
        goto out_client;
    }

    ret = remTest_KeyCacheImport(client, req, sizeof(req));
    if (ret == WH_ERROR_OK) {
        ret = remTest_KeyExport(client);
    }
#if defined(WOLFHSM_CFG_KEYWRAP) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(HAVE_AESGCM)
    if (ret == WH_ERROR_OK) {
        ret = remTest_KeyUnwrapAndExport(client);
    }
#endif

    (void)wh_Client_CommClose(client);
out_client:
    (void)wh_Client_Cleanup(client);
out_server:
    g_remServerRun = 0;
    pthread_join(sthread, NULL);
    (void)wh_Server_Cleanup(server);
    (void)wh_Nvm_Cleanup(nvm);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    (void)wc_FreeRng(crypto->rng);
    (void)wolfCrypt_Cleanup();
#endif

#if defined(WOLFHSM_CFG_DMA) && defined(WOLFSSL_STATIC_MEMORY)
    if (ret == WH_ERROR_OK) {
        ret = remTest_DmaBounce();
    }
#endif

    if (ret == WH_ERROR_OK) {
        WH_TEST_PRINT("REMANENCE TESTS SUCCESS\n");
    }
    return ret;
}

#else  /* !WOLFHSM_CFG_TEST_POSIX */
static int whTest_Remanence(void)
{
    /* Requires an in-process client+server POSIX build */
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_POSIX */

int whTest_Unit(void)
{
    WH_TEST_PRINT("Enter unit tests\n");

    /* Component Tests */
    WH_TEST_ASSERT(0 == whTest_Flash_RamSim());
    WH_TEST_ASSERT(0 == whTest_NvmFlash());
#ifdef WOLFHSM_CFG_LOGGING
    WH_TEST_ASSERT(0 == whTest_Log());
#endif
#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
    WH_TEST_ASSERT(0 == whTest_CertRamSim(WH_NVM_TEST_BACKEND_FLASH));

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    WH_TEST_ASSERT(0 == whTest_CertRamSim(WH_NVM_TEST_BACKEND_FLASH_LOG));
#endif /* WOLFHSM_CFG_SERVER_NVM_FLASH_LOG */

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */

#ifdef WOLFHSM_CFG_DMA
    WH_TEST_ASSERT(0 == whTest_Dma());
#endif

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
    /* Keystore req_size validation */
    WH_TEST_ASSERT(0 == whTest_KeystoreReqSize());
#endif /* WOLFHSM_CFG_ENABLE_SERVER && !WOLFHSM_CFG_NO_CRYPTO */

    /* Comm tests */
    WH_TEST_ASSERT(0 == whTest_Comm());
    WH_TEST_ASSERT(0 == whTest_ClientServer());

    /* Key-material remanence regression tests (#5473/#5474/#6030/#5476) */
    WH_TEST_ASSERT(0 == whTest_Remanence());

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    /* Auth tests */
    WH_TEST_ASSERT(0 == whTest_AuthMEM());
#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION */

#ifndef WOLFHSM_CFG_NO_CRYPTO
    /* Crypto Tests */
    WH_TEST_ASSERT(0 == whTest_Crypto());

#ifdef WOLF_CRYPTO_CB
    WH_TEST_ASSERT(0 == whTest_CryptoAffinity());
#endif

#if defined(WOLFHSM_CFG_SERVER_IMG_MGR) && !defined(WOLFHSM_CFG_NO_CRYPTO)
    /* Image Manager Tests */
    WH_TEST_ASSERT(0 == whTest_ServerImgMgr(WH_NVM_TEST_BACKEND_FLASH));

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    WH_TEST_ASSERT(0 == whTest_ServerImgMgr(WH_NVM_TEST_BACKEND_FLASH_LOG));
#endif

#endif /* WOLFHSM_CFG_SERVER_IMG_MGR && !WOLFHSM_CFG_NO_CRYPTO */

    /* Multi-Client Tests (includes Global Keys when enabled) */
    WH_TEST_ASSERT(0 == whTest_MultiClient());

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_THREADSAFE)
    WH_TEST_ASSERT(0 == whTest_LockPosix());
#endif

#if defined(WOLFHSM_CFG_SHE_EXTENSION)
    WH_TEST_ASSERT(0 == whTest_She());
#endif /* WOLFHSM_SHE_EXTENTION */

#if defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)
    WH_TEST_ASSERT(0 == whTest_WolfCryptTest());
#endif

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#if defined(WOLFHSM_CFG_ENABLE_TIMEOUT) && defined(WOLFHSM_CFG_TEST_POSIX)
    WH_TEST_ASSERT(0 == whTest_TimeoutPosix());
#endif

    return 0;
}
#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)
/*
 * Run all the client-only tests on the specified client configuration
 */
int whTest_ClientConfig(whClientConfig* clientCfg)
{
    if (clientCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(whTest_ClientServerClientConfig(clientCfg));

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    WH_TEST_RETURN_ON_FAIL(whTest_CryptoClientConfig(clientCfg));

#if defined(WOLFHSM_CFG_KEYWRAP)
    WH_TEST_RETURN_ON_FAIL(whTest_KeyWrapClientConfig(clientCfg));
#endif /*WOLFHSM_CFG_KEYWRAP */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#if defined(WOLFHSM_CFG_SHE_EXTENSION)
    WH_TEST_RETURN_ON_FAIL(whTest_SheClientConfig(clientCfg));
#endif /* WOLFHSM_CFG_SHE_EXTENSION */

#if defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)
    WH_TEST_RETURN_ON_FAIL(whTest_WolfCryptTestCfg(clientCfg));
#endif /* WOLFHSM_CFG_TEST_WOLFCRYPTTEST */

#if defined(WOLFHSM_CFG_ENABLE_TIMEOUT)
    WH_TEST_RETURN_ON_FAIL(whTest_TimeoutClientConfig(clientCfg));
#endif /* WOLFHSM_CFG_ENABLE_TIMEOUT */

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    WH_TEST_RETURN_ON_FAIL(whTest_AuthTCP(clientCfg));
#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION */

    return WH_ERROR_OK;
}

#if defined(WOLFHSM_CFG_TEST_CLIENT_ONLY) && defined(WOLFHSM_CFG_TEST_POSIX)
#if !defined(WOLFHSM_CFG_TLS)
/*
 * Run all the client-only tests on a default client configuration matching the
 * example server TCP configuration.
 */
int whTest_ClientTcp(void)
{
    /* Client configuration/contexts */
    whTransportClientCb            pttccb[1]      = {PTT_CLIENT_CB};
    posixTransportTcpClientContext tcc[1]         = {0};
    posixTransportTcpConfig        mytcpconfig[1] = {{
               .server_ip_string = "127.0.0.1",
               .server_port      = 23456,
    }};

    whCommClientConfig cc_conf[1] = {{
        .transport_cb      = pttccb,
        .transport_context = (void*)tcc,
        .transport_config  = (void*)mytcpconfig,
        .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientConfig     c_conf[1]  = {{
             .comm = cc_conf,
    }};

    return whTest_ClientConfig(c_conf);
}
#endif /* WOLFHSM_CFG_TEST_POSIX && !WOLFHSM_CFG_TLS */

#if defined(WOLFHSM_CFG_TLS)
/* client configuration setup example for TLS transport */

#define WH_POSIX_SERVER_TCP_PORT 23456
#define WH_POSIX_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_POSIX_CLIENT_ID 12

#undef USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048
#include "wolfssl/certs_test.h"

posixTransportTlsClientContext tccTls;
posixTransportTlsConfig        tlsConfig;
whCommClientConfig             c_comm;
whTransportClientCb            tlsCb = PTTLS_CLIENT_CB;

static int whPosixClient_ExampleTlsConfig(void* conf)
{
    whClientConfig* c_conf = (whClientConfig*)conf;

    memset(&tccTls, 0, sizeof(posixTransportTlsClientContext));

    /* Initialize TLS context fields that need specific values */
    tccTls.state         = 0;
    tccTls.connect_fd_p1 = 0; /* Invalid fd */

    tlsConfig.server_ip_string          = WH_POSIX_SERVER_TCP_IPSTRING;
    tlsConfig.server_port               = WH_POSIX_SERVER_TCP_PORT;
    tlsConfig.disable_peer_verification = false;

    /* Set certificate buffers in config structure */
    tlsConfig.ca_cert     = ca_cert_der_2048;
    tlsConfig.ca_cert_len = sizeof_ca_cert_der_2048;
    tlsConfig.cert        = client_cert_der_2048;
    tlsConfig.cert_len    = sizeof_client_cert_der_2048;
    tlsConfig.key         = client_key_der_2048;
    tlsConfig.key_len     = sizeof_client_key_der_2048;

    c_comm.transport_cb      = &tlsCb;
    c_comm.transport_context = (void*)&tccTls;
    c_comm.transport_config  = (void*)&tlsConfig;
    c_comm.client_id         = WH_POSIX_CLIENT_ID;
    c_conf->comm             = &c_comm;

    return WH_ERROR_OK;
}


/*
 * Run all the client-only tests on a default client configuration matching the
 * example server TLS configuration.
 */
int whTest_ClientTls(void)
{
    int            ret;
    whClientConfig c_conf[1];

    if (whPosixClient_ExampleTlsConfig(c_conf) != WH_ERROR_OK) {
        ret = -1;
    }
    else {
        ret = whTest_ClientConfig(c_conf);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_TLS */
#endif /* WOLFHSM_CFG_TEST_CLIENT_ONLY && WOLFHSM_CFG_TEST_POSIX */
#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#if !defined(WOLFHSM_CFG_TEST_UNIT_NO_MAIN)

int main(void)
{
    int ret = 0;

#if defined(WOLFHSM_CFG_THREADSAFE) && defined(WOLFHSM_CFG_TEST_STRESS) && \
    defined(WOLFHSM_CFG_TEST_POSIX)
    /* Stress test mode: only run thread safety stress test */
    ret = whTest_ThreadSafeStress();

#elif defined(WOLFHSM_CFG_TEST_CLIENT_ONLY) && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_TEST_POSIX)

    /* Test driver should run client tests against the example server */
#if defined(WOLFHSM_CFG_TLS)
    /* Run TLS client tests */
    ret = whTest_ClientTls();
#else
    /* Run TCP client tests (default) */
    ret = whTest_ClientTcp();
#endif

#elif defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

    /* Default case: Test driver should run all the unit tests locally */
    ret = whTest_Unit();

#else
#error "No client or server enabled in build, one or both must be enabled"
#endif

    return ret;
}

#endif /* WOLFHSM_CFG_TEST_UNIT_NO_MAIN */
