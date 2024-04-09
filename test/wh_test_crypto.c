/*
 * test/wh_test.c
 *
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"

#if defined(WH_CONFIG)
#include "wh_config.h"
#endif

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"

#if defined(WH_CFG_TEST_POSIX)
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

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


int whTest_CryptoClientConfig(whClientConfig* config)
{
    whClientContext client[1] = {0};
    int ret = 0;
    /* wolfcrypt */
    WC_RNG rng[1];
    curve25519_key curve25519PrivateKey[1];
    curve25519_key curve25519PublicKey[1];
    uint32_t outLen;
    uint16_t keyId;
    uint8_t key[16];
    uint8_t keyEnd[16];
    uint8_t labelStart[WOLFHSM_NVM_LABEL_LEN];
    uint8_t labelEnd[WOLFHSM_NVM_LABEL_LEN];
    uint8_t sharedOne[CURVE25519_KEYSIZE];
    uint8_t sharedTwo[CURVE25519_KEYSIZE];

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));
    memset(labelStart, 0xff, sizeof(labelStart));

    /* test rng */
    if ((ret = wc_InitRng_ex(rng, NULL, WOLFHSM_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    if ((ret = wc_RNG_GenerateBlock(rng, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit;
    }
    /* test cache/export */
    if ((ret = wh_Client_KeyCacheRequest(client, 0, labelStart, sizeof(labelStart), key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCacheRequest %d\n", ret);
        goto exit;
    }
    do {
        ret = wh_Client_KeyCacheResponse(client, &keyId);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCacheResponse %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyExportRequest(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExportRequest %d\n", ret);
        goto exit;
    }
    outLen = sizeof(keyEnd);
    do {
        ret = wh_Client_KeyExportResponse(client, labelEnd, sizeof(labelEnd), keyEnd, &outLen);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExportResponse %d\n", ret);
        goto exit;
    }
    if (ret == 0 && XMEMCMP(key, keyEnd, outLen) == 0 && XMEMCMP(labelStart, labelEnd, sizeof(labelStart)) == 0)
        printf("KEY CACHE/EXPORT SUCCESS\n");
    else {
        WH_ERROR_PRINT("KEY CACHE/EXPORT FAILED TO MATCH\n");
        goto exit;
    }
    /* test evict */
    if ((ret = wh_Client_KeyEvictRequest(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEvictRequest %d\n", ret);
        goto exit;
    }
    do {
        ret = wh_Client_KeyEvictResponse(client);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEvictResponse %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyExportRequest(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExportRequest %d\n", ret);
        goto exit;
    }
    outLen = sizeof(keyEnd);
    do {
        ret = wh_Client_KeyExportResponse(client, labelEnd, sizeof(labelEnd), keyEnd, &outLen);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret == WH_ERROR_NOTFOUND) {
        printf("KEY EVICT SUCCESS\n");
    }
    else {
        if (ret != 0)
            WH_ERROR_PRINT("Failed to wh_Client_KeyExportResponse %d\n", ret);
        goto exit;
    }
    /* test commit */
    if ((ret = wh_Client_KeyCacheRequest(client, WOLFHSM_ID_ERASED, labelStart, sizeof(labelStart), key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCacheRequest %d\n", ret);
        goto exit;
    }
    do {
        ret = wh_Client_KeyCacheResponse(client, &keyId);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCacheResponse %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyCommitRequest(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCommitRequest %d\n", ret);
        goto exit;
    }
    do {
        ret = wh_Client_KeyCommitResponse(client);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCommitResponse %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyEvictRequest(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEvictRequest %d\n", ret);
        goto exit;
    }
    do {
        ret = wh_Client_KeyEvictResponse(client);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEvictResponse %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyExportRequest(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExportRequest %d\n", ret);
        goto exit;
    }
    outLen = sizeof(keyEnd);
    do {
        ret = wh_Client_KeyExportResponse(client, labelEnd, sizeof(labelEnd), keyEnd, &outLen);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExportResponse %d\n", ret);
        goto exit;
    }
    if (ret == 0 && XMEMCMP(key, keyEnd, outLen) == 0 && XMEMCMP(labelStart, labelEnd, sizeof(labelStart)) == 0)
        printf("KEY COMMIT/EXPORT SUCCESS\n");
    else {
        WH_ERROR_PRINT("KEY COMMIT/EXPORT FAILED TO MATCH\n");
        goto exit;
    }
    /* test erase */
    if ((ret = wh_Client_KeyEraseRequest(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEraseRequest %d\n", ret);
        goto exit;
    }
    do {
        ret = wh_Client_KeyEraseResponse(client);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyEraseResponse %d\n", ret);
        goto exit;
    }
    if ((ret = wh_Client_KeyExportRequest(client, keyId)) != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyExportRequest %d\n", ret);
        goto exit;
    }
    outLen = sizeof(keyEnd);
    do {
        ret = wh_Client_KeyExportResponse(client, labelEnd, sizeof(labelEnd), keyEnd, &outLen);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret == WH_ERROR_NOTFOUND) {
        printf("KEY ERASE SUCCESS\n");
    }
    else {
        if (ret != 0)
            WH_ERROR_PRINT("Failed to wh_Client_KeyExportResponse %d\n", ret);
        goto exit;
    }

    /* test curve25519 */
    if ((ret = wc_curve25519_init_ex(curve25519PrivateKey, NULL, WOLFHSM_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    if ((ret = wc_curve25519_init_ex(curve25519PublicKey, NULL, WOLFHSM_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    if ((ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PrivateKey)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }

    if ((ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PublicKey)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }

    outLen = sizeof(sharedOne);
    if ((ret = wc_curve25519_shared_secret(curve25519PrivateKey, curve25519PublicKey, sharedOne, &outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    if ((ret = wc_curve25519_shared_secret(curve25519PublicKey, curve25519PrivateKey, sharedTwo, &outLen)) != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }
    if (XMEMCMP(sharedOne, sharedTwo, outLen) != 0) {
        WH_ERROR_PRINT("CURVE25519 shared secrets don't match\n");
    }

exit:
    wc_curve25519_free(curve25519PrivateKey);
    wc_curve25519_free(curve25519PublicKey);
    wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));
    }
    else {
        wh_Client_Cleanup(client);
    }

    return ret;
}


int whTest_CryptoServerConfig(whServerConfig* config)
{
    whServerContext server[1] = {0};
    int ret = 0;
    int i;

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, config));

    /* handle client rng */
    do {
        ret = wh_Server_HandleRequestMessage(server);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
        goto exit;
    }
    /* handle cache/export */
    for (i = 0; i < 2; i++) {
        do {
            ret = wh_Server_HandleRequestMessage(server);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            goto exit;
        }
    }
    /* handle evict/export, expect not found */
    for (i = 0; i < 2; i++) {
        do {
            ret = wh_Server_HandleRequestMessage(server);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != 0 && ret != WH_ERROR_NOTFOUND) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            goto exit;
        }
    }
    /* handle cache/commit/evict/export */
    for (i = 0; i < 4; i++) {
        do {
            ret = wh_Server_HandleRequestMessage(server);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            goto exit;
        }
    }
    /* handle erase/export, expect not found */
    for (i = 0; i < 2; i++) {
        do {
            ret = wh_Server_HandleRequestMessage(server);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != 0 && ret != WH_ERROR_NOTFOUND) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            goto exit;
        }
    }
    /* handle curve */
    for (i = 0; i < 4; i++) {
        do {
            ret = wh_Server_HandleRequestMessage(server);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            goto exit;
        }
    }
exit:
    if (ret == 0) {
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    }
    else {
        ret = wh_Server_Cleanup(server);
    }

    return ret;
}


#if defined(WH_CFG_TEST_POSIX)
static void* _whClientTask(void *cf)
{
    (void)whTest_CryptoClientConfig(cf);
    return NULL;
}

static void* _whServerTask(void* cf)
{
    (void)whTest_CryptoServerConfig(cf);
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
                 .client_id         = 1234,
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
                 .server_id         = 5678,
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
    crypto_context crypto[1] = {{
            .devId = INVALID_DEVID,
    }};

    whServerConfig                  s_conf[1] = {{
       .comm_config = cs_conf,
       .nvm = nvm,
       .crypto = crypto,
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


int whTest_Crypto(void)
{
#if defined(WH_CFG_TEST_POSIX)
    printf("Testing crypto: (pthread) mem...\n");
    WH_TEST_RETURN_ON_FAIL(wh_ClientServer_MemThreadTest());
#endif
    return 0;
}
