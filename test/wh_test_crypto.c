/*
 * test/wh_test.c
 *
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"

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
    RsaKey rsa[1];
    curve25519_key curve25519PrivateKey[1];
    curve25519_key curve25519PublicKey[1];
    uint32_t outLen;
    uint8_t key[16];
    char plainText[16];
    char cipherText[256];
    char finalText[256];
    uint8_t sharedOne[CURVE25519_KEYSIZE];
    uint8_t sharedTwo[CURVE25519_KEYSIZE];

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));

    /* test rng */
    if((ret = wc_InitRng_ex(rng, NULL, WOLFHSM_DEV_ID)) != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    if((ret = wc_RNG_GenerateBlock(rng, key, sizeof(key))) != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit;
    }
    printf("RNG SUCCESS\n");
    /* test rsa */
    if((ret = wc_InitRsaKey_ex(rsa, NULL, WOLFHSM_DEV_ID)) != 0) {
        printf("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }
    if((ret = wc_MakeRsaKey(rsa, 2048, 65537, rng)) != 0) {
        printf("Failed to wc_MakeRsaKey %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText), (byte*)cipherText,
        sizeof(cipherText), rsa, rng)) < 0) {
        printf("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }
    if ((ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret, (byte*)finalText,
        sizeof(finalText), rsa)) < 0) {
        printf("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }
#if 0
    if((ret = wolfHSM_EvictKey(ctx, (uint32_t)rsa->devCtx)) != 0) {
        printf("Failed to wolfHSM_EraseKey %d\n", ret);
        return 1;
    }
#endif
    if((ret = wc_FreeRsaKey(rsa)) != 0) {
        printf("Failed to wc_FreeRsaKey %d\n", ret);
        goto exit;
    }
    printf("RSA KEYGEN SUCCESS\n");
    if (memcmp(plainText, finalText, sizeof(plainText)) == 0)
        printf("RSA SUCCESS\n");
    else
        printf("RSA FAILED TO MATCH\n");
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
    whServerConfig* config = (whServerConfig*)cf;
    int ret = 0;
    int i;
    whServerContext server[1];

    if (config == NULL) {
        return NULL;
    }

    ret = wh_Server_Init(server, config);
    if (ret != 0) {
        printf("Failed to wh_Server_Init: %d", ret);
        return NULL;
    }
    /* handle rng */
    do {
        ret = wh_Server_HandleRequestMessage(server);
        sleep(1);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != 0) {
        printf("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
        goto exit;
    }
    /* handle rsa */
    for (i = 0; i < 5; i++) {
        do {
            ret = wh_Server_HandleRequestMessage(server);
            sleep(1);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != 0) {
            printf("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            goto exit;
        }
    }
    /* handle curve25519 */
    for (i = 0; i < 4; i++) {
        do {
            ret = wh_Server_HandleRequestMessage(server);
            sleep(1);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != 0) {
            printf("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            goto exit;
        }
    }
exit:
    ret = wh_Server_Cleanup(server);
    printf("ServerCleanup:%d\n", ret);

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

static void wh_ClientServer_MemThreadTest(void)
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

    whServerConfig                  s_conf[1] = {{
       .comm_config = cs_conf,
       .nvm_config = n_conf,
    }};


    _whClientServerThreadTest(c_conf, s_conf);
}
#endif /* WH_CFG_TEST_POSIX */


int whTest_Crypto(void)
{
#if defined(WH_CFG_TEST_POSIX)
    printf("Testing crypto: (pthread) mem...\n");
    wh_ClientServer_MemThreadTest();
#endif
    return 0;
}
