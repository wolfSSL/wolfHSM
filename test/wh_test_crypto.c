/*
 * test/wh_test.c
 *
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */
#include <unistd.h> /* For sleep */

#include <pthread.h> /* For pthread_create/cancel/join/_t */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"


#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wh_config.h"


#include "wolfhsm/wh_transport_mem.h"

#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

enum {
        REPEAT_COUNT = 10,
        REQ_SIZE = 32,
        RESP_SIZE = 64,
        BUFFER_SIZE = 4096,
        ONE_MS = 1000,
    };

uint8_t req[BUFFER_SIZE] = {0};
uint8_t resp[BUFFER_SIZE] = {0};

whClientContext _client[1] = {0};
whServerContext _server[1] = {0};


static void* _whClientTask(void *cf)
{
    whClientConfig* config = (whClientConfig*)cf;
    int ret = 0;
    whClientContext* client = _client;

    /* wolfcrypt */
    WC_RNG rng[1];
    curve25519_key curve25519PrivateKey[1];
    curve25519_key curve25519PublicKey[1];
    uint32_t outLen;
    uint8_t key[16];
    uint8_t sharedOne[CURVE25519_KEYSIZE];
    uint8_t sharedTwo[CURVE25519_KEYSIZE];

    if (config == NULL) {
        return NULL;
    }

    ret = wh_Client_Init(client, config);
    if (ret != 0) {
        printf("Failed to wh_Client_Init: %d", ret);
        return NULL;
    }
    /* test rng */
    if((ret = wc_InitRng_ex(rng, NULL, WOLFHSM_DEV_ID)) != 0) {
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }
    if((ret = wc_RNG_GenerateBlock(rng, key, sizeof(key))) != 0) {
        printf("Failed to wc_RNG_GenerateBlock %d\n", ret);
        goto exit;
    }
    printf("RNG SUCCESS\n");
    /* test curve25519 */
    if ((ret = wc_curve25519_init_ex(curve25519PrivateKey, NULL, WOLFHSM_DEV_ID)) != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    if ((ret = wc_curve25519_init_ex(curve25519PublicKey, NULL, WOLFHSM_DEV_ID)) != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    if ((ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PrivateKey)) != 0) {
        printf("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }
    if ((ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PublicKey)) != 0) {
        printf("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }
    outLen = sizeof(sharedOne);
    if ((ret = wc_curve25519_shared_secret(curve25519PrivateKey, curve25519PublicKey, sharedOne, &outLen)) != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }
    if ((ret = wc_curve25519_shared_secret(curve25519PublicKey, curve25519PrivateKey, sharedTwo, &outLen)) != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }
    if (XMEMCMP(sharedOne, sharedTwo, outLen) == 0)
        printf("CURVE25519 SUCCESS\n");
    else
        printf("CURVE25519 FAILURE\n");
    wc_curve25519_free(curve25519PrivateKey);
    wc_curve25519_free(curve25519PublicKey);
exit:
    wc_FreeRng(rng);
    ret = wh_Client_Cleanup(client);
    printf("wh_Client_Cleanup:%d\n", ret);
    return NULL;
}

static void* _whServerTask(void* cf)
{
    whServerConfig* config = (whServerConfig*)cf;
    int ret = 0;
    int i;
    whServerContext* server = _server;

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
    /* handle curve */
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
    printf(" WH Server thread create:%d\n", rc);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whClientTask, c_conf);
        printf("WH Client thread create:%d\n", rc);
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
int whTest_Crypto(void)
{
#if defined(WH_CFG_TEST_POSIX)
    printf("Testing crypto: (pthread) mem...\n");
    wh_ClientServer_MemThreadTest();
#endif
    return 0;
}
