/*
 * wolfHSM Client POSIX Example
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */
#include <unistd.h> /* for read */
#include <time.h>   /* For nanosleep */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_transport_shm.h"

#include "examples/demo/client/wh_demo_client_all.h"
#include "wh_posix_cfg.h"
#include "wh_posix_client_cfg.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
/* included to print out the version of wolfSSL linked with */
#include "wolfssl/version.h"
#endif

/** Local declarations */
static void _sleepMs(long milliseconds);
static int  wh_ClientTask(void* cf, const char* type, int test);


static void _sleepMs(long milliseconds)
{
    struct timespec req;
    req.tv_sec  = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&req, NULL);
}

enum {
    REPEAT_COUNT = 20,
    REQ_SIZE     = 32,
    RESP_SIZE    = 64,
    ONE_MS       = 1,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_CLIENT_ID 12

static int wh_ClientTask(void* cf, const char* type, int test)
{
    whClientConfig* config = (whClientConfig*)cf;
    int             ret    = 0;
    whClientContext client[1];
    int             counter = 1;

    uint8_t  tx_req[REQ_SIZE] = {0};
    uint16_t tx_req_len       = 0;

    uint8_t  rx_resp[RESP_SIZE] = {0};
    uint16_t rx_resp_len        = 0;

    if (config == NULL) {
        return -1;
    }

    ret = wh_Client_Init(client, config);

    if (ret == 0) {
        ret = wh_Client_CommInit(client, NULL, NULL);
        if (ret != 0) {
            WOLFHSM_CFG_PRINTF("Failed to initialize client communication\n");
            return -1;
        }
    }

    if (strcmp(type, "dma") == 0) {
#ifdef WOLFSSL_STATIC_MEMORY
        WOLFHSM_CFG_PRINTF("Setting up DMA heap with static memory buckets\n");

        ret = wh_PosixClient_ExampleSetupDmaMemory(client, config);
        if (ret != 0) {
            WOLFHSM_CFG_PRINTF("Failed to setup DMA heap\n");
            return -1;
        }
#else
        return -1;
#endif
    }

    WOLFHSM_CFG_PRINTF("Client connecting to server...\n");
    if (ret == 0 && test) {
        WOLFHSM_CFG_PRINTF("Running client demos...\n");
        ret = wh_DemoClient_All(client);
    }

    if (ret != 0) {
        perror("Init error:");
        return -1;
    }

    for (counter = 0; counter < REPEAT_COUNT; counter++) {
        sprintf((char*)tx_req, "Request:%u", counter);
        tx_req_len = strlen((char*)tx_req);
        do {
            ret = wh_Client_EchoRequest(client, tx_req_len, tx_req);
            if (ret != WH_ERROR_NOTREADY) {
                if (ret != 0) {
                    WOLFHSM_CFG_PRINTF("wh_Client_EchoRequest failed with ret=%d\n", ret);
                }
            }
            _sleepMs(ONE_MS);
        } while (ret == WH_ERROR_NOTREADY);

        if (ret != 0) {
            WOLFHSM_CFG_PRINTF("Client had failure. Exiting\n");
            break;
        }

        rx_resp_len = 0;
        memset(rx_resp, 0, sizeof(rx_resp));

        do {
            ret = wh_Client_EchoResponse(client, &rx_resp_len, rx_resp);
            _sleepMs(ONE_MS);
        } while (ret == WH_ERROR_NOTREADY);

        if (ret != 0) {
            WOLFHSM_CFG_PRINTF("Client had failure. Exiting\n");
            break;
        }
    }
#if defined(DWOLFHSM_CFG_NO_CRYPTO)
    /* Context 1: Client Local Crypto */
    WC_RNG  rng[1];
    uint8_t buffer[128] = {0};
    wc_InitRng_ex(rng, NULL, INVALID_DEVID);
    wc_RNG_GenerateBlock(rng, buffer, sizeof(buffer));
    wc_FreeRng(rng);
    wh_Utils_Hexdump("Context 1: Client Local RNG:\n", buffer, sizeof(buffer));

    /* Context 2: Client Remote Crypto */
    memset(buffer, 0, sizeof(buffer));
    wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    wc_RNG_GenerateBlock(rng, buffer, sizeof(buffer));
    wc_FreeRng(rng);
    wh_Utils_Hexdump("Context 2: Client Remote RNG:\n", buffer, sizeof(buffer));
#endif

    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);
    WOLFHSM_CFG_PRINTF("Client disconnected\n");
    return ret;
}

void Usage(const char* exeName)
{
    WOLFHSM_CFG_PRINTF("Usage: %s --type <type> --test\n", exeName);
    WOLFHSM_CFG_PRINTF("Example: %s --type tcp\n", exeName);
    WOLFHSM_CFG_PRINTF("type: tcp (default), shm");
#ifndef WOLFHSM_CFG_NO_CRYPTO
    WOLFHSM_CFG_PRINTF(", tls");
#endif
#ifndef NO_PSK
    WOLFHSM_CFG_PRINTF(", psk");
#endif
#ifdef WOLFSSL_STATIC_MEMORY
    WOLFHSM_CFG_PRINTF(", dma");
#endif
    WOLFHSM_CFG_PRINTF("\n");
}

int main(int argc, char** argv)
{
    const char*    type = "tcp";
    int            test = 0; /* flag if running wolfcrypt test */
    whClientConfig c_conf[1];
    int            i;

    (void)argc;
    (void)argv;

    memset(c_conf, 0, sizeof(whClientConfig));
    WOLFHSM_CFG_PRINTF("Example wolfHSM POSIX client ");
#ifndef WOLFHSM_CFG_NO_CRYPTO
    WOLFHSM_CFG_PRINTF("built with wolfSSL version %s\n", LIBWOLFSSL_VERSION_STRING);
#else
    WOLFHSM_CFG_PRINTF("built with WOLFHSM_CFG_NO_CRYPTO\n");
#endif

    /* Parse command-line arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            type = argv[++i];
        }
        else if (strcmp(argv[i], "--test") == 0) {
            test = 1;
        }
        else {
            WOLFHSM_CFG_PRINTF("Invalid argument: %s\n", argv[i]);
            Usage(argv[0]);
            return -1;
        }
    }

    if (strcmp(type, "tcp") == 0) {
        WOLFHSM_CFG_PRINTF("Using TCP transport\n");
        wh_PosixClient_ExampleTcpConfig(c_conf);
    }
    else if (strcmp(type, "shm") == 0) {
        WOLFHSM_CFG_PRINTF("Using shared memory transport\n");
        wh_PosixClient_ExampleShmConfig(c_conf);
    }
#ifndef WOLFHSM_CFG_NO_CRYPTO
    else if (strcmp(type, "tls") == 0) {
        WOLFHSM_CFG_PRINTF("Using TLS transport\n");
        wh_PosixClient_ExampleTlsConfig(c_conf);
    }
#endif
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && !defined(NO_PSK)
    else if (strcmp(type, "psk") == 0) {
        WOLFHSM_CFG_PRINTF("Using TLS PSK transport\n");
        wh_PosixClient_ExamplePskConfig(c_conf);
    }
#endif
#ifdef WOLFSSL_STATIC_MEMORY
    else if (strcmp(type, "dma") == 0) {
        WOLFHSM_CFG_PRINTF("Using DMA with shared memory transport\n");
        wh_PosixClient_ExampleShmDmaConfig(c_conf);
    }
#endif
    else {
        WOLFHSM_CFG_PRINTF("Invalid client type: %s\n", type);
        Usage(argv[0]);
        return -1;
    }

    return wh_ClientTask(c_conf, type, test);
}
