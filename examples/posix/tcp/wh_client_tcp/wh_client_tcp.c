/*
 * wolfHSM Client TCP Example
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

#include "wh_demo_client_all.h"

/** Local declarations */
static void _sleepMs(long milliseconds);
static int  wh_ClientTask(void* cf);


static void _sleepMs(long milliseconds)
{
    struct timespec req;
    req.tv_sec  = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&req, NULL);
}

enum {
    REPEAT_COUNT = 10,
    REQ_SIZE     = 32,
    RESP_SIZE    = 64,
    ONE_MS       = 1,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_CLIENT_ID 12

static int wh_ClientTask(void* cf)
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

    printf("Client connecting to server...\n");

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
                if (ret == 0) {
                    printf("Client sent request successfully\n");
                }
                else {
                    printf("wh_CLient_EchoRequest failed with ret=%d\n", ret);
                }
            }
            _sleepMs(ONE_MS);
        } while (ret == WH_ERROR_NOTREADY);

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }

        rx_resp_len = 0;
        memset(rx_resp, 0, sizeof(rx_resp));

        do {
            ret = wh_Client_EchoResponse(client, &rx_resp_len, rx_resp);
            _sleepMs(ONE_MS);
        } while (ret == WH_ERROR_NOTREADY);

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }
    }
#ifndef WOLFHSM_CFG_NO_CRYPTO
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

    /* run the client demos */
    ret = wh_DemoClient_All(client);
    if (ret != 0) {
        printf("Client demo failed: ret=%d\n", ret);
    }


    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);
    printf("Client disconnected\n");
    return ret;
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    /* Client configuration/contexts */
    whTransportClientCb            pttccb[1]      = {PTT_CLIENT_CB};
    posixTransportTcpClientContext tcc[1]         = {};
    posixTransportTcpConfig        mytcpconfig[1] = {{
               .server_ip_string = WH_SERVER_TCP_IPSTRING,
               .server_port      = WH_SERVER_TCP_PORT,
    }};

    whCommClientConfig cc_conf[1] = {{
        .transport_cb      = pttccb,
        .transport_context = (void*)tcc,
        .transport_config  = (void*)mytcpconfig,
        .client_id         = WH_CLIENT_ID,
    }};
    whClientConfig     c_conf[1]  = {{
             .comm = cc_conf,
    }};

    return wh_ClientTask(c_conf);
}