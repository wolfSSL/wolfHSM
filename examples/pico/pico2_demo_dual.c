/*
 * Combined dual-core demo: server on Core 0, client on Core 1.
 */
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"
#include "pico2_transport_shm.h"

#define SHARED_MEM_SIZE (4 * 1024)
__attribute__((section(".shared_ram")))
static uint8_t pico2_shared_mem[SHARED_MEM_SIZE];
static size_t pico2_shared_mem_size = SHARED_MEM_SIZE;

#define SERVER_ID 1
#define CLIENT_ID 2
#define REQ_SIZE 1024
#define RESP_SIZE 1024
#define DMA_SIZE 1024

static int server_init(whCommServer *server, pico2TransportShmContext *ctx)
{
    static const whTransportServerCb server_cb = PICO2_TRANSPORT_SHM_SERVER_CB;
    memset(ctx, 0, sizeof(*ctx));
    pico2TransportShmConfig cfg = {
        .req_size = REQ_SIZE,
        .resp_size = RESP_SIZE,
        .dma_size = DMA_SIZE,
        .shared_mem = pico2_shared_mem,
        .shared_mem_size = pico2_shared_mem_size,
    };
    whCommServerConfig scfg = {
        .transport_cb = &server_cb,
        .transport_context = ctx,
        .transport_config = &cfg,
        .server_id = SERVER_ID,
    };
    int rc = wh_CommServer_Init(server, &scfg, NULL, NULL);
    if (rc != WH_ERROR_OK) {
        printf("ERROR: server init failed (rc=%d)\n", rc);
        return rc;
    }
    return 0;
}

static int server_handle_message(whCommServer *server, int *handled)
{
    uint8_t req_data[256];
    uint8_t resp_data[256];
    uint16_t resp_len = 0;
    uint16_t magic = 0, kind = 0, seq = 0, req_len = 0;
    int rc = wh_CommServer_RecvRequest(server, &magic, &kind, &seq, &req_len, req_data);
    if (rc == WH_ERROR_NOTREADY) {
        return 0;
    }
    if (rc != WH_ERROR_OK) {
        printf("ERROR: recv request rc=%d\n", rc);
        return rc;
    }
    memcpy(resp_data, "Echo: ", 6);
    resp_len = 6;
    if (req_len < sizeof(resp_data) - 6) {
        memcpy(&resp_data[6], req_data, req_len);
        resp_len += req_len;
    }
    rc = wh_CommServer_SendResponse(server, magic, kind, seq, resp_len, resp_data);
    if (rc != WH_ERROR_OK) {
        printf("ERROR: send response rc=%d\n", rc);
        return rc;
    }
    (*handled)++;
    printf("Server handled message %d\n", *handled);
    return 0;
}

static int client_init(whCommClient *client, pico2TransportShmContext *ctx)
{
    static const whTransportClientCb client_cb = PICO2_TRANSPORT_SHM_CLIENT_CB;
    memset(ctx, 0, sizeof(*ctx));
    pico2TransportShmConfig cfg = {
        .req_size = REQ_SIZE,
        .resp_size = RESP_SIZE,
        .dma_size = DMA_SIZE,
        .shared_mem = pico2_shared_mem,
        .shared_mem_size = pico2_shared_mem_size,
    };
    whCommClientConfig ccfg = {
        .transport_cb = &client_cb,
        .transport_context = ctx,
        .transport_config = &cfg,
        .client_id = CLIENT_ID,
    };
    int rc = wh_CommClient_Init(client, &ccfg);
    if (rc != WH_ERROR_OK) {
        printf("ERROR: client init failed (rc=%d)\n", rc);
        return rc;
    }
    printf("Client initialized rc = %d\n", rc);
    return 0;
}

static int client_send_requests(whCommClient *client)
{
    uint8_t req[128];
    uint8_t resp[128];
    uint16_t resp_len = 128;
    uint16_t magic = 0x1234;
    uint16_t kind = 0;
    uint16_t seq = 0;
    int rc;

    memcpy(req, "Hello from Core 1", 17);
    printf("Client sending first request\n");
    do {
        rc = wh_CommClient_SendRequest(client, magic, kind, &seq, 17, req);
        if (rc == WH_ERROR_NOTREADY) {
            sleep_ms(1);
        }
    } while (rc == WH_ERROR_NOTREADY);
    if (rc != WH_ERROR_OK) {
        printf("ERROR: send request rc=%d\n", rc);
        return rc;
    }
    printf("Client waiting for first response\n");
    do {
        rc = wh_CommClient_RecvResponse(client, &magic, &kind, &seq, &resp_len, resp);
        if (rc == WH_ERROR_NOTREADY) {
            sleep_ms(1);
        }
    } while (rc == WH_ERROR_NOTREADY);
    if (rc != WH_ERROR_OK) {
        printf("ERROR: recv response rc=%d\n", rc);
        return rc;
    }
    for (int i = 0; i < 5; i++) {
        printf("Client sending request %d\n", i);
        sprintf((char*)req, "Request %d from Core 1", i);
        uint16_t req_len = strlen((char*)req);
        do {
            rc = wh_CommClient_SendRequest(client, magic, kind, &seq, req_len, req);
            if (rc == WH_ERROR_NOTREADY) {
                sleep_ms(1);
            }
        } while (rc == WH_ERROR_NOTREADY);
        if (rc != WH_ERROR_OK) {
            printf("ERROR: send request rc=%d\n", rc);
            return rc;
        }
        resp_len = 128;
        do {
            rc = wh_CommClient_RecvResponse(client, &magic, &kind, &seq, &resp_len, resp);
            if (rc == WH_ERROR_NOTREADY) {
                sleep_ms(1);
            }
        } while (rc == WH_ERROR_NOTREADY);
        if (rc != WH_ERROR_OK) {
            printf("ERROR: recv response rc=%d\n", rc);
            return rc;
        }
        sleep_ms(2000);
        printf("Client received response %d: %.*s\n", i, resp_len, resp);
    }
    return 0;
}

static void core1_entry(void)
{
    whCommClient client[1];
    pico2TransportShmContext ctx[1];
    sleep_ms(5000);
    printf("\n=== Core 1: Client start ===\n");
    if (client_init(client, ctx) != 0) {
        printf("Client init failed\n");
        multicore_fifo_push_blocking(0xDEAD0001);
        return;
    }
    sleep_ms(500);
    printf("Client initialized, sending requests\n");
    if (client_send_requests(client) != 0) {
        printf("Client requests failed\n");
    }
    pico2TransportShm_Cleanup(ctx);
    multicore_fifo_push_blocking(0xC1E17E);
    printf("Core 1 done\n");
}
int main(void)
{
    whCommServer server[1];
    pico2TransportShmContext ctx[1];
    int handled = 0;

    stdio_init_all();
    sleep_ms(5000);
    printf("\n=== Pico-2 Dual-Core wolfHSM Demo ===\n");
    printf("Shared memory @%p size %u\n", pico2_shared_mem, (unsigned)pico2_shared_mem_size);

    if (server_init(server, ctx) != 0) {
        printf("Server init failed\n");
        return 1;
    }

    multicore_launch_core1(core1_entry);
    printf("Server running on Core 0, client on Core 1\n");

    const int expected = 6; /* 1 echo + 5 looped */
    while (handled < expected) {
        if (server_handle_message(server, &handled) != 0) {
            printf("Server loop error\n");
            break;
        }
        sleep_ms(5000);
    }

    pico2TransportShm_Cleanup(ctx);
    multicore_fifo_pop_blocking(); /* wait for client */
   
    return 0;
}
