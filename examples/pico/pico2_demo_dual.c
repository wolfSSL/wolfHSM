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
__attribute__((section(".shared_ram"), aligned(4)))
static uint8_t pico2_shared_mem[SHARED_MEM_SIZE];
static size_t pico2_shared_mem_size = SHARED_MEM_SIZE;

#define SERVER_ID 1
#define CLIENT_ID 2
#define REQ_SIZE 1024
#define RESP_SIZE 1024
#define DMA_SIZE 1024
#define BUFFER_SIZE 256
#define CLIENT_REQ_BUF_SIZE 128
#define CLIENT_RESP_BUF_SIZE 128
#define MAGIC_VALUE 0x1234
#define ECHO_PREFIX "Echo: "
#define ECHO_PREFIX_LEN 6
#define HELLO_MSG "Hello from Core 1"
#define HELLO_MSG_LEN 17
#define REQUEST_FMT "Request %d from Core 1"
#define STARTUP_DELAY_MS 5000
#define CLIENT_INIT_DELAY_MS 500
#define REQUEST_LOOP_DELAY_MS 2000
#define POLL_DELAY_MS 1
#define NUM_LOOP_REQUESTS 5
#define FIFO_ERROR_VAL 0xDEAD0001
#define FIFO_SUCCESS_VAL 0xC1E17E
#define EXPECTED_HANDLED_COUNT (1 + NUM_LOOP_REQUESTS)

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
    uint8_t req_data[BUFFER_SIZE];
    uint8_t resp_data[BUFFER_SIZE];
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
    memcpy(resp_data, ECHO_PREFIX, ECHO_PREFIX_LEN);
    uint16_t copy_len = req_len;
    if (copy_len > sizeof(resp_data) - ECHO_PREFIX_LEN) {
        copy_len = sizeof(resp_data) - ECHO_PREFIX_LEN;
    }
    memcpy(&resp_data[ECHO_PREFIX_LEN], req_data, copy_len);
    resp_len = ECHO_PREFIX_LEN + copy_len;
    
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
    uint8_t req[CLIENT_REQ_BUF_SIZE];
    uint8_t resp[CLIENT_RESP_BUF_SIZE];
    uint16_t resp_len = CLIENT_RESP_BUF_SIZE;
    uint16_t magic = MAGIC_VALUE;
    uint16_t kind = 0;
    uint16_t seq = 0;
    int rc;

    memcpy(req, HELLO_MSG, HELLO_MSG_LEN);
    printf("Client sending first request\n");
    do {
        rc = wh_CommClient_SendRequest(client, magic, kind, &seq, HELLO_MSG_LEN, req);
        if (rc == WH_ERROR_NOTREADY) {
            sleep_ms(POLL_DELAY_MS);
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
            sleep_ms(POLL_DELAY_MS);
        }
    } while (rc == WH_ERROR_NOTREADY);
    if (rc != WH_ERROR_OK) {
        printf("ERROR: recv response rc=%d\n", rc);
        return rc;
    }
    for (int i = 0; i < NUM_LOOP_REQUESTS; i++) {
        printf("Client sending request %d\n", i);
        sprintf((char*)req, REQUEST_FMT, i);
        uint16_t req_len = strlen((char*)req);
        do {
            rc = wh_CommClient_SendRequest(client, magic, kind, &seq, req_len, req);
            if (rc == WH_ERROR_NOTREADY) {
                sleep_ms(POLL_DELAY_MS);
            }
        } while (rc == WH_ERROR_NOTREADY);
        if (rc != WH_ERROR_OK) {
            printf("ERROR: send request rc=%d\n", rc);
            return rc;
        }
        resp_len = CLIENT_RESP_BUF_SIZE;
        do {
            rc = wh_CommClient_RecvResponse(client, &magic, &kind, &seq, &resp_len, resp);
            if (rc == WH_ERROR_NOTREADY) {
                sleep_ms(POLL_DELAY_MS);
            }
        } while (rc == WH_ERROR_NOTREADY);
        if (rc != WH_ERROR_OK) {
            printf("ERROR: recv response rc=%d\n", rc);
            return rc;
        }
        sleep_ms(REQUEST_LOOP_DELAY_MS);
        printf("Client received response %d: %.*s\n", i, resp_len, resp);
    }
    return 0;
}

static void core1_entry(void)
{
    whCommClient client[1];
    pico2TransportShmContext ctx[1];
    sleep_ms(STARTUP_DELAY_MS);
    printf("\n=== Core 1: Client start ===\n");
    if (client_init(client, ctx) != 0) {
        printf("Client init failed\n");
        multicore_fifo_push_blocking(FIFO_ERROR_VAL);
        return;
    }
    sleep_ms(CLIENT_INIT_DELAY_MS);
    printf("Client initialized, sending requests\n");
    if (client_send_requests(client) != 0) {
        printf("Client requests failed\n");
    }
    pico2TransportShm_Cleanup(ctx);
    multicore_fifo_push_blocking(FIFO_SUCCESS_VAL);
    printf("Core 1 done\n");
}
int main(void)
{
    whCommServer server[1];
    pico2TransportShmContext ctx[1];
    int handled = 0;

    stdio_init_all();
    sleep_ms(STARTUP_DELAY_MS);
    printf("\n=== Pico-2 Dual-Core wolfHSM Demo ===\n");
    printf("Shared memory @%p size %u\n", pico2_shared_mem, (unsigned)pico2_shared_mem_size);

    if (server_init(server, ctx) != 0) {
        printf("Server init failed\n");
        return 1;
    }

    multicore_launch_core1(core1_entry);
    printf("Server running on Core 0, client on Core 1\n");

    const int expected = EXPECTED_HANDLED_COUNT;
    while (handled < expected) {
        if (server_handle_message(server, &handled) != 0) {
            printf("Server loop error\n");
            break;
        }
        sleep_ms(POLL_DELAY_MS);
    }

    pico2TransportShm_Cleanup(ctx);
    
    while (!multicore_fifo_rvalid()) {
        sleep_ms(POLL_DELAY_MS);
    }
    uint32_t popped_val = multicore_fifo_pop_blocking(); /* wait for client */
   
    if (popped_val == FIFO_SUCCESS_VAL) {
        return 0;
    }

    printf("Core 1 reported error: 0x%x\n", (unsigned int)popped_val);
    return -1;
}
