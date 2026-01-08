/*
 * Combined dual-core demo: server on Core 0, client on Core 1.
 * Demonstrates SHA256 hashing via wolfHSM using the wolfCrypt API.
 */
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_cryptocb.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfcrypt/sha256.h"
#include "wolfcrypt/error-crypt.h"
#include "pico2_transport_shm.h"

int rc; // Define rc as global or local as needed, but let's just make sure it's declared in functions where it's used.

#define SHARED_MEM_SIZE (4 * 1024)
__attribute__((section(".shared_ram")))
static uint8_t pico2_shared_mem[SHARED_MEM_SIZE];
static size_t pico2_shared_mem_size = SHARED_MEM_SIZE;

#define SERVER_ID 1
#define CLIENT_ID 2
#define REQ_SIZE 1024
#define RESP_SIZE 1024
#define DMA_SIZE 1024

/*
 * Server Setup
 */
static int server_init(whServerContext *serverCtx, whCommServer *serverComm, whServerCryptoContext *cryptoCtx, pico2TransportShmContext *ctx)
{
    int rc;
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

    /* Initialize crypto context (RNG, etc.) */
    memset(cryptoCtx, 0, sizeof(*cryptoCtx));
    cryptoCtx->devId = -2; /* Use software crypto for the server's backend */
#ifndef WC_NO_RNG
    rc = wc_InitRng(cryptoCtx->rng);
    if (rc != 0) {
        printf("ERROR: server wc_InitRng failed (rc=%d)\n", rc);
        return rc;
    }
#endif

    /* Initialize the full Server Application */
    memset(serverCtx, 0, sizeof(*serverCtx));
    /* wh_Server_Init takes whServerConfig */
    whServerConfig serverCfg;
    memset(&serverCfg, 0, sizeof(serverCfg));
    serverCfg.comm_config = &scfg;
    serverCfg.crypto = cryptoCtx;
    serverCfg.nvm = NULL; /* No NVM for this demo */

    rc = wh_Server_Init(serverCtx, &serverCfg);
    if (rc != WH_ERROR_OK) {
        printf("ERROR: wh_Server_Init failed (rc=%d)\n", rc);
        return rc;
    }
    
    /* Set connected state */
    wh_Server_SetConnected(serverCtx, WH_COMM_CONNECTED);

    return 0;
}

/*
 * Client Setup
 */
static int client_init(whClientContext *clientCtx, pico2TransportShmContext *ctx)
{
    static const whTransportClientCb client_cb = PICO2_TRANSPORT_SHM_CLIENT_CB;
    memset(ctx, 0, sizeof(*ctx));
    
    /* Step 1: Allocate and initialize transport configuration */
    pico2TransportShmConfig cfg = {
        .req_size = REQ_SIZE,
        .resp_size = RESP_SIZE,
        .dma_size = DMA_SIZE,
        .shared_mem = pico2_shared_mem,
        .shared_mem_size = pico2_shared_mem_size,
    };
    
    /* Step 2: Allocate comm client configuration and bind to the transport */
    whCommClientConfig commClientCfg = {
        .transport_cb = &client_cb,
        .transport_context = ctx,
        .transport_config = &cfg,
        .client_id = CLIENT_ID,
    };

    /* Step 3: Allocate and initialize the client configuration */
    whClientConfig clientCfg;
    memset(&clientCfg, 0, sizeof(clientCfg));
    clientCfg.comm = &commClientCfg;

    /* Step 5: Init */
    printf("Client initializing...\n");
    int rc = wh_Client_Init(clientCtx, &clientCfg);
    if (rc != 0) {
        printf("ERROR: wh_Client_Init failed (rc=%d)\n", rc);
        return rc;
    }
    printf("Client initialized via wh_Client_Init\n");

    return 0;
}

static void print_hash(const uint8_t *hash, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

static int client_run_demo(void)
{
    int ret;
    uint8_t hash[32];
    const char *test_inputs[] = {
        "Hello from Core 1",
        "The quick brown fox",
        "wolfHSM SHA256 Demo",
        "Pico2 Dual Core",
        "SHA256 Hash Test"
    };

    printf("\n--- Starting SHA256 Demo ---\n");

    for (int i = 0; i < 5; i++) {
        const char *plaintext = test_inputs[i];
        size_t len = strlen(plaintext);
        
        printf("\nInput [%d]: \"%s\" (%zu bytes)\n", i, plaintext, len);

        /* Standard wolfCrypt API usage, but redirected to HSM via WH_DEV_ID */
        wc_Sha256 sha256[1];
        
        /* Initialize with devId = WH_DEV_ID to trigger the callback */
        ret = wc_InitSha256_ex(sha256, NULL, WH_DEV_ID);
        if (ret == 0) {
            printf("SHA256 Initialized Successfully\n");
            ret = wc_Sha256Update(sha256, (const byte*)plaintext, (word32)len);
            if (ret == 0) {
                printf("SHA256 Update Successful\n");
                ret = wc_Sha256Final(sha256, hash);
                if (ret != 0) {
                     printf("Error: wc_Sha256Final failed with %d\n", ret);
                }
            } else {
                printf("Error: wc_Sha256Update failed with %d\n", ret);
            }
            printf("SHA256 Finalizing...\n");
            wc_Sha256Free(sha256);
        } else {
            printf("Error: wc_InitSha256_ex failed with %d\n", ret);
        }

        if (ret == 0) {
            printf("SHA256 Hash: ");
            print_hash(hash, 32);
        } else {
            printf("Failed to compute hash\n");
            return ret;
        }

        sleep_ms(1000);
    }
    printf("\n--- Demo Complete ---\n");
    return 0;
}

static void core1_entry(void)
{
    static whClientContext clientCtx[1];
    static pico2TransportShmContext clientTransportCtx[1];

    sleep_ms(2000); /* Wait for server to start */
    printf("\n=== Core 1: Client start ===\n");
    
    if (client_init(clientCtx, clientTransportCtx) != 0) {
        printf("Client init failed\n");
        multicore_fifo_push_blocking(0xDEAD0001);
        return;
    }
    
    if (client_run_demo() != 0) {
        printf("Client demo failed\n");
    }
    
    pico2TransportShm_Cleanup(clientTransportCtx);
    multicore_fifo_push_blocking(0xC1E17E);
    printf("Core 1 done\n");
}

int main(void)
{
    whServerContext serverCtx[1];
    whCommServer serverComm[1];
    whServerCryptoContext cryptoCtx[1];
    pico2TransportShmContext serverTransportCtx[1];

    stdio_init_all();
    sleep_ms(5000);
    printf("\n=== Pico-2 Dual-Core wolfHSM SHA256 Demo (wolfCrypt API) ===\n");
    printf("Shared memory @%p size %u\n", pico2_shared_mem, (unsigned)pico2_shared_mem_size);

    /* Use serverComm wrapper in serverCtx if we use wh_Server_Init, 
       but here we passed scfg which uses a local transort context.
       The server_init call handles internal wh_Server_Init.
    */
    if (server_init(serverCtx, serverComm, cryptoCtx, serverTransportCtx) != 0) {
        printf("Server init failed\n");
        return 1;
    }

    /* Start client on core 1 */
    multicore_launch_core1(core1_entry);
    printf("Server running on Core 0, client on Core 1\n");

    /* 
     * Main Server Loop 
     */
    while (1) {
        int ret = wh_Server_HandleRequestMessage(serverCtx);
        if (ret == WH_ERROR_NOTREADY) {
            /* No message, yield briefly */
        } else if (ret != WH_ERROR_OK) {
            printf("Server loop error: %d\n", ret);
        }
    }

    return 0;
}
