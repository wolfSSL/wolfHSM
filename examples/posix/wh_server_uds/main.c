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
 * examples/posix/wh_server_uds/main.c
 *
 * wolfHSM PKCS#11 daemon — serves the p11-kit remote protocol over a Unix
 * domain socket so that any p11-kit-aware application can use wolfHSM as a
 * PKCS#11 token without installing a custom .so.
 *
 * Architecture:
 *
 *   [p11-kit application]
 *          |  p11-kit remote protocol (binary, over UDS)
 *   [wh_server_uds daemon] (this file)
 *          |  wolfPKCS11 C_ API  ─────────────────────────────────┐
 *          |  wolfHSM NVM store (port/pkcs11/wh_pkcs11_store.c)   |
 *          |  wolfHSM client (wh_client.c, in-process)            |
 *          |  mem transport (wh_transport_mem.c)                   |
 *          |  wolfHSM server (wh_server.c, server_thread)  ────────┘
 *          |  software wolfCrypt (AES, RSA, ECC, ...)
 *
 * Threading model:
 *   main thread  — initialization, accept loop, signal handling
 *   server_thread — runs wh_Server_HandleRequestMessage() in a tight loop;
 *                   services wolfHSM client RPC calls from wolfPKCS11
 *   conn_thread × N — one per accepted p11-kit connection; calls
 *                   p11_kit_remote_serve_module() until connection closes
 *
 * wolfPKCS11 integration:
 *   wolfPKCS11 must be built with:
 *     -DWOLFPKCS11_CUSTOM_STORE   (routes storage through our NVM callbacks)
 *     -DWOLFPKCS11_WOLFHSM        (sets slot->devId = WH_DEV_ID in Slot_Init)
 *   Without WOLFPKCS11_WOLFHSM, crypto goes through in-process software
 *   wolfCrypt instead of the wolfHSM server — storage still works, but the
 *   wolfHSM server's key-opacity guarantee does not apply.
 *
 * Environment variables:
 *   WH_UDS_PATH  — Unix socket path for p11-kit clients to connect to
 *                  Default: /tmp/wolfhsm-pkcs11.sock
 *
 * p11-kit discovery:
 *   Set P11_KIT_SERVER_ADDRESS=unix:path=<WH_UDS_PATH> in the client env, or
 *   install a p11-kit module config file:
 *     [module]
 *     module: p11-kit-client.so
 *     remote: unix:path=/tmp/wolfhsm-pkcs11.sock
 *
 * Build requirements:
 *   pkg-config --cflags p11-kit-1
 *   pkg-config --libs   p11-kit-1
 *   Link against: wolfPKCS11 (.a), wolfHSM (.a), wolfSSL (.a), -lpthread
 *
 * Compile flag required by p11-kit to expose p11_kit_remote_serve_module:
 *   -DP11_KIT_FUTURE_UNSTABLE_API
 */

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>   /* NULL */
#include <stdint.h>   /* uint8_t */
#include <stdio.h>    /* fprintf, perror */
#include <stdlib.h>   /* exit */
#include <string.h>   /* memset, memcpy */
#include <errno.h>    /* errno */
#include <signal.h>   /* sigaction */
#include <pthread.h>  /* pthread_t, pthread_create, pthread_join */
#include <unistd.h>   /* close */
#include <sys/socket.h> /* socket, bind, listen, accept */
#include <sys/un.h>     /* struct sockaddr_un */

/*
 * p11-kit headers.
 *
 * p11-kit/pkcs11.h provides all standard CK_ types (CK_FUNCTION_LIST,
 * CK_RV, CK_VOID_PTR, etc.).  We use it instead of a standalone pkcs11.h
 * so that p11_kit_remote_serve_module and the PKCS#11 types match exactly.
 *
 * P11_KIT_FUTURE_UNSTABLE_API must be defined before including remote.h to
 * unlock p11_kit_remote_serve_module.  Pass it via -DP11_KIT_FUTURE_UNSTABLE_API
 * on the compiler command line (see Makefile) rather than defining it here to
 * avoid a redefinition warning when the flag is already set by the build system.
 */
#include <p11-kit/pkcs11.h>
#include <p11-kit/remote.h>

/*
 * wolfSSL / wolfCrypt
 *
 * wolfcrypt/settings.h pulls in user_settings.h (via WOLFSSL_USER_SETTINGS).
 * The wolfCrypt crypto callback mechanism (WOLF_CRYPTO_CB) routes wolfCrypt
 * operations directed to WH_DEV_ID through the wolfHSM client.
 */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/wc_port.h"   /* wolfCrypt_Init, wolfCrypt_Cleanup */
#include "wolfssl/wolfcrypt/random.h"    /* wc_InitRng_ex, wc_FreeRng */
#include "wolfssl/wolfcrypt/cryptocb.h"  /* wc_CryptoCb_RegisterDevice */

/*
 * wolfHSM headers
 */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_cryptocb.h"  /* wh_Client_CryptoCb, WH_DEV_ID */

/*
 * wolfHSM PKCS#11 NVM store callbacks
 *
 * These are our wolfHSM-backed implementations of the wolfPKCS11 custom store
 * interface.  They route wolfPKCS11's key persistence through wolfHSM NVM.
 */
#include "port/pkcs11/wh_pkcs11_store.h"

/* ── Default configuration ─────────────────────────────────────────────────── */

/* Unix socket path that p11-kit clients connect to.
 * Override with the WH_UDS_PATH environment variable. */
#define WH_SERVER_UDS_DEFAULT_PATH "/tmp/wolfhsm-pkcs11.sock"

/* Flash size for the wolfHSM server's NVM: 1 MB RAM sim.
 * A real deployment would use wh_flash_posixsim.c backed by a file on disk
 * for persistence across daemon restarts.  The RAM sim loses all keys on
 * shutdown; it is sufficient for development and testing. */
#define WH_SERVER_UDS_FLASH_RAM_SIZE (1024u * 1024u)

/* Mem transport buffer sizes: must be >= sizeof(header) + COMM_DATA_LEN */
#define WH_SERVER_UDS_REQ_SIZE  (sizeof(uint32_t) + WOLFHSM_CFG_COMM_DATA_LEN)
#define WH_SERVER_UDS_RESP_SIZE (sizeof(uint32_t) + WOLFHSM_CFG_COMM_DATA_LEN)

/* Maximum concurrent p11-kit client connections we allow.
 * Each consumes one thread + one wolfPKCS11 session.  wolfPKCS11's internal
 * lock serialises all PKCS#11 calls regardless. */
#define WH_SERVER_UDS_MAX_CONNECTIONS 8

/* ── wolfPKCS11 forward declarations ───────────────────────────────────────── */

/*
 * wolfPKCS11 exports the standard PKCS#11 C_ functions as global symbols.
 * p11-kit/pkcs11.h declares the types; we forward-declare the functions here
 * so we can call them without including wolfpkcs11's own headers (which
 * require wolfPKCS11 to be installed locally).
 *
 * At link time, wolfPKCS11 (.a or .so) provides the implementations.
 */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
CK_RV C_Finalize(CK_VOID_PTR pReserved);
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

/* ── Global state shared between threads ───────────────────────────────────── */

/*
 * wolfHSM server and client (in-process via mem transport).
 *
 * Decision: single shared client context for the lifetime of the process.
 * wolfPKCS11 serialises all PKCS#11 calls through its internal mutex, so
 * the client never has two concurrent in-flight requests.  A per-session
 * client would waste connection setup overhead with no safety benefit.
 */
static whServerContext    g_server;
static whClientContext    g_client;

/* Server thread handle; joined on shutdown */
static pthread_t          g_server_tid;

/* Set to 1 after pthread_create succeeds; cleared after pthread_join */
static int                g_server_thread_started = 0;

/* p11-kit PKCS#11 function list (set by C_GetFunctionList) */
static CK_FUNCTION_LIST*  g_pkcs11_fns = NULL;

/* Accept socket fd+1 (0 = invalid) for the p11-kit accept loop */
static int                g_accept_fd_p1 = 0;

/* Stop flag: set to 1 by SIGTERM/SIGINT handler to break all loops */
static volatile int       g_stop = 0;

/* ── wolfHSM server thread ─────────────────────────────────────────────────── */

/*
 * The server thread spins calling wh_Server_HandleRequestMessage.  Each call
 * processes one pending RPC from the client (wolfPKCS11 calling into wolfHSM
 * for a crypto or NVM operation) or returns WH_ERROR_NOTREADY if no request
 * is queued.
 *
 * We sched_yield on NOTREADY to avoid burning a full CPU core on the spin.
 * A real production daemon should use a condition variable or semaphore
 * signalled by the mem transport when a new request arrives.
 */
static void* server_thread_fn(void* arg)
{
    int rc;
    (void)arg;

    while (!g_stop) {
        rc = wh_Server_HandleRequestMessage(&g_server);
        if (rc == WH_ERROR_NOTREADY) {
            /* No request pending — yield this timeslice to avoid busy-wait */
            sched_yield();
        } else if (rc != WH_ERROR_OK) {
            fprintf(stderr, "wh_server_uds: server error %d — server thread exiting\n", rc);
            break;
        }
    }

    return NULL;
}

/* ── p11-kit connection handler thread ─────────────────────────────────────── */

/*
 * Each accepted p11-kit connection is handed off to a detached thread.
 * p11_kit_remote_serve_module handles the full p11-kit wire protocol:
 *   1. 1-byte version handshake (server sends 0 = "speak p11-kit protocol")
 *   2. Loop: read 12-byte frame header, dispatch CK_ call, send response
 *   3. Returns when the connection closes or an error occurs
 *
 * arg is a heap-allocated int* holding the accepted fd; this thread owns
 * and frees it.  Using a pointer avoids data races if the main thread's
 * stack variable is reused before this thread reads it.
 */
static void* connection_thread_fn(void* arg)
{
    int* fdp = (int*)arg;
    int  fd  = *fdp;
    free(fdp);

    /* p11_kit_remote_serve_module blocks until the connection closes.
     * wolfPKCS11's internal lock serialises concurrent calls from multiple
     * connection threads — no additional locking needed here. */
    (void)p11_kit_remote_serve_module(g_pkcs11_fns, fd, fd);

    close(fd);
    return NULL;
}

/* ── Signal handler ────────────────────────────────────────────────────────── */

static void sigterm_handler(int sig)
{
    (void)sig;
    /* Closing the accept socket unblocks the accept() call in the main loop.
     *
     * Do NOT set g_stop here: the wolfHSM server thread must remain alive
     * until C_Finalize completes, because WP11_Library_Final calls
     * wp11_Slot_Store which makes wolfHSM NVM RPCs that need the server.
     * g_stop is set in cleanup after C_Finalize returns. */
    if (g_accept_fd_p1 > 0) {
        close(g_accept_fd_p1 - 1);
        g_accept_fd_p1 = 0;
    }
}

/* ── Main ──────────────────────────────────────────────────────────────────── */

int main(int argc, char** argv)
{
    /*
     * Static storage for the wolfHSM server-side subsystems.
     * These outlive main() cleanup, so static avoids stack-size concerns.
     */

    /* Flash RAM simulator: 1 MB simulated flash in process heap */
    static uint8_t           s_flash_mem[WH_SERVER_UDS_FLASH_RAM_SIZE];
    static whFlashRamsimCtx  s_flash_ctx;
    static whFlashRamsimCfg  s_flash_cfg;
    static const whFlashCb   s_flash_cb = WH_FLASH_RAMSIM_CB;

    /* NVM flash layer on top of the flash simulator */
    static whNvmFlashConfig  s_nvmf_cfg;
    static whNvmFlashContext s_nvmf_ctx;
    static const whNvmCb     s_nvm_cb = WH_NVM_FLASH_CB;
    static whNvmConfig       s_nvm_cfg;
    static whNvmContext      s_nvm;

    /* Mem transport: shared request/response buffers between server and client.
     * Sized to hold the frame header + max payload. */
    static uint8_t           s_req_buf[WH_SERVER_UDS_REQ_SIZE];
    static uint8_t           s_resp_buf[WH_SERVER_UDS_RESP_SIZE];
    static whTransportMemConfig   s_mem_cfg;
    static whTransportMemContext  s_mem_srv_ctx;
    static whTransportMemContext  s_mem_cli_ctx;

    /* wolfHSM server */
    static whServerCryptoContext  s_crypto;
    static const whTransportServerCb s_mem_srv_cb = WH_TRANSPORT_MEM_SERVER_CB;
    static whCommServerConfig     s_comm_srv_cfg;
    static whServerConfig         s_srv_cfg;

    /* wolfHSM client */
    static const whTransportClientCb s_mem_cli_cb = WH_TRANSPORT_MEM_CLIENT_CB;
    static whCommClientConfig     s_comm_cli_cfg;
    static whClientConfig         s_cli_cfg;

    /* p11-kit accept socket */
    struct sockaddr_un listen_addr;
    const char*        uds_path;
    int                listen_fd  = -1;
    int                rc         = 0;
    CK_RV              ckrv;
    struct sigaction   sa;

    (void)argc;
    (void)argv;

    /* ── Determine Unix socket path ── */
    uds_path = getenv("WH_UDS_PATH");
    if (uds_path == NULL) {
        uds_path = WH_SERVER_UDS_DEFAULT_PATH;
    }

    fprintf(stderr, "wh_server_uds: starting, socket path = %s\n", uds_path);

    /* ── Install signal handlers ── */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) != 0 ||
            sigaction(SIGINT,  &sa, NULL) != 0) {
        perror("wh_server_uds: sigaction");
        return 1;
    }

    /* ── wolfCrypt init ── */
    rc = wolfCrypt_Init();
    if (rc != 0) {
        fprintf(stderr, "wh_server_uds: wolfCrypt_Init failed: %d\n", rc);
        return 1;
    }

    /* ── Flash RAM sim init ── */
    memset(s_flash_mem, 0, sizeof(s_flash_mem));
    s_flash_cfg.size       = WH_SERVER_UDS_FLASH_RAM_SIZE;
    s_flash_cfg.sectorSize = WH_SERVER_UDS_FLASH_RAM_SIZE / 2;
    s_flash_cfg.pageSize   = 8;
    s_flash_cfg.erasedByte = (uint8_t)0;
    s_flash_cfg.memory     = s_flash_mem;

    /* ── NVM flash init ── */
    s_nvmf_cfg.cb      = &s_flash_cb;
    s_nvmf_cfg.context = &s_flash_ctx;
    s_nvmf_cfg.config  = &s_flash_cfg;

    s_nvm_cfg.cb      = (whNvmCb*)&s_nvm_cb;
    s_nvm_cfg.context = &s_nvmf_ctx;
    s_nvm_cfg.config  = &s_nvmf_cfg;

    rc = wh_Nvm_Init(&s_nvm, &s_nvm_cfg);
    if (rc != 0) {
        fprintf(stderr, "wh_server_uds: wh_Nvm_Init failed: %d\n", rc);
        goto cleanup_wolfcrypt;
    }

    /* ── Mem transport config ── */
    s_mem_cfg.req      = s_req_buf;
    s_mem_cfg.req_size = sizeof(s_req_buf);
    s_mem_cfg.resp      = s_resp_buf;
    s_mem_cfg.resp_size = sizeof(s_resp_buf);

    /* ── wolfHSM server init ── */
    s_comm_srv_cfg.transport_cb      = &s_mem_srv_cb;
    s_comm_srv_cfg.transport_context = &s_mem_srv_ctx;
    s_comm_srv_cfg.transport_config  = &s_mem_cfg;
    s_comm_srv_cfg.server_id         = 1;

    memset(&s_crypto, 0, sizeof(s_crypto));

    /* ── Server RNG init ── */
    /*
     * The server crypto context's RNG must be initialised before wh_Server_Init
     * so that server-side operations that need entropy (key generation, ECDSA
     * signing, etc.) have a valid RNG.  INVALID_DEVID forces software
     * wolfCrypt — the server must not recurse into its own wolfHSM callback.
     */
    rc = wc_InitRng_ex(s_crypto.rng, NULL, INVALID_DEVID);
    if (rc != 0) {
        fprintf(stderr, "wh_server_uds: wc_InitRng_ex failed: %d\n", rc);
        goto cleanup_nvm;
    }

    s_srv_cfg.comm_config = &s_comm_srv_cfg;
    s_srv_cfg.nvm         = &s_nvm;
    s_srv_cfg.crypto      = &s_crypto;
    s_srv_cfg.devId       = INVALID_DEVID;  /* server uses local software wolfCrypt */

    rc = wh_Server_Init(&g_server, &s_srv_cfg);
    if (rc != 0) {
        fprintf(stderr, "wh_server_uds: wh_Server_Init failed: %d\n", rc);
        wc_FreeRng(s_crypto.rng);
        goto cleanup_nvm;
    }

    /*
     * Mark the server as connected immediately.  The mem transport does not
     * perform a handshake; the client is already "present" from the server's
     * perspective.
     */
    wh_Server_SetConnected(&g_server, WH_COMM_CONNECTED);

    /* ── Start server thread ── */
    rc = pthread_create(&g_server_tid, NULL, server_thread_fn, NULL);
    if (rc != 0) {
        fprintf(stderr, "wh_server_uds: pthread_create (server) failed: %d\n", rc);
        goto cleanup_server;
    }
    g_server_thread_started = 1;

    /* ── wolfHSM client init ── */
    s_comm_cli_cfg.transport_cb      = &s_mem_cli_cb;
    s_comm_cli_cfg.transport_context = &s_mem_cli_ctx;
    s_comm_cli_cfg.transport_config  = &s_mem_cfg;
    s_comm_cli_cfg.client_id         = 1;

    s_cli_cfg.comm = &s_comm_cli_cfg;

    rc = wh_Client_Init(&g_client, &s_cli_cfg);
    if (rc != 0) {
        fprintf(stderr, "wh_server_uds: wh_Client_Init failed: %d\n", rc);
        goto cleanup_server_thread;
    }

    /*
     * Register wolfHSM as the wolfCrypt device callback at WH_DEV_ID.
     * wolfPKCS11 (with WOLFPKCS11_WOLFHSM) sets slot->devId = WH_DEV_ID
     * during C_Initialize, routing all wolfCrypt operations for that slot
     * through this callback → wolfHSM client → mem transport → server.
     *
     * Without WOLFPKCS11_WOLFHSM: devId stays INVALID_DEVID and wolfPKCS11
     * uses local software wolfCrypt instead of the wolfHSM server.  The NVM
     * store callbacks still route key storage through wolfHSM NVM.
     */
    rc = wc_CryptoCb_RegisterDevice(WH_DEV_ID, wh_Client_CryptoCb, &g_client);
    if (rc != 0) {
        fprintf(stderr,
                "wh_server_uds: wc_CryptoCb_RegisterDevice failed: %d\n", rc);
        goto cleanup_client;
    }

    /* ── Inject wolfHSM client into PKCS#11 NVM store ── */
    /*
     * wh_Pkcs11Store_SetClient must be called before C_Initialize so that
     * wolfPKCS11_Store_Open/Read/Write/Close/Remove can find the client.
     * The client context is process-global and remains valid for the daemon
     * lifetime; the store callbacks do not take ownership.
     */
    wh_Pkcs11Store_SetClient(&g_client);

    /* ── wolfPKCS11 init ── */
    /*
     * C_Initialize with NULL uses the default CKF_OS_LOCKING_OK behaviour.
     * wolfPKCS11 initialises its internal mutex and, if built with
     * WOLFPKCS11_WOLFHSM, calls wp11_WolfHSM_Init which sets
     * slot->devId = WH_DEV_ID.
     *
     * Important: wolfHSM client must be initialised and the crypto callback
     * registered BEFORE this call, so that any wolfCrypt operation wolfPKCS11
     * performs during init (e.g. RNG seeding) routes correctly.
     */
    ckrv = C_Initialize(NULL);
    if (ckrv != CKR_OK) {
        fprintf(stderr, "wh_server_uds: C_Initialize failed: 0x%08lX\n",
                (unsigned long)ckrv);
        goto cleanup_client;
    }

    ckrv = C_GetFunctionList(&g_pkcs11_fns);
    if (ckrv != CKR_OK || g_pkcs11_fns == NULL) {
        fprintf(stderr, "wh_server_uds: C_GetFunctionList failed: 0x%08lX\n",
                (unsigned long)ckrv);
        goto cleanup_pkcs11;
    }

    /* ── Create p11-kit accept socket ── */
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("wh_server_uds: socket");
        goto cleanup_pkcs11;
    }

    /* Remove stale socket from a previous crash */
    (void)unlink(uds_path);

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sun_family = AF_UNIX;
    if (strlen(uds_path) >= sizeof(listen_addr.sun_path)) {
        fprintf(stderr, "wh_server_uds: socket path too long (max %zu)\n",
                sizeof(listen_addr.sun_path) - 1);
        close(listen_fd);
        goto cleanup_pkcs11;
    }
    strncpy(listen_addr.sun_path, uds_path, sizeof(listen_addr.sun_path) - 1);

    if (bind(listen_fd, (struct sockaddr*)&listen_addr,
             sizeof(listen_addr)) != 0) {
        perror("wh_server_uds: bind");
        close(listen_fd);
        goto cleanup_pkcs11;
    }

    /* chmod 0660: only owning user + group may connect.
     * The daemon should run as a dedicated user/group pair. */
    if (chmod(uds_path, 0660) != 0) {
        perror("wh_server_uds: chmod");
        /* Non-fatal: continue with default permissions */
    }

    if (listen(listen_fd, WH_SERVER_UDS_MAX_CONNECTIONS) != 0) {
        perror("wh_server_uds: listen");
        close(listen_fd);
        goto cleanup_socket_path;
    }

    g_accept_fd_p1 = listen_fd + 1;

    fprintf(stderr, "wh_server_uds: listening on %s\n", uds_path);

    /* ── Accept loop ── */
    while (!g_stop) {
        int    conn_fd;
        int*   fdp;
        pthread_t tid;
        pthread_attr_t tattr;

        conn_fd = accept(listen_fd, NULL, NULL);
        if (conn_fd < 0) {
            if (errno == EINTR || errno == EBADF) {
                /* SIGTERM caused close() on listen_fd */
                break;
            }
            perror("wh_server_uds: accept");
            break;
        }

        /*
         * Heap-allocate the fd so the connection thread has its own copy.
         * The thread frees it after reading.
         */
        fdp = (int*)malloc(sizeof(int));
        if (fdp == NULL) {
            fprintf(stderr, "wh_server_uds: malloc failed for conn fd\n");
            close(conn_fd);
            continue;
        }
        *fdp = conn_fd;

        /* Detach: we do not join connection threads; they clean up themselves */
        pthread_attr_init(&tattr);
        pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &tattr, connection_thread_fn, fdp) != 0) {
            perror("wh_server_uds: pthread_create (connection)");
            free(fdp);
            close(conn_fd);
        }
        pthread_attr_destroy(&tattr);
    }

    fprintf(stderr, "wh_server_uds: shutting down\n");

cleanup_socket_path:
    unlink(uds_path);

cleanup_pkcs11:
    (void)C_Finalize(NULL);

    /*
     * WP11_Library_Final (called by C_Finalize) calls wp11_Slot_Store which
     * makes wolfHSM NVM RPCs.  The server thread must be alive while
     * C_Finalize runs.  Set g_stop and join only after C_Finalize returns.
     * cleanup_server_thread below is a no-op for this normal path.
     */
    if (g_server_thread_started) {
        g_stop = 1;
        pthread_join(g_server_tid, NULL);
        g_server_thread_started = 0;
    }

cleanup_client:
    (void)wh_Client_Cleanup(&g_client);

cleanup_server_thread:
    /* Early-exit paths (wc_CryptoCb_RegisterDevice or C_Initialize failures)
     * jump here directly, bypassing cleanup_pkcs11.  Join the server thread
     * here for those paths.  No-op if already joined above. */
    if (g_server_thread_started) {
        g_stop = 1;
        pthread_join(g_server_tid, NULL);
        g_server_thread_started = 0;
    }

cleanup_server:
    (void)wh_Server_Cleanup(&g_server);
    (void)wc_FreeRng(s_crypto.rng);

cleanup_nvm:
    (void)wh_Nvm_Cleanup(&s_nvm);

cleanup_wolfcrypt:
    (void)wolfCrypt_Cleanup();

    fprintf(stderr, "wh_server_uds: done\n");
    return (rc != 0) ? 1 : 0;
}
