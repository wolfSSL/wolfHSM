/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * test-refactor/posix/wh_test_keygen_unique_id.c
 *
 * Concurrent unique-id allocation test for the crypto keygen handlers in
 * src/wh_server_crypto.c.
 *
 * KU_NUM_CLIENTS client/server pairs share a single locked NVM. For each
 * supported algorithm, all clients issue a barrier-aligned cache keygen
 * with an ERASED global key id, so every server auto-allocates an id from
 * the shared global namespace. Each round asserts that all successful
 * keygens returned distinct ids.
 *
 * Under TSAN (TSAN=1) unserialized cache accesses are additionally
 * reported as data races.
 */

#include "wolfhsm/wh_settings.h"

/* pthread_barrier_t is unavailable on macOS. */
#if defined(WOLFHSM_CFG_THREADSAFE) && defined(WOLFHSM_CFG_TEST_POSIX) &&     \
    defined(WOLFHSM_CFG_GLOBAL_KEYS) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO) &&  \
    !defined(__APPLE__)
#define WH_KU_ENABLED
#endif

#include "wh_test_common.h"
#include "wh_test_list.h" /* WH_TEST_SKIPPED */
#include "wh_test_keygen_unique_id.h"

#ifndef WH_KU_ENABLED

int whTest_KeygenUniqueIdConcurrent(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

#else /* WH_KU_ENABLED */

#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_lock.h"
#include "wolfhsm/wh_keyid.h"

#include "port/posix/posix_lock.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#ifdef HAVE_CURVE25519
#include "wolfssl/wolfcrypt/curve25519.h"
#endif
#ifdef HAVE_ECC
#include "wolfssl/wolfcrypt/ecc.h"
#endif
#ifdef HAVE_DILITHIUM
#include "wolfssl/wolfcrypt/dilithium.h"
#endif

/* TSAN transport shims: TSAN can't see the mem transport's notify-counter
 * handshake, so annotate the send/recv pairs to keep the analysis on
 * keystore/NVM locking. */
#ifdef WOLFHSM_CFG_TEST_STRESS_TSAN

#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__SANITIZE_THREAD__) && !__has_feature(thread_sanitizer)
#error ThreadSanitizer not enabled for this build
#endif

#include <sanitizer/tsan_interface.h>

static int ku_SendRequest(void* c, uint16_t len, const void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    __tsan_release((void*)ctx->req);
    return wh_TransportMem_SendRequest(c, len, data);
}
static int ku_RecvResponse(void* c, uint16_t* out_len, void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    int                    rc  = wh_TransportMem_RecvResponse(c, out_len, data);
    if (rc == WH_ERROR_OK) {
        __tsan_acquire((void*)ctx->resp);
    }
    return rc;
}
static int ku_RecvRequest(void* c, uint16_t* out_len, void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    int                    rc  = wh_TransportMem_RecvRequest(c, out_len, data);
    if (rc == WH_ERROR_OK) {
        __tsan_acquire((void*)ctx->req);
    }
    return rc;
}
static int ku_SendResponse(void* c, uint16_t len, const void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    __tsan_release((void*)ctx->resp);
    return wh_TransportMem_SendResponse(c, len, data);
}

static const whTransportClientCb clientTransportCb = {
    .Init    = wh_TransportMem_InitClear,
    .Send    = ku_SendRequest,
    .Recv    = ku_RecvResponse,
    .Cleanup = wh_TransportMem_Cleanup,
};
static const whTransportServerCb serverTransportCb = {
    .Init    = wh_TransportMem_Init,
    .Recv    = ku_RecvRequest,
    .Send    = ku_SendResponse,
    .Cleanup = wh_TransportMem_Cleanup,
};

#else /* !WOLFHSM_CFG_TEST_STRESS_TSAN */

static const whTransportClientCb clientTransportCb = WH_TRANSPORT_MEM_CLIENT_CB;
static const whTransportServerCb serverTransportCb = WH_TRANSPORT_MEM_SERVER_CB;

#endif /* WOLFHSM_CFG_TEST_STRESS_TSAN */

#define KU_ATOMIC_LOAD(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define KU_ATOMIC_STORE(ptr, v) __atomic_store_n((ptr), (v), __ATOMIC_RELEASE)
#define KU_ATOMIC_ADD(ptr, v) __atomic_add_fetch((ptr), (v), __ATOMIC_ACQ_REL)

/* Four concurrent client/server pairs sharing one NVM. Four fits
 * WOLFHSM_CFG_SERVER_KEYCACHE_COUNT but can over-subscribe the big-key
 * cache; that's fine, only *successful* keygens must have distinct ids. */
#define KU_NUM_CLIENTS 4

#define KU_FLASH_RAM_SIZE (1024 * 1024)
#define KU_FLASH_SECTOR_SIZE (128 * 1024)
#define KU_FLASH_PAGE_SIZE 8

#define KU_BUFFER_SIZE 4096

/* Rounds per algorithm; the slower big-key keygens use fewer to bound
 * wall-clock. */
#define KU_ROUNDS_SMALL 100
#define KU_ROUNDS_BIG 24

/* Each thunk issues one blocking cache keygen for a GLOBAL key with an
 * ERASED id, so the server auto-allocates an id from the shared global
 * namespace. *outId receives it in client (flagged) format, suitable for
 * wh_Client_KeyEvict(). */
typedef int (*kuGenFn)(whClientContext* client, whKeyId* outId);

#define KU_ERASED_GLOBAL WH_CLIENT_KEYID_MAKE_GLOBAL(0)

#ifdef HAVE_CURVE25519
static int kuGen_Curve25519(whClientContext* client, whKeyId* outId)
{
    whKeyId id = KU_ERASED_GLOBAL;
    int     rc = wh_Client_Curve25519MakeCacheKey(
        client, (uint16_t)CURVE25519_KEYSIZE, &id, WH_NVM_FLAGS_NONE, NULL, 0);
    *outId = id;
    return rc;
}
#endif

#ifdef HAVE_ED25519
static int kuGen_Ed25519(whClientContext* client, whKeyId* outId)
{
    whKeyId id = KU_ERASED_GLOBAL;
    int     rc =
        wh_Client_Ed25519MakeCacheKey(client, &id, WH_NVM_FLAGS_NONE, 0, NULL);
    *outId = id;
    return rc;
}
#endif

#if defined(HAVE_ECC) && defined(WOLFSSL_KEY_GEN)
static int kuGen_Ecc(whClientContext* client, whKeyId* outId)
{
    whKeyId id = KU_ERASED_GLOBAL;
    int     rc = wh_Client_EccMakeCacheKey(client, 32, ECC_SECP256R1, &id,
                                           WH_NVM_FLAGS_NONE, 0, NULL);
    *outId     = id;
    return rc;
}
#endif

#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY)
static int kuGen_MlDsa(whClientContext* client, whKeyId* outId)
{
    whKeyId id = KU_ERASED_GLOBAL;
    int     rc = wh_Client_MlDsaMakeCacheKey(client, 0, WC_ML_DSA_44, &id,
                                             WH_NVM_FLAGS_NONE, 0, NULL);
    *outId     = id;
    return rc;
}
#endif

typedef struct {
    const char* name;
    kuGenFn     gen;
    int         rounds;
} KuAlgo;

static const KuAlgo kuAlgos[] = {
#ifdef HAVE_CURVE25519
    {"Curve25519", kuGen_Curve25519, KU_ROUNDS_SMALL},
#endif
#ifdef HAVE_ED25519
    {"Ed25519", kuGen_Ed25519, KU_ROUNDS_SMALL},
#endif
#if defined(HAVE_ECC) && defined(WOLFSSL_KEY_GEN)
    {"ECC", kuGen_Ecc, KU_ROUNDS_SMALL},
#endif
#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY)
    {"ML-DSA", kuGen_MlDsa, KU_ROUNDS_BIG},
#endif
};

#define KU_NUM_ALGOS ((int)(sizeof(kuAlgos) / sizeof(kuAlgos[0])))

struct KuContext;

typedef struct {
    uint8_t              reqBuf[KU_BUFFER_SIZE];
    uint8_t              respBuf[KU_BUFFER_SIZE];
    whTransportMemConfig tmConfig;

    whTransportMemClientContext clientTransportCtx;
    whCommClientConfig          clientCommConfig;
    whClientContext             client;
    whClientConfig              clientConfig;

    whTransportMemServerContext serverTransportCtx;
    whCommServerConfig          serverCommConfig;
    whServerContext             server;
    whServerConfig              serverConfig;
    whServerCryptoContext       cryptoCtx;

    pthread_t clientThread;
    pthread_t serverThread;
    int       idx;

    struct KuContext* shared;
} KuPair;

typedef struct KuContext {
    /* Shared, locked NVM */
    uint8_t           flashMemory[KU_FLASH_RAM_SIZE];
    whFlashRamsimCtx  flashCtx;
    whFlashRamsimCfg  flashCfg;
    whNvmFlashContext nvmFlashCtx;
    whNvmFlashConfig  nvmFlashCfg;
    whNvmContext      nvm;
    whNvmConfig       nvmCfg;

    posixLockContext    nvmLockCtx;
    pthread_mutexattr_t mutexAttr;
    posixLockConfig     posixLockCfg;
    whLockConfig        lockCfg;

    KuPair pairs[KU_NUM_CLIENTS];

    /* Servers stay up across every algorithm; client threads are respawned
     * per algorithm. A readiness counter rather than a barrier, so a server
     * that fails to spawn does not hang the others. */
    volatile int serversReady;
    volatile int serverError;
    volatile int stopFlag;

    /* Per-round client synchronization (clients only) */
    pthread_barrier_t roundStart;
    pthread_barrier_t roundMid;
    pthread_barrier_t roundEnd;

    /* Current algorithm under test */
    kuGenFn     genFn;
    int         rounds;
    const char* algoName;

    /* Per-round results, indexed by client */
    volatile whKeyId roundIds[KU_NUM_CLIENTS];
    volatile int     roundRc[KU_NUM_CLIENTS];

    /* Outcome counters */
    volatile int collisions;
    volatile int hardErrors;
    volatile int successes;
} KuContext;

/* The context is large (1 MB flash buffer); keep it off the thread stack. */
static KuContext g_ku;

static int kuInitSharedNvm(KuContext* ctx)
{
    static whFlashCb flashCb = WH_FLASH_RAMSIM_CB;
    static whNvmCb   nvmCb   = WH_NVM_FLASH_CB;
    static whLockCb  lockCb  = POSIX_LOCK_CB;
    int              rc;

    memset(ctx->flashMemory, 0xFF, sizeof(ctx->flashMemory));

    ctx->flashCfg.size       = KU_FLASH_RAM_SIZE;
    ctx->flashCfg.sectorSize = KU_FLASH_SECTOR_SIZE;
    ctx->flashCfg.pageSize   = KU_FLASH_PAGE_SIZE;
    ctx->flashCfg.erasedByte = 0xFF;
    ctx->flashCfg.memory     = ctx->flashMemory;

    ctx->nvmFlashCfg.cb      = &flashCb;
    ctx->nvmFlashCfg.context = &ctx->flashCtx;
    ctx->nvmFlashCfg.config  = &ctx->flashCfg;

    rc = wh_NvmFlash_Init(&ctx->nvmFlashCtx, &ctx->nvmFlashCfg);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("NVM flash init failed: %d\n", rc);
        return rc;
    }

    /* Error-checking mutex catches lock misuse (double-unlock, etc.). */
    memset(&ctx->nvmLockCtx, 0, sizeof(ctx->nvmLockCtx));
    pthread_mutexattr_init(&ctx->mutexAttr);
    pthread_mutexattr_settype(&ctx->mutexAttr, PTHREAD_MUTEX_ERRORCHECK);
    ctx->posixLockCfg.attr = &ctx->mutexAttr;
    ctx->lockCfg.cb        = &lockCb;
    ctx->lockCfg.context   = &ctx->nvmLockCtx;
    ctx->lockCfg.config    = &ctx->posixLockCfg;

    ctx->nvmCfg.cb         = &nvmCb;
    ctx->nvmCfg.context    = &ctx->nvmFlashCtx;
    ctx->nvmCfg.config     = &ctx->nvmFlashCfg;
    ctx->nvmCfg.lockConfig = &ctx->lockCfg;

    rc = wh_Nvm_Init(&ctx->nvm, &ctx->nvmCfg);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("NVM init failed: %d\n", rc);
        return rc;
    }
    return WH_ERROR_OK;
}

static int kuInitPair(KuContext* ctx, int idx)
{
    KuPair* pair = &ctx->pairs[idx];
    int     rc;

    pair->idx    = idx;
    pair->shared = ctx;

    pair->tmConfig.req       = (whTransportMemCsr*)pair->reqBuf;
    pair->tmConfig.req_size  = sizeof(pair->reqBuf);
    pair->tmConfig.resp      = (whTransportMemCsr*)pair->respBuf;
    pair->tmConfig.resp_size = sizeof(pair->respBuf);

    memset(&pair->clientTransportCtx, 0, sizeof(pair->clientTransportCtx));
    pair->clientCommConfig.transport_cb      = &clientTransportCb;
    pair->clientCommConfig.transport_context = &pair->clientTransportCtx;
    pair->clientCommConfig.transport_config  = &pair->tmConfig;
    /* client_id must be in [1, WH_CLIENT_ID_MAX]; distinct per pair. */
    pair->clientCommConfig.client_id = (uint8_t)(1 + idx);
    pair->clientConfig.comm          = &pair->clientCommConfig;

    memset(&pair->serverTransportCtx, 0, sizeof(pair->serverTransportCtx));
    pair->serverCommConfig.transport_cb      = &serverTransportCb;
    pair->serverCommConfig.transport_context = &pair->serverTransportCtx;
    pair->serverCommConfig.transport_config  = &pair->tmConfig;
    pair->serverCommConfig.server_id         = (uint16_t)(200 + idx);

    rc = wc_InitRng_ex(pair->cryptoCtx.rng, NULL, INVALID_DEVID);
    if (rc != 0) {
        WH_ERROR_PRINT("RNG init failed for pair %d: %d\n", idx, rc);
        return rc;
    }

    /* All servers share the one locked NVM. */
    pair->serverConfig.comm_config = &pair->serverCommConfig;
    pair->serverConfig.nvm         = &ctx->nvm;
    pair->serverConfig.crypto      = &pair->cryptoCtx;
    pair->serverConfig.devId       = INVALID_DEVID;

    /* Init the client here (main thread) to avoid concurrent wolfCrypt
     * init/register from the worker threads. */
    rc = wh_Client_Init(&pair->client, &pair->clientConfig);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Client %d init failed: %d\n", idx, rc);
        wc_FreeRng(pair->cryptoCtx.rng);
        return rc;
    }
    return WH_ERROR_OK;
}

static void kuCleanupPair(KuPair* pair)
{
    wh_Client_Cleanup(&pair->client);
    wc_FreeRng(pair->cryptoCtx.rng);
}

/* Serve requests for one pair until stopFlag is set. */
static void* kuServerThread(void* arg)
{
    KuPair*    pair = (KuPair*)arg;
    KuContext* ctx  = pair->shared;
    int        rc;

    rc = wh_Server_Init(&pair->server, &pair->serverConfig);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Server %d init failed: %d\n", pair->idx, rc);
        KU_ATOMIC_STORE(&ctx->serverError, 1);
        KU_ATOMIC_ADD(&ctx->serversReady, 1);
        return NULL;
    }
    rc = wh_Server_SetConnected(&pair->server, WH_COMM_CONNECTED);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Server %d SetConnected failed: %d\n", pair->idx, rc);
        KU_ATOMIC_STORE(&ctx->serverError, 1);
        wh_Server_Cleanup(&pair->server);
        KU_ATOMIC_ADD(&ctx->serversReady, 1);
        return NULL;
    }

    /* Announce readiness; main waits for all servers before clients run. */
    KU_ATOMIC_ADD(&ctx->serversReady, 1);

    while (!KU_ATOMIC_LOAD(&ctx->stopFlag)) {
        rc = wh_Server_HandleRequestMessage(&pair->server);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
        /* Other per-request errors surface to the client as response codes. */
    }

    wh_Server_Cleanup(&pair->server);
    return NULL;
}

/* Per-round detector, run by client 0 once every keygen has landed. */
static void kuCheckRound(KuContext* ctx, int round)
{
    int i;
    int j;

    for (i = 0; i < KU_NUM_CLIENTS; i++) {
        int rc = ctx->roundRc[i];
        if (rc == WH_ERROR_OK) {
            KU_ATOMIC_ADD(&ctx->successes, 1);
        }
        else if (rc != WH_ERROR_NOSPACE) {
            /* NOSPACE is expected: the global id/cache space is finite under
             * contention. Any other failure invalidates the round. */
            KU_ATOMIC_ADD(&ctx->hardErrors, 1);
            WH_ERROR_PRINT("%s round %d: client %d keygen failed: %d\n",
                           ctx->algoName, round, i, rc);
        }
    }

    /* Two successful concurrent keygens must never auto-allocate the same
     * id. */
    for (i = 0; i < KU_NUM_CLIENTS; i++) {
        if (ctx->roundRc[i] != WH_ERROR_OK) {
            continue;
        }
        for (j = i + 1; j < KU_NUM_CLIENTS; j++) {
            if (ctx->roundRc[j] != WH_ERROR_OK) {
                continue;
            }
            if (ctx->roundIds[i] == ctx->roundIds[j]) {
                KU_ATOMIC_ADD(&ctx->collisions, 1);
                WH_ERROR_PRINT(
                    "%s round %d: id collision 0x%04X (clients %d and %d)\n",
                    ctx->algoName, round, (unsigned)ctx->roundIds[i], i, j);
            }
        }
    }
}

/* Run ctx->rounds barrier-aligned keygens for the current algorithm. */
static void* kuClientThread(void* arg)
{
    KuPair*    pair = (KuPair*)arg;
    KuContext* ctx  = pair->shared;
    int        round;

    for (round = 0; round < ctx->rounds; round++) {
        whKeyId id = WH_KEYID_ERASED;
        int     rc;

        /* Line all clients up so their id allocations overlap. */
        pthread_barrier_wait(&ctx->roundStart);

        rc                       = ctx->genFn(&pair->client, &id);
        ctx->roundRc[pair->idx]  = rc;
        ctx->roundIds[pair->idx] = (rc == WH_ERROR_OK) ? id : WH_KEYID_ERASED;

        /* All ids recorded before the detector reads them. */
        pthread_barrier_wait(&ctx->roundMid);

        if (pair->idx == 0) {
            kuCheckRound(ctx, round);
        }

        /* Drop this round's key so the next round starts from a clean cache
         * (best effort: a colliding id may already be gone). */
        if (rc == WH_ERROR_OK) {
            (void)wh_Client_KeyEvict(&pair->client, id);
        }

        /* Hold everyone until this round's keys are evicted. */
        pthread_barrier_wait(&ctx->roundEnd);
    }
    return NULL;
}

int whTest_KeygenUniqueIdConcurrent(void* ctx_arg)
{
    KuContext* ctx = &g_ku;
    int        i;
    int        a;
    int        rc;
    int        result         = WH_TEST_SUCCESS;
    int        serversUp      = 0;
    int        nvmInited      = 0;
    int        pairsInited    = 0;
    int        barriersInited = 0;

    (void)ctx_arg;

    if (KU_NUM_ALGOS == 0) {
        return WH_TEST_SKIPPED;
    }

    memset(ctx, 0, sizeof(*ctx));

    WH_TEST_PRINT("    Concurrent keygen unique-id: %d clients, %d algo(s)\n",
                  KU_NUM_CLIENTS, KU_NUM_ALGOS);

    rc = wolfCrypt_Init();
    if (rc != 0) {
        WH_ERROR_PRINT("wolfCrypt_Init failed: %d\n", rc);
        return rc;
    }

    rc = kuInitSharedNvm(ctx);
    if (rc != WH_ERROR_OK) {
        result = rc;
        goto out;
    }
    nvmInited = 1;

    for (i = 0; i < KU_NUM_CLIENTS; i++) {
        rc = kuInitPair(ctx, i);
        if (rc != WH_ERROR_OK) {
            result = rc;
            goto out;
        }
        pairsInited = i + 1;
    }

    /* Round barriers synchronize the client threads only. */
    if (pthread_barrier_init(&ctx->roundStart, NULL, KU_NUM_CLIENTS) != 0 ||
        pthread_barrier_init(&ctx->roundMid, NULL, KU_NUM_CLIENTS) != 0 ||
        pthread_barrier_init(&ctx->roundEnd, NULL, KU_NUM_CLIENTS) != 0) {
        WH_ERROR_PRINT("barrier init failed\n");
        result = WH_ERROR_ABORTED;
        goto out;
    }
    barriersInited = 1;

    /* Bring up the server threads and wait until all are connected. */
    for (i = 0; i < KU_NUM_CLIENTS; i++) {
        rc = pthread_create(&ctx->pairs[i].serverThread, NULL, kuServerThread,
                            &ctx->pairs[i]);
        if (rc != 0) {
            WH_ERROR_PRINT("server thread %d create failed: %d\n", i, rc);
            KU_ATOMIC_STORE(&ctx->stopFlag, 1);
            result = WH_ERROR_ABORTED;
            goto join_servers;
        }
        serversUp = i + 1;
    }
    while (KU_ATOMIC_LOAD(&ctx->serversReady) < serversUp) {
        sched_yield();
    }

    if (KU_ATOMIC_LOAD(&ctx->serverError)) {
        WH_ERROR_PRINT("a server failed to start\n");
        result = WH_ERROR_ABORTED;
        goto stop_servers;
    }

    /* Run each algorithm: spawn client threads, run all rounds, join. */
    for (a = 0; a < KU_NUM_ALGOS; a++) {
        /* Snapshot so the per-algorithm line reports deltas; the counters
         * stay cumulative for the final pass/fail check. */
        int okBefore         = KU_ATOMIC_LOAD(&ctx->successes);
        int collisionsBefore = KU_ATOMIC_LOAD(&ctx->collisions);

        ctx->genFn    = kuAlgos[a].gen;
        ctx->rounds   = kuAlgos[a].rounds;
        ctx->algoName = kuAlgos[a].name;
        memset((void*)ctx->roundIds, 0, sizeof(ctx->roundIds));
        memset((void*)ctx->roundRc, 0, sizeof(ctx->roundRc));

        for (i = 0; i < KU_NUM_CLIENTS; i++) {
            rc = pthread_create(&ctx->pairs[i].clientThread, NULL,
                                kuClientThread, &ctx->pairs[i]);
            if (rc != 0) {
                WH_ERROR_PRINT("client thread %d create failed: %d\n", i, rc);
                /* A short barrier party would hang the started clients; join
                 * them first, then abort. Creation failure is not expected. */
                result = WH_ERROR_ABORTED;
                for (--i; i >= 0; i--) {
                    pthread_join(ctx->pairs[i].clientThread, NULL);
                }
                goto stop_servers;
            }
        }
        for (i = 0; i < KU_NUM_CLIENTS; i++) {
            pthread_join(ctx->pairs[i].clientThread, NULL);
        }

        WH_TEST_PRINT(
            "    %-10s: %d rounds x %d clients, %d ok, %d collision(s)\n",
            kuAlgos[a].name, kuAlgos[a].rounds, KU_NUM_CLIENTS,
            KU_ATOMIC_LOAD(&ctx->successes) - okBefore,
            KU_ATOMIC_LOAD(&ctx->collisions) - collisionsBefore);
    }

stop_servers:
    KU_ATOMIC_STORE(&ctx->stopFlag, 1);

join_servers:
    for (i = 0; i < serversUp; i++) {
        pthread_join(ctx->pairs[i].serverThread, NULL);
    }

    if (result == WH_TEST_SUCCESS) {
        if (KU_ATOMIC_LOAD(&ctx->collisions) != 0) {
            WH_ERROR_PRINT("FAILED: %d unique-id collision(s) detected\n",
                           KU_ATOMIC_LOAD(&ctx->collisions));
            result = WH_ERROR_ABORTED;
        }
        else if (KU_ATOMIC_LOAD(&ctx->hardErrors) != 0) {
            WH_ERROR_PRINT("FAILED: %d keygen error(s) during the run\n",
                           KU_ATOMIC_LOAD(&ctx->hardErrors));
            result = WH_ERROR_ABORTED;
        }
    }

out:
    if (barriersInited) {
        pthread_barrier_destroy(&ctx->roundStart);
        pthread_barrier_destroy(&ctx->roundMid);
        pthread_barrier_destroy(&ctx->roundEnd);
    }
    for (i = 0; i < pairsInited; i++) {
        kuCleanupPair(&ctx->pairs[i]);
    }
    if (nvmInited) {
        pthread_mutexattr_destroy(&ctx->mutexAttr);
        wh_Nvm_Cleanup(&ctx->nvm);
    }
    wolfCrypt_Cleanup();

    return result;
}

#endif /* WH_KU_ENABLED */
