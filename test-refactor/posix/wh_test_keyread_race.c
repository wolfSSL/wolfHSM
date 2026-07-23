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
 * test-refactor/posix/wh_test_keyread_race.c
 *
 * Concurrent cached-key read test for the crypto request handlers.
 * KR_NUM_CLIENTS client/server pairs share one locked NVM, seeded with more
 * committed global AES keys than the shared cache has slots, so reads churn
 * the cache. Barrier-aligned clients have their server AES-ECB encrypt a
 * fixed block under a rotating key id and compare the result against a
 * software-AES oracle; a mismatch means the handler read the wrong key
 * material. Companion to wh_test_keygen_unique_id.c, which covers the write
 * side. Under TSAN (TSAN=1) unserialized cache accesses are additionally
 * reported as data races.
 */

#include "wolfhsm/wh_settings.h"

/* pthread_barrier_t is unavailable on macOS. AES-ECB with a server-cached
 * key is the operation under test, so gate on it too. */
#if defined(WOLFHSM_CFG_THREADSAFE) && defined(WOLFHSM_CFG_TEST_POSIX) &&     \
    defined(WOLFHSM_CFG_GLOBAL_KEYS) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO) &&  \
    !defined(NO_AES) && defined(HAVE_AES_ECB) && !defined(__APPLE__)
#define WH_KR_ENABLED
#endif

#include "wh_test_common.h"
#include "wh_test_list.h" /* WH_TEST_SKIPPED */
#include "wh_test_keyread_race.h"

#ifndef WH_KR_ENABLED

int whTest_KeyReadRace(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

#else /* WH_KR_ENABLED */

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
#include "wolfhsm/wh_common.h"

#include "port/posix/posix_lock.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/aes.h"

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

static int kr_SendRequest(void* c, uint16_t len, const void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    __tsan_release((void*)ctx->req);
    return wh_TransportMem_SendRequest(c, len, data);
}
static int kr_RecvResponse(void* c, uint16_t* out_len, void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    int                    rc  = wh_TransportMem_RecvResponse(c, out_len, data);
    if (rc == WH_ERROR_OK) {
        __tsan_acquire((void*)ctx->resp);
    }
    return rc;
}
static int kr_RecvRequest(void* c, uint16_t* out_len, void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    int                    rc  = wh_TransportMem_RecvRequest(c, out_len, data);
    if (rc == WH_ERROR_OK) {
        __tsan_acquire((void*)ctx->req);
    }
    return rc;
}
static int kr_SendResponse(void* c, uint16_t len, const void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    __tsan_release((void*)ctx->resp);
    return wh_TransportMem_SendResponse(c, len, data);
}

static const whTransportClientCb clientTransportCb = {
    .Init    = wh_TransportMem_InitClear,
    .Send    = kr_SendRequest,
    .Recv    = kr_RecvResponse,
    .Cleanup = wh_TransportMem_Cleanup,
};
static const whTransportServerCb serverTransportCb = {
    .Init    = wh_TransportMem_Init,
    .Recv    = kr_RecvRequest,
    .Send    = kr_SendResponse,
    .Cleanup = wh_TransportMem_Cleanup,
};

#else /* !WOLFHSM_CFG_TEST_STRESS_TSAN */

static const whTransportClientCb clientTransportCb = WH_TRANSPORT_MEM_CLIENT_CB;
static const whTransportServerCb serverTransportCb = WH_TRANSPORT_MEM_SERVER_CB;

#endif /* WOLFHSM_CFG_TEST_STRESS_TSAN */

#define KR_ATOMIC_LOAD(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define KR_ATOMIC_STORE(ptr, v) __atomic_store_n((ptr), (v), __ATOMIC_RELEASE)
#define KR_ATOMIC_ADD(ptr, v) __atomic_add_fetch((ptr), (v), __ATOMIC_ACQ_REL)

/* Four concurrent client/server pairs sharing one NVM. */
#define KR_NUM_CLIENTS 4

/* More keys than WOLFHSM_CFG_SERVER_KEYCACHE_COUNT slots, so reads race to
 * claim and reload slots, but within WOLFHSM_CFG_NVM_OBJECT_COUNT. */
#define KR_NUM_KEYS 24

/* AES-128; each key is a distinct constant byte, so any wrong key byte
 * changes the whole ciphertext block. */
#define KR_KEYSZ AES_128_KEY_SIZE

/* Rounds per client, each barrier-aligned so the server-side reads overlap. */
#define KR_ROUNDS 400

#define KR_FLASH_RAM_SIZE (1024 * 1024)
#define KR_FLASH_SECTOR_SIZE (128 * 1024)
#define KR_FLASH_PAGE_SIZE 8

#define KR_BUFFER_SIZE 4096

/* Distinct nonzero constant byte per key */
#define KR_KEYBYTE(i) ((uint8_t)(0x01 + (i)))
/* Server-internal id of the i-th seeded global key (ids start at 1). */
#define KR_SERVER_KEYID(i) \
    WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_KEYUSER_GLOBAL, (whNvmId)((i) + 1))
/* Client-facing id the client passes to reference that same global key. */
#define KR_CLIENT_KEYID(i) WH_CLIENT_KEYID_MAKE_GLOBAL((whKeyId)((i) + 1))

struct KrContext;

typedef struct {
    uint8_t              reqBuf[KR_BUFFER_SIZE];
    uint8_t              respBuf[KR_BUFFER_SIZE];
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

    struct KrContext* shared;
} KrPair;

typedef struct KrContext {
    /* Shared, locked NVM */
    uint8_t           flashMemory[KR_FLASH_RAM_SIZE];
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

    KrPair pairs[KR_NUM_CLIENTS];

    /* Fixed plaintext and its per-key software-AES ciphertext oracle */
    uint8_t plaintext[AES_BLOCK_SIZE];
    uint8_t expected[KR_NUM_KEYS][AES_BLOCK_SIZE];

    /* A readiness counter rather than a barrier, so a server that fails to
     * spawn does not hang the others. */
    volatile int serversReady;
    volatile int serverError;
    volatile int stopFlag;

    /* Per-round client synchronization */
    pthread_barrier_t roundStart;
    pthread_barrier_t roundEnd;

    /* Per-client outcome counters */
    volatile int mismatches[KR_NUM_CLIENTS];
    volatile int hardErrors[KR_NUM_CLIENTS];
    volatile int successes[KR_NUM_CLIENTS];
} KrContext;

/* The context is large (1 MB flash buffer); keep it off the thread stack. */
static KrContext g_kr;

static int krInitSharedNvm(KrContext* ctx)
{
    static whFlashCb flashCb = WH_FLASH_RAMSIM_CB;
    static whNvmCb   nvmCb   = WH_NVM_FLASH_CB;
    static whLockCb  lockCb  = POSIX_LOCK_CB;
    int              rc;

    memset(ctx->flashMemory, 0xFF, sizeof(ctx->flashMemory));

    ctx->flashCfg.size       = KR_FLASH_RAM_SIZE;
    ctx->flashCfg.sectorSize = KR_FLASH_SECTOR_SIZE;
    ctx->flashCfg.pageSize   = KR_FLASH_PAGE_SIZE;
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

/* Commit KR_NUM_KEYS distinct global AES keys straight to NVM (not the
 * cache), and compute the ciphertext each produces for the fixed plaintext. */
static int krSeedKeys(KrContext* ctx)
{
    uint8_t       data[KR_KEYSZ];
    whNvmMetadata meta;
    Aes           aes[1];
    int           i;
    int           rc;

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        ctx->plaintext[i] = (uint8_t)(0xA0 + i);
    }

    for (i = 0; i < KR_NUM_KEYS; i++) {
        memset(data, KR_KEYBYTE(i), sizeof(data));

        memset(&meta, 0, sizeof(meta));
        meta.id     = KR_SERVER_KEYID(i);
        meta.access = WH_NVM_ACCESS_ANY;
        meta.flags  = WH_NVM_FLAGS_USAGE_ANY;
        meta.len    = KR_KEYSZ;

        rc = wh_Nvm_AddObject(&ctx->nvm, &meta, sizeof(data), data);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("seed key %d add failed: %d\n", i, rc);
            return rc;
        }

        /* Independent software-AES oracle for this key. */
        rc = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (rc == 0) {
            rc = wc_AesSetKey(aes, data, sizeof(data), NULL, AES_ENCRYPTION);
        }
        if (rc == 0) {
            rc = wc_AesEcbEncrypt(aes, ctx->expected[i], ctx->plaintext,
                                  AES_BLOCK_SIZE);
        }
        (void)wc_AesFree(aes);
        if (rc != 0) {
            WH_ERROR_PRINT("oracle encrypt for key %d failed: %d\n", i, rc);
            return WH_ERROR_ABORTED;
        }
    }
    return WH_ERROR_OK;
}

static int krInitPair(KrContext* ctx, int idx)
{
    KrPair* pair = &ctx->pairs[idx];
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

static void krCleanupPair(KrPair* pair)
{
    wh_Client_Cleanup(&pair->client);
    wc_FreeRng(pair->cryptoCtx.rng);
}

/* Serve requests for one pair until stopFlag is set. */
static void* krServerThread(void* arg)
{
    KrPair*    pair = (KrPair*)arg;
    KrContext* ctx  = pair->shared;
    int        rc;

    rc = wh_Server_Init(&pair->server, &pair->serverConfig);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Server %d init failed: %d\n", pair->idx, rc);
        KR_ATOMIC_STORE(&ctx->serverError, 1);
        KR_ATOMIC_ADD(&ctx->serversReady, 1);
        return NULL;
    }
    rc = wh_Server_SetConnected(&pair->server, WH_COMM_CONNECTED);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Server %d SetConnected failed: %d\n", pair->idx, rc);
        KR_ATOMIC_STORE(&ctx->serverError, 1);
        wh_Server_Cleanup(&pair->server);
        KR_ATOMIC_ADD(&ctx->serversReady, 1);
        return NULL;
    }

    /* Announce readiness; main waits for all servers before clients run. */
    KR_ATOMIC_ADD(&ctx->serversReady, 1);

    while (!KR_ATOMIC_LOAD(&ctx->stopFlag)) {
        rc = wh_Server_HandleRequestMessage(&pair->server);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
        /* Other per-request errors surface to the client as response codes. */
    }

    wh_Server_Cleanup(&pair->server);
    return NULL;
}

/* Run KR_ROUNDS barrier-aligned AES-ECB encrypts against a rotating shared
 * global key, checking each ciphertext against the oracle. */
static void* krClientThread(void* arg)
{
    KrPair*    pair = (KrPair*)arg;
    KrContext* ctx  = pair->shared;
    int        round;

    for (round = 0; round < KR_ROUNDS; round++) {
        /* Rotate the key per client so all keys cycle through the shared
         * cache and evict one another. */
        int     keyIdx = (round * KR_NUM_CLIENTS + pair->idx) % KR_NUM_KEYS;
        whKeyId cid    = KR_CLIENT_KEYID(keyIdx);
        uint8_t out[AES_BLOCK_SIZE];
        Aes     aes[1];
        int     rc;

        memset(out, 0, sizeof(out));

        /* Line all clients up so their server-side reads overlap. */
        pthread_barrier_wait(&ctx->roundStart);

        /* INVALID_DEVID: the explicit client API is used instead of the
         * cryptocb, so the Aes struct only carries the key id. */
        rc = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (rc == 0) {
            rc = wh_Client_AesSetKeyId(aes, cid);
        }
        if (rc == 0) {
            rc = wh_Client_AesEcb(&pair->client, aes, 1, ctx->plaintext,
                                  AES_BLOCK_SIZE, out);
        }
        (void)wc_AesFree(aes);

        if (rc != 0) {
            /* Not a mismatch, but it invalidates the round. */
            KR_ATOMIC_ADD(&ctx->hardErrors[pair->idx], 1);
            WH_ERROR_PRINT("round %d: client %d ECB key 0x%04X failed: %d\n",
                           round, pair->idx, (unsigned)cid, rc);
        }
        else if (memcmp(out, ctx->expected[keyIdx], AES_BLOCK_SIZE) != 0) {
            /* Ciphertext for some other key: the server read the wrong key
             * material out of the shared cache. */
            KR_ATOMIC_ADD(&ctx->mismatches[pair->idx], 1);
            WH_ERROR_PRINT(
                "round %d: client %d key 0x%04X ciphertext mismatch\n", round,
                pair->idx, (unsigned)cid);
        }
        else {
            KR_ATOMIC_ADD(&ctx->successes[pair->idx], 1);
        }

        /* Hold everyone until every read in this round is done. */
        pthread_barrier_wait(&ctx->roundEnd);
    }
    return NULL;
}

int whTest_KeyReadRace(void* ctx_arg)
{
    KrContext* ctx = &g_kr;
    int        i;
    int        rc;
    int        result         = WH_TEST_SUCCESS;
    int        serversUp      = 0;
    int        nvmInited      = 0;
    int        pairsInited    = 0;
    int        barriersInited = 0;
    int        clientsStarted = 0;
    int        totalMiss      = 0;
    int        totalHard      = 0;
    int        totalSuccess   = 0;

    (void)ctx_arg;

    memset(ctx, 0, sizeof(*ctx));

    WH_TEST_PRINT("    Concurrent key read: %d clients, %d keys, %d rounds\n",
                  KR_NUM_CLIENTS, KR_NUM_KEYS, KR_ROUNDS);

    rc = wolfCrypt_Init();
    if (rc != 0) {
        WH_ERROR_PRINT("wolfCrypt_Init failed: %d\n", rc);
        return rc;
    }

    rc = krInitSharedNvm(ctx);
    if (rc != WH_ERROR_OK) {
        result = rc;
        goto out;
    }
    nvmInited = 1;

    rc = krSeedKeys(ctx);
    if (rc != WH_ERROR_OK) {
        result = rc;
        goto out;
    }

    for (i = 0; i < KR_NUM_CLIENTS; i++) {
        rc = krInitPair(ctx, i);
        if (rc != WH_ERROR_OK) {
            result = rc;
            goto out;
        }
        pairsInited = i + 1;
    }

    /* Round barriers synchronize the client threads only. */
    if (pthread_barrier_init(&ctx->roundStart, NULL, KR_NUM_CLIENTS) != 0 ||
        pthread_barrier_init(&ctx->roundEnd, NULL, KR_NUM_CLIENTS) != 0) {
        WH_ERROR_PRINT("barrier init failed\n");
        result = WH_ERROR_ABORTED;
        goto out;
    }
    barriersInited = 1;

    for (i = 0; i < KR_NUM_CLIENTS; i++) {
        rc = pthread_create(&ctx->pairs[i].serverThread, NULL, krServerThread,
                            &ctx->pairs[i]);
        if (rc != 0) {
            WH_ERROR_PRINT("server thread %d create failed: %d\n", i, rc);
            KR_ATOMIC_STORE(&ctx->stopFlag, 1);
            result = WH_ERROR_ABORTED;
            goto join_servers;
        }
        serversUp = i + 1;
    }
    while (KR_ATOMIC_LOAD(&ctx->serversReady) < serversUp) {
        sched_yield();
    }

    if (KR_ATOMIC_LOAD(&ctx->serverError)) {
        WH_ERROR_PRINT("a server failed to start\n");
        result = WH_ERROR_ABORTED;
        goto stop_servers;
    }

    for (i = 0; i < KR_NUM_CLIENTS; i++) {
        rc = pthread_create(&ctx->pairs[i].clientThread, NULL, krClientThread,
                            &ctx->pairs[i]);
        if (rc != 0) {
            WH_ERROR_PRINT("client thread %d create failed: %d\n", i, rc);
            /* A short barrier party would hang the started clients; join
             * them before aborting. */
            result = WH_ERROR_ABORTED;
            for (--i; i >= 0; i--) {
                pthread_join(ctx->pairs[i].clientThread, NULL);
            }
            goto stop_servers;
        }
        clientsStarted = i + 1;
    }
    for (i = 0; i < clientsStarted; i++) {
        pthread_join(ctx->pairs[i].clientThread, NULL);
    }

stop_servers:
    KR_ATOMIC_STORE(&ctx->stopFlag, 1);

join_servers:
    for (i = 0; i < serversUp; i++) {
        pthread_join(ctx->pairs[i].serverThread, NULL);
    }

    if (result == WH_TEST_SUCCESS) {
        for (i = 0; i < KR_NUM_CLIENTS; i++) {
            totalMiss += KR_ATOMIC_LOAD(&ctx->mismatches[i]);
            totalHard += KR_ATOMIC_LOAD(&ctx->hardErrors[i]);
            totalSuccess += KR_ATOMIC_LOAD(&ctx->successes[i]);
        }
        WH_TEST_PRINT("    reads=%d, mismatches=%d, hardErrors=%d\n",
                      totalSuccess, totalMiss, totalHard);
        if (totalMiss != 0) {
            WH_ERROR_PRINT("FAILED: %d ciphertext mismatch(es) detected\n",
                           totalMiss);
            result = WH_ERROR_ABORTED;
        }
        else if (totalHard != 0) {
            WH_ERROR_PRINT("FAILED: %d read error(s) during the run\n",
                           totalHard);
            result = WH_ERROR_ABORTED;
        }
    }

out:
    if (barriersInited) {
        pthread_barrier_destroy(&ctx->roundStart);
        pthread_barrier_destroy(&ctx->roundEnd);
    }
    for (i = 0; i < pairsInited; i++) {
        krCleanupPair(&ctx->pairs[i]);
    }
    if (nvmInited) {
        pthread_mutexattr_destroy(&ctx->mutexAttr);
        wh_Nvm_Cleanup(&ctx->nvm);
    }
    wolfCrypt_Cleanup();

    return result;
}

#endif /* WH_KR_ENABLED */
