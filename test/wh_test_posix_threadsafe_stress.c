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
 * test/wh_test_posix_threadsafe_stress.c
 *
 * POSIX-based phased contention test for thread safety validation.
 *
 * Intended to drive a high volume of concurrent requests across multiple
 * servers sharing a single NVM context, while running under TSAN to detect any
 * data races. Uses POSIX threading primitives (pthreads).
 *
 * Architecture:
 * - 1 shared NVM context with lock
 * - 4 server contexts sharing the NVM
 * - 4 client threads (all doing both NVM and keystore ops)
 * - Different contention phases to stress test contention patterns across
 *    various different APIs
 *
 * NOTE: Uses PTHREAD_MUTEX_ERRORCHECK attribute to trap undefined behavior
 * errors (EDEADLK for deadlock, EPERM for non-owner unlock) which indicate
 * bugs in the locking implementation.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_THREADSAFE) && defined(WOLFHSM_CFG_TEST_POSIX) &&     \
    defined(WOLFHSM_CFG_GLOBAL_KEYS) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_lock.h"
#include "wolfhsm/wh_keyid.h"

#include "port/posix/posix_lock.h"

#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wh_test_common.h"
#include "wh_test_posix_threadsafe_stress.h"


/*
 * TSAN Transport Shims
 *
 * These wrap the transport layer functions with acquire/release annotations
 * to tell TSAN about the happens-before relationship established by the
 * CSR handshake. This eliminates false positives on DMA buffer accesses
 * while still allowing TSAN to analyze keystore/NVM locking.
 */

#ifdef WOLFHSM_CFG_TEST_STRESS_TSAN

/* Provide a sane error message if we want to use TSAN but no TSAN detected.
 * GCC uses __SANITIZE_THREAD__, Clang uses __has_feature
 */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__SANITIZE_THREAD__) && !__has_feature(thread_sanitizer)
#error ThreadSanitizer not enabled for this build
#endif

#include <sanitizer/tsan_interface.h>

/* Client sends request - release all prior writes (including DMA buffers)
 * IMPORTANT: Release MUST happen BEFORE the send, not after. The transport's
 * notify counter synchronizes message delivery, but TSAN doesn't see it.
 * If we release after send, the server could acquire before we release,
 * breaking the happens-before chain for DMA buffer accesses. */
static int tsan_SendRequest(void* c, uint16_t len, const void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    __tsan_release((void*)ctx->req);
    return wh_TransportMem_SendRequest(c, len, data);
}

/* Client receives response - acquire all server writes */
static int tsan_RecvResponse(void* c, uint16_t* out_len, void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    int                    rc  = wh_TransportMem_RecvResponse(c, out_len, data);
    if (rc == WH_ERROR_OK) {
        __tsan_acquire((void*)ctx->resp);
    }
    return rc;
}

/* Server receives request - acquire all client writes (including DMA buffers)
 */
static int tsan_RecvRequest(void* c, uint16_t* out_len, void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    int                    rc  = wh_TransportMem_RecvRequest(c, out_len, data);
    if (rc == WH_ERROR_OK) {
        __tsan_acquire((void*)ctx->req);
    }
    return rc;
}

/* Server sends response - release all prior writes (including DMA write-backs)
 * IMPORTANT: Release MUST happen BEFORE the send (see tsan_SendRequest). */
static int tsan_SendResponse(void* c, uint16_t len, const void* data)
{
    whTransportMemContext* ctx = (whTransportMemContext*)c;
    __tsan_release((void*)ctx->resp);
    return wh_TransportMem_SendResponse(c, len, data);
}

/* TSAN-annotated transport callbacks */
static const whTransportClientCb clientTransportCb = {
    .Init    = wh_TransportMem_InitClear,
    .Send    = tsan_SendRequest,
    .Recv    = tsan_RecvResponse,
    .Cleanup = wh_TransportMem_Cleanup,
};

static const whTransportServerCb serverTransportCb = {
    .Init    = wh_TransportMem_Init,
    .Recv    = tsan_RecvRequest,
    .Send    = tsan_SendResponse,
    .Cleanup = wh_TransportMem_Cleanup,
};

#else /* !WOLFHSM_CFG_TEST_STRESS_TSAN */

/* Non-TSAN: use standard transport callbacks */
static const whTransportClientCb clientTransportCb = WH_TRANSPORT_MEM_CLIENT_CB;
static const whTransportServerCb serverTransportCb = WH_TRANSPORT_MEM_SERVER_CB;

#endif /* WOLFHSM_CFG_TEST_STRESS_TSAN */

/* Atomic helpers for C99 compatibility (GCC/Clang built-ins) */
#define ATOMIC_LOAD_INT(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define ATOMIC_STORE_INT(ptr, val) \
    __atomic_store_n((ptr), (val), __ATOMIC_RELEASE)
#define ATOMIC_ADD_INT(ptr, val) \
    __atomic_add_fetch((ptr), (val), __ATOMIC_ACQ_REL)

/* Test configuration */
#define NUM_CLIENTS 4
/* Allow external configuration of phase iterations */
#ifndef WOLFHSM_CFG_TEST_STRESS_PHASE_ITERATIONS
#define WOLFHSM_CFG_TEST_STRESS_PHASE_ITERATIONS 800
#endif
#define PHASE_ITERATIONS WOLFHSM_CFG_TEST_STRESS_PHASE_ITERATIONS

#define BUFFER_SIZE 4096
#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (128 * 1024)
#define FLASH_PAGE_SIZE 8
#define MAX_TEST_DURATION_SEC 300

/* NVM object parameters */
#define NVM_OBJECT_DATA_SIZE 64

/* Key parameters */
#define KEY_DATA_SIZE 32

/* Hot resources - all clients target these same IDs
 * NOTE: Use client-facing keyId format (simple ID + flags), NOT server-internal
 * format (WH_MAKE_KEYID). The server's wh_KeyId_TranslateFromClient() extracts
 * only the lower 8 bits as ID and checks WH_KEYID_CLIENT_GLOBAL_FLAG for
 * global. Using WH_MAKE_KEYID with user=1 sets bit 8, which is
 * WH_KEYID_CLIENT_GLOBAL_FLAG!
 *
 * We need separate key IDs for different test categories because:
 * - Revoked keys have NONMODIFIABLE flag and can't be erased or re-cached
 * - Each revoke-related phase needs its own key that won't be used elsewhere
 */
#define HOT_KEY_ID_GLOBAL WH_CLIENT_KEYID_MAKE_GLOBAL(1) /* ID=1, global */
#define HOT_KEY_ID_LOCAL 2                               /* ID=2, local */

/* Separate key IDs for revoke-related phases (can't be reused after revoke) */
#define REVOKE_CACHE_KEY_GLOBAL \
    WH_CLIENT_KEYID_MAKE_GLOBAL(10) /* ID=10, global */
#define REVOKE_CACHE_KEY_LOCAL 11   /* ID=11, local */
#define REVOKE_EXPORT_KEY_GLOBAL \
    WH_CLIENT_KEYID_MAKE_GLOBAL(12)                        /* ID=12, global */
#define REVOKE_EXPORT_KEY_LOCAL 13                         /* ID=13, local */
#define FRESHEN_KEY_GLOBAL WH_CLIENT_KEYID_MAKE_GLOBAL(14) /* ID=14, global */
#define FRESHEN_KEY_LOCAL 15                               /* ID=15, local */
#define HOT_NVM_ID ((whNvmId)100)
#define HOT_NVM_ID_2 ((whNvmId)101)
#define HOT_NVM_ID_3 ((whNvmId)102)
#define HOT_COUNTER_ID ((whNvmId)200)

/* ============================================================================
 * PHASE DEFINITIONS
 * ========================================================================== */

/* Contention phase enumeration */
typedef enum {
    /* Keystore phases */
    PHASE_KS_CONCURRENT_CACHE,
    PHASE_KS_CACHE_VS_EVICT,
    PHASE_KS_CACHE_VS_EXPORT,
    PHASE_KS_EVICT_VS_EXPORT,
    PHASE_KS_CACHE_VS_COMMIT,
    PHASE_KS_COMMIT_VS_EVICT,
    PHASE_KS_CONCURRENT_EXPORT,
    PHASE_KS_CONCURRENT_EVICT,

    /* NVM phases */
    PHASE_NVM_CONCURRENT_ADD,
    PHASE_NVM_ADD_VS_READ,
    PHASE_NVM_ADD_VS_DESTROY,
    PHASE_NVM_READ_VS_DESTROY,
    PHASE_NVM_CONCURRENT_READ,
    PHASE_NVM_LIST_DURING_MODIFY,
    PHASE_NVM_CONCURRENT_DESTROY,
    PHASE_NVM_READ_VS_RESIZE,    /* 2 read, 2 resize same object */
    PHASE_NVM_CONCURRENT_RESIZE, /* 4 threads resize same object */

    /* Cross-subsystem phases */
    PHASE_CROSS_COMMIT_VS_ADD,
    PHASE_CROSS_COMMIT_VS_DESTROY,
    PHASE_CROSS_FRESHEN_VS_MODIFY,

    /* Keystore - Erase/Revoke */
    PHASE_KS_ERASE_VS_CACHE,   /* 2 erase, 2 cache same key */
    PHASE_KS_ERASE_VS_EXPORT,  /* 2 erase, 2 export same key */
    PHASE_KS_REVOKE_VS_CACHE,  /* 2 revoke, 2 cache same key */
    PHASE_KS_REVOKE_VS_EXPORT, /* 2 revoke, 2 export same key */

    /* Keystore - GetUniqueId/Freshen */
    PHASE_KS_CONCURRENT_GETUNIQUEID, /* 4 threads request unique IDs */
    PHASE_KS_EXPLICIT_FRESHEN,       /* 4 threads freshen same uncached key */

    /* NVM - GetAvailable/GetMetadata/Reclaim */
    PHASE_NVM_ADD_WITH_RECLAIM, /* Fill NVM, concurrent adds trigger reclaim */
    PHASE_NVM_GETAVAILABLE_VS_ADD,    /* 2 query space, 2 add objects */
    PHASE_NVM_GETMETADATA_VS_DESTROY, /* 2 query metadata, 2 destroy */

    /* Counter */
    PHASE_COUNTER_CONCURRENT_INCREMENT, /* 4 threads increment same counter */
    PHASE_COUNTER_INCREMENT_VS_READ,    /* 2 increment, 2 read same counter */

#ifdef WOLFHSM_CFG_DMA
    /* DMA Operations */
    PHASE_KS_CACHE_DMA_VS_EXPORT,  /* 2 DMA cache, 2 regular export */
    PHASE_KS_EXPORT_DMA_VS_EVICT,  /* 2 DMA export, 2 evict */
    PHASE_NVM_ADD_DMA_VS_READ,     /* 2 DMA add, 2 regular read */
    PHASE_NVM_READ_DMA_VS_DESTROY, /* 2 DMA read, 2 destroy */
    PHASE_NVM_READ_DMA_VS_RESIZE,  /* 2 DMA read, 2 resize same object */
#endif

    PHASE_COUNT
} ContentionPhase;

/* Client role assignment per phase */
typedef enum {
    ROLE_OP_A, /* Perform operation A (e.g., Cache, Add) */
    ROLE_OP_B, /* Perform operation B (e.g., Evict, Read) */
} ClientRole;

/* Phase configuration */
typedef struct {
    ContentionPhase phase;
    const char*     name;
    int             iterations;
    ClientRole      roles[NUM_CLIENTS];
} PhaseConfig;

/* Phase configurations - all 18 phases */
static const PhaseConfig phases[] = {
    /* Keystore phases */
    {PHASE_KS_CONCURRENT_CACHE,
     "KS: Concurrent Cache",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},
    {PHASE_KS_CACHE_VS_EVICT,
     "KS: Cache vs Evict",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_KS_CACHE_VS_EXPORT,
     "KS: Cache vs Export",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_KS_EVICT_VS_EXPORT,
     "KS: Evict vs Export",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_KS_CACHE_VS_COMMIT,
     "KS: Cache vs Commit",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_KS_COMMIT_VS_EVICT,
     "KS: Commit vs Evict",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_KS_CONCURRENT_EXPORT,
     "KS: Concurrent Export",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},
    {PHASE_KS_CONCURRENT_EVICT,
     "KS: Concurrent Evict",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},

    /* NVM phases */
    {PHASE_NVM_CONCURRENT_ADD,
     "NVM: Concurrent Add",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},
    {PHASE_NVM_ADD_VS_READ,
     "NVM: Add vs Read",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_NVM_ADD_VS_DESTROY,
     "NVM: Add vs Destroy",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_NVM_READ_VS_DESTROY,
     "NVM: Read vs Destroy",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_NVM_CONCURRENT_READ,
     "NVM: Concurrent Read",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},
    {PHASE_NVM_LIST_DURING_MODIFY,
     "NVM: List During Modify",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_NVM_CONCURRENT_DESTROY,
     "NVM: Concurrent Destroy",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},

    /* Cross-subsystem phases */
    {PHASE_CROSS_COMMIT_VS_ADD,
     "Cross: Commit vs NVM Add",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_CROSS_COMMIT_VS_DESTROY,
     "Cross: Commit vs NVM Destroy",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_CROSS_FRESHEN_VS_MODIFY,
     "Cross: Export/Freshen vs NVM Modify",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},

    /* Keystore Erase/Revoke */
    {PHASE_KS_ERASE_VS_CACHE,
     "KS: Erase vs Cache",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_KS_ERASE_VS_EXPORT,
     "KS: Erase vs Export",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_KS_REVOKE_VS_CACHE,
     "KS: Revoke vs Cache",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_KS_REVOKE_VS_EXPORT,
     "KS: Revoke vs Export",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},

    /* Keystore GetUniqueId/Freshen */
    {PHASE_KS_CONCURRENT_GETUNIQUEID,
     "KS: Concurrent GetUniqueId",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},
    {PHASE_KS_EXPLICIT_FRESHEN,
     "KS: Explicit Freshen",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},

    /* NVM */
    {PHASE_NVM_ADD_WITH_RECLAIM,
     "NVM: Add With Reclaim",
     PHASE_ITERATIONS / 10,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},
    {PHASE_NVM_GETAVAILABLE_VS_ADD,
     "NVM: GetAvailable vs Add",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_NVM_GETMETADATA_VS_DESTROY,
     "NVM: GetMetadata vs Destroy",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_NVM_READ_VS_RESIZE,
     "NVM Read vs Resize",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},

    {PHASE_NVM_CONCURRENT_RESIZE,
     "NVM Concurrent Resize",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},

    /* Counter */
    {PHASE_COUNTER_CONCURRENT_INCREMENT,
     "Counter Concurrent Increment",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_A, ROLE_OP_A}},
    {PHASE_COUNTER_INCREMENT_VS_READ,
     "Counter Increment vs Read",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},

#ifdef WOLFHSM_CFG_DMA
    /* DMA Operations */
    {PHASE_KS_CACHE_DMA_VS_EXPORT,
     "KS: Cache DMA vs Export",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_KS_EXPORT_DMA_VS_EVICT,
     "KS: Export DMA vs Evict",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_NVM_ADD_DMA_VS_READ,
     "NVM: Add DMA vs Read",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_NVM_READ_DMA_VS_DESTROY,
     "NVM: Read DMA vs Destroy",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
    {PHASE_NVM_READ_DMA_VS_RESIZE,
     "NVM Read DMA vs Resize",
     PHASE_ITERATIONS,
     {ROLE_OP_A, ROLE_OP_A, ROLE_OP_B, ROLE_OP_B}},
#endif
};

/* ============================================================================
 * DATA STRUCTURES
 * ========================================================================== */

/* Forward declaration */
struct StressTestContext;

/* Per client-server pair configuration */
typedef struct {
    /* Transport buffers */
    uint8_t              reqBuf[BUFFER_SIZE];
    uint8_t              respBuf[BUFFER_SIZE];
    whTransportMemConfig tmConfig;

    /* Client side */
    whTransportMemClientContext clientTransportCtx;
    whCommClientConfig          clientCommConfig;
    whClientContext             client;
    whClientConfig              clientConfig;

    /* Server side */
    whTransportMemServerContext serverTransportCtx;
    whCommServerConfig          serverCommConfig;
    whServerContext             server;
    whServerConfig              serverConfig;

    /* Crypto context for this server */
    whServerCryptoContext cryptoCtx;

    /* Thread control */
    pthread_t    clientThread;
    pthread_t    serverThread;
    int          clientId;
    volatile int stopFlag;
    volatile int errorCount;
    volatile int iterationCount;

    /* Pointer back to shared context */
    struct StressTestContext* sharedCtx;

#ifdef WOLFHSM_CFG_DMA
    /* Per-client DMA buffers */
    uint8_t dmaKeyBuffer[KEY_DATA_SIZE];
    uint8_t dmaNvmBuffer[NVM_OBJECT_DATA_SIZE];
#endif
} ClientServerPair;

/* Shared test context */
typedef struct StressTestContext {
    /* Shared NVM */
    uint8_t           flashMemory[FLASH_RAM_SIZE];
    whFlashRamsimCtx  flashCtx;
    whFlashRamsimCfg  flashCfg;
    whNvmFlashContext nvmFlashCtx;
    whNvmFlashConfig  nvmFlashCfg;
    whNvmContext      nvm;
    whNvmConfig       nvmCfg;

    /* Lock for NVM */
    posixLockContext    nvmLockCtx;
    pthread_mutexattr_t mutexAttr;
    posixLockConfig     posixLockCfg;
    whLockConfig        lockCfg;

    /* Client-server pairs */
    ClientServerPair pairs[NUM_CLIENTS];

    /* Synchronization - initial start */
    pthread_barrier_t startBarrier;
    volatile int      globalStopFlag;

    /* Phase synchronization */
    pthread_barrier_t setupBarrier;
    pthread_barrier_t setupCompleteBarrier;
    pthread_barrier_t streamStartBarrier;
    pthread_barrier_t streamEndBarrier;

    /* Phase control */
    volatile int             phaseRunning;
    volatile ContentionPhase currentPhase;
    volatile whKeyId         currentKeyId;
    volatile ClientRole      clientRoles[NUM_CLIENTS];
} StressTestContext;

/* Forward declarations */
static void* serverThread(void* arg);
static void* contentionClientThread(void* arg);

/* ============================================================================
 * INITIALIZATION HELPERS
 * ========================================================================== */

static int initSharedNvm(StressTestContext* ctx)
{
    static whFlashCb flashCb = WH_FLASH_RAMSIM_CB;
    static whNvmCb   nvmCb   = WH_NVM_FLASH_CB;
    static whLockCb  lockCb  = POSIX_LOCK_CB;
    int              rc;

    /* Initialize flash memory */
    memset(ctx->flashMemory, 0xFF, sizeof(ctx->flashMemory));

    /* Configure flash simulator */
    ctx->flashCfg.size       = FLASH_RAM_SIZE;
    ctx->flashCfg.sectorSize = FLASH_SECTOR_SIZE;
    ctx->flashCfg.pageSize   = FLASH_PAGE_SIZE;
    ctx->flashCfg.erasedByte = 0xFF;
    ctx->flashCfg.memory     = ctx->flashMemory;

    /* Configure NVM flash layer */
    ctx->nvmFlashCfg.cb      = &flashCb;
    ctx->nvmFlashCfg.context = &ctx->flashCtx;
    ctx->nvmFlashCfg.config  = &ctx->flashCfg;

    /* Initialize NVM flash layer */
    rc = wh_NvmFlash_Init(&ctx->nvmFlashCtx, &ctx->nvmFlashCfg);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to initialize NVM flash: %d\n", rc);
        return rc;
    }

    /* Configure lock with error-checking mutex for better debugging */
    memset(&ctx->nvmLockCtx, 0, sizeof(ctx->nvmLockCtx));
    pthread_mutexattr_init(&ctx->mutexAttr);
    pthread_mutexattr_settype(&ctx->mutexAttr, PTHREAD_MUTEX_ERRORCHECK);
    ctx->posixLockCfg.attr = &ctx->mutexAttr;
    ctx->lockCfg.cb        = &lockCb;
    ctx->lockCfg.context   = &ctx->nvmLockCtx;
    ctx->lockCfg.config    = &ctx->posixLockCfg;

    /* Configure NVM with lock */
    ctx->nvmCfg.cb         = &nvmCb;
    ctx->nvmCfg.context    = &ctx->nvmFlashCtx;
    ctx->nvmCfg.config     = &ctx->nvmFlashCfg;
    ctx->nvmCfg.lockConfig = &ctx->lockCfg;

    /* Initialize NVM */
    rc = wh_Nvm_Init(&ctx->nvm, &ctx->nvmCfg);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to initialize NVM: %d\n", rc);
        return rc;
    }

    return WH_ERROR_OK;
}

static int initClientServerPair(StressTestContext* ctx, int pairIndex)
{
    ClientServerPair* pair = &ctx->pairs[pairIndex];
    int               rc;

    pair->clientId       = pairIndex;
    pair->sharedCtx      = ctx;
    pair->stopFlag       = 0;
    pair->errorCount     = 0;
    pair->iterationCount = 0;

    /* Configure transport memory */
    pair->tmConfig.req       = (whTransportMemCsr*)pair->reqBuf;
    pair->tmConfig.req_size  = sizeof(pair->reqBuf);
    pair->tmConfig.resp      = (whTransportMemCsr*)pair->respBuf;
    pair->tmConfig.resp_size = sizeof(pair->respBuf);

    /* Configure client transport */
    memset(&pair->clientTransportCtx, 0, sizeof(pair->clientTransportCtx));

    /* Configure client comm */
    pair->clientCommConfig.transport_cb      = &clientTransportCb;
    pair->clientCommConfig.transport_context = &pair->clientTransportCtx;
    pair->clientCommConfig.transport_config  = &pair->tmConfig;
    pair->clientCommConfig.client_id         = (uint16_t)(100 + pairIndex);

    /* Configure client */
    pair->clientConfig.comm = &pair->clientCommConfig;

    /* Configure server transport */
    memset(&pair->serverTransportCtx, 0, sizeof(pair->serverTransportCtx));

    /* Configure server comm */
    pair->serverCommConfig.transport_cb      = &serverTransportCb;
    pair->serverCommConfig.transport_context = &pair->serverTransportCtx;
    pair->serverCommConfig.transport_config  = &pair->tmConfig;
    pair->serverCommConfig.server_id         = (uint16_t)(200 + pairIndex);

    /* Configure crypto context */
    pair->cryptoCtx.devId = INVALID_DEVID;

    /* Initialize RNG for this server */
    rc = wc_InitRng_ex(pair->cryptoCtx.rng, NULL, pair->cryptoCtx.devId);
    if (rc != 0) {
        WH_ERROR_PRINT("Failed to init RNG for pair %d: %d\n", pairIndex, rc);
        return rc;
    }

    /* Configure server - all share the same NVM */
    pair->serverConfig.comm_config = &pair->serverCommConfig;
    pair->serverConfig.nvm         = &ctx->nvm;
    pair->serverConfig.crypto      = &pair->cryptoCtx;
    pair->serverConfig.devId       = INVALID_DEVID;

    return WH_ERROR_OK;
}

static void cleanupClientServerPair(ClientServerPair* pair)
{
    wc_FreeRng(pair->cryptoCtx.rng);
}

/* ============================================================================
 * SERVER THREAD
 * ========================================================================== */

static void* serverThread(void* arg)
{
    ClientServerPair*  pair = (ClientServerPair*)arg;
    StressTestContext* ctx  = pair->sharedCtx;
    int                rc;

    /* Initialize server */
    rc = wh_Server_Init(&pair->server, &pair->serverConfig);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Server %d init failed: %d\n", pair->clientId, rc);
        ATOMIC_ADD_INT(&pair->errorCount, 1);
        return NULL;
    }

    /* Set connected state */
    rc = wh_Server_SetConnected(&pair->server, WH_COMM_CONNECTED);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Server %d SetConnected failed: %d\n", pair->clientId,
                       rc);
        ATOMIC_ADD_INT(&pair->errorCount, 1);
        wh_Server_Cleanup(&pair->server);
        return NULL;
    }

    /* Wait for all threads to start */
    pthread_barrier_wait(&ctx->startBarrier);

    /* Process requests until stopped */
    while (!ATOMIC_LOAD_INT(&pair->stopFlag) &&
           !ATOMIC_LOAD_INT(&ctx->globalStopFlag)) {
        rc = wh_Server_HandleRequestMessage(&pair->server);

        if (rc == WH_ERROR_NOTREADY) {
            /* No request pending, yield CPU */
            sched_yield();
            continue;
        }

        /* Don't count server errors - they're expected during stress */
    }

    wh_Server_Cleanup(&pair->server);
    return NULL;
}

/* ============================================================================
 * CLIENT OPERATIONS
 * ========================================================================== */

static int doNvmAddObject(whClientContext* client, whNvmId id, int iteration)
{
    uint8_t data[NVM_OBJECT_DATA_SIZE];
    int32_t out_rc;
    int     rc;

    /* Fill data with pattern */
    memset(data, (uint8_t)(iteration & 0xFF), sizeof(data));

    /* Send request */
    rc = wh_Client_NvmAddObjectRequest(client, id, WH_NVM_ACCESS_ANY,
                                       WH_NVM_FLAGS_USAGE_ANY, 0, NULL,
                                       sizeof(data), data);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_NvmAddObjectResponse(client, &out_rc);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != WH_ERROR_OK) {
        return rc;
    }

    return out_rc;
}

static int doNvmRead(whClientContext* client, whNvmId id)
{
    uint8_t   data[NVM_OBJECT_DATA_SIZE];
    whNvmSize outSz = sizeof(data);
    int32_t   out_rc;
    int       rc;

    /* Send request */
    rc = wh_Client_NvmReadRequest(client, id, 0, sizeof(data));
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_NvmReadResponse(client, &out_rc, &outSz, data);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != WH_ERROR_OK) {
        return rc;
    }

    return out_rc;
}

static int doNvmList(whClientContext* client)
{
    whNvmId   outId;
    whNvmSize outCount;
    int32_t   out_rc;
    int       rc;

    /* Send request */
    rc = wh_Client_NvmListRequest(client, WH_NVM_ACCESS_ANY,
                                  WH_NVM_FLAGS_USAGE_ANY, 0);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_NvmListResponse(client, &out_rc, &outCount, &outId);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != WH_ERROR_OK) {
        return rc;
    }

    return out_rc;
}

static int doNvmDestroy(whClientContext* client, whNvmId id)
{
    int32_t out_rc;
    int     rc;

    /* Send request */
    rc = wh_Client_NvmDestroyObjectsRequest(client, 1, &id);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_NvmDestroyObjectsResponse(client, &out_rc);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != WH_ERROR_OK) {
        return rc;
    }

    return out_rc;
}

static int doNvmGetAvailable(whClientContext* client)
{
    uint32_t availSize;
    whNvmId  availObjects;
    uint32_t reclaimSize;
    whNvmId  reclaimObjects;
    int32_t  out_rc;
    int      rc;

    /* Send request */
    rc = wh_Client_NvmGetAvailableRequest(client);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_NvmGetAvailableResponse(client, &out_rc, &availSize,
                                               &availObjects, &reclaimSize,
                                               &reclaimObjects);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != WH_ERROR_OK) {
        return rc;
    }

    return out_rc;
}

static int doNvmGetMetadata(whClientContext* client, whNvmId id)
{
    whNvmId     outId;
    whNvmAccess outAccess;
    whNvmFlags  outFlags;
    whNvmSize   outLen;
    uint8_t     label[WH_NVM_LABEL_LEN];
    int32_t     out_rc;
    int         rc;

    /* Send request */
    rc = wh_Client_NvmGetMetadataRequest(client, id);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_NvmGetMetadataResponse(client, &out_rc, &outId,
                                              &outAccess, &outFlags, &outLen,
                                              sizeof(label), label);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != WH_ERROR_OK) {
        return rc;
    }

    return out_rc;
}

static int doKeyCache(whClientContext* client, whKeyId keyId, int iteration)
{
    uint8_t keyData[KEY_DATA_SIZE];
    uint8_t label[WH_NVM_LABEL_LEN];
    whKeyId outKeyId;
    int     rc;

    /* Fill key data with pattern */
    memset(keyData, (uint8_t)(iteration & 0xFF), sizeof(keyData));
    snprintf((char*)label, sizeof(label), "Key%04X", keyId);

    /* Send request */
    rc = wh_Client_KeyCacheRequest_ex(client, WH_NVM_FLAGS_USAGE_ANY, label,
                                      sizeof(label), keyData, sizeof(keyData),
                                      keyId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_KeyCacheResponse(client, &outKeyId);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doKeyExport(whClientContext* client, whKeyId keyId)
{
    uint8_t  keyData[KEY_DATA_SIZE];
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz = sizeof(label);
    uint16_t keySz   = sizeof(keyData);
    int      rc;

    /* Send request */
    rc = wh_Client_KeyExportRequest(client, keyId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_KeyExportResponse(client, label, labelSz, keyData,
                                         &keySz);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doKeyEvict(whClientContext* client, whKeyId keyId)
{
    int rc;

    /* Send request */
    rc = wh_Client_KeyEvictRequest(client, keyId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_KeyEvictResponse(client);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doKeyCommit(whClientContext* client, whKeyId keyId)
{
    int rc;

    /* Send request */
    rc = wh_Client_KeyCommitRequest(client, keyId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_KeyCommitResponse(client);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doKeyErase(whClientContext* client, whKeyId keyId)
{
    int rc;

    /* Send request */
    rc = wh_Client_KeyEraseRequest(client, keyId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_KeyEraseResponse(client);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doKeyRevoke(whClientContext* client, whKeyId keyId)
{
    int rc;

    /* Send request */
    rc = wh_Client_KeyRevokeRequest(client, keyId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_KeyRevokeResponse(client);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doCounterInit(whClientContext* client, whNvmId counterId,
                         uint32_t initialValue)
{
    uint32_t counter = 0;
    int      rc;

    /* Send request */
    rc = wh_Client_CounterInitRequest(client, counterId, initialValue);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_CounterInitResponse(client, &counter);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doCounterIncrement(whClientContext* client, whNvmId counterId,
                              uint32_t* out_counter)
{
    int rc;

    /* Send request */
    rc = wh_Client_CounterIncrementRequest(client, counterId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_CounterIncrementResponse(client, out_counter);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doCounterRead(whClientContext* client, whNvmId counterId,
                         uint32_t* out_counter)
{
    int rc;

    /* Send request */
    rc = wh_Client_CounterReadRequest(client, counterId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_CounterReadResponse(client, out_counter);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doCounterDestroy(whClientContext* client, whNvmId counterId)
{
    int rc;

    /* Send request */
    rc = wh_Client_CounterDestroyRequest(client, counterId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_CounterDestroyResponse(client);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

#ifdef WOLFHSM_CFG_DMA
static int doKeyCacheDma(ClientServerPair* pair, whKeyId keyId, int iteration)
{
    uint8_t label[WH_NVM_LABEL_LEN];
    whKeyId outKeyId;
    int     rc;

    /* Fill key data with pattern */
    memset(pair->dmaKeyBuffer, (uint8_t)(iteration & 0xFF),
           sizeof(pair->dmaKeyBuffer));
    snprintf((char*)label, sizeof(label), "DmaKey%04X", keyId);

    /* Send DMA request */
    rc = wh_Client_KeyCacheDmaRequest(&pair->client, 0, label, sizeof(label),
                                      pair->dmaKeyBuffer,
                                      sizeof(pair->dmaKeyBuffer), keyId);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_KeyCacheDmaResponse(&pair->client, &outKeyId);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doKeyExportDma(ClientServerPair* pair, whKeyId keyId)
{
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t outSz;
    int      rc;

    /* Send DMA request - provide buffer for DMA export */
    rc = wh_Client_KeyExportDmaRequest(&pair->client, keyId, pair->dmaKeyBuffer,
                                       sizeof(pair->dmaKeyBuffer));
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_KeyExportDmaResponse(&pair->client, label, sizeof(label),
                                            &outSz);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

static int doNvmAddObjectDma(ClientServerPair* pair, whNvmId id, int iteration)
{
    whNvmMetadata meta;
    int32_t       out_rc;
    int           rc;

    /* Fill DMA buffer with pattern */
    memset(pair->dmaNvmBuffer, (uint8_t)(iteration & 0xFF),
           sizeof(pair->dmaNvmBuffer));

    /* Set up metadata */
    memset(&meta, 0, sizeof(meta));
    meta.id     = id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_USAGE_ANY;
    meta.len    = sizeof(pair->dmaNvmBuffer);

    /* Send DMA request */
    rc = wh_Client_NvmAddObjectDmaRequest(
        &pair->client, &meta, sizeof(pair->dmaNvmBuffer), pair->dmaNvmBuffer);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_NvmAddObjectDmaResponse(&pair->client, &out_rc);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != WH_ERROR_OK) {
        return rc;
    }

    return out_rc;
}

static int doNvmReadDma(ClientServerPair* pair, whNvmId id)
{
    int32_t out_rc;
    int     rc;

    /* Send DMA request */
    rc = wh_Client_NvmReadDmaRequest(
        &pair->client, id, 0, sizeof(pair->dmaNvmBuffer), pair->dmaNvmBuffer);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Wait for response from server thread */
    do {
        rc = wh_Client_NvmReadDmaResponse(&pair->client, &out_rc);
        if (rc == WH_ERROR_NOTREADY) {
            sched_yield();
        }
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != WH_ERROR_OK) {
        return rc;
    }

    return out_rc;
}
#endif /* WOLFHSM_CFG_DMA */

/* ============================================================================
 * PHASE SETUP
 * ========================================================================== */

static int doPhaseSetup(ClientServerPair* pair, ContentionPhase phase,
                        whKeyId keyId)
{
    whClientContext* client = &pair->client;
    int              rc;

    switch (phase) {
        /* Keystore phases that need clean state (evict first) */
        case PHASE_KS_CONCURRENT_CACHE:
            rc = doKeyEvict(client, keyId);
            /* Ignore NOTFOUND - key might not exist */
            if (rc == WH_ERROR_NOTFOUND)
                rc = WH_ERROR_OK;
            return rc;

        /* Keystore phases that need key to exist (cache first) */
        case PHASE_KS_CACHE_VS_EVICT:
        case PHASE_KS_CACHE_VS_EXPORT:
        case PHASE_KS_EVICT_VS_EXPORT:
        case PHASE_KS_CACHE_VS_COMMIT:
        case PHASE_KS_COMMIT_VS_EVICT:
        case PHASE_KS_CONCURRENT_EXPORT:
        case PHASE_KS_CONCURRENT_EVICT:
            return doKeyCache(client, keyId, 0);

        /* NVM phases that need clean state (destroy first) */
        case PHASE_NVM_CONCURRENT_ADD:
            rc = doNvmDestroy(client, HOT_NVM_ID);
            if (rc == WH_ERROR_NOTFOUND)
                rc = WH_ERROR_OK;
            return rc;

        /* NVM phases that need object to exist (add first) */
        case PHASE_NVM_ADD_VS_READ:
        case PHASE_NVM_ADD_VS_DESTROY:
        case PHASE_NVM_READ_VS_DESTROY:
        case PHASE_NVM_CONCURRENT_READ:
        case PHASE_NVM_CONCURRENT_DESTROY:
            /* First destroy any existing object to make space */
            (void)doNvmDestroy(client, HOT_NVM_ID);
            return doNvmAddObject(client, HOT_NVM_ID, 0);

        /* List during modify needs multiple objects */
        case PHASE_NVM_LIST_DURING_MODIFY:
            rc = doNvmAddObject(client, HOT_NVM_ID, 0);
            if (rc != WH_ERROR_OK && rc != WH_ERROR_NOSPACE)
                return rc;
            rc = doNvmAddObject(client, HOT_NVM_ID_2, 0);
            if (rc != WH_ERROR_OK && rc != WH_ERROR_NOSPACE)
                return rc;
            rc = doNvmAddObject(client, HOT_NVM_ID_3, 0);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

        /* Cross-subsystem: cache key AND add NVM object */
        case PHASE_CROSS_COMMIT_VS_ADD:
        case PHASE_CROSS_COMMIT_VS_DESTROY:
            rc = doKeyCache(client, keyId, 0);
            if (rc != WH_ERROR_OK)
                return rc;
            rc = doNvmAddObject(client, HOT_NVM_ID, 0);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

        /* Freshen test: commit key to NVM, then evict from cache */
        case PHASE_CROSS_FRESHEN_VS_MODIFY:
            rc = doKeyCache(client, keyId, 0);
            if (rc != WH_ERROR_OK)
                return rc;
            rc = doKeyCommit(client, keyId);
            if (rc != WH_ERROR_OK && rc != WH_ERROR_NOSPACE)
                return rc;
            rc = doKeyEvict(client, keyId);
            if (rc != WH_ERROR_OK && rc != WH_ERROR_NOTFOUND)
                return rc;
            /* Add NVM object for the NVM modify operations */
            rc = doNvmAddObject(client, HOT_NVM_ID, 0);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

        /* Erase phases: cache key, commit to NVM (erase needs both) */
        case PHASE_KS_ERASE_VS_CACHE:
        case PHASE_KS_ERASE_VS_EXPORT:
            rc = doKeyCache(client, keyId, 0);
            if (rc != WH_ERROR_OK)
                return rc;
            rc = doKeyCommit(client, keyId);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

        /* Revoke phases: cache key, commit to NVM
         * Each revoke phase uses a unique key ID (see selectKeyIdForPhase)
         * because revoked keys have NONMODIFIABLE flag and can't be erased */
        case PHASE_KS_REVOKE_VS_CACHE:
        case PHASE_KS_REVOKE_VS_EXPORT:
            rc = doKeyCache(client, keyId, 0);
            if (rc != WH_ERROR_OK)
                return rc;
            rc = doKeyCommit(client, keyId);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

        /* GetUniqueId: no setup needed */
        case PHASE_KS_CONCURRENT_GETUNIQUEID:
            return WH_ERROR_OK;

        /* Explicit freshen: evict any existing key, cache, commit, then evict
         * The initial evict makes room in cache. NOSPACE is tolerated because
         * NVM may be full from revoke phases - test still runs testing NOTFOUND
         */
        case PHASE_KS_EXPLICIT_FRESHEN:
            /* Evict first to make room if key already cached */
            (void)doKeyEvict(client, keyId);
            rc = doKeyCache(client, keyId, 0);
            /* NOSPACE is OK - NVM may be full from revoke phases */
            if (rc != WH_ERROR_OK && rc != WH_ERROR_NOSPACE)
                return rc;
            if (rc == WH_ERROR_OK) {
                rc = doKeyCommit(client, keyId);
                if (rc != WH_ERROR_OK && rc != WH_ERROR_NOSPACE)
                    return rc;
                rc = doKeyEvict(client, keyId);
                if (rc == WH_ERROR_NOTFOUND)
                    rc = WH_ERROR_OK;
            }
            else {
                rc = WH_ERROR_OK; /* Tolerate NOSPACE */
            }
            return rc;

        /* Add with reclaim: fill NVM with objects to trigger reclaim */
        case PHASE_NVM_ADD_WITH_RECLAIM: {
            int i;
            /* Add 10 objects to fill up NVM and trigger reclaim during test */
            for (i = 0; i < 10; i++) {
                rc = doNvmAddObject(client, (whNvmId)(HOT_NVM_ID + i), 0);
                if (rc != WH_ERROR_OK && rc != WH_ERROR_NOSPACE)
                    return rc;
            }
            return WH_ERROR_OK;
        }

        /* GetAvailable vs Add: add one object */
        case PHASE_NVM_GETAVAILABLE_VS_ADD:
            (void)doNvmDestroy(client, HOT_NVM_ID);
            rc = doNvmAddObject(client, HOT_NVM_ID, 0);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

        /* GetMetadata vs Destroy: destroy then add object */
        case PHASE_NVM_GETMETADATA_VS_DESTROY:
            (void)doNvmDestroy(client, HOT_NVM_ID);
            rc = doNvmAddObject(client, HOT_NVM_ID, 0);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

        /* Counter phases - create counter with initial value 0 */
        case PHASE_COUNTER_CONCURRENT_INCREMENT:
        case PHASE_COUNTER_INCREMENT_VS_READ:
            /* Destroy any existing counter first */
            (void)doCounterDestroy(client, HOT_COUNTER_ID);
            /* Initialize counter with value 0 */
            rc = doCounterInit(client, HOT_COUNTER_ID, 0);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

        /* NVM Read vs Resize - create object with initial size */
        case PHASE_NVM_READ_VS_RESIZE:
        case PHASE_NVM_CONCURRENT_RESIZE:
            /* Destroy any existing object first */
            (void)doNvmDestroy(client, HOT_NVM_ID);
            /* Create object with initial size (64 bytes) */
            rc = doNvmAddObject(client, HOT_NVM_ID, 0);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

#ifdef WOLFHSM_CFG_DMA
        /* DMA phases: evict first to make room in cache, tolerate NOSPACE
         * (cache may be full from earlier phases like GetUniqueId) */
        case PHASE_KS_CACHE_DMA_VS_EXPORT:
        case PHASE_KS_EXPORT_DMA_VS_EVICT:
            /* Evict first to make room if key already cached */
            (void)doKeyEvict(client, keyId);
            rc = doKeyCache(client, keyId, 0);
            /* NOSPACE is OK - cache may be full from earlier phases */
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;

        case PHASE_NVM_ADD_DMA_VS_READ:
            (void)doNvmDestroy(client, HOT_NVM_ID);
            return doNvmAddObject(client, HOT_NVM_ID, 0);

        case PHASE_NVM_READ_DMA_VS_DESTROY:
            (void)doNvmDestroy(client, HOT_NVM_ID);
            return doNvmAddObject(client, HOT_NVM_ID, 0);

        /* NVM Read DMA vs Resize */
        case PHASE_NVM_READ_DMA_VS_RESIZE:
            (void)doNvmDestroy(client, HOT_NVM_ID);
            rc = doNvmAddObject(client, HOT_NVM_ID, 0);
            if (rc == WH_ERROR_NOSPACE)
                rc = WH_ERROR_OK;
            return rc;
#endif

        default:
            return WH_ERROR_OK;
    }
}

/* ============================================================================
 * PHASE OPERATION DISPATCH
 * ========================================================================== */

static int executePhaseOperation(ClientServerPair* pair, ContentionPhase phase,
                                 ClientRole role, int iteration, whKeyId keyId)
{
    whClientContext* client = &pair->client;

    switch (phase) {
        /* Keystore phases */
        case PHASE_KS_CONCURRENT_CACHE:
            return doKeyCache(client, keyId, iteration);

        case PHASE_KS_CACHE_VS_EVICT:
            if (role == ROLE_OP_A)
                return doKeyCache(client, keyId, iteration);
            else
                return doKeyEvict(client, keyId);

        case PHASE_KS_CACHE_VS_EXPORT:
            if (role == ROLE_OP_A)
                return doKeyCache(client, keyId, iteration);
            else
                return doKeyExport(client, keyId);

        case PHASE_KS_EVICT_VS_EXPORT:
            if (role == ROLE_OP_A)
                return doKeyEvict(client, keyId);
            else
                return doKeyExport(client, keyId);

        case PHASE_KS_CACHE_VS_COMMIT:
            if (role == ROLE_OP_A)
                return doKeyCache(client, keyId, iteration);
            else
                return doKeyCommit(client, keyId);

        case PHASE_KS_COMMIT_VS_EVICT:
            if (role == ROLE_OP_A)
                return doKeyCommit(client, keyId);
            else
                return doKeyEvict(client, keyId);

        case PHASE_KS_CONCURRENT_EXPORT:
            return doKeyExport(client, keyId);

        case PHASE_KS_CONCURRENT_EVICT:
            return doKeyEvict(client, keyId);

        /* NVM phases */
        case PHASE_NVM_CONCURRENT_ADD:
            return doNvmAddObject(client, HOT_NVM_ID, iteration);

        case PHASE_NVM_ADD_VS_READ:
            if (role == ROLE_OP_A)
                return doNvmAddObject(client, HOT_NVM_ID, iteration);
            else
                return doNvmRead(client, HOT_NVM_ID);

        case PHASE_NVM_ADD_VS_DESTROY:
            if (role == ROLE_OP_A)
                return doNvmAddObject(client, HOT_NVM_ID, iteration);
            else
                return doNvmDestroy(client, HOT_NVM_ID);

        case PHASE_NVM_READ_VS_DESTROY:
            if (role == ROLE_OP_A)
                return doNvmRead(client, HOT_NVM_ID);
            else
                return doNvmDestroy(client, HOT_NVM_ID);

        case PHASE_NVM_CONCURRENT_READ:
            return doNvmRead(client, HOT_NVM_ID);

        case PHASE_NVM_LIST_DURING_MODIFY:
            if (role == ROLE_OP_A) {
                /* Alternate between add and destroy */
                if (iteration % 2 == 0)
                    return doNvmAddObject(client, HOT_NVM_ID, iteration);
                else
                    return doNvmDestroy(client, HOT_NVM_ID);
            }
            else {
                return doNvmList(client);
            }

        case PHASE_NVM_CONCURRENT_DESTROY:
            return doNvmDestroy(client, HOT_NVM_ID);

        /* Cross-subsystem phases */
        case PHASE_CROSS_COMMIT_VS_ADD:
            if (role == ROLE_OP_A)
                return doKeyCommit(client, keyId);
            else
                return doNvmAddObject(client, HOT_NVM_ID, iteration);

        case PHASE_CROSS_COMMIT_VS_DESTROY:
            if (role == ROLE_OP_A)
                return doKeyCommit(client, keyId);
            else
                return doNvmDestroy(client, HOT_NVM_ID);

        case PHASE_CROSS_FRESHEN_VS_MODIFY:
            if (role == ROLE_OP_A) {
                /* Export triggers freshen from NVM if not in cache */
                return doKeyExport(client, keyId);
            }
            else {
                /* Modify NVM while freshen might be happening */
                if (iteration % 2 == 0)
                    return doNvmAddObject(client, HOT_NVM_ID, iteration);
                else
                    return doNvmDestroy(client, HOT_NVM_ID);
            }

        /* Erase vs Cache */
        case PHASE_KS_ERASE_VS_CACHE:
            if (role == ROLE_OP_A)
                return doKeyErase(client, keyId);
            else
                return doKeyCache(client, keyId, iteration);

        /* Erase vs Export */
        case PHASE_KS_ERASE_VS_EXPORT:
            if (role == ROLE_OP_A)
                return doKeyErase(client, keyId);
            else
                return doKeyExport(client, keyId);

        /* Revoke vs Cache */
        case PHASE_KS_REVOKE_VS_CACHE:
            if (role == ROLE_OP_A)
                return doKeyRevoke(client, keyId);
            else
                return doKeyCache(client, keyId, iteration);

        /* Revoke vs Export */
        case PHASE_KS_REVOKE_VS_EXPORT:
            if (role == ROLE_OP_A)
                return doKeyRevoke(client, keyId);
            else
                return doKeyExport(client, keyId);

        /* Concurrent GetUniqueId: all threads request fresh keys via cache with
         * ERASED */
        case PHASE_KS_CONCURRENT_GETUNIQUEID:
            return doKeyCache(client, WH_KEYID_ERASED, iteration);

        /* Explicit Freshen: all threads export (triggers freshen from NVM) */
        case PHASE_KS_EXPLICIT_FRESHEN:
            return doKeyExport(client, keyId);

        /* Add With Reclaim: all threads add unique objects to trigger reclaim
         */
        case PHASE_NVM_ADD_WITH_RECLAIM:
            /* Use client ID and iteration to create unique object IDs */
            return doNvmAddObject(client,
                                  (whNvmId)(HOT_NVM_ID + 10 +
                                            (pair->clientId * 1000) +
                                            iteration),
                                  iteration);

        /* GetAvailable vs Add */
        case PHASE_NVM_GETAVAILABLE_VS_ADD:
            if (role == ROLE_OP_A)
                return doNvmGetAvailable(client);
            else
                return doNvmAddObject(client, HOT_NVM_ID, iteration);

        /* GetMetadata vs Destroy */
        case PHASE_NVM_GETMETADATA_VS_DESTROY:
            if (role == ROLE_OP_A)
                return doNvmGetMetadata(client, HOT_NVM_ID);
            else
                return doNvmDestroy(client, HOT_NVM_ID);

        /* Counter Concurrent Increment */
        case PHASE_COUNTER_CONCURRENT_INCREMENT: {
            uint32_t counter = 0;
            return doCounterIncrement(client, HOT_COUNTER_ID, &counter);
        }

        /* Counter Increment vs Read */
        case PHASE_COUNTER_INCREMENT_VS_READ: {
            uint32_t counter = 0;
            if (role == ROLE_OP_A)
                return doCounterIncrement(client, HOT_COUNTER_ID, &counter);
            else
                return doCounterRead(client, HOT_COUNTER_ID, &counter);
        }

        /* NVM Read vs Resize - alternating object sizes */
        case PHASE_NVM_READ_VS_RESIZE:
            if (role == ROLE_OP_A) {
                /* Read operation */
                return doNvmRead(client, HOT_NVM_ID);
            }
            else {
                /* Resize operation: destroy and re-add with different size
                 * Alternate between 64 bytes (full) and 32 bytes (half) */
                int       rc;
                uint8_t   data[NVM_OBJECT_DATA_SIZE];
                int32_t   out_rc;
                whNvmSize newSize = (iteration % 2 == 0)
                                        ? NVM_OBJECT_DATA_SIZE
                                        : (NVM_OBJECT_DATA_SIZE / 2);

                /* Destroy existing object */
                (void)doNvmDestroy(client, HOT_NVM_ID);

                /* Re-add with new size */
                memset(data, (uint8_t)(iteration & 0xFF), newSize);
                rc = wh_Client_NvmAddObjectRequest(
                    client, HOT_NVM_ID, WH_NVM_ACCESS_ANY,
                    WH_NVM_FLAGS_USAGE_ANY, 0, NULL, newSize, data);
                if (rc != WH_ERROR_OK) {
                    return rc;
                }

                do {
                    rc = wh_Client_NvmAddObjectResponse(client, &out_rc);
                    if (rc == WH_ERROR_NOTREADY) {
                        sched_yield();
                    }
                } while (rc == WH_ERROR_NOTREADY);

                return (rc == WH_ERROR_OK) ? out_rc : rc;
            }

        /* NVM Concurrent Resize */
        case PHASE_NVM_CONCURRENT_RESIZE: {
            /* All threads resize: destroy and re-add with different size */
            int       rc;
            uint8_t   data[NVM_OBJECT_DATA_SIZE];
            int32_t   out_rc;
            whNvmSize newSize = (iteration % 2 == 0)
                                    ? NVM_OBJECT_DATA_SIZE
                                    : (NVM_OBJECT_DATA_SIZE / 2);

            /* Destroy existing object */
            (void)doNvmDestroy(client, HOT_NVM_ID);

            /* Re-add with new size */
            memset(data, (uint8_t)(iteration & 0xFF), newSize);
            rc = wh_Client_NvmAddObjectRequest(
                client, HOT_NVM_ID, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_USAGE_ANY,
                0, NULL, newSize, data);
            if (rc != WH_ERROR_OK) {
                return rc;
            }

            do {
                rc = wh_Client_NvmAddObjectResponse(client, &out_rc);
                if (rc == WH_ERROR_NOTREADY) {
                    sched_yield();
                }
            } while (rc == WH_ERROR_NOTREADY);

            return (rc == WH_ERROR_OK) ? out_rc : rc;
        }

#ifdef WOLFHSM_CFG_DMA
        /* DMA: Cache DMA vs Export */
        case PHASE_KS_CACHE_DMA_VS_EXPORT:
            if (role == ROLE_OP_A)
                return doKeyCacheDma(pair, keyId, iteration);
            else
                return doKeyExport(client, keyId);

        /* DMA: Export DMA vs Evict */
        case PHASE_KS_EXPORT_DMA_VS_EVICT:
            if (role == ROLE_OP_A)
                return doKeyExportDma(pair, keyId);
            else
                return doKeyEvict(client, keyId);

        /* DMA: Add DMA vs Read */
        case PHASE_NVM_ADD_DMA_VS_READ:
            if (role == ROLE_OP_A)
                return doNvmAddObjectDma(pair, HOT_NVM_ID, iteration);
            else
                return doNvmRead(client, HOT_NVM_ID);

        /* DMA: Read DMA vs Destroy */
        case PHASE_NVM_READ_DMA_VS_DESTROY:
            if (role == ROLE_OP_A)
                return doNvmReadDma(pair, HOT_NVM_ID);
            else
                return doNvmDestroy(client, HOT_NVM_ID);

        /* NVM Read DMA vs Resize */
        case PHASE_NVM_READ_DMA_VS_RESIZE:
            if (role == ROLE_OP_A) {
                /* DMA Read operation */
                return doNvmReadDma(pair, HOT_NVM_ID);
            }
            else {
                /* Resize operation: destroy and re-add with different size */
                int           rc;
                uint8_t       data[NVM_OBJECT_DATA_SIZE];
                int32_t       out_rc;
                whNvmSize     newSize = (iteration % 2 == 0)
                                            ? NVM_OBJECT_DATA_SIZE
                                            : (NVM_OBJECT_DATA_SIZE / 2);
                whNvmMetadata meta;

                /* Destroy existing object */
                (void)doNvmDestroy(client, HOT_NVM_ID);

                /* Re-add with new size */
                memset(data, (uint8_t)(iteration & 0xFF), newSize);
                memset(&meta, 0, sizeof(meta));
                meta.id     = HOT_NVM_ID;
                meta.access = WH_NVM_ACCESS_ANY;
                meta.flags  = WH_NVM_FLAGS_USAGE_ANY;
                meta.len    = newSize;

                rc = wh_Client_NvmAddObjectRequest(
                    client, HOT_NVM_ID, WH_NVM_ACCESS_ANY,
                    WH_NVM_FLAGS_USAGE_ANY, 0, NULL, newSize, data);
                if (rc != WH_ERROR_OK) {
                    return rc;
                }

                do {
                    rc = wh_Client_NvmAddObjectResponse(client, &out_rc);
                    if (rc == WH_ERROR_NOTREADY) {
                        sched_yield();
                    }
                } while (rc == WH_ERROR_NOTREADY);

                return (rc == WH_ERROR_OK) ? out_rc : rc;
            }
#endif

        default:
            return WH_ERROR_OK;
    }
}

/* ============================================================================
 * RESULT VALIDATION
 * ========================================================================== */

static int isAcceptableResult(ContentionPhase phase, int rc)
{
    /* Always acceptable */
    if (rc == WH_ERROR_OK)
        return 1;

    switch (phase) {
        /* Cache operations: NOSPACE acceptable (cache full) */
        case PHASE_KS_CONCURRENT_CACHE:
        case PHASE_KS_CACHE_VS_EVICT:
        case PHASE_KS_CACHE_VS_EXPORT:
        case PHASE_KS_CACHE_VS_COMMIT:
            return (rc == WH_ERROR_NOSPACE || rc == WH_ERROR_NOTFOUND);

        /* Evict/Export: NOTFOUND acceptable (already evicted) */
        case PHASE_KS_EVICT_VS_EXPORT:
        case PHASE_KS_COMMIT_VS_EVICT:
        case PHASE_KS_CONCURRENT_EVICT:
        case PHASE_KS_CONCURRENT_EXPORT:
            return (rc == WH_ERROR_NOTFOUND || rc == WH_ERROR_NOSPACE);

        /* NVM Add: NOSPACE acceptable */
        case PHASE_NVM_CONCURRENT_ADD:
        case PHASE_NVM_ADD_VS_READ:
        case PHASE_NVM_ADD_VS_DESTROY:
        case PHASE_NVM_LIST_DURING_MODIFY:
            return (rc == WH_ERROR_NOSPACE || rc == WH_ERROR_NOTFOUND);

        /* NVM Read/Destroy: NOTFOUND acceptable */
        case PHASE_NVM_READ_VS_DESTROY:
        case PHASE_NVM_CONCURRENT_READ:
        case PHASE_NVM_CONCURRENT_DESTROY:
            return (rc == WH_ERROR_NOTFOUND);

        /* Cross-subsystem: multiple acceptable */
        case PHASE_CROSS_COMMIT_VS_ADD:
        case PHASE_CROSS_COMMIT_VS_DESTROY:
        case PHASE_CROSS_FRESHEN_VS_MODIFY:
            return (rc == WH_ERROR_NOSPACE || rc == WH_ERROR_NOTFOUND);

        /* Erase phases: NOTFOUND, NOSPACE acceptable */
        case PHASE_KS_ERASE_VS_CACHE:
        case PHASE_KS_ERASE_VS_EXPORT:
            return (rc == WH_ERROR_NOTFOUND || rc == WH_ERROR_NOSPACE);

        /* Revoke phases: NOTFOUND, ACCESS, USAGE, NOSPACE acceptable */
        case PHASE_KS_REVOKE_VS_CACHE:
        case PHASE_KS_REVOKE_VS_EXPORT:
            return (rc == WH_ERROR_NOTFOUND || rc == WH_ERROR_ACCESS ||
                    rc == WH_ERROR_USAGE || rc == WH_ERROR_NOSPACE);

        /* GetUniqueId: NOSPACE acceptable */
        case PHASE_KS_CONCURRENT_GETUNIQUEID:
            return (rc == WH_ERROR_NOSPACE);

        /* Explicit Freshen: NOTFOUND, NOSPACE acceptable */
        case PHASE_KS_EXPLICIT_FRESHEN:
            return (rc == WH_ERROR_NOTFOUND || rc == WH_ERROR_NOSPACE);

        /* Add With Reclaim: NOSPACE, ACCESS acceptable
         * ACCESS can occur if reclaim is modifying object metadata
         * concurrently with add operations */
        case PHASE_NVM_ADD_WITH_RECLAIM:
            return (rc == WH_ERROR_NOSPACE || rc == WH_ERROR_ACCESS);

        /* GetAvailable vs Add: NOSPACE, NOTFOUND acceptable */
        case PHASE_NVM_GETAVAILABLE_VS_ADD:
            return (rc == WH_ERROR_NOSPACE || rc == WH_ERROR_NOTFOUND);

        /* GetMetadata vs Destroy: NOTFOUND acceptable */
        case PHASE_NVM_GETMETADATA_VS_DESTROY:
            return (rc == WH_ERROR_NOTFOUND);

        /* Counter phases - NOTFOUND marked acceptable to prevent test abort,
         * but validation will catch it as a bug (counter < expectedMin).
         * NOTFOUND shouldn't occur in CONCURRENT_INCREMENT (no destroys). */
        case PHASE_COUNTER_CONCURRENT_INCREMENT:
        case PHASE_COUNTER_INCREMENT_VS_READ:
            return (rc == WH_ERROR_NOTFOUND);

        /* NVM Read vs Resize - NOTFOUND acceptable (object destroyed
         * during resize), NOSPACE acceptable (NVM full) */
        case PHASE_NVM_READ_VS_RESIZE:
        case PHASE_NVM_CONCURRENT_RESIZE:
            return (rc == WH_ERROR_NOTFOUND || rc == WH_ERROR_NOSPACE);

#ifdef WOLFHSM_CFG_DMA
        /* DMA phases: same as non-DMA equivalents */
        case PHASE_KS_CACHE_DMA_VS_EXPORT:
            return (rc == WH_ERROR_NOSPACE || rc == WH_ERROR_NOTFOUND);

        case PHASE_KS_EXPORT_DMA_VS_EVICT:
            return (rc == WH_ERROR_NOTFOUND || rc == WH_ERROR_NOSPACE);

        case PHASE_NVM_ADD_DMA_VS_READ:
            return (rc == WH_ERROR_NOSPACE || rc == WH_ERROR_NOTFOUND);

        case PHASE_NVM_READ_DMA_VS_DESTROY:
            return (rc == WH_ERROR_NOTFOUND);

        /* NVM Read DMA vs Resize */
        case PHASE_NVM_READ_DMA_VS_RESIZE:
            return (rc == WH_ERROR_NOTFOUND || rc == WH_ERROR_NOSPACE);
#endif

        default:
            return 0;
    }
}

/* ============================================================================
 * CLIENT THREAD (CONTINUOUS STREAMING)
 * ========================================================================== */

static void* contentionClientThread(void* arg)
{
    ClientServerPair*  pair = (ClientServerPair*)arg;
    StressTestContext* ctx  = pair->sharedCtx;
    int                rc;
    int                localIteration;

    /* Initialize client */
    rc = wh_Client_Init(&pair->client, &pair->clientConfig);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Client %d init failed: %d\n", pair->clientId, rc);
        ATOMIC_ADD_INT(&pair->errorCount, 1);
        return NULL;
    }

    /* Wait for all threads to start */
    pthread_barrier_wait(&ctx->startBarrier);

    /* Always call barrier first, then check exit flag - prevents deadlock */
    while (1) {
        /* ===== SETUP PHASE (once per phase) ===== */
        pthread_barrier_wait(&ctx->setupBarrier);
        if (ATOMIC_LOAD_INT(&ctx->globalStopFlag)) {
            /* Call remaining barriers before exiting to prevent deadlock */
            pthread_barrier_wait(&ctx->setupCompleteBarrier);
            pthread_barrier_wait(&ctx->streamStartBarrier);
            pthread_barrier_wait(&ctx->streamEndBarrier);
            break;
        }

        /* Only client 0 does setup */
        if (pair->clientId == 0) {
            rc = doPhaseSetup(pair, ctx->currentPhase, ctx->currentKeyId);
            if (rc != WH_ERROR_OK) {
                WH_ERROR_PRINT("Setup failed for phase %d: %d\n",
                               ctx->currentPhase, rc);
            }
        }

        pthread_barrier_wait(&ctx->setupCompleteBarrier);

        /* ===== STREAMING PHASE (tight loop, no barriers) ===== */
        pthread_barrier_wait(&ctx->streamStartBarrier);

        ContentionPhase phase = ctx->currentPhase;
        whKeyId         keyId = ctx->currentKeyId;
        ClientRole      role  = ctx->clientRoles[pair->clientId];
        localIteration        = 0;

        /* Stream requests until phaseRunning becomes 0 */
        while (ATOMIC_LOAD_INT(&ctx->phaseRunning)) {
            rc =
                executePhaseOperation(pair, phase, role, localIteration, keyId);

            /* Count iteration */
            localIteration++;
            ATOMIC_ADD_INT(&pair->iterationCount, 1);

            /* Track unexpected errors */
            if (!isAcceptableResult(phase, rc)) {
                ATOMIC_ADD_INT(&pair->errorCount, 1);
            }

            /* NO BARRIER HERE - continuous streaming */
        }

        /* Wait for all clients to finish streaming */
        pthread_barrier_wait(&ctx->streamEndBarrier);
    }

    wh_Client_Cleanup(&pair->client);
    return NULL;
}

/* ============================================================================
 * PHASE EXECUTION
 * ========================================================================== */

static int allClientsReachedIterations(StressTestContext* ctx, int target)
{
    int i;
    for (i = 0; i < NUM_CLIENTS; i++) {
        if (ATOMIC_LOAD_INT(&ctx->pairs[i].iterationCount) < target) {
            return 0;
        }
    }
    return 1;
}

/* Post-phase validation for applicable tests
 * Returns WH_ERROR_OK if validation passes, error code otherwise */
static int validatePhaseResult(StressTestContext* ctx, ContentionPhase phase,
                               int totalIterations, int totalErrors)
{
    int rc;

    switch (phase) {
        case PHASE_COUNTER_CONCURRENT_INCREMENT: {
            /* Validate counter value matches expected increments
             * Expected: number of successful increments
             * Count ROLE_OP_A threads (all 4 in this phase) */
            uint32_t counter  = 0;
            int      opACount = 0;
            int      i;

            /* Count how many threads were doing increments (ROLE_OP_A) */
            for (i = 0; i < NUM_CLIENTS; i++) {
                if (ctx->clientRoles[i] == ROLE_OP_A) {
                    opACount++;
                }
            }

            /* Read final counter value using client 0 */
            rc = doCounterRead(&ctx->pairs[0].client, HOT_COUNTER_ID, &counter);
            if (rc != WH_ERROR_OK) {
                WH_ERROR_PRINT(
                    "    VALIDATION FAILED: Counter read failed: %d\n", rc);
                return WH_ERROR_ABORTED;
            }

            /* Calculate expected value: iterations per client × number of
             * incrementing clients Each incrementing client did
             * config->iterations increments
             * Account for errors: totalIterations counts all attempts,
             * but totalErrors counts unacceptable failures that didn't
             * increment */
            uint32_t expectedMin = totalIterations - totalErrors;

            WH_TEST_PRINT("    Counter validation: value=%u, expected_min=%u "
                          "(iters=%d, errors=%d)\n",
                          counter, expectedMin, totalIterations, totalErrors);

            /* Counter must equal expectedMin. If counter < expectedMin, this
             * indicates either:
             * 1. Lost increments due to locking bug (race condition)
             * 2. NOTFOUND occurred (shouldn't happen - no concurrent destroys)
             */
            if (counter < expectedMin) {
                WH_ERROR_PRINT("    VALIDATION FAILED: Counter value %u < "
                               "expected min %u\n",
                               counter, expectedMin);
                return WH_ERROR_ABORTED;
            }

            return WH_ERROR_OK;
        }

        /* Other phases don't need special validation yet */
        default:
            return WH_ERROR_OK;
    }
}

/* Select the appropriate keyId for a phase.
 * Revoke-related phases need unique key IDs because revoked keys can't be
 * erased or re-cached. Each phase type that might leave a key revoked needs
 * its own key ID to avoid conflicts.
 */
static whKeyId selectKeyIdForPhase(ContentionPhase phase, int isGlobal)
{
    switch (phase) {
        case PHASE_KS_REVOKE_VS_CACHE:
            return isGlobal ? REVOKE_CACHE_KEY_GLOBAL : REVOKE_CACHE_KEY_LOCAL;
        case PHASE_KS_REVOKE_VS_EXPORT:
            return isGlobal ? REVOKE_EXPORT_KEY_GLOBAL
                            : REVOKE_EXPORT_KEY_LOCAL;
        /* Freshen uses HOT_KEY_ID (not unique IDs) so it can reuse keys that
         * are already committed by earlier phases - avoids NVM space issues */
        default:
            return isGlobal ? HOT_KEY_ID_GLOBAL : HOT_KEY_ID_LOCAL;
    }
}

static int runPhase(StressTestContext* ctx, const PhaseConfig* config,
                    whKeyId keyId)
{
    int i;
    int rc;
#ifdef WOLFHSM_CFG_TEST_STRESS_PHASE_TIMEOUT_SEC
    time_t phaseStart;
#endif
    int         totalIterations = 0;
    int         totalErrors     = 0;
    int         timedOut        = 0;
    const char* keyScope =
        (keyId & WH_KEYID_CLIENT_GLOBAL_FLAG) ? "global" : "local";

    WH_TEST_PRINT("  Phase: %s (%s key)\n", config->name, keyScope);

    /* 1. Set phase info for all clients */
    ctx->currentPhase = config->phase;
    ctx->currentKeyId = keyId;
    for (i = 0; i < NUM_CLIENTS; i++) {
        ctx->clientRoles[i] = config->roles[i];
    }

    /* 2. Signal clients to run setup */
    pthread_barrier_wait(&ctx->setupBarrier);

    /* 3. Wait for setup to complete */
    pthread_barrier_wait(&ctx->setupCompleteBarrier);

    /* 4. Reset iteration counts */
    for (i = 0; i < NUM_CLIENTS; i++) {
        ATOMIC_STORE_INT(&ctx->pairs[i].iterationCount, 0);
        ATOMIC_STORE_INT(&ctx->pairs[i].errorCount, 0);
    }

    /* 5. Signal clients to start streaming */
    ATOMIC_STORE_INT(&ctx->phaseRunning, 1);
    pthread_barrier_wait(&ctx->streamStartBarrier);

    /* 6. Let clients stream for configured iterations OR duration */
#ifdef WOLFHSM_CFG_TEST_STRESS_PHASE_TIMEOUT_SEC
    phaseStart = time(NULL);
#endif
    while (!allClientsReachedIterations(ctx, config->iterations)) {
#ifdef WOLFHSM_CFG_TEST_STRESS_PHASE_TIMEOUT_SEC
        if (time(NULL) - phaseStart >
            WOLFHSM_CFG_TEST_STRESS_PHASE_TIMEOUT_SEC) {
            WH_ERROR_PRINT("    Phase timeout after %d seconds\n",
                           WOLFHSM_CFG_TEST_STRESS_PHASE_TIMEOUT_SEC);
            timedOut = 1;
            break;
        }
#endif
        {
            struct timespec ts = {0, 10000000}; /* 10ms */
            nanosleep(&ts, NULL);
        }
    }

    /* 7. Signal clients to stop streaming */
    ATOMIC_STORE_INT(&ctx->phaseRunning, 0);

    /* 8. Wait for all clients to finish current operation */
    pthread_barrier_wait(&ctx->streamEndBarrier);

    /* 9. Collect and print results */
    for (i = 0; i < NUM_CLIENTS; i++) {
        int iters  = ATOMIC_LOAD_INT(&ctx->pairs[i].iterationCount);
        int errors = ATOMIC_LOAD_INT(&ctx->pairs[i].errorCount);
        totalIterations += iters;
        totalErrors += errors;
    }
    WH_TEST_PRINT("    Total: %d iterations, %d errors\n", totalIterations,
                  totalErrors);

    /* 10. Run phase-specific validation */
    rc = validatePhaseResult(ctx, config->phase, totalIterations, totalErrors);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Return error if phase failed */
    if (timedOut || totalErrors > 0) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

/* ============================================================================
 * MAIN TEST FUNCTION
 * ========================================================================== */

static void printFinalStats(StressTestContext* ctx)
{
    int i;
    int totalErrors = 0;

    WH_TEST_PRINT("\n=== Final Statistics ===\n");
    for (i = 0; i < NUM_CLIENTS; i++) {
        WH_TEST_PRINT("Client %d: total errors=%d\n", i,
                      ctx->pairs[i].errorCount);
        totalErrors += ctx->pairs[i].errorCount;
    }
    WH_TEST_PRINT("Total errors across all phases: %d\n", totalErrors);
}

int whTest_ThreadSafeStress(void)
{
    StressTestContext ctx;
    int               i;
    int               rc;
    int               testResult   = 0;
    int               phasesFailed = 0;
    size_t            phaseIdx;

    memset(&ctx, 0, sizeof(ctx));

    WH_TEST_PRINT("=== Deterministic Contention Stress Test ===\n");
    WH_TEST_PRINT("Clients: %d, Phases: %zu, Iterations per phase: %d\n",
                  NUM_CLIENTS, sizeof(phases) / sizeof(phases[0]),
                  PHASE_ITERATIONS);
    WH_TEST_PRINT("Key scopes: global, local\n");

    /* Initialize wolfCrypt */
    rc = wolfCrypt_Init();
    if (rc != 0) {
        WH_ERROR_PRINT("wolfCrypt_Init failed: %d\n", rc);
        return rc;
    }

    /* Initialize shared NVM with lock */
    rc = initSharedNvm(&ctx);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to initialize shared NVM\n");
        wolfCrypt_Cleanup();
        return rc;
    }

    /* Initialize client-server pairs */
    for (i = 0; i < NUM_CLIENTS; i++) {
        rc = initClientServerPair(&ctx, i);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to initialize pair %d\n", i);
            testResult = rc;
            goto cleanup;
        }
    }

    /* Initialize barriers
     * startBarrier: main + servers + clients = NUM_CLIENTS * 2 + 1
     * phase barriers: main + clients = NUM_CLIENTS + 1
     */
    rc = pthread_barrier_init(&ctx.startBarrier, NULL, NUM_CLIENTS * 2 + 1);
    if (rc != 0) {
        WH_ERROR_PRINT("Failed to init start barrier: %d\n", rc);
        testResult = rc;
        goto cleanup;
    }

    rc = pthread_barrier_init(&ctx.setupBarrier, NULL, NUM_CLIENTS + 1);
    if (rc != 0) {
        WH_ERROR_PRINT("Failed to init setup barrier: %d\n", rc);
        testResult = rc;
        goto cleanup;
    }

    rc = pthread_barrier_init(&ctx.setupCompleteBarrier, NULL, NUM_CLIENTS + 1);
    if (rc != 0) {
        WH_ERROR_PRINT("Failed to init setupComplete barrier: %d\n", rc);
        testResult = rc;
        goto cleanup;
    }

    rc = pthread_barrier_init(&ctx.streamStartBarrier, NULL, NUM_CLIENTS + 1);
    if (rc != 0) {
        WH_ERROR_PRINT("Failed to init streamStart barrier: %d\n", rc);
        testResult = rc;
        goto cleanup;
    }

    rc = pthread_barrier_init(&ctx.streamEndBarrier, NULL, NUM_CLIENTS + 1);
    if (rc != 0) {
        WH_ERROR_PRINT("Failed to init streamEnd barrier: %d\n", rc);
        testResult = rc;
        goto cleanup;
    }

    WH_TEST_PRINT("Starting %d server threads and %d client threads...\n",
                  NUM_CLIENTS, NUM_CLIENTS);

    /* Start all server threads */
    for (i = 0; i < NUM_CLIENTS; i++) {
        rc = pthread_create(&ctx.pairs[i].serverThread, NULL, serverThread,
                            &ctx.pairs[i]);
        if (rc != 0) {
            WH_ERROR_PRINT("Failed to create server thread %d: %d\n", i, rc);
            ATOMIC_STORE_INT(&ctx.globalStopFlag, 1);
            testResult = rc;
            goto join_threads;
        }
    }

    /* Start all client threads */
    for (i = 0; i < NUM_CLIENTS; i++) {
        rc = pthread_create(&ctx.pairs[i].clientThread, NULL,
                            contentionClientThread, &ctx.pairs[i]);
        if (rc != 0) {
            WH_ERROR_PRINT("Failed to create client thread %d: %d\n", i, rc);
            ATOMIC_STORE_INT(&ctx.globalStopFlag, 1);
            testResult = rc;
            goto join_threads;
        }
    }

    /* Synchronize start - wait for all threads to be ready */
    pthread_barrier_wait(&ctx.startBarrier);
    WH_TEST_PRINT("All threads started, running phases...\n\n");

    /* Run all phases */
    for (phaseIdx = 0; phaseIdx < sizeof(phases) / sizeof(phases[0]);
         phaseIdx++) {
        whKeyId globalKey = selectKeyIdForPhase(phases[phaseIdx].phase, 1);
        whKeyId localKey  = selectKeyIdForPhase(phases[phaseIdx].phase, 0);

        rc = runPhase(&ctx, &phases[phaseIdx], globalKey);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Phase %zu (global) failed: %d\n", phaseIdx, rc);
            phasesFailed++;
            if (testResult == 0) {
                testResult = rc; /* Record first error */
            }
            /* Continue to next phase - don't break */
        }

        rc = runPhase(&ctx, &phases[phaseIdx], localKey);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Phase %zu (local) failed: %d\n", phaseIdx, rc);
            phasesFailed++;
            if (testResult == 0) {
                testResult = rc; /* Record first error */
            }
            /* Continue to next phase - don't break */
        }
    }

    /* Signal global stop */
    ATOMIC_STORE_INT(&ctx.globalStopFlag, 1);

    /* Need to release clients from barrier waits - run one more "dummy" phase
     */
    pthread_barrier_wait(&ctx.setupBarrier);
    pthread_barrier_wait(&ctx.setupCompleteBarrier);
    ATOMIC_STORE_INT(&ctx.phaseRunning, 0);
    pthread_barrier_wait(&ctx.streamStartBarrier);
    pthread_barrier_wait(&ctx.streamEndBarrier);

join_threads:
    /* Signal stop for servers */
    for (i = 0; i < NUM_CLIENTS; i++) {
        ATOMIC_STORE_INT(&ctx.pairs[i].stopFlag, 1);
    }

    /* Join all client threads */
    for (i = 0; i < NUM_CLIENTS; i++) {
        if (ctx.pairs[i].clientThread != 0) {
            pthread_join(ctx.pairs[i].clientThread, NULL);
        }
    }

    /* Join all server threads */
    for (i = 0; i < NUM_CLIENTS; i++) {
        if (ctx.pairs[i].serverThread != 0) {
            pthread_join(ctx.pairs[i].serverThread, NULL);
        }
    }

    /* Print statistics */
    printFinalStats(&ctx);

    pthread_barrier_destroy(&ctx.startBarrier);
    pthread_barrier_destroy(&ctx.setupBarrier);
    pthread_barrier_destroy(&ctx.setupCompleteBarrier);
    pthread_barrier_destroy(&ctx.streamStartBarrier);
    pthread_barrier_destroy(&ctx.streamEndBarrier);

cleanup:
    /* Cleanup client-server pairs */
    for (i = 0; i < NUM_CLIENTS; i++) {
        cleanupClientServerPair(&ctx.pairs[i]);
    }

    /* Cleanup NVM */
    wh_Nvm_Cleanup(&ctx.nvm);

    /* Cleanup mutex attributes */
    pthread_mutexattr_destroy(&ctx.mutexAttr);

    /* Cleanup wolfCrypt */
    wolfCrypt_Cleanup();

    if (testResult == 0) {
        WH_TEST_PRINT(
            "\n=== Deterministic Contention Stress Test PASSED ===\n");
    }
    else {
        WH_ERROR_PRINT("\nPhases failed: %d\n", phasesFailed);
        WH_ERROR_PRINT("=== Deterministic Contention Stress Test FAILED ===\n");
    }

    return testResult;
}

#else /* !WOLFHSM_CFG_THREADSAFE || !WOLFHSM_CFG_TEST_POSIX ||     \
         !WOLFHSM_CFG_GLOBAL_KEYS || !WOLFHSM_CFG_ENABLE_CLIENT || \
         !WOLFHSM_CFG_ENABLE_SERVER || WOLFHSM_CFG_NO_CRYPTO */

#include "wh_test_posix_threadsafe_stress.h"
#include "wh_test_common.h"

int whTest_ThreadSafeStress(void)
{
    WH_TEST_PRINT("Thread safety stress test skipped ");
    WH_TEST_PRINT("(requires THREADSAFE + TEST_POSIX + GLOBAL_KEYS + ");
    WH_TEST_PRINT("ENABLE_CLIENT + ENABLE_SERVER + crypto)\n");
    return 0;
}

#endif /* WOLFHSM_CFG_THREADSAFE && WOLFHSM_CFG_TEST_POSIX && ... */
