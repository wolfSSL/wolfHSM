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
 * port/autosar/classic/examples/csm_smoke/test_concurrency.c
 *
 * STRESS_WORKERS threads submit async RNG jobs for STRESS_DURATION_MS while
 * one more thread cancels random submitted jobs; checks callbacks and leaks.
 */

#include "test_helpers.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STRESS_WORKERS 2
#define STRESS_DURATION_MS 500
#define STRESS_MAX_ASYNC 16 /* per worker */

typedef struct {
    int                          id;
    int                          asyncSubmitted;
    int                          cancelsRequested;
    Crypto_JobType*              jobs;
    Crypto_JobPrimitiveInfoType* jpis;
    uint8 (*outs)[32];
    uint32*         outLens;
    volatile uint8* cancelled;
} stressWorker;

static volatile int s_stressStop  = 0;
static volatile int s_totalAsync  = 0;
static volatile int s_totalCancel = 0;

static int randInt(unsigned int* seed, int lo, int hi)
{
    *seed = (*seed * 1103515245u + 12345u) & 0x7fffffffu;
    return lo + (int)((*seed >> 8) % (unsigned)(hi - lo + 1));
}

static int stressAsyncRng(stressWorker* w)
{
    int idx = w->asyncSubmitted;
    if (idx >= STRESS_MAX_ASYNC)
        return 0;
    Crypto_JobType*                       job = &w->jobs[idx];
    Crypto_JobPrimitiveInfoType*          jpi = &w->jpis[idx];
    static const Crypto_PrimitiveInfoType pi  = {CRYPTO_RANDOMGENERATE,
                                                 {CRYPTO_ALGOFAM_RNG,
                                                  CRYPTO_ALGOFAM_NOT_SET, 0u,
                                                  CRYPTO_ALGOMODE_NOT_SET}};

    memset(jpi, 0, sizeof(*jpi));
    jpi->primitiveInfo  = &pi;
    jpi->processingType = CRYPTO_PROCESSING_ASYNC;
    memset(job, 0, sizeof(*job));
    job->jobId                             = (uint32)(w->id * 100000 + idx);
    job->jobPrimitiveInfo                  = jpi;
    w->outLens[idx]                        = (uint32)sizeof(w->outs[idx]);
    job->jobPrimitiveInputOutput.outputPtr = w->outs[idx];
    job->jobPrimitiveInputOutput.outputLengthPtr = &w->outLens[idx];
    job->jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;

    if (testCryIfProcessJob(0u, job) != E_OK) {
        /* Queue full is expected back-pressure; retry next iteration. */
        return 0;
    }
    __atomic_store_n(&w->asyncSubmitted, idx + 1, __ATOMIC_RELEASE);
    __sync_fetch_and_add(&s_totalAsync, 1);
    return 0;
}

static void* stressWorkerFn(void* arg)
{
    stressWorker*   w        = (stressWorker*)arg;
    int             failures = 0;
    struct timespec start, now;
    long            elapsedMs = 0;
    struct timespec gap       = {0, 1 * 1000 * 1000};

    /* Async only: the wolfHSM client is single-threaded, so sync jobs
     * here would race MainFunction. */
    (void)w;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (elapsedMs < STRESS_DURATION_MS &&
           !__atomic_load_n(&s_stressStop, __ATOMIC_ACQUIRE)) {
        failures += stressAsyncRng(w);
        nanosleep(&gap, NULL);
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsedMs = (now.tv_sec - start.tv_sec) * 1000 +
                    (now.tv_nsec - start.tv_nsec) / 1000000;
    }
    return (void*)(intptr_t)failures;
}

static void* stressCancelFn(void* arg)
{
    stressWorker*   workers = (stressWorker*)arg;
    unsigned int    seed    = 12345u;
    struct timespec start, now;
    long            elapsedMs = 0;
    struct timespec sleepReq  = {0, 2 * 1000 * 1000}; /* 2 ms */

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (elapsedMs < STRESS_DURATION_MS &&
           !__atomic_load_n(&s_stressStop, __ATOMIC_ACQUIRE)) {
        int           wId = randInt(&seed, 0, STRESS_WORKERS - 1);
        stressWorker* w   = &workers[wId];
        int           n = __atomic_load_n(&w->asyncSubmitted, __ATOMIC_ACQUIRE);
        if (n > 0) {
            int pick = randInt(&seed, 0, n - 1);
            if (!w->cancelled[pick]) {
                if (Crypto_CancelJob(0u, &w->jobs[pick]) == E_OK) {
                    w->cancelled[pick] = 1u;
                    w->cancelsRequested++;
                    __sync_fetch_and_add(&s_totalCancel, 1);
                }
            }
        }
        nanosleep(&sleepReq, NULL);
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsedMs = (now.tv_sec - start.tv_sec) * 1000 +
                    (now.tv_nsec - start.tv_nsec) / 1000000;
    }
    return NULL;
}

static int testConcurrencyStress(void)
{
    pthread_t    threads[STRESS_WORKERS];
    pthread_t    cancelThread;
    stressWorker workers[STRESS_WORKERS];
    int          i, failures = 0;

    for (i = 0; i < STRESS_WORKERS; ++i) {
        workers[i].id               = i;
        workers[i].asyncSubmitted   = 0;
        workers[i].cancelsRequested = 0;
        workers[i].jobs = calloc(STRESS_MAX_ASYNC, sizeof(Crypto_JobType));
        workers[i].jpis =
            calloc(STRESS_MAX_ASYNC, sizeof(Crypto_JobPrimitiveInfoType));
        workers[i].outs = calloc(STRESS_MAX_ASYNC, sizeof(workers[i].outs[0]));
        workers[i].outLens   = calloc(STRESS_MAX_ASYNC, sizeof(uint32));
        workers[i].cancelled = calloc(STRESS_MAX_ASYNC, sizeof(uint8));
    }

    s_stressStop  = 0;
    s_totalAsync  = 0;
    s_totalCancel = 0;
    int prev      = testCallbackTotal();

    for (i = 0; i < STRESS_WORKERS; ++i) {
        pthread_create(&threads[i], NULL, stressWorkerFn, &workers[i]);
    }
    pthread_create(&cancelThread, NULL, stressCancelFn, workers);

    for (i = 0; i < STRESS_WORKERS; ++i) {
        void* rc = NULL;
        pthread_join(threads[i], &rc);
        failures += (int)(intptr_t)rc;
    }
    __atomic_store_n(&s_stressStop, 1, __ATOMIC_RELEASE);
    pthread_join(cancelThread, NULL);

    int expected = s_totalAsync - s_totalCancel;
    if (testWaitCallbacks(prev + expected, 30000) != 0) {
        fprintf(
            stderr,
            "  concurrency: only %d/%d callbacks fired (async=%d, cancel=%d)\n",
            testCallbackTotal() - prev, expected, s_totalAsync, s_totalCancel);
        failures++;
    }

    /* Let MainFunction drain cancelled slots before the leak check. */
    struct timespec t = {0, 50 * 1000 * 1000};
    nanosleep(&t, NULL);

    printf("  concurrency: %d async submitted, %d cancelled, %d callbacks "
           "delivered\n",
           s_totalAsync, s_totalCancel, testCallbackTotal() - prev);

    for (i = 0; i < STRESS_WORKERS; ++i) {
        free(workers[i].jobs);
        free(workers[i].jpis);
        free(workers[i].outs);
        free(workers[i].outLens);
        free((void*)workers[i].cancelled);
    }
    return failures;
}

int testConcurrencyAll(void)
{
    int failures = 0;
    TEST_RUN(failures, testConcurrencyStress);
    return failures;
}
