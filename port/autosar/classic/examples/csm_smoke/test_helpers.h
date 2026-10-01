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
 * port/autosar/classic/examples/csm_smoke/test_helpers.h
 *
 * Shared infrastructure used by the csm_smoke test files:
 *  - CryIf callback bookkeeping with per-job counters
 *  - DET event capture for asserting parameter checks fire
 *  - MainFunction worker thread control
 *  - Slot lock hooks
 *  - Common assertions
 */

#ifndef TEST_HELPERS_H_
#define TEST_HELPERS_H_

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "Std_Types.h"
#include "Crypto.h"
#include "Crypto_GeneralTypes.h"
#include "CryIf_Cbk.h"
#include "wh_autosar_classic_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- Callback bookkeeping ------------------------------------------- */

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  cv;
    int             total; /* total callbacks observed */
    Std_ReturnType  lastResult;
    Crypto_JobType* lastJob;
    int             perJobCount[64]; /* indexed by job pointer hash */
} testCallbackState;

extern testCallbackState gTestCb;

/* Wait until total reaches target, or timeoutMs elapses. Returns 0 on
 * success, non-zero on timeout. */
int testWaitCallbacks(int target, int timeoutMs);

/* Snapshot current callback total under the lock. */
int testCallbackTotal(void);

/* Count of callbacks observed for the given job pointer specifically.
 * NOTE: this hashes the pointer into 64 buckets and the table is never
 * reset, so the ABSOLUTE value carries residue from earlier tests whose
 * jobs hashed to the same bucket (stack addresses get reused). Callers
 * must baseline before submitting and compare the delta, just like the
 * testCallbackTotal() / testWaitCallbacks(prev + N) pattern. */
int testCallbacksForJob(const Crypto_JobType* job);

/* Block until all driver-object 0 slots return to IDLE, or timeoutMs
 * elapses. Returns 0 on full drain, 1 on timeout. */
int testWaitDrain(int timeoutMs);

/* --- DET capture ---------------------------------------------------- */

typedef struct {
    uint16 moduleId;
    uint8  instanceId;
    uint8  apiId;
    uint8  errorId;
} testDetEvent;

#define TEST_DET_RING 32

extern pthread_mutex_t gTestDetLock;
extern testDetEvent    gTestDetRing[TEST_DET_RING];
extern int             gTestDetCount;

void testDetReset(void);

/* Returns the number of recorded events whose apiId/errorId match. */
int testDetCount(uint8 apiId, uint8 errorId);

/* --- MainFunction worker thread ------------------------------------- */

void testStartMainFunctionThread(void);
void testStopMainFunctionThread(void);

/* Pause / resume the worker thread so a test can drive MainFunction
 * manually for deterministic ordering (used by the timeout test). */
void testPauseMainFunctionThread(void);
void testResumeMainFunctionThread(void);

/* --- Test runner ---------------------------------------------------- */

/* Run one test function, ensuring no slot or hash-state leaks remain
 * in driver object 0 after it returns. Increments *failures on error. */
typedef int (*test_fn)(void);

#define TEST_RUN(failures, fn) testRun(&(failures), (fn), #fn)

void testRun(int* failures, test_fn fn, const char* name);

/* Hex helper: lowercase hex string → bytes; returns length, or -1. */
int testHexDecode(const char* hex, uint8* out, int outCap);

/* --- Category entrypoints (defined in their own .c files) ----------- */

int testKatAll(void);         /* category 1 — KAT vectors */
int testDetAll(void);         /* category 2 — DET coverage */
int testAccountingAll(void);  /* category 3 — resource accounting */
int testConcurrencyAll(void); /* category 4 — concurrency stress */
int testTimeoutAll(void);     /* category 5 — timeout */
int testCancelAll(void);      /* category 6 — cancel-during-pending */

#ifdef __cplusplus
}
#endif

#endif /* TEST_HELPERS_H_ */
