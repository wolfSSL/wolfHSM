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
 * Shared helpers for the csm_smoke tests.
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

/* Callbacks seen for job, hashed into buckets that are never reset, so
 * only the delta across a test is meaningful. */
int testCallbacksForJob(const Crypto_JobType* job);

/* Block until all driver-object 0 slots return to IDLE, or timeoutMs
 * elapses. Returns 0 on full drain, 1 on timeout. */
int testWaitDrain(int timeoutMs);

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

void testStartMainFunctionThread(void);
void testStopMainFunctionThread(void);

/* Pause or resume the worker so a test controls MainFunction ordering. */
void testPauseMainFunctionThread(void);
void testResumeMainFunctionThread(void);

/* Stands in for CryIf: copies the CryIf key ids into the driver key ids
 * (identity mapping), then calls Crypto_ProcessJob. */
Std_ReturnType testCryIfProcessJob(uint32 objectId, Crypto_JobType* job);

/* Removes a test key from the server cache and NVM and clears its state. */
void testEraseKey(uint32 cryptoKeyId);

/* Fills job, jpi and pi for a single-call job on cryptoKeyId keyId. */
void testBuildJob(Crypto_JobType* job, Crypto_JobPrimitiveInfoType* jpi,
                  Crypto_PrimitiveInfoType* pi, Crypto_ServiceInfoType svc,
                  Crypto_AlgorithmFamilyType fam, Crypto_AlgorithmModeType mode,
                  uint32 keyId, Crypto_ProcessingType pt, uint32 jobId);

/* Submits an async job and waits for its callback; *result gets the
 * callback's result. */
Std_ReturnType testRunAsync(Crypto_JobType* job, Std_ReturnType* result);

/* Runs body with the given keys erased before and after. */
int testWithKeys(int (*body)(void), const uint32* keys, size_t n);

/* Run one test function, ensuring no slot or hash-state leaks remain
 * in driver object 0 after it returns. Increments *failures on error. */
typedef int (*test_fn)(void);

#define TEST_RUN(failures, fn) testRun(&(failures), (fn), #fn)

void testRun(int* failures, test_fn fn, const char* name);

/* Decodes a lowercase hex string; returns the byte count, or -1. */
int testHexDecode(const char* hex, uint8* out, int outCap);

/* Makes wh_Autosar_PlatformClientConfig fail while non-zero. */
extern int gTestFailClientConfig;

int testKatAll(void);         /* KAT vectors */
int testDetAll(void);         /* DET coverage */
int testDetBeforeInit(void);  /* UNINIT and INIT_FAILED, before Crypto_Init */
int testAccountingAll(void);  /* resource accounting */
int testConcurrencyAll(void); /* concurrency stress */
int testTimeoutAll(void);     /* async timeout */
int testCancelAll(void);      /* cancel during pending */
int testKeyMgmtAll(void);     /* key state and key management jobs */
int testSigAll(void);         /* signatures, interop with software verify */
int testCipherAll(void);      /* AES modes, key copy, multi-call hash */
int testEdgeAll(void);        /* parameter checks and edge cases */
int testPolicyAll(void);      /* key policy, cancel, verify results */
int testLimitsAll(void);      /* full tables and failed hash streams */

#ifdef __cplusplus
}
#endif

#endif /* TEST_HELPERS_H_ */
