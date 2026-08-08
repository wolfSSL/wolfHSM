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
 * port/autosar/classic/examples/csm_smoke/test_helpers.c
 *
 * Implementation of the shared test infrastructure.
 */

#include "test_helpers.h"

#include <stdio.h>
#include <time.h>

/* --- Callback bookkeeping ------------------------------------------- */

testCallbackState gTestCb = {PTHREAD_MUTEX_INITIALIZER,
                             PTHREAD_COND_INITIALIZER,
                             0,
                             E_NOT_OK,
                             NULL,
                             {0}};

void CryIf_CallbackNotification(Crypto_JobType* job, Std_ReturnType result)
{
    pthread_mutex_lock(&gTestCb.lock);
    gTestCb.total++;
    gTestCb.lastResult = result;
    gTestCb.lastJob    = job;
    if (job != NULL) {
        /* Cheap hash of the job pointer into the small per-job table. */
        size_t h = ((size_t)job >> 4) % 64u;
        gTestCb.perJobCount[h]++;
    }
    pthread_cond_broadcast(&gTestCb.cv);
    pthread_mutex_unlock(&gTestCb.lock);
}

int testWaitCallbacks(int target, int timeoutMs)
{
    struct timespec abs;
    int             rc = 0;
    clock_gettime(CLOCK_REALTIME, &abs);
    abs.tv_sec += timeoutMs / 1000;
    abs.tv_nsec += (timeoutMs % 1000) * 1000000;
    if (abs.tv_nsec >= 1000000000) {
        abs.tv_sec++;
        abs.tv_nsec -= 1000000000;
    }
    pthread_mutex_lock(&gTestCb.lock);
    while (gTestCb.total < target && rc == 0) {
        rc = pthread_cond_timedwait(&gTestCb.cv, &gTestCb.lock, &abs);
    }
    pthread_mutex_unlock(&gTestCb.lock);
    return rc;
}

int testCallbackTotal(void)
{
    int n;
    pthread_mutex_lock(&gTestCb.lock);
    n = gTestCb.total;
    pthread_mutex_unlock(&gTestCb.lock);
    return n;
}

int testCallbacksForJob(const Crypto_JobType* job)
{
    int    n;
    size_t h = ((size_t)job >> 4) % 64u;
    pthread_mutex_lock(&gTestCb.lock);
    n = gTestCb.perJobCount[h];
    pthread_mutex_unlock(&gTestCb.lock);
    return n;
}

int testWaitDrain(int timeoutMs)
{
    wh_AutosarDriverObject* obj    = wh_Autosar_GetDriverObject(0u);
    struct timespec         t      = {0, 5 * 1000 * 1000};
    int                     waited = 0;
    while (waited < timeoutMs) {
        if (wh_Autosar_DebugActiveSlotCount(obj) == 0u &&
            wh_Autosar_DebugActiveHashStateCount(obj) == 0u) {
            return 0;
        }
        nanosleep(&t, NULL);
        waited += 5;
    }
    return (wh_Autosar_DebugActiveSlotCount(obj) == 0u &&
            wh_Autosar_DebugActiveHashStateCount(obj) == 0u)
               ? 0
               : 1;
}

/* --- DET capture ---------------------------------------------------- */

pthread_mutex_t gTestDetLock = PTHREAD_MUTEX_INITIALIZER;
testDetEvent    gTestDetRing[TEST_DET_RING];
int             gTestDetCount = 0;

Std_ReturnType Det_ReportError(uint16 m, uint8 i, uint8 api, uint8 err)
{
    pthread_mutex_lock(&gTestDetLock);
    if (gTestDetCount < TEST_DET_RING) {
        gTestDetRing[gTestDetCount].moduleId   = m;
        gTestDetRing[gTestDetCount].instanceId = i;
        gTestDetRing[gTestDetCount].apiId      = api;
        gTestDetRing[gTestDetCount].errorId    = err;
    }
    gTestDetCount++;
    pthread_mutex_unlock(&gTestDetLock);
    return E_OK;
}

void testDetReset(void)
{
    pthread_mutex_lock(&gTestDetLock);
    gTestDetCount = 0;
    pthread_mutex_unlock(&gTestDetLock);
}

int testDetCount(uint8 apiId, uint8 errorId)
{
    int n = 0;
    int i;
    pthread_mutex_lock(&gTestDetLock);
    int cap = (gTestDetCount < TEST_DET_RING) ? gTestDetCount : TEST_DET_RING;
    for (i = 0; i < cap; ++i) {
        if (gTestDetRing[i].apiId == apiId &&
            gTestDetRing[i].errorId == errorId) {
            n++;
        }
    }
    pthread_mutex_unlock(&gTestDetLock);
    return n;
}

/* --- MainFunction worker thread ------------------------------------- */

static pthread_t       s_mainThread;
static volatile int    s_mainStop      = 0;
static volatile int    s_mainPaused    = 0;
static pthread_mutex_t s_mainPauseLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  s_mainResumeCv  = PTHREAD_COND_INITIALIZER;

static void* mainFunctionLoop(void* arg)
{
    (void)arg;
    while (!s_mainStop) {
        pthread_mutex_lock(&s_mainPauseLock);
        while (s_mainPaused && !s_mainStop) {
            pthread_cond_wait(&s_mainResumeCv, &s_mainPauseLock);
        }
        pthread_mutex_unlock(&s_mainPauseLock);
        if (s_mainStop)
            break;
        Crypto_MainFunction();
        struct timespec t = {0, 1 * 1000 * 1000}; /* 1 ms */
        nanosleep(&t, NULL);
    }
    return NULL;
}

void testStartMainFunctionThread(void)
{
    pthread_create(&s_mainThread, NULL, mainFunctionLoop, NULL);
}

void testStopMainFunctionThread(void)
{
    pthread_mutex_lock(&s_mainPauseLock);
    s_mainStop   = 1;
    s_mainPaused = 0;
    pthread_cond_broadcast(&s_mainResumeCv);
    pthread_mutex_unlock(&s_mainPauseLock);
    pthread_join(s_mainThread, NULL);
}

void testPauseMainFunctionThread(void)
{
    pthread_mutex_lock(&s_mainPauseLock);
    s_mainPaused = 1;
    pthread_mutex_unlock(&s_mainPauseLock);
    /* Sleep long enough for the worker to finish its current iteration
     * and observe the pause flag. */
    struct timespec t = {0, 5 * 1000 * 1000};
    nanosleep(&t, NULL);
}

void testResumeMainFunctionThread(void)
{
    pthread_mutex_lock(&s_mainPauseLock);
    s_mainPaused = 0;
    pthread_cond_broadcast(&s_mainResumeCv);
    pthread_mutex_unlock(&s_mainPauseLock);
}

/* --- Test runner ---------------------------------------------------- */

void testRun(int* failures, test_fn fn, const char* name)
{
    wh_AutosarDriverObject* obj = wh_Autosar_GetDriverObject(0u);
    int                     rc;
    uint32                  leakedSlots, leakedHash;

    testDetReset();
    rc = fn();
    if (rc != 0) {
        fprintf(stderr, "  [FAIL] %s\n", name);
        (*failures)++;
        /* Test bailed early — its stack-allocated job structs are
         * about to be reused by the next test. Force-reset all slots
         * so MainFunction's eventual Response handler doesn't dereference
         * a stale pointer. */
        wh_Autosar_DebugForceResetSlots(obj);
        return;
    }
    /* Give MainFunction time to drain anything the test set in motion
     * (a cancel-during-pending leaves the slot in CANCELLING until the
     * Response arrives; async ops take a few ms to round-trip). */
    (void)testWaitDrain(2000);
    leakedSlots = wh_Autosar_DebugActiveSlotCount(obj);
    leakedHash  = wh_Autosar_DebugActiveHashStateCount(obj);
    if (leakedSlots != 0u || leakedHash != 0u) {
        fprintf(stderr,
                "  [LEAK] %s: %u slot(s), %u hash state(s) still active\n",
                name, leakedSlots, leakedHash);
        wh_Autosar_DebugForceResetSlots(obj);
        (*failures)++;
    }
}

/* --- Hex decoder ---------------------------------------------------- */

static int hexNibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int testHexDecode(const char* hex, uint8* out, int outCap)
{
    int len    = (int)strlen(hex);
    int outLen = len / 2;
    int i;
    if ((len & 1) != 0 || outLen > outCap)
        return -1;
    for (i = 0; i < outLen; ++i) {
        int hi = hexNibble(hex[2 * i]);
        int lo = hexNibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8)((hi << 4) | lo);
    }
    return outLen;
}

/* --- Slot lock hooks: strong override of the WH_AUTOSAR_WEAK defaults. */

static pthread_mutex_t s_slotLock = PTHREAD_MUTEX_INITIALIZER;

void wh_Autosar_LockSlots(wh_AutosarDriverObject* obj)
{
    (void)obj;
    pthread_mutex_lock(&s_slotLock);
}
void wh_Autosar_UnlockSlots(wh_AutosarDriverObject* obj)
{
    (void)obj;
    pthread_mutex_unlock(&s_slotLock);
}
