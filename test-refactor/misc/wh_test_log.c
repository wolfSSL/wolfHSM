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
 * test-refactor/misc/wh_test_log.c
 *
 * Portable logging tests from legacy test/wh_test_log.c: frontend API,
 * log macros, the ring buffer backend, and the backend-agnostic harness
 * run against the mock and ring buffer backends. The POSIX file backend,
 * concurrent, and client/server log tests live in the POSIX port.
 */

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_LOGGING

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_log.h"
#include "wolfhsm/wh_log_ringbuf.h"
#include "wolfhsm/wh_log_printf.h"

#include "wh_test_common.h"
#include "wh_test_list.h"
#include "wh_test_log_backend.h"

#define ITERATE_STOP_MAGIC 99
#define ITERATE_STOP_COUNT 3

/* Mock log backend definitions */

#define MOCK_LOG_MAX_ENTRIES 16

typedef struct {
    whLogEntry entries[MOCK_LOG_MAX_ENTRIES];
    int        count;
    int        init_called;
    int        cleanup_called;
} mockLogContext;

static int mockLog_Init(void* context, const void* config)
{
    mockLogContext* ctx = (mockLogContext*)context;
    (void)config;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->init_called = 1;
    return 0;
}

static int mockLog_Cleanup(void* context)
{
    mockLogContext* ctx = (mockLogContext*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->cleanup_called = 1;
    return 0;
}

static int mockLog_AddEntry(void* context, const whLogEntry* entry)
{
    mockLogContext* ctx = (mockLogContext*)context;

    if (ctx == NULL || entry == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->count >= MOCK_LOG_MAX_ENTRIES) {
        return WH_ERROR_NOSPACE;
    }

    memcpy(&ctx->entries[ctx->count], entry, sizeof(whLogEntry));
    ctx->count++;
    return 0;
}

/* Test-specific export structure for mock backend */
typedef struct {
    int (*callback)(void* arg, const whLogEntry* entry);
    void* callback_arg;
} mockLogExportArg;

static int mockLog_Export(void* context, void* export_arg)
{
    mockLogContext*   ctx  = (mockLogContext*)context;
    mockLogExportArg* args = (mockLogExportArg*)export_arg;
    int               i;
    int               ret;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* If no export args or callback, just succeed */
    if (args == NULL || args->callback == NULL) {
        return 0;
    }

    /* Iterate and call user's callback */
    for (i = 0; i < ctx->count; i++) {
        ret = args->callback(args->callback_arg, &ctx->entries[i]);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

static int mockLog_Iterate(void* context, whLogIterateCb iterate_cb,
                           void* iterate_arg)
{
    mockLogContext* ctx = (mockLogContext*)context;
    int             i;
    int             ret;

    if (ctx == NULL || iterate_cb == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Iterate and call user's callback */
    for (i = 0; i < ctx->count; i++) {
        ret = iterate_cb(iterate_arg, &ctx->entries[i]);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

static int mockLog_Clear(void* context)
{
    mockLogContext* ctx = (mockLogContext*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->count = 0;
    memset(ctx->entries, 0, sizeof(ctx->entries));
    return 0;
}

static whLogCb mockLogCb = {
    .Init     = mockLog_Init,
    .Cleanup  = mockLog_Cleanup,
    .AddEntry = mockLog_AddEntry,
    .Export   = mockLog_Export,
    .Iterate  = mockLog_Iterate,
    .Clear    = mockLog_Clear,
};


/* Helper for iterate callback - counts entries */
static int iterateCallbackCount(void* arg, const whLogEntry* entry)
{
    int* count = (int*)arg;
    (void)entry;
    (*count)++;
    return 0;
}

/* Helper callback - stops iteration after a fixed number of entries */
static int iterateCallbackStopAt2(void* arg, const whLogEntry* entry)
{
    int* count = (int*)arg;
    (void)entry;
    (*count)++;
    if (*count >= ITERATE_STOP_COUNT) {
        /* Custom return code to test propagation */
        return ITERATE_STOP_MAGIC;
    }
    return WH_ERROR_OK;
}

/* Helper for iterate callback - validates specific entries */
typedef struct {
    int count;
    int valid; /* Set to 0 if entry doesn't match expected pattern */
} iterateValidationArgs;

static int iterateCallbackValidator(void* arg, const whLogEntry* entry)
{
    iterateValidationArgs* args = (iterateValidationArgs*)arg;
    char                   expected[32];

    /* Expect messages like "Entry 0", "Entry 1", etc. */
    snprintf(expected, sizeof(expected), "Entry %d", args->count);

    if (strncmp(entry->msg, expected, WOLFHSM_CFG_LOG_MSG_MAX) != 0) {
        args->valid = 0;
    }
    if (entry->level != WH_LOG_LEVEL_INFO) {
        args->valid = 0;
    }

    args->count++;
    return 0;
}

/* Frontend API test using mock backend */
static int whTest_LogFrontend(void)
{
    whLogContext          logCtx;
    mockLogContext        mockCtx;
    whLogConfig           logConfig;
    int                   iterate_count = 0;
    int                   i;
    mockLogExportArg      exportArgs;
    iterateValidationArgs valArgs;
    whLogEntry            entry = {0};

    /* Setup */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&mockCtx, 0, sizeof(mockCtx));
    logConfig.cb      = &mockLogCb;
    logConfig.context = &mockCtx;
    logConfig.config  = NULL;

    /* Test: NULL input rejections */
    WH_TEST_ASSERT_RETURN(wh_Log_Init(NULL, &logConfig) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Init(&logCtx, NULL) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_AddEntry(NULL, &entry) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_AddEntry(&logCtx, NULL) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Cleanup(NULL) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Clear(NULL) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Export(NULL, &exportArgs) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Iterate(NULL, iterateCallbackCount,
                                         &iterate_count) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Log_Iterate(&logCtx, NULL, &iterate_count) ==
                          WH_ERROR_BADARGS);

    /* Initialize the log context */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));
    WH_TEST_ASSERT_RETURN(mockCtx.init_called == 1);

    /* Test: Fill buffer completely and verify all entries */
    for (i = 0; i < MOCK_LOG_MAX_ENTRIES; i++) {
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Entry %d", i);
    }
    WH_TEST_ASSERT_RETURN(mockCtx.count == MOCK_LOG_MAX_ENTRIES);

    /* Verify each entry has correct content */
    for (i = 0; i < MOCK_LOG_MAX_ENTRIES; i++) {
        char expected[32];
        snprintf(expected, sizeof(expected), "Entry %d", i);
        WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[i].msg, expected,
                                      WOLFHSM_CFG_LOG_MSG_MAX) == 0);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[i].level == WH_LOG_LEVEL_INFO);
        WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[i].file, __FILE__,
                                      WOLFHSM_CFG_LOG_MSG_MAX) == 0);
        WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[i].function, __func__,
                                      WOLFHSM_CFG_LOG_MSG_MAX) == 0);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[i].line > 0);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[i].timestamp > 0);
    }

    /* Test: Export works */
    iterate_count           = 0;
    exportArgs.callback     = iterateCallbackCount;
    exportArgs.callback_arg = &iterate_count;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, &exportArgs));
    WH_TEST_ASSERT_RETURN(iterate_count == MOCK_LOG_MAX_ENTRIES);

    /* Test: Iterate works and iterates over expected elements */
    valArgs.count = 0;
    valArgs.valid = 1;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackValidator, &valArgs));
    WH_TEST_ASSERT_RETURN(valArgs.count == MOCK_LOG_MAX_ENTRIES);
    WH_TEST_ASSERT_RETURN(valArgs.valid == 1);

    /* Test: Clear works */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    WH_TEST_ASSERT_RETURN(mockCtx.count == 0);

    /* Verify buffer is actually empty via iterate */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 0);

    /* Test: Can write after clear */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Entry 0");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 1);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[0].msg, "Entry 0",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    WH_TEST_ASSERT_RETURN(mockCtx.cleanup_called == 1);

    return 0;
}

/* Test helper macros using mock backend */
static int whTest_LogMacros(void)
{
    whLogContext   logCtx;
    mockLogContext mockCtx;
    whLogConfig    logConfig;

    /* Setup */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&mockCtx, 0, sizeof(mockCtx));
    logConfig.cb      = &mockLogCb;
    logConfig.context = &mockCtx;
    logConfig.config  = NULL;

    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: WH_LOG_INFO creates proper entry with __FILE__/__LINE__ */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Info message");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 1);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].level == WH_LOG_LEVEL_INFO);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[0].msg, "Info message",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[0].file, __FILE__,
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[0].function, __func__,
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].line > 0);

    /* Test: WH_LOG_ERROR creates proper entry */
    WH_LOG(&logCtx, WH_LOG_LEVEL_ERROR, "Error message");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 2);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[1].level == WH_LOG_LEVEL_ERROR);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[1].msg, "Error message",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);

    /* Test: WH_LOG_SECEVENT creates proper entry */
    WH_LOG(&logCtx, WH_LOG_LEVEL_SECEVENT, "Security event");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 3);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[2].level == WH_LOG_LEVEL_SECEVENT);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[2].msg, "Security event",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);

    /* Test: WH_LOG_F creates proper entry with runtime string */
    {
        const char* runtime_info = "Runtime info message";
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "%s", runtime_info);
        WH_TEST_ASSERT_RETURN(mockCtx.count == 4);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[3].level == WH_LOG_LEVEL_INFO);
        WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[3].msg, runtime_info,
                                      WOLFHSM_CFG_LOG_MSG_MAX) == 0);
        WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[3].file, __FILE__,
                                      WOLFHSM_CFG_LOG_MSG_MAX) == 0);
        WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[3].function, __func__,
                                      WOLFHSM_CFG_LOG_MSG_MAX) == 0);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[3].line > 0);
    }

    /* Test: WH_LOG_F with empty string */
    {
        const char* empty_str = "";
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "%s", empty_str);
        WH_TEST_ASSERT_RETURN(mockCtx.count == 5);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[4].level == WH_LOG_LEVEL_INFO);
        WH_TEST_ASSERT_RETURN(
            strncmp(mockCtx.entries[4].msg, "", WOLFHSM_CFG_LOG_MSG_MAX) == 0);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[4].msg_len == 0);
    }

    /* Test: WH_LOG_F with string exactly at max length */
    {
        char exact_msg[WOLFHSM_CFG_LOG_MSG_MAX];
        int  i;
        /* Fill with 'B' characters, leaving room for null terminator */
        for (i = 0; i < WOLFHSM_CFG_LOG_MSG_MAX - 1; i++) {
            exact_msg[i] = 'B';
        }
        exact_msg[WOLFHSM_CFG_LOG_MSG_MAX - 1] = '\0';

        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "%s", exact_msg);
        WH_TEST_ASSERT_RETURN(mockCtx.count == 6);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[5].level == WH_LOG_LEVEL_INFO);
        /* Message should be exactly max length - 1 */
        WH_TEST_ASSERT_RETURN(mockCtx.entries[5].msg_len ==
                              WOLFHSM_CFG_LOG_MSG_MAX - 1);
        WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[5].msg, exact_msg,
                                      WOLFHSM_CFG_LOG_MSG_MAX) == 0);
        /* Should be null-terminated */
        WH_TEST_ASSERT_RETURN(
            mockCtx.entries[5].msg[mockCtx.entries[5].msg_len] == '\0');
    }

    /* Test: Log assert with true condition doesn't add log entry */
    WH_LOG_ASSERT(&logCtx, WH_LOG_LEVEL_ERROR, 1, "Assert Message");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 6);

    /* Test: Log assert with false condition adds log entry */
    WH_LOG_ASSERT(&logCtx, WH_LOG_LEVEL_ERROR, 0, "Assert Message");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 7);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[6].level == WH_LOG_LEVEL_ERROR);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[6].msg, "Assert Message",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);

    /* Test: Timestamp is populated */
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].timestamp > 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[1].timestamp >=
                          mockCtx.entries[0].timestamp);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));

    return 0;
}


static int whTest_LogFormattedMacros(void)
{
    whLogContext   logCtx;
    mockLogContext mockCtx;
    whLogConfig    logConfig;

    /* Setup */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&mockCtx, 0, sizeof(mockCtx));
    logConfig.cb      = &mockLogCb;
    logConfig.context = &mockCtx;
    logConfig.config  = NULL;

    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: WH_LOG_INFO_F with single integer */
    WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Value: %d", 42);
    WH_TEST_ASSERT_RETURN(mockCtx.count == 1);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].level == WH_LOG_LEVEL_INFO);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[0].msg, "Value: 42",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].msg_len == 9);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[0].file, __FILE__,
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[0].function, __func__,
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].line > 0);

    /* Test: WH_LOG_ERROR_F with multiple integers */
    WH_LOG_F(&logCtx, WH_LOG_LEVEL_ERROR, "x=%d, y=%d", 10, 20);
    WH_TEST_ASSERT_RETURN(mockCtx.count == 2);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[1].level == WH_LOG_LEVEL_ERROR);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[1].msg, "x=10, y=20",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[1].msg_len == 10);

    /* Test: WH_LOG_SECEVENT_F with string formatting */
    WH_LOG_F(&logCtx, WH_LOG_LEVEL_SECEVENT, "User: %s", "admin");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 3);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[2].level == WH_LOG_LEVEL_SECEVENT);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[2].msg, "User: admin",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[2].msg_len == 11);

    /* Test: WH_LOG_INFO_F with mixed types */
    WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Status %d: %s", 404, "Not Found");
    WH_TEST_ASSERT_RETURN(mockCtx.count == 4);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[3].level == WH_LOG_LEVEL_INFO);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[3].msg,
                                  "Status 404: Not Found",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[3].msg_len == 21);

    /* Test: WH_LOG_ERROR_F with hex formatting */
    WH_LOG_F(&logCtx, WH_LOG_LEVEL_ERROR, "Addr: 0x%08x", 0xDEADBEEF);
    WH_TEST_ASSERT_RETURN(mockCtx.count == 5);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[4].level == WH_LOG_LEVEL_ERROR);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[4].msg, "Addr: 0xdeadbeef",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[4].msg_len == 16);

    /* Test: WH_LOG_F generic macro with level */
    WH_LOG_F(&logCtx, WH_LOG_LEVEL_ERROR, "val=%d", 123);
    WH_TEST_ASSERT_RETURN(mockCtx.count == 6);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[5].level == WH_LOG_LEVEL_ERROR);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[5].msg, "val=123",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[5].msg_len == 7);

    /* Test: Long formatted output (truncation) */
    {
        char expected[WOLFHSM_CFG_LOG_MSG_MAX];
        char longStr[WOLFHSM_CFG_LOG_MSG_MAX + 100];

        /* Create a string longer than the log buffer limit and pass via %s */
        memset(longStr, 'X', sizeof(longStr) - 1);
        longStr[sizeof(longStr) - 1] = '\0';
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "%s", longStr);

        WH_TEST_ASSERT_RETURN(mockCtx.count == 7);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[6].level == WH_LOG_LEVEL_INFO);
        /* Message should be truncated to WOLFHSM_CFG_LOG_MSG_MAX - 1 */
        WH_TEST_ASSERT_RETURN(mockCtx.entries[6].msg_len ==
                              WOLFHSM_CFG_LOG_MSG_MAX - 1);
        /* Should be null-terminated */
        WH_TEST_ASSERT_RETURN(
            mockCtx.entries[6].msg[mockCtx.entries[6].msg_len] == '\0');

        /* Verify the beginning of the truncated message */
        memset(expected, 'X', WOLFHSM_CFG_LOG_MSG_MAX - 1);
        expected[WOLFHSM_CFG_LOG_MSG_MAX - 1] = '\0';
        /* Compare up to the truncated length */
        WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[6].msg, expected,
                                      WOLFHSM_CFG_LOG_MSG_MAX - 1) == 0);
    }

    /* Test: Format with multiple argument types */
    WH_LOG_F(&logCtx, WH_LOG_LEVEL_SECEVENT, "ID=%u, Name=%s, Code=0x%04x", 100,
             "test", 0xABCD);
    WH_TEST_ASSERT_RETURN(mockCtx.count == 8);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[7].level == WH_LOG_LEVEL_SECEVENT);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[7].msg,
                                  "ID=100, Name=test, Code=0xabcd",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[7].msg_len == 30);

    /* Test: Pointer formatting */
    {
        void* ptr = (void*)0x1234;
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Pointer: %p", ptr);
        WH_TEST_ASSERT_RETURN(mockCtx.count == 9);
        WH_TEST_ASSERT_RETURN(mockCtx.entries[8].level == WH_LOG_LEVEL_INFO);
        /* Just verify message contains "Pointer:" and is non-empty */
        WH_TEST_ASSERT_RETURN(mockCtx.entries[8].msg_len > 9);
        WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[8].msg, "Pointer: ", 9) ==
                              0);
    }

    /* Test: Character formatting */
    WH_LOG_F(&logCtx, WH_LOG_LEVEL_ERROR, "Char: %c", 'X');
    WH_TEST_ASSERT_RETURN(mockCtx.count == 10);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[9].msg, "Char: X",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[9].msg_len == 7);


    /* Test assert formatting with simple int args */
    WH_LOG_ASSERT_F(&logCtx, WH_LOG_LEVEL_ERROR, 0, "Assert Message: %d", 42);
    WH_TEST_ASSERT_RETURN(mockCtx.count == 11);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[10].level == WH_LOG_LEVEL_ERROR);
    WH_TEST_ASSERT_RETURN(strncmp(mockCtx.entries[10].msg, "Assert Message: 42",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);

    /* Test: Timestamp is populated */
    WH_TEST_ASSERT_RETURN(mockCtx.entries[0].timestamp > 0);
    WH_TEST_ASSERT_RETURN(mockCtx.entries[1].timestamp >=
                          mockCtx.entries[0].timestamp);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));

    return 0;
}


/*
 * Generic backend test - smoke test for basic operations
 */
static int whTest_LogBackend_BasicOperations(whTestLogBackendTestConfig* cfg)
{
    whLogContext logCtx;
    whLogConfig  logConfig;
    void*        backend_context;
    int          iterate_count;

    /* Use driver-provided backend context */
    backend_context = cfg->backend_context;
    WH_TEST_ASSERT_RETURN(backend_context != NULL);
    memset(backend_context, 0, cfg->config_size);

    /* Setup log configuration */
    memset(&logCtx, 0, sizeof(logCtx));
    logConfig.cb      = cfg->cb;
    logConfig.context = backend_context;
    logConfig.config  = cfg->config;

    /* Test: Init with valid config */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: Add single entry */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Single entry");
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 1);

    /* Test: Add multiple entries (3) */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Entry 0");
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Entry 1");
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Entry 2");

    /* Verify count via Iterate */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 4); /* 1 + 3 */

    /* Test: Clear and verify empty */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 0);

    /* Test: Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));

    return WH_ERROR_OK;
}

/*
 * Generic backend test - Capacity Handling
 * Tests behavior when buffer reaches capacity
 */
static int whTest_LogBackend_CapacityHandling(whTestLogBackendTestConfig* cfg)
{
    whLogContext logCtx;
    whLogConfig  logConfig;
    void*        backend_context;
    int          iterate_count;
    int          i;

    /* Skip if capacity is unlimited */
    if (cfg->expected_capacity < 0) {
        WH_TEST_PRINT("    Skipped (unlimited capacity)\n");
        return WH_ERROR_OK;
    }

    /* Use driver-provided backend context */
    backend_context = cfg->backend_context;
    WH_TEST_ASSERT_RETURN(backend_context != NULL);
    memset(backend_context, 0, cfg->config_size);

    /* Setup and init */
    memset(&logCtx, 0, sizeof(logCtx));
    logConfig.cb      = cfg->cb;
    logConfig.context = backend_context;
    logConfig.config  = cfg->config;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: Fill to capacity */
    for (i = 0; i < cfg->expected_capacity; i++) {
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Entry %d", i);
    }

    /* Verify count == capacity */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == cfg->expected_capacity);

    /* Test: Add 10 more entries (overflow) */
    for (i = 0; i < 10; i++) {
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Overflow %d", i);
    }

    /* Verify count still == capacity (overflow behavior) */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == cfg->expected_capacity);

    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    return WH_ERROR_OK;
}

/*
 * Generic backend test - Message Handling
 * Tests various message sizes and special characters
 */
static int whTest_LogBackend_MessageHandling(whTestLogBackendTestConfig* cfg)
{
    whLogContext logCtx;
    whLogConfig  logConfig;
    void*        backend_context;
    int          iterate_count;
    char         maxMsg[WOLFHSM_CFG_LOG_MSG_MAX];

    /* Use driver-provided backend context */
    backend_context = cfg->backend_context;
    WH_TEST_ASSERT_RETURN(backend_context != NULL);
    memset(backend_context, 0, cfg->config_size);

    /* Setup and init */
    memset(&logCtx, 0, sizeof(logCtx));
    logConfig.cb      = cfg->cb;
    logConfig.context = backend_context;
    logConfig.config  = cfg->config;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: Empty message */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "");

    /* Test: Short message */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Hi");

    /* Test: Max size message (255 chars + null) */
    memset(maxMsg, 'A', sizeof(maxMsg) - 1);
    maxMsg[sizeof(maxMsg) - 1] = '\0';
    WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "%s", maxMsg);


    /* Verify all entries were added */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 3);

    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    return WH_ERROR_OK;
}

/*
 * Generic backend test - Iteration
 * Tests iteration behavior in various scenarios
 */
static int whTest_LogBackend_Iteration(whTestLogBackendTestConfig* cfg)
{
    whLogContext logCtx;
    whLogConfig  logConfig;
    void*        backend_context;
    int          iterate_count;
    int          ret;

    /* Use driver-provided backend context */
    backend_context = cfg->backend_context;
    WH_TEST_ASSERT_RETURN(backend_context != NULL);
    memset(backend_context, 0, cfg->config_size);

    /* Setup and init */
    memset(&logCtx, 0, sizeof(logCtx));
    logConfig.cb      = cfg->cb;
    logConfig.context = backend_context;
    logConfig.config  = cfg->config;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Clear first to ensure clean state for persistent backends */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));

    /* Test: Iterate empty log */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 0);

    /* Test: Iterate single entry */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Single");
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 1);

    /* Test: Iterate 3 entries */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Entry 1");
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Entry 2");
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Entry 3");
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 3);

    /* Test: Early termination (callback returns magic number after
     * fixed number of entries) */
    iterate_count = 0;
    ret = wh_Log_Iterate(&logCtx, iterateCallbackStopAt2, &iterate_count);
    WH_TEST_ASSERT_RETURN(ret == ITERATE_STOP_MAGIC);
    WH_TEST_ASSERT_RETURN(iterate_count == ITERATE_STOP_COUNT);

    /* Test: Iterate after clear */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 0);

    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    return WH_ERROR_OK;
}

/*
 * Generic backend tests - Main runner
 * Executes all generic backend tests on a given backend test config
 */
int whTest_LogBackend_RunAll(whTestLogBackendTestConfig* cfg)
{
    int ret = 0;

    /* Call setup hook if provided */
    if (cfg->setup != NULL) {
        if (cfg->setup(&cfg->test_context) != 0) {
            WH_ERROR_PRINT("Setup hook failed\n");
            return WH_TEST_FAIL;
        }
    }

    /* Run all test suites */
    ret = whTest_LogBackend_BasicOperations(cfg);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("whTest_LogBackend_BasicOperations returned %d\n", ret);
    }

    if (ret == WH_ERROR_OK) {
        ret = whTest_LogBackend_CapacityHandling(cfg);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("whTest_LogBackend_CapacityHandling returned %d\n",
                           ret);
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = whTest_LogBackend_MessageHandling(cfg);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("whTest_LogBackend_MessageHandling returned %d\n",
                           ret);
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = whTest_LogBackend_Iteration(cfg);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("whTest_LogBackend_Iteration returned %d\n", ret);
        }
    }

    /* Call teardown hook if provided */
    if (cfg->teardown != NULL) {
        if (cfg->teardown(cfg->test_context) != 0) {
            WH_ERROR_PRINT("Teardown hook failed\n");
            return WH_TEST_FAIL;
        }
    }

    return ret;
}


/* Ring buffer backend tests */
static int whTest_LogRingbuf(void)
{
    whLogContext        logCtx;
    whLogRingbufContext ringbufCtx;
    whLogRingbufConfig  ringbufConfig;
    whLogConfig         logConfig;
    int                 i;
    int                 iterate_count;
    uint32_t            capacity;
    /* Backend storage for ring buffer */
    const size_t numLogEntries = 32;
    whLogEntry   ringbuf_buffer[32];
    whLogCb      ringbufCb = WH_LOG_RINGBUF_CB;

    /* Setup ring buffer backend */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&ringbufCtx, 0, sizeof(ringbufCtx));
    memset(&ringbuf_buffer, 0, sizeof(ringbuf_buffer));

    /* Configure ring buffer with user-supplied buffer */
    ringbufConfig.buffer      = ringbuf_buffer;
    ringbufConfig.buffer_size = sizeof(ringbuf_buffer);

    logConfig.cb      = &ringbufCb;
    logConfig.context = &ringbufCtx;
    logConfig.config  = &ringbufConfig;

    /* Test: Init with valid config */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));
    WH_TEST_ASSERT_RETURN(ringbufCtx.initialized == 1);
    WH_TEST_ASSERT_RETURN(ringbufCtx.count == 0);

    /* Get capacity from initialized context */
    capacity = ringbufCtx.capacity;
    WH_TEST_ASSERT_RETURN(capacity == numLogEntries);

    /* Test: Add a few entries */
    for (i = 0; i < 5; i++) {
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Message %d", i);
    }

    WH_TEST_ASSERT_RETURN(ringbufCtx.count == 5);

    /* Verify the entries are correct */
    WH_TEST_ASSERT_RETURN(ringbufCtx.count == 5);
    for (i = 0; i < 5; i++) {
        char expected[32];
        snprintf(expected, sizeof(expected), "Message %d", i);
        WH_TEST_ASSERT_RETURN(strncmp(ringbufCtx.entries[i].msg, expected,
                                      sizeof(expected)) == 0);
    }

    /* Test: Clear buffer */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    WH_TEST_ASSERT_RETURN(ringbufCtx.count == 0);

    /* Test: Fill buffer to capacity */
    for (i = 0; i < (int)capacity; i++) {
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Entry %d", i);
    }

    WH_TEST_ASSERT_RETURN(ringbufCtx.count == capacity);

    /* Test: Wraparound - add more entries to overwrite oldest */
    for (i = 0; i < 5; i++) {
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Wrapped %d", i);
    }

    /* Count increments freely to track total messages ever written */
    WH_TEST_ASSERT_RETURN(ringbufCtx.count == capacity + 5);

    /* Verify oldest entries were overwritten */
    WH_TEST_ASSERT_RETURN(strncmp(ringbufCtx.entries[0].msg, "Wrapped 0",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);
    WH_TEST_ASSERT_RETURN(strncmp(ringbufCtx.entries[4].msg, "Wrapped 4",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);

    /* Verify some non-overwritten entries still exist */
    WH_TEST_ASSERT_RETURN(strncmp(ringbufCtx.entries[5].msg, "Entry 5",
                                  WOLFHSM_CFG_LOG_MSG_MAX) == 0);

    /* Test: Iterate through ring buffer */
    /* Clear and add known entries for iteration test */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    for (i = 0; i < 3; i++) {
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Iterate test %d", i);
    }

    /* Count entries via iteration */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 3);

    /* Test: Iterate when buffer is full and wrapped */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    for (i = 0; i < (int)capacity + 5; i++) {
        WH_LOG_F(&logCtx, WH_LOG_LEVEL_INFO, "Wrap %d", i);
    }

    /* Should iterate exactly capacity entries */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == (int)capacity);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));
    WH_TEST_ASSERT_RETURN(ringbufCtx.initialized == 0);

    return 0;
}

/* Mock backend generic tests */
static int whTest_LogMock_Generic(void)
{
    mockLogContext             mockCtx;
    whTestLogBackendTestConfig testCfg;

    memset(&mockCtx, 0, sizeof(mockCtx));

    testCfg.backend_name        = "Mock";
    testCfg.cb                  = &mockLogCb;
    testCfg.config              = NULL;
    testCfg.config_size         = sizeof(mockLogContext);
    testCfg.backend_context     = &mockCtx;
    testCfg.expected_capacity   = MOCK_LOG_MAX_ENTRIES;
    testCfg.supports_concurrent = 0;
    testCfg.setup               = NULL;
    testCfg.teardown            = NULL;
    testCfg.test_context        = NULL;

    return whTest_LogBackend_RunAll(&testCfg);
}

/* Ring buffer backend generic tests */
static int whTest_LogRingbuf_Generic(void)
{
    whLogRingbufContext        ringbufCtx;
    whLogRingbufConfig         ringbufConfig;
    whTestLogBackendTestConfig testCfg;
    whLogCb                    ringbufCb;
    const size_t               numLogEntries = 32;
    static whLogEntry          ringbuf_buffer[32];

    /* Setup ring buffer configuration with user-supplied buffer */
    memset(&ringbuf_buffer, 0, sizeof(ringbuf_buffer));
    memset(&ringbufCtx, 0, sizeof(ringbufCtx));
    ringbufConfig.buffer      = ringbuf_buffer;
    ringbufConfig.buffer_size = sizeof(ringbuf_buffer);

    /* Initialize callback table (C90 compatible) */
    memset(&ringbufCb, 0, sizeof(ringbufCb));
    ringbufCb.Init     = whLogRingbuf_Init;
    ringbufCb.Cleanup  = whLogRingbuf_Cleanup;
    ringbufCb.AddEntry = whLogRingbuf_AddEntry;
    ringbufCb.Export   = whLogRingbuf_Export;
    ringbufCb.Iterate  = whLogRingbuf_Iterate;
    ringbufCb.Clear    = whLogRingbuf_Clear;

    testCfg.backend_name        = "RingBuffer";
    testCfg.cb                  = &ringbufCb;
    testCfg.config              = &ringbufConfig;
    testCfg.config_size         = sizeof(whLogRingbufContext);
    testCfg.backend_context     = &ringbufCtx;
    testCfg.expected_capacity   = numLogEntries;
    testCfg.supports_concurrent = 0;
    testCfg.setup               = NULL;
    testCfg.teardown            = NULL;
    testCfg.test_context        = NULL;

    return whTest_LogBackend_RunAll(&testCfg);
}

/* Printf backend tests. The printf backend is a write-only sink: it
 * implements only Init and AddEntry, so the remaining frontend ops
 * report NOTIMPL. Exercises both the "log always" and "drop unless
 * debug" config paths and the bad-args/uninitialized rejections. */
static int whTest_LogPrintf(void)
{
    whLogContext       logCtx;
    whLogPrintfContext printfCtx;
    whLogPrintfConfig  printfCfg;
    whLogConfig        logConfig;
    whLogCb            printfCb      = WH_LOG_PRINTF_CB;
    whLogEntry         entry         = {0};
    int                iterate_count = 0;

    memset(&printfCtx, 0, sizeof(printfCtx));

    /* Direct backend bad-args rejections */
    WH_TEST_ASSERT_RETURN(whLogPrintf_Init(NULL, NULL) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(whLogPrintf_AddEntry(NULL, &entry) ==
                          WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(whLogPrintf_AddEntry(&printfCtx, NULL) ==
                          WH_ERROR_BADARGS);

    /* Adding to an uninitialized backend is rejected */
    WH_TEST_ASSERT_RETURN(whLogPrintf_AddEntry(&printfCtx, &entry) ==
                          WH_ERROR_ABORTED);

    /* Init with NULL config uses defaults (logIfNotDebug = 0) */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&printfCtx, 0, sizeof(printfCtx));
    logConfig.cb      = &printfCb;
    logConfig.context = &printfCtx;
    logConfig.config  = NULL;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));
    WH_TEST_ASSERT_RETURN(printfCtx.initialized == 1);
    WH_TEST_ASSERT_RETURN(printfCtx.logIfNotDebug == 0);

    /* With logIfNotDebug = 0 and a non-debug build, entries are dropped */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Dropped unless debug build");

    /* Re-init with logIfNotDebug = 1 so entries are always printed */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&printfCtx, 0, sizeof(printfCtx));
    printfCfg.logIfNotDebug = 1;
    logConfig.config        = &printfCfg;
    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));
    WH_TEST_ASSERT_RETURN(printfCtx.logIfNotDebug == 1);

    /* Exercise the print path for each known level */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Printf info");
    WH_LOG(&logCtx, WH_LOG_LEVEL_ERROR, "Printf error");
    WH_LOG(&logCtx, WH_LOG_LEVEL_SECEVENT, "Printf secevent");

    /* An out-of-range level exercises the level-to-string default */
    entry.timestamp = 1;
    entry.level     = (whLogLevel)999;
    entry.file      = __FILE__;
    entry.function  = __func__;
    entry.line      = __LINE__;
    entry.msg_len   = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Log_AddEntry(&logCtx, &entry));

    /* The printf backend implements no store, so the remaining frontend
     * operations report NOTIMPL */
    WH_TEST_ASSERT_RETURN(wh_Log_Cleanup(&logCtx) == WH_ERROR_NOTIMPL);
    WH_TEST_ASSERT_RETURN(wh_Log_Export(&logCtx, NULL) == WH_ERROR_NOTIMPL);
    WH_TEST_ASSERT_RETURN(
        wh_Log_Iterate(&logCtx, iterateCallbackCount, &iterate_count) ==
        WH_ERROR_NOTIMPL);
    WH_TEST_ASSERT_RETURN(wh_Log_Clear(&logCtx) == WH_ERROR_NOTIMPL);

    return WH_ERROR_OK;
}

/* Portable log test entry point (Misc group) */
int whTest_Log(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing log frontend API...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogFrontend());

    WH_TEST_PRINT("Testing log macros...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogMacros());

    WH_TEST_PRINT("Testing formatted log macros...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogFormattedMacros());

    WH_TEST_PRINT("Testing mock log backend in generic harness...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogMock_Generic());

    WH_TEST_PRINT("Testing ringbuf backend in generic harness...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogRingbuf_Generic());

    WH_TEST_PRINT("Testing ring buffer backend...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogRingbuf());

    WH_TEST_PRINT("Testing printf backend...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_LogPrintf());

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_LOGGING */
