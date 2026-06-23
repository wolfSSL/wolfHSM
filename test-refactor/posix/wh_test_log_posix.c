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
 * test-refactor/posix/wh_test_log_posix.c
 *
 * POSIX-specific logging tests from legacy test/wh_test_log.c: the
 * POSIX file backend (via the shared generic harness and directly),
 * concurrent access from multiple threads, and a client/server log
 * smoke test over the mem transport. These are invoked from the POSIX
 * port main via whTestGroup_RunOne, not from the portable registry.
 */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFHSM_CFG_LOGGING)

#include <pthread.h>
#include <unistd.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_log.h"

#include "port/posix/posix_log_file.h"

#include "wh_test_log_backend.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfhsm/wh_server_crypto.h"
#endif
#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */


/* Helper for iterate callback - counts entries */
static int _logIterateCount(void* arg, const whLogEntry* entry)
{
    int* count = (int*)arg;
    (void)entry;
    (*count)++;
    return 0;
}


/* POSIX file backend in the generic harness */
int whTest_LogPosixFile_Generic(void* ctx)
{
    posixLogFileContext        posixCtx;
    posixLogFileConfig         posixCfg;
    whTestLogBackendTestConfig testCfg;
    whLogCb                    posixCb;
    const char*                test_log_file = "/tmp/wolfhsm_test_generic.log";

    (void)ctx;

    /* Initialize callback table (C90 compatible) */
    memset(&posixCtx, 0, sizeof(posixCtx));
    memset(&posixCb, 0, sizeof(posixCb));
    posixCb.Init     = posixLogFile_Init;
    posixCb.Cleanup  = posixLogFile_Cleanup;
    posixCb.AddEntry = posixLogFile_AddEntry;
    posixCb.Export   = posixLogFile_Export;
    posixCb.Iterate  = posixLogFile_Iterate;
    posixCb.Clear    = posixLogFile_Clear;

    /* Remove any existing test log file */
    unlink(test_log_file);

    posixCfg.filename = test_log_file;

    testCfg.backend_name        = "PosixFile";
    testCfg.cb                  = &posixCb;
    testCfg.config              = &posixCfg;
    testCfg.config_size         = sizeof(posixLogFileContext);
    testCfg.backend_context     = &posixCtx;
    testCfg.expected_capacity   = -1; /* Unlimited */
    testCfg.supports_concurrent = 1;
    testCfg.setup               = NULL;
    testCfg.teardown            = NULL;
    testCfg.test_context        = NULL;

    return whTest_LogBackend_RunAll(&testCfg);
}


/* POSIX file backend tests */
int whTest_LogPosixFile(void* ctx)
{
    whLogContext        logCtx;
    posixLogFileContext posixCtx;
    posixLogFileConfig  posixCfg;
    whLogConfig         logConfig;
    whLogCb             posixCb       = POSIX_LOG_FILE_CB;
    const char*         test_log_file = "/tmp/wolfhsm_test_log.txt";
    int                 export_count;
    int                 iterate_count;
    FILE*               export_fp;
    char                line[2048];

    (void)ctx;

    /* Remove any existing test log file */
    unlink(test_log_file);

    /* Test: Create log file, add entries, verify file exists */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&posixCtx, 0, sizeof(posixCtx));
    posixCfg.filename = test_log_file;

    logConfig.cb      = &posixCb;
    logConfig.context = &posixCtx;
    logConfig.config  = &posixCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));
    WH_TEST_ASSERT_RETURN(posixCtx.initialized == 1);
    WH_TEST_ASSERT_RETURN(posixCtx.fd >= 0);

    /* Add some log entries */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "First info message");
    WH_LOG(&logCtx, WH_LOG_LEVEL_ERROR, "First error message");
    WH_LOG(&logCtx, WH_LOG_LEVEL_SECEVENT, "First security event");

    /* Test: Export reads back all entries correctly */
    /* For POSIX backend, export to a temp file and count lines */
    export_fp = tmpfile();
    WH_TEST_ASSERT_RETURN(export_fp != NULL);
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, export_fp));
    fflush(export_fp);
    rewind(export_fp);

    export_count = 0;
    while (fgets(line, sizeof(line), export_fp) != NULL) {
        export_count++;
    }
    fclose(export_fp);
    WH_TEST_ASSERT_RETURN(export_count == 3);

    /* Test: Append preserves existing entries */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Second info message");
    export_fp = tmpfile();
    WH_TEST_ASSERT_RETURN(export_fp != NULL);
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, export_fp));
    fflush(export_fp);
    rewind(export_fp);

    export_count = 0;
    while (fgets(line, sizeof(line), export_fp) != NULL) {
        export_count++;
    }
    fclose(export_fp);
    WH_TEST_ASSERT_RETURN(export_count == 4);

    /* Test: Clear truncates file */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Clear(&logCtx));
    export_fp = tmpfile();
    WH_TEST_ASSERT_RETURN(export_fp != NULL);
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, export_fp));
    fflush(export_fp);
    rewind(export_fp);

    export_count = 0;
    while (fgets(line, sizeof(line), export_fp) != NULL) {
        export_count++;
    }
    fclose(export_fp);
    WH_TEST_ASSERT_RETURN(export_count == 0);

    /* Test: Iterate functionality with parsing */
    /* Add entries for iterate test */
    WH_LOG(&logCtx, WH_LOG_LEVEL_INFO, "Iterate message 1");
    WH_LOG(&logCtx, WH_LOG_LEVEL_ERROR, "Iterate message 2");
    WH_LOG(&logCtx, WH_LOG_LEVEL_SECEVENT, "Iterate message 3");

    /* Count entries via iteration */
    iterate_count = 0;
    WH_TEST_RETURN_ON_FAIL(
        wh_Log_Iterate(&logCtx, _logIterateCount, &iterate_count));
    WH_TEST_ASSERT_RETURN(iterate_count == 3);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));

    /* Remove test log file */
    unlink(test_log_file);

    return 0;
}


/* Thread function for concurrent access test */
typedef struct {
    whLogContext* ctx;
    int           thread_id;
    int           iterations;
} thread_test_args;

static void* threadTestFunc(void* arg)
{
    thread_test_args* args = (thread_test_args*)arg;
    int               i;

    for (i = 0; i < args->iterations; i++) {
        WH_LOG_F(args->ctx, WH_LOG_LEVEL_INFO, "Thread %d iteration %d",
                 args->thread_id, i);
    }

    return (void*)0;
}

int whTest_LogPosixFileConcurrent(void* ctx)
{
    whLogContext        logCtx;
    posixLogFileContext posixCtx;
    posixLogFileConfig  posixCfg;
    whLogConfig         logConfig;
    whLogCb             posixCb       = POSIX_LOG_FILE_CB;
    const char*         test_log_file = "/tmp/wolfhsm_test_log_concurrent.txt";
    int                 export_count;
    const int           NUM_THREADS           = 4;
    const int           ITERATIONS_PER_THREAD = 10;
    pthread_t           threads[4];
    thread_test_args    args[4];
    int                 i;
    FILE*               verify_fp;
    char                line[2048];

    (void)ctx;

    /* Remove any existing test log file */
    unlink(test_log_file);

    /* Setup */
    memset(&logCtx, 0, sizeof(logCtx));
    memset(&posixCtx, 0, sizeof(posixCtx));
    posixCfg.filename = test_log_file;

    logConfig.cb      = &posixCb;
    logConfig.context = &posixCtx;
    logConfig.config  = &posixCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Log_Init(&logCtx, &logConfig));

    /* Test: Concurrent access from multiple threads */
    for (i = 0; i < NUM_THREADS; i++) {
        args[i].ctx        = &logCtx;
        args[i].thread_id  = i;
        args[i].iterations = ITERATIONS_PER_THREAD;

        if (pthread_create(&threads[i], NULL, threadTestFunc, &args[i]) != 0) {
            WH_ERROR_PRINT("Failed to create thread %d\n", i);
            return WH_TEST_FAIL;
        }
    }

    /* Wait for all threads */
    for (i = 0; i < NUM_THREADS; i++) {
        void* result;
        pthread_join(threads[i], &result);
        if (result != (void*)0) {
            WH_ERROR_PRINT("Thread %d failed\n", i);
            return WH_TEST_FAIL;
        }
    }

    /* Verify all entries were written */
    /* For POSIX backend, export to a temp file and count lines */
    verify_fp = tmpfile();
    WH_TEST_ASSERT_RETURN(verify_fp != NULL);
    WH_TEST_RETURN_ON_FAIL(wh_Log_Export(&logCtx, verify_fp));
    fflush(verify_fp);
    rewind(verify_fp);

    /* Count lines in exported file */
    export_count = 0;
    while (fgets(line, sizeof(line), verify_fp) != NULL) {
        export_count++;
    }
    fclose(verify_fp);
    WH_TEST_ASSERT_RETURN(export_count == NUM_THREADS * ITERATIONS_PER_THREAD);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Log_Cleanup(&logCtx));

    /* Remove test log file */
    unlink(test_log_file);

    return 0;
}


#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#define WH_LOG_TEST_FLASH_RAM_SIZE (1024 * 1024)
#define WH_LOG_TEST_FLASH_SECTOR_SIZE (128 * 1024)
#define WH_LOG_TEST_FLASH_PAGE_SIZE (8)
#define WH_LOG_TEST_SERVER_LOG_FILE "/tmp/wh_log_clientserver_posix.txt"

enum {
    WH_LOG_TEST_BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                              WOLFHSM_CFG_COMM_DATA_LEN,
};

static int _clientServerLogSmokeTest(whClientContext* client)
{
    FILE*  log_file         = NULL;
    size_t entry_count      = 0;
    char   line[1024];
    size_t expected_entries = 3;

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    /* When authentication is compiled in but no auth context is configured,
     * server init emits an extra SECEVENT warning after the startup INFO log */
    expected_entries++;
#endif

    /* Connect to the server, which should trigger an info log entry */
    WH_TEST_ASSERT(WH_ERROR_OK == wh_Client_CommInit(client, NULL, NULL));

    /* Disconnect the server, which should trigger an info log entry */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommClose(client));

    /* Now read the log file and verify that the log entries are present */
    log_file = fopen(WH_LOG_TEST_SERVER_LOG_FILE, "r");
    WH_TEST_ASSERT(log_file != NULL);

    while (fgets(line, sizeof(line), log_file) != NULL) {
        entry_count++;
        WH_TEST_PRINT("Log entry: %s", line);

        /* First log entry should be startup INFO log */
        if (entry_count == 1) {
            WH_TEST_ASSERT(strstr(line, "INFO") != NULL);
        }
#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
        else if (entry_count == 2) {
            /* Auth enabled with no auth context triggers a SECEVENT */
            WH_TEST_ASSERT(strstr(line, "SECEVENT") != NULL);
        }
        else if (entry_count == 3) {
            WH_TEST_ASSERT(strstr(line, "INFO") != NULL);
        }
        else if (entry_count == 4) {
            WH_TEST_ASSERT(strstr(line, "INFO") != NULL);
        }
#else
        else if (entry_count == 2) {
            /* Second log entry should the connect INFO log */
            WH_TEST_ASSERT(strstr(line, "INFO") != NULL);
        }
        else if (entry_count == 3) {
            /* Third log entry should be another INFO from comm close */
            WH_TEST_ASSERT(strstr(line, "INFO") != NULL);
        }
#endif
        else {
            break;
        }
    }
    fclose(log_file);

    /* Ensure we have at least the number of expected log entries */
    WH_TEST_ASSERT(entry_count >= expected_entries);

    return WH_ERROR_OK;
}

static void* _whLogClientTask(void* cfg)
{
    whClientConfig* client_cfg = (whClientConfig*)cfg;
    whClientContext client[1]  = {{0}};

    if (client_cfg == NULL) {
        return NULL;
    }

    WH_TEST_ASSERT(WH_ERROR_OK == wh_Client_Init(client, client_cfg));

    WH_TEST_ASSERT(WH_ERROR_OK == _clientServerLogSmokeTest(client));

    WH_TEST_ASSERT(WH_ERROR_OK == wh_Client_Cleanup(client));
    return NULL;
}

static void* _whLogServerTask(void* cfg)
{
    whServerConfig* server_cfg = (whServerConfig*)cfg;
    whServerContext server[1]  = {{0}};
    whCommConnected connected  = WH_COMM_CONNECTED;
    int             ret;

    if (server_cfg == NULL) {
        return NULL;
    }

    WH_TEST_ASSERT(WH_ERROR_OK == wh_Server_Init(server, server_cfg));
    WH_TEST_ASSERT(WH_ERROR_OK == wh_Server_SetConnected(server, connected));

    while (connected == WH_COMM_CONNECTED) {
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) && (ret != WH_ERROR_OK)) {
            WH_ERROR_PRINT(
                "[server] Failed to wh_Server_HandleRequestMessage ret=%d\n",
                ret);
            break;
        }
        wh_Server_GetConnected(server, &connected);
    }

    WH_TEST_ASSERT(0 == wh_Server_Cleanup(server));
    return NULL;
}

static void _whLogClientServerThreadTest(whClientConfig* c_conf,
                                         whServerConfig* s_conf)
{
    pthread_t client_thread;
    pthread_t server_thread;
    void*     retval = NULL;
    int       rc;

    rc = pthread_create(&server_thread, NULL, _whLogServerTask, s_conf);
    WH_TEST_ASSERT(rc == 0);

    rc = pthread_create(&client_thread, NULL, _whLogClientTask, c_conf);
    if (rc != 0) {
        pthread_cancel(server_thread);
        pthread_join(server_thread, &retval);
        WH_TEST_ASSERT(rc == 0);
        return;
    }

    pthread_join(client_thread, &retval);
    pthread_join(server_thread, &retval);
}

int whTest_LogClientServerMemTransport(void* ctx)
{
    uint8_t              req[WH_LOG_TEST_BUFFER_SIZE]  = {0};
    uint8_t              resp[WH_LOG_TEST_BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]                       = {{
                              .req       = (whTransportMemCsr*)req,
                              .req_size  = sizeof(req),
                              .resp      = (whTransportMemCsr*)resp,
                              .resp_size = sizeof(resp),
    }};

    /* Client configuration */
    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {{0}};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};

#ifdef WOLFHSM_CFG_DMA
    whClientDmaConfig clientDmaConfig = {0};
#endif

    whClientConfig c_conf[1] = {{
        .comm = cc_conf,
#ifdef WOLFHSM_CFG_DMA
        .dmaConfig = &clientDmaConfig,
#endif
    }};

    /* Server configuration */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {{0}};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    uint8_t          memory[WH_LOG_TEST_FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]                              = {{0}};
    whFlashRamsimCfg fc_conf[1]                         = {{
                                .size       = WH_LOG_TEST_FLASH_RAM_SIZE,
                                .sectorSize = WH_LOG_TEST_FLASH_SECTOR_SIZE,
                                .pageSize   = WH_LOG_TEST_FLASH_PAGE_SIZE,
                                .erasedByte = ~(uint8_t)0,
                                .memory     = memory,
    }};
    const whFlashCb  fcb[1]                             = {WH_FLASH_RAMSIM_CB};

    whTestNvmBackendUnion nvm_setup;
    whNvmConfig           n_conf[1] = {0};
    whNvmContext          nvm[1]    = {{0}};

#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext crypto[1] = {0};
#endif

    posixLogFileContext posixCtx[1]  = {0};
    posixLogFileConfig  posixCfg[1]  = {{
          .filename = WH_LOG_TEST_SERVER_LOG_FILE,
    }};
    whLogCb             posixCb      = POSIX_LOG_FILE_CB;
    whLogConfig         logConfig[1] = {{
                .cb      = &posixCb,
                .context = posixCtx,
                .config  = posixCfg,
    }};

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
        .crypto = crypto,
        .devId  = INVALID_DEVID,
#endif
        .logConfig = logConfig,
    }};

    (void)ctx;

    WH_TEST_RETURN_ON_FAIL(whTest_NvmCfgBackend(
        WH_NVM_TEST_BACKEND_FLASH, &nvm_setup, n_conf, fc_conf, fc, fcb));

    unlink(WH_LOG_TEST_SERVER_LOG_FILE);

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));
#endif

    _whLogClientServerThreadTest(c_conf, s_conf);

#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();
#endif
    wh_Nvm_Cleanup(nvm);

    return WH_ERROR_OK;
}

#else /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */

int whTest_LogClientServerMemTransport(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */

#else /* WOLFHSM_CFG_LOGGING */

int whTest_LogPosixFile_Generic(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

int whTest_LogPosixFile(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

int whTest_LogPosixFileConcurrent(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

int whTest_LogClientServerMemTransport(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

#endif /* WOLFHSM_CFG_LOGGING */
