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
 * test-refactor/wh_test_posix_main.c
 *
 * POSIX threaded test driver. Runs the misc group inline, then
 * spawns a server thread and a client thread. The server thread
 * runs the server-only group first (no client is active yet),
 * then marks itself connected, signals the client thread, and
 * enters a request-handling loop. The client thread waits for
 * that signal, runs the client-only group against the live
 * server, and calls CommClose -- the server processes the close
 * message, drops its connected state, and the loop exits on the
 * next iteration. Suite dispatch is delegated to the portable
 * group entry points in wh_test_groups.c; this file also
 * implements the reset hooks they invoke between suites.
 */

#include <pthread.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server.h"

#include "wh_test_common.h"
#include "wh_test_groups.h"
#include "wh_test_list.h"
#include "wh_test_port.h"

#include "wh_test_posix_client.h"
#include "wh_test_posix_server.h"

/* POSIX-only thread-safety stress test. Called directly rather
 * than through the suite runner: the legacy test owns its own
 * client/server threads and doesn't fit the runner's context
 * model. Kept out of the portable client group since it's not
 * meaningful (or portable) on bare-metal client targets. */
#if defined(WOLFHSM_CFG_THREADSAFE) \
    && defined(WOLFHSM_CFG_GLOBAL_KEYS) \
    && !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wh_test_posix_threadsafe_stress.h"
#endif

/* Host-sim flash/NVM tests. The ramsim test exercises the
 * RAM-based flash simulator, which is a host-sim component;
 * the nvm_flash test wires the NVM stack to that simulator
 * with a 1 MB buffer that's not realistic on embedded targets.
 * Both run from the POSIX port directly until the NVM test is
 * reworked to take a port-supplied flash fixture (then it can
 * lift back into whTestGroup_Server). */
int whTest_FlashWriteLock(void* ctx);
int whTest_FlashEraseProgramVerify(void* ctx);
int whTest_FlashUnitOps(void* ctx);
int whTest_NvmAddOverwriteDestroy(void* ctx);

/*
 * Port-owned contexts. The thread functions fill these in and
 * hand them to the group functions, paralleling the firmware
 * pattern where these handles come from the normal init flow.
 */
static whServerContext _server;
static whClientContext _client;

/*
 * Server-ready gate. The client thread blocks on this until
 * the server finishes its group and enters the request loop,
 * so the client never issues a request against a server that
 * isn't listening yet.
 */
static pthread_mutex_t _readyMtx   = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  _readyCond  = PTHREAD_COND_INITIALIZER;
static int             _serverReady = 0;

/*
 * Per-thread return codes. main collects these after join so a
 * failure in either thread propagates to the process exit
 * status.
 */
static int _serverRc = 0;
static int _clientRc = 0;


static void _signalServerReady(void)
{
    pthread_mutex_lock(&_readyMtx);
    _serverReady = 1;
    pthread_cond_broadcast(&_readyCond);
    pthread_mutex_unlock(&_readyMtx);
}


static void _waitServerReady(void)
{
    pthread_mutex_lock(&_readyMtx);
    while (_serverReady == 0) {
        pthread_cond_wait(&_readyCond, &_readyMtx);
    }
    pthread_mutex_unlock(&_readyMtx);
}


static void* _serverThread(void* arg)
{
    whCommConnected connected = WH_COMM_CONNECTED;
    int             rc;

    (void)arg;

    rc = whTestPosix_Server_Init(&_server);
    if (rc != 0) {
        _serverRc = rc;
        /* Release the client thread so it doesn't stall on the
         * ready gate waiting for a server that never came up. */
        _signalServerReady();
        return NULL;
    }

    rc = whTestGroup_Server(&_server);
    if (rc != 0) {
        _serverRc = rc;
        (void)whTestPosix_Server_Cleanup(&_server);
        _signalServerReady();
        return NULL;
    }

    /* Mark connected before signaling -- otherwise the client's
     * CommInit request can arrive before the server is willing
     * to handle it and HandleRequestMessage short-circuits to
     * NOTREADY. */
    rc = wh_Server_SetConnected(&_server, WH_COMM_CONNECTED);
    if (rc != 0) {
        _serverRc = rc;
        (void)whTestPosix_Server_Cleanup(&_server);
        _signalServerReady();
        return NULL;
    }

    _signalServerReady();

    /* Handle requests until the server's CommClose handler flips
     * us to DISCONNECTED in response to the client's CommClose
     * message. */
    while (1) {
        rc = wh_Server_HandleRequestMessage(&_server);
        if (rc != WH_ERROR_OK && rc != WH_ERROR_NOTREADY) {
            _serverRc = rc;
            break;
        }
        (void)wh_Server_GetConnected(&_server, &connected);
        if (connected == WH_COMM_DISCONNECTED) {
            break;
        }
    }

    (void)whTestPosix_Server_Cleanup(&_server);
    return NULL;
}


static void* _clientThread(void* arg)
{
    int rc;

    (void)arg;

    _waitServerReady();

    /* Server init or the server-only group may have failed.
     * Don't try to talk to a server that never entered the
     * request loop; propagate the server's error instead. */
    if (_serverRc != 0) {
        _clientRc = _serverRc;
        return NULL;
    }

    rc = whTestPosix_Client_Init(&_client);
    if (rc != 0) {
        _clientRc = rc;
        return NULL;
    }

    rc = whTestGroup_Client(&_client);
    if (rc != 0) {
        _clientRc = rc;
    }

#if defined(WOLFHSM_CFG_THREADSAFE) \
    && defined(WOLFHSM_CFG_GLOBAL_KEYS) \
    && !defined(WOLFHSM_CFG_NO_CRYPTO)
    /* Run the POSIX-only stress test after the portable client
     * group so a failure there doesn't mask earlier results. */
    if (_clientRc == 0) {
        rc = whTest_ThreadSafeStress();
        if (rc != 0) {
            _clientRc = rc;
        }
    }
#endif

    /* CommClose triggers the server-side SetConnected(DISCONNECTED)
     * inside HandleRequestMessage, which is what lets the server
     * thread exit its loop. Always attempt it so the server can
     * shut down even when a test failed. */
    (void)wh_Client_CommClose(&_client);
    (void)whTestPosix_Client_Cleanup(&_client);
    return NULL;
}


int main(void)
{
    pthread_t sthread;
    pthread_t cthread;
    int       rc;
    int       miscRc;

    /* Run everything to the end so the summary reflects the
     * whole suite; a misc failure doesn't skip the client or
     * server groups. */
    miscRc = whTestGroup_Misc();

    /* POSIX-only host-sim flash/NVM tests. Run inline alongside
     * the misc group so they appear in the same pre-server slot
     * in the suite output. */
    {
        int rc;
        rc = whTestGroup_RunOne("whTest_FlashWriteLock",
            whTest_FlashWriteLock, NULL);
        if (rc != 0 && rc != WH_TEST_SKIPPED && miscRc == 0) {
            miscRc = rc;
        }
        rc = whTestGroup_RunOne("whTest_FlashEraseProgramVerify",
            whTest_FlashEraseProgramVerify, NULL);
        if (rc != 0 && rc != WH_TEST_SKIPPED && miscRc == 0) {
            miscRc = rc;
        }
        rc = whTestGroup_RunOne("whTest_FlashUnitOps",
            whTest_FlashUnitOps, NULL);
        if (rc != 0 && rc != WH_TEST_SKIPPED && miscRc == 0) {
            miscRc = rc;
        }
        rc = whTestGroup_RunOne("whTest_NvmAddOverwriteDestroy",
            whTest_NvmAddOverwriteDestroy, NULL);
        if (rc != 0 && rc != WH_TEST_SKIPPED && miscRc == 0) {
            miscRc = rc;
        }
    }

    rc = pthread_create(&sthread, NULL, _serverThread, NULL);
    if (rc != 0) {
        (void)whTestGroup_Summary();
        return rc;
    }

    rc = pthread_create(&cthread, NULL, _clientThread, NULL);
    if (rc != 0) {
        /* Drop the server out of its loop so the best-effort
         * join below doesn't block forever. */
        (void)wh_Server_SetConnected(&_server,
            WH_COMM_DISCONNECTED);
        (void)pthread_join(sthread, NULL);
        (void)whTestGroup_Summary();
        return rc;
    }

    (void)pthread_join(cthread, NULL);
    (void)pthread_join(sthread, NULL);

    (void)whTestGroup_Summary();

    if (miscRc != 0) {
        return miscRc;
    }
    if (_serverRc != 0) {
        return _serverRc;
    }
    return _clientRc;
}


/*
 * Reset hooks invoked by the group functions between suites.
 * Placeholder implementations -- once suites drop their own
 * setup/cleanup and run against the live contexts, these get
 * filled in to scrub persistent state (key cache, NVM, etc.).
 */
int whTestPort_ResetServer(whServerContext* server)
{
    (void)server;
    return 0;
}


int whTestPort_ResetClient(whClientContext* client)
{
    (void)client;
    return 0;
}
