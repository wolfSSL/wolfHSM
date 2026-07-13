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
 * test-refactor/misc/wh_test_she_uid_cb.c
 *
 * SHE UID storage callback tests. Lives in the misc group because it needs to
 * build its own whServerConfig to exercise the sheConfig init path, which the
 * port's shared server cannot provide. The server is driven directly through
 * wh_Server_HandleSheRequest, so no client or transport pumping is needed.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_SHE_EXTENSION) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_she.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_she.h"
#include "wolfhsm/wh_she_common.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Value from the wh_server_she.c internal WH_SHE_SB_STATE enum. Mirrored here
 * since the enum is private to that translation unit. */
#define TEST_SHE_SB_STATE_SUCCESS 3

enum {
    BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                  WOLFHSM_CFG_COMM_DATA_LEN,
};

/* UID reported by the read-only backing store */
static const uint8_t s_fusedUid[WH_SHE_UID_SZ] = {
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE};

/* UID a client provisions over the wire */
static const uint8_t s_wireUid[WH_SHE_UID_SZ] = {0x11, 0x22, 0x33, 0x44, 0x55,
                                                 0x66, 0x77, 0x88, 0x99, 0xAA,
                                                 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

/* Integrator-supplied UID store, standing in for NVM, fuses or static RAM */
typedef struct {
    uint8_t uid[WH_SHE_UID_SZ];
    int     provisioned;
    int     readOnly;
    int     getErr; /* forced error from the get callback */
    int     getCount;
    int     setCount;
} TestUidStore;

typedef struct {
    whServerContext       server[1];
    whServerCryptoContext crypto[1];
    whServerSheContext    she[1];
    whServerSheConfig     sheConfig[1];
    whServerConfig        s_conf[1];
    /* Transport, server side only */
    uint8_t                     reqBuf[BUFFER_SIZE];
    uint8_t                     respBuf[BUFFER_SIZE];
    whTransportMemConfig        tmcf[1];
    whTransportServerCb         tscb[1];
    whTransportMemServerContext tmsc[1];
    whCommServerConfig          cs_conf[1];
} TestCtx;

/* Static to keep the misc group's stack footprint small */
static TestCtx     _testCtx;
static TestUidStore _uidStore;

static int _TestGetUid(struct whServerContext_t* server, void* ctx,
                       uint8_t* outUid)
{
    TestUidStore* store = (TestUidStore*)ctx;
    (void)server;

    store->getCount++;

    if (store->getErr != 0) {
        return store->getErr;
    }
    if (store->provisioned == 0) {
        return WH_ERROR_NOTFOUND;
    }
    memcpy(outUid, store->uid, WH_SHE_UID_SZ);
    return WH_ERROR_OK;
}

static int _TestSetUid(struct whServerContext_t* server, void* ctx,
                       const uint8_t* uid)
{
    TestUidStore* store = (TestUidStore*)ctx;
    (void)server;

    store->setCount++;

    memcpy(store->uid, uid, WH_SHE_UID_SZ);
    store->provisioned = 1;
    return WH_ERROR_OK;
}

/* Send one SHE action through the server and return its response rc. */
static int32_t _SheActionRc(whServerContext* server, uint16_t action,
                            const void* req_packet, uint16_t req_size,
                            void* resp_packet)
{
    uint16_t resp_size = 0;
    int      ret;

    *((int32_t*)resp_packet) = WH_SHE_ERC_NO_ERROR;
    ret = wh_Server_HandleSheRequest(server, WH_COMM_MAGIC_NATIVE, action,
                                     req_size, req_packet, &resp_size,
                                     resp_packet);
    if (ret != 0 || resp_size < sizeof(int32_t)) {
        return WH_SHE_ERC_GENERAL_ERROR;
    }
    return *((const int32_t*)resp_packet);
}

/* Bring up a server whose SHE UID is backed by _uidStore. When useConfig is
 * set the callbacks arrive via whServerConfig.sheConfig, otherwise the server
 * starts with in-context storage and the caller registers them later. */
static int _SetupServer(TestCtx* t, int useConfig, int readOnly)
{
    memset(t, 0, sizeof(*t));

    t->tmcf[0] = (whTransportMemConfig){
        .req       = (whTransportMemCsr*)t->reqBuf,
        .req_size  = sizeof(t->reqBuf),
        .resp      = (whTransportMemCsr*)t->respBuf,
        .resp_size = sizeof(t->respBuf),
    };
    t->tscb[0]    = (whTransportServerCb)WH_TRANSPORT_MEM_SERVER_CB;
    t->cs_conf[0] = (whCommServerConfig){
        .transport_cb      = t->tscb,
        .transport_context = (void*)t->tmsc,
        .transport_config  = (void*)t->tmcf,
        .server_id         = 124,
    };

    t->sheConfig[0] = (whServerSheConfig){
        .getUidCb = _TestGetUid,
        .setUidCb = (readOnly != 0) ? NULL : _TestSetUid,
        .uidCtx   = &_uidStore,
    };

    t->s_conf[0] = (whServerConfig){
        .comm_config = t->cs_conf,
        .nvm         = NULL,
        .crypto      = t->crypto,
        .she         = t->she,
        .sheConfig   = (useConfig != 0) ? t->sheConfig : NULL,
        .devId       = INVALID_DEVID,
    };

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(t->crypto->rng, NULL, INVALID_DEVID));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(t->server, t->s_conf));

    return WH_ERROR_OK;
}

static void _CleanupServer(TestCtx* t)
{
    (void)wh_Server_Cleanup(t->server);
    (void)wc_FreeRng(t->crypto->rng);
    (void)wolfCrypt_Cleanup();
}

/* Run GET_ID and check that the response carries the expected UID. */
static int _CheckGetIdUid(whServerContext* server, const uint8_t* expectUid,
                          uint8_t* req_packet, uint8_t* resp_packet)
{
    whMessageShe_GetIdRequest*  req  = (whMessageShe_GetIdRequest*)req_packet;
    whMessageShe_GetIdResponse* resp = (whMessageShe_GetIdResponse*)resp_packet;
    int32_t                     rc;

    memset(req, 0, sizeof(*req));
    memset(req->challenge, 0xA5, sizeof(req->challenge));

    rc = _SheActionRc(server, WH_SHE_GET_ID, req_packet, sizeof(*req),
                      resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_NO_ERROR);
    WH_TEST_ASSERT_RETURN(memcmp(resp->uid, expectUid, WH_SHE_UID_SZ) == 0);

    return WH_ERROR_OK;
}

/* A read-only store rejects provisioning and serves its UID to GET_ID. */
static int _TestReadOnlyUid(TestCtx* t, uint8_t* req_packet,
                            uint8_t* resp_packet)
{
    whServerContext* server = t->server;
    int32_t          rc;
    int              getCount;

    /* The UID is already provisioned, so SET_UID hits the one-shot rule. */
    {
        whMessageShe_SetUidRequest* uidReq =
            (whMessageShe_SetUidRequest*)req_packet;
        memset(uidReq, 0, sizeof(*uidReq));
        memcpy(uidReq->uid, s_wireUid, WH_SHE_UID_SZ);
        rc = _SheActionRc(server, WH_SHE_SET_UID, req_packet, sizeof(*uidReq),
                          resp_packet);
        WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_SEQUENCE_ERROR);
    }
    WH_TEST_ASSERT_RETURN(_uidStore.setCount == 0);
    WH_TEST_ASSERT_RETURN(
        memcmp(_uidStore.uid, s_fusedUid, WH_SHE_UID_SZ) == 0);

    /* GET_STATUS is answered without consulting the UID store. */
    getCount = _uidStore.getCount;
    rc = _SheActionRc(server, WH_SHE_GET_STATUS, req_packet, 0, resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_NO_ERROR);
    WH_TEST_ASSERT_RETURN(_uidStore.getCount == getCount);

    /* GET_ID reports the store's UID and reads it back from the store. */
    server->she->sbState = TEST_SHE_SB_STATE_SUCCESS;
    getCount             = _uidStore.getCount;
    WH_TEST_RETURN_ON_FAIL(
        _CheckGetIdUid(server, s_fusedUid, req_packet, resp_packet));
    WH_TEST_ASSERT_RETURN(_uidStore.getCount > getCount);

    /* Nothing was cached in the SHE context. */
    WH_TEST_ASSERT_RETURN(server->she->uidSet == 0);
    WH_TEST_ASSERT_RETURN(
        wh_Utils_memeqzero(server->she->uid, WH_SHE_UID_SZ) == 1);

    return WH_ERROR_OK;
}

/* A writable store accepts one provisioning round and then serves the UID. */
static int _TestWritableUid(TestCtx* t, uint8_t* req_packet,
                            uint8_t* resp_packet)
{
    whServerContext*            server = t->server;
    whMessageShe_SetUidRequest* uidReq =
        (whMessageShe_SetUidRequest*)req_packet;
    int32_t rc;

    /* Before provisioning, protected commands are refused. */
    memset(req_packet, 0, WOLFHSM_CFG_COMM_DATA_LEN);
    rc = _SheActionRc(server, WH_SHE_LOAD_PLAIN_KEY, req_packet,
                      sizeof(whMessageShe_LoadPlainKeyRequest), resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_SEQUENCE_ERROR);
    rc = _SheActionRc(server, WH_SHE_GET_ID, req_packet,
                      sizeof(whMessageShe_GetIdRequest), resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_SEQUENCE_ERROR);

    /* SET_UID reaches the store. */
    memset(uidReq, 0, sizeof(*uidReq));
    memcpy(uidReq->uid, s_wireUid, WH_SHE_UID_SZ);
    rc = _SheActionRc(server, WH_SHE_SET_UID, req_packet, sizeof(*uidReq),
                      resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_NO_ERROR);
    WH_TEST_ASSERT_RETURN(_uidStore.setCount == 1);
    WH_TEST_ASSERT_RETURN(_uidStore.provisioned == 1);
    WH_TEST_ASSERT_RETURN(memcmp(_uidStore.uid, s_wireUid, WH_SHE_UID_SZ) == 0);

    /* Provisioning stays one-shot when it is the store that remembers. */
    memset(uidReq, 0, sizeof(*uidReq));
    memcpy(uidReq->uid, s_fusedUid, WH_SHE_UID_SZ);
    rc = _SheActionRc(server, WH_SHE_SET_UID, req_packet, sizeof(*uidReq),
                      resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_SEQUENCE_ERROR);
    WH_TEST_ASSERT_RETURN(_uidStore.setCount == 1);
    WH_TEST_ASSERT_RETURN(memcmp(_uidStore.uid, s_wireUid, WH_SHE_UID_SZ) == 0);

    /* GET_ID echoes the provisioned UID, still with nothing cached. */
    server->she->sbState = TEST_SHE_SB_STATE_SUCCESS;
    WH_TEST_RETURN_ON_FAIL(
        _CheckGetIdUid(server, s_wireUid, req_packet, resp_packet));
    WH_TEST_ASSERT_RETURN(server->she->uidSet == 0);
    WH_TEST_ASSERT_RETURN(
        wh_Utils_memeqzero(server->she->uid, WH_SHE_UID_SZ) == 1);

    return WH_ERROR_OK;
}

/* A read-only store that has nothing to serve can never be provisioned. */
static int _TestReadOnlyUnprovisioned(TestCtx* t, uint8_t* req_packet,
                                      uint8_t* resp_packet)
{
    whMessageShe_SetUidRequest* uidReq =
        (whMessageShe_SetUidRequest*)req_packet;
    int32_t rc;

    memset(uidReq, 0, sizeof(*uidReq));
    memcpy(uidReq->uid, s_wireUid, WH_SHE_UID_SZ);
    rc = _SheActionRc(t->server, WH_SHE_SET_UID, req_packet, sizeof(*uidReq),
                      resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_WRITE_PROTECTED);
    WH_TEST_ASSERT_RETURN(_uidStore.provisioned == 0);

    return WH_ERROR_OK;
}

/* A failing store fails every command closed, except GET_STATUS. */
static int _TestFailingUid(TestCtx* t, uint8_t* req_packet,
                           uint8_t* resp_packet)
{
    whServerContext* server = t->server;
    int32_t          rc;
    uint32_t         i;

    const struct {
        uint16_t action;
        uint16_t req_size;
    } actions[] = {
        {WH_SHE_SET_UID, sizeof(whMessageShe_SetUidRequest)},
        {WH_SHE_GET_ID, sizeof(whMessageShe_GetIdRequest)},
        {WH_SHE_LOAD_PLAIN_KEY, sizeof(whMessageShe_LoadPlainKeyRequest)},
        {WH_SHE_INIT_RND, 0},
        {WH_SHE_ENC_ECB, sizeof(whMessageShe_EncEcbRequest)},
    };
    const uint32_t actionCount = sizeof(actions) / sizeof(actions[0]);

    memset(req_packet, 0, WOLFHSM_CFG_COMM_DATA_LEN);
    server->she->sbState = TEST_SHE_SB_STATE_SUCCESS;
    _uidStore.getErr     = WH_ERROR_ABORTED;

    for (i = 0; i < actionCount; i++) {
        rc = _SheActionRc(server, actions[i].action, req_packet,
                          actions[i].req_size, resp_packet);
        WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_MEMORY_FAILURE);
    }

    /* Status stays readable even with the store broken. */
    rc = _SheActionRc(server, WH_SHE_GET_STATUS, req_packet, 0, resp_packet);
    WH_TEST_ASSERT_RETURN(rc == WH_SHE_ERC_NO_ERROR);

    _uidStore.getErr = 0;

    return WH_ERROR_OK;
}

int whTest_SheUidCb(void* ctx)
{
    TestCtx* t = &_testCtx;
    /* Buffers for request and response packets */
    static uint8_t req_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    static uint8_t resp_packet[WOLFHSM_CFG_COMM_DATA_LEN];

    (void)ctx;

    /* Read-only store, callbacks installed through whServerConfig.sheConfig */
    memset(&_uidStore, 0, sizeof(_uidStore));
    memcpy(_uidStore.uid, s_fusedUid, WH_SHE_UID_SZ);
    _uidStore.provisioned = 1;
    WH_TEST_RETURN_ON_FAIL(_SetupServer(t, 1, 1));
    WH_TEST_RETURN_ON_FAIL(_TestReadOnlyUid(t, req_packet, resp_packet));
    _CleanupServer(t);

    /* Read-only store with no UID yet: provisioning is refused outright */
    memset(&_uidStore, 0, sizeof(_uidStore));
    WH_TEST_RETURN_ON_FAIL(_SetupServer(t, 1, 1));
    WH_TEST_RETURN_ON_FAIL(
        _TestReadOnlyUnprovisioned(t, req_packet, resp_packet));
    _CleanupServer(t);

    /* Writable store, starting unprovisioned */
    memset(&_uidStore, 0, sizeof(_uidStore));
    WH_TEST_RETURN_ON_FAIL(_SetupServer(t, 1, 0));
    WH_TEST_RETURN_ON_FAIL(_TestWritableUid(t, req_packet, resp_packet));
    _CleanupServer(t);

    /* Failing store */
    memset(&_uidStore, 0, sizeof(_uidStore));
    _uidStore.provisioned = 1;
    WH_TEST_RETURN_ON_FAIL(_SetupServer(t, 1, 0));
    WH_TEST_RETURN_ON_FAIL(_TestFailingUid(t, req_packet, resp_packet));
    _CleanupServer(t);

    /* Late registration reaches the same behavior as the config path */
    memset(&_uidStore, 0, sizeof(_uidStore));
    memcpy(_uidStore.uid, s_fusedUid, WH_SHE_UID_SZ);
    _uidStore.provisioned = 1;
    WH_TEST_RETURN_ON_FAIL(_SetupServer(t, 0, 1));
    WH_TEST_ASSERT_RETURN(t->server->she->getUidCb == NULL);
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_SheSetUidCb(t->server, _TestGetUid, NULL, &_uidStore));
    WH_TEST_RETURN_ON_FAIL(_TestReadOnlyUid(t, req_packet, resp_packet));

    /* Clearing the callbacks restores in-context storage */
    WH_TEST_RETURN_ON_FAIL(wh_Server_SheSetUidCb(t->server, NULL, NULL, NULL));
    {
        whMessageShe_SetUidRequest* uidReq =
            (whMessageShe_SetUidRequest*)req_packet;
        memset(uidReq, 0, sizeof(*uidReq));
        memcpy(uidReq->uid, s_wireUid, WH_SHE_UID_SZ);
        WH_TEST_ASSERT_RETURN(_SheActionRc(t->server, WH_SHE_SET_UID,
                                           req_packet, sizeof(*uidReq),
                                           resp_packet) ==
                              WH_SHE_ERC_NO_ERROR);
    }
    WH_TEST_ASSERT_RETURN(t->server->she->uidSet == 1);
    WH_TEST_ASSERT_RETURN(
        memcmp(t->server->she->uid, s_wireUid, WH_SHE_UID_SZ) == 0);
    WH_TEST_ASSERT_RETURN(_uidStore.setCount == 0);
    WH_TEST_RETURN_ON_FAIL(
        _CheckGetIdUid(t->server, s_wireUid, req_packet, resp_packet));

    WH_TEST_ASSERT_RETURN(wh_Server_SheSetUidCb(NULL, _TestGetUid, NULL,
                                                &_uidStore) ==
                          WH_ERROR_BADARGS);
    _CleanupServer(t);

    WH_TEST_PRINT("SHE UID callback test SUCCESS\n");

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_SHE_EXTENSION && !WOLFHSM_CFG_NO_CRYPTO &&
        * WOLFHSM_CFG_ENABLE_SERVER */
