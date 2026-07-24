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
/* test-refactor/server/wh_test_dma_zerofill.c: a server DMA WRITE_POST sends
 * the full PRE length, so bytes the handler never wrote must reach the client
 * as zeros rather than as whatever the bounce buffer last held. */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && defined(WOLFHSM_CFG_DMA)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_dma.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_nvm.h"
#include "wolfhsm/wh_message_nvm.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfhsm/wh_server_cert.h"
#include "wolfhsm/wh_message_cert.h"
#define WH_TEST_DMAZF_CERT
#endif

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Exceeds every request length below, so a mapping is never refused. */
#define WH_TEST_DMAZF_SCRATCH_LEN 512
#define WH_TEST_DMAZF_POISON ((uint8_t)0xA7)

/* Pre-fills the destination, so "all zero" also proves the POST ran. */
#define WH_TEST_DMAZF_DEST_FILL ((uint8_t)0x5C)

#define WH_TEST_DMAZF_REQ_LEN 256
#define WH_TEST_DMAZF_OBJ_LEN 32

/* NVM ids 0x60-0x62 are reserved for this test; other server-group tests use
 * 1, 2, 0x55, 0x57, 0x58 and 0x5A. ID_ABSENT must never be provisioned. */
#define WH_TEST_DMAZF_ID_DENY 0x60
#define WH_TEST_DMAZF_ID_PLAIN 0x61
#define WH_TEST_DMAZF_ID_ABSENT 0x62

static uint8_t _dmaScratch[WH_TEST_DMAZF_SCRATCH_LEN];
static int     _dmaWritePres;
static int     _dmaWritePosts;
static size_t  _dmaLastPreLen;
static size_t  _dmaLastPostLen;

/* Static, to keep two 8K packets out of the sub-test stack frames */
static uint8_t _reqPacket[WOLFHSM_CFG_COMM_DATA_LEN];
static uint8_t _respPacket[WOLFHSM_CFG_COMM_DATA_LEN];

/* Distinct from _dmaSecret, so a carry-over between operations is
 * unambiguous. */
static const uint8_t _dmaPublic[WH_TEST_DMAZF_OBJ_LEN] = {
    0x8f, 0x21, 0xd6, 0x4b, 0xa0, 0x37, 0xc9, 0x15, 0x62, 0xee, 0x0d,
    0xb3, 0x74, 0x58, 0xfc, 0x29, 0x91, 0x4e, 0xa5, 0x07, 0xdb, 0x36,
    0x6a, 0xcf, 0x18, 0x82, 0x53, 0xe7, 0x2b, 0xb4, 0x70, 0x9d};

/* Models a split-address-space port: the server works in _dmaScratch and the
 * WRITE_POST copies it out, the shape in which residue becomes a disclosure. */
static int _dmaBounceCb(struct whServerContext_t* server, uintptr_t clientAddr,
                        void** serverPtr, size_t len, whServerDmaOper oper,
                        whServerDmaFlags flags)
{
    (void)server;
    (void)flags;

    if (len == 0) {
        return WH_ERROR_OK;
    }
    /* Bound by the destination, not by _dmaScratch: the POST copies len bytes
     * into a WH_TEST_DMAZF_REQ_LEN caller buffer, so a longer accepted request
     * would smash the stack instead of failing an assertion. */
    if (len > WH_TEST_DMAZF_REQ_LEN) {
        return WH_ERROR_ACCESS;
    }

    switch (oper) {
        case WH_DMA_OPER_CLIENT_READ_PRE:
            memcpy(_dmaScratch, (const void*)clientAddr, len);
            *serverPtr = _dmaScratch;
            break;

        case WH_DMA_OPER_CLIENT_READ_POST:
            break;

        case WH_DMA_OPER_CLIENT_WRITE_PRE:
            *serverPtr = _dmaScratch;
            _dmaWritePres++;
            _dmaLastPreLen = len;
            break;

        case WH_DMA_OPER_CLIENT_WRITE_POST:
            memcpy((void*)clientAddr, _dmaScratch, len);
            _dmaWritePosts++;
            _dmaLastPostLen = len;
            break;
    }

    return WH_ERROR_OK;
}

/* Accepts the address but hands back no writable pointer. The POST copies the
 * poisoned scratch out, so a POST wrongly paired with this pointerless PRE
 * leaves poison in the destination instead of the client's fill byte. */
static int _dmaNullMapCb(struct whServerContext_t* server, uintptr_t clientAddr,
                         void** serverPtr, size_t len, whServerDmaOper oper,
                         whServerDmaFlags flags)
{
    (void)server;
    (void)flags;

    if (oper == WH_DMA_OPER_CLIENT_WRITE_PRE) {
        *serverPtr = NULL;
        _dmaWritePres++;
    }
    else if (oper == WH_DMA_OPER_CLIENT_WRITE_POST) {
        memcpy((void*)clientAddr, _dmaScratch, len);
        _dmaWritePosts++;
    }

    return WH_ERROR_OK;
}

static void _dmaResetCounters(void)
{
    _dmaWritePres   = 0;
    _dmaWritePosts  = 0;
    _dmaLastPreLen  = 0;
    _dmaLastPostLen = 0;
}

/* Poison the bounce buffer and fill the destination, so a leak and a skipped
 * POST are both distinguishable from a correct zero-fill. */
static void _dmaArm(uint8_t* dest, size_t dest_len)
{
    memset(_dmaScratch, WH_TEST_DMAZF_POISON, sizeof(_dmaScratch));
    memset(dest, WH_TEST_DMAZF_DEST_FILL, dest_len);
    _dmaResetCounters();
}

static int _dmaAllZero(const uint8_t* buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* Local to the two handlers under test, which keep PRE and POST symmetric.
 * Asserts nothing about the crypto DMA handlers, whose pairing and residue
 * behavior vary per handler and are not audited here. */
static int _dmaPairingOk(void)
{
    return (_dmaWritePres == 1) && (_dmaWritePosts == 1) &&
           (_dmaLastPreLen == _dmaLastPostLen);
}

static int _dmaAddObject(whServerContext* server, whNvmId id, whNvmFlags flags,
                         const uint8_t* data, whNvmSize len)
{
    whNvmMetadata meta = {0};

    meta.id     = id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = flags;
    meta.len    = len;

    return wh_Nvm_AddObject(server->nvm, &meta, len, data);
}

static int _dmaDestroyObject(whServerContext* server, whNvmId id)
{
    whNvmId id_list[1];

    id_list[0] = id;
    return wh_Nvm_DestroyObjects(server->nvm, 1, id_list);
}

/* The buffer was never mapped, so the handler cannot have written to it. */
static int _dmaNoMapping(void)
{
    return (_dmaWritePres == 0) && (_dmaWritePosts == 0);
}

static int _dmaUntouched(const uint8_t* buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (buf[i] != WH_TEST_DMAZF_DEST_FILL) {
            return 0;
        }
    }
    return 1;
}

/* Contents of the object every denied read targets */
static const uint8_t _dmaSecret[WH_TEST_DMAZF_OBJ_LEN] = {
    0x3c, 0xb7, 0x40, 0xe2, 0x19, 0x8d, 0x56, 0xfa, 0x07, 0x63, 0xcc,
    0x2e, 0x95, 0xd1, 0x4a, 0x78, 0xbe, 0x03, 0x67, 0xf1, 0x2c, 0x88,
    0xa9, 0x50, 0xdf, 0x14, 0x76, 0x3b, 0xe0, 0x9c, 0x45, 0xab};

/* Drive one READDMA through the dispatcher, where the deny check and the DMA
 * bracket live. */
static int _dmaNvmReadDma(whServerContext* server, whNvmId id, whNvmSize offset,
                          void* dest, uint16_t dest_len, int32_t* out_rc)
{
    whMessageNvm_ReadDmaRequest req       = {0};
    whMessageNvm_SimpleResponse resp      = {0};
    const uint16_t              magic     = WH_COMM_MAGIC_NATIVE;
    uint16_t                    resp_size = 0;

    req.id            = id;
    req.offset        = offset;
    req.data_len      = dest_len;
    req.data_hostaddr = (uint64_t)(uintptr_t)dest;

    memset(_reqPacket, 0, sizeof(_reqPacket));
    memset(_respPacket, 0, sizeof(_respPacket));
    wh_MessageNvm_TranslateReadDmaRequest(
        magic, &req, (whMessageNvm_ReadDmaRequest*)_reqPacket);

    (void)wh_Server_HandleNvmRequest(
        server, magic, WH_MESSAGE_NVM_ACTION_READDMA, 0, sizeof(req),
        _reqPacket, &resp_size, _respPacket);

    wh_MessageNvm_TranslateSimpleResponse(
        magic, (whMessageNvm_SimpleResponse*)_respPacket, &resp);

    if (resp_size != sizeof(resp)) {
        return WH_ERROR_ABORTED;
    }
    *out_rc = resp.rc;
    return WH_ERROR_OK;
}

#ifdef WH_TEST_DMAZF_CERT
/* Drive one READTRUSTED_DMA through the dispatcher, where the deny check and
 * the DMA bracket live. */
static int _dmaCertReadTrusted(whServerContext* server, whNvmId id, void* dest,
                               uint32_t dest_len, int32_t* out_rc)
{
    whMessageCert_ReadTrustedDmaRequest req       = {0};
    whMessageCert_SimpleResponse        resp      = {0};
    const uint16_t                      magic     = WH_COMM_MAGIC_NATIVE;
    uint16_t                            resp_size = 0;

    req.id        = id;
    req.cert_addr = (uint64_t)(uintptr_t)dest;
    req.cert_len  = dest_len;

    memset(_reqPacket, 0, sizeof(_reqPacket));
    memset(_respPacket, 0, sizeof(_respPacket));
    wh_MessageCert_TranslateReadTrustedDmaRequest(
        magic, &req, (whMessageCert_ReadTrustedDmaRequest*)_reqPacket);

    (void)wh_Server_HandleCertRequest(
        server, magic, WH_MESSAGE_CERT_ACTION_READTRUSTED_DMA, 0, sizeof(req),
        _reqPacket, &resp_size, _respPacket);

    wh_MessageCert_TranslateSimpleResponse(
        magic, (whMessageCert_SimpleResponse*)_respPacket, &resp);

    if (resp_size != sizeof(resp)) {
        return WH_ERROR_ABORTED;
    }
    *out_rc = resp.rc;
    return WH_ERROR_OK;
}

/* A refused read must not map the client buffer at all, so the destination is
 * left exactly as the client had it. */
static int _whTest_DmaZeroFillCertDenied(whServerContext* server)
{
    uint8_t out_buf[WH_TEST_DMAZF_REQ_LEN];
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(
        _dmaAddObject(server, WH_TEST_DMAZF_ID_DENY,
                      WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_NONEXPORTABLE,
                      _dmaSecret, sizeof(_dmaSecret)));

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_DENY,
                                               out_buf, sizeof(out_buf), &rc));

    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);
    WH_TEST_ASSERT_RETURN(_dmaNoMapping());
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_DENY));
    return WH_ERROR_OK;
}

/* Same requirement on the metadata-lookup failure path. */
static int _whTest_DmaZeroFillCertMissingId(whServerContext* server)
{
    uint8_t       out_buf[WH_TEST_DMAZF_REQ_LEN];
    whNvmMetadata probe;
    int32_t       rc = WH_ERROR_OK;

    /* The id must really be absent, or this passes for the wrong reason. */
    WH_TEST_ASSERT_RETURN(wh_Nvm_GetMetadata(server->nvm,
                                             WH_TEST_DMAZF_ID_ABSENT,
                                             &probe) != WH_ERROR_OK);

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_ABSENT,
                                               out_buf, sizeof(out_buf), &rc));

    WH_TEST_ASSERT_RETURN(rc != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(_dmaNoMapping());
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    return WH_ERROR_OK;
}

/* A read shorter than the request still POSTs the whole request length, so
 * the tail past the object must be zeros. */
static int _whTest_DmaZeroFillCertShortRead(whServerContext* server)
{
    uint8_t out_buf[WH_TEST_DMAZF_REQ_LEN];
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_PLAIN,
                                               out_buf, sizeof(out_buf), &rc));

    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(_dmaPairingOk());
    WH_TEST_ASSERT_RETURN(0 == memcmp(out_buf, _dmaPublic, sizeof(_dmaPublic)));
    WH_TEST_ASSERT_RETURN(_dmaAllZero(out_buf + sizeof(_dmaPublic),
                                      sizeof(out_buf) - sizeof(_dmaPublic)));

    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    return WH_ERROR_OK;
}

/* A denied request following a successful one must not hand back the earlier
 * payload. Deliberately does not re-poison between the two operations. */
static int _whTest_DmaZeroFillCertNoCarry(whServerContext* server)
{
    uint8_t out_buf[WH_TEST_DMAZF_REQ_LEN];
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));
    WH_TEST_RETURN_ON_FAIL(
        _dmaAddObject(server, WH_TEST_DMAZF_ID_DENY,
                      WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_NONEXPORTABLE,
                      _dmaSecret, sizeof(_dmaSecret)));

    /* Leaves the object's bytes in the bounce buffer. */
    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_PLAIN,
                                               out_buf, sizeof(out_buf), &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    memset(out_buf, WH_TEST_DMAZF_DEST_FILL, sizeof(out_buf));
    _dmaResetCounters();

    WH_TEST_RETURN_ON_FAIL(_dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_DENY,
                                               out_buf, sizeof(out_buf), &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);
    WH_TEST_ASSERT_RETURN(_dmaNoMapping());
    /* Named separately from the untouched check: this is the disclosure. */
    WH_TEST_ASSERT_RETURN(0 != memcmp(out_buf, _dmaPublic, sizeof(_dmaPublic)));
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_DENY));
    return WH_ERROR_OK;
}

/* A length past WOLFHSM_CFG_MAX_CERT_SIZE bounds the zero-fill, so it must be
 * refused before the buffer is mapped. */
static int _whTest_DmaZeroFillCertOversized(whServerContext* server)
{
    uint8_t out_buf[WH_TEST_DMAZF_REQ_LEN];
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(
        _dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_PLAIN, out_buf,
                            WOLFHSM_CFG_MAX_CERT_SIZE + 1, &rc));

    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(_dmaNoMapping());
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    /* A denied id must still report ACCESS, not the length error. */
    WH_TEST_RETURN_ON_FAIL(
        _dmaAddObject(server, WH_TEST_DMAZF_ID_DENY,
                      WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_NONEXPORTABLE,
                      _dmaSecret, sizeof(_dmaSecret)));
    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(
        _dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_DENY, out_buf,
                            WOLFHSM_CFG_MAX_CERT_SIZE + 1, &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);
    WH_TEST_ASSERT_RETURN(_dmaNoMapping());

    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_DENY));
    return WH_ERROR_OK;
}

/* A destination smaller than the stored cert fails BUFFER_SIZE after the map,
 * so the documented "all zeros if the read fails" must hold: the client sees
 * cert_len zero bytes, not its prior contents. */
static int _whTest_DmaZeroFillCertBufferTooSmall(whServerContext* server)
{
    uint8_t        out_buf[WH_TEST_DMAZF_REQ_LEN];
    const uint32_t small = sizeof(_dmaPublic) / 2;
    int32_t        rc    = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_PLAIN,
                                               out_buf, small, &rc));

    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BUFFER_SIZE);
    WH_TEST_ASSERT_RETURN(_dmaPairingOk());
    WH_TEST_ASSERT_RETURN(_dmaAllZero(out_buf, small));

    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    return WH_ERROR_OK;
}
#endif /* WH_TEST_DMAZF_CERT */

/* NVM READDMA clamps the read but hands the unclamped length to both halves
 * of the DMA bracket, so it has the same tail exposure. */
static int _whTest_DmaZeroFillNvmShortRead(whServerContext* server)
{
    uint8_t out_buf[WH_TEST_DMAZF_REQ_LEN];
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_PLAIN, 0,
                                          out_buf, (uint16_t)sizeof(out_buf),
                                          &rc));

    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(_dmaPairingOk());
    WH_TEST_ASSERT_RETURN(0 == memcmp(out_buf, _dmaPublic, sizeof(_dmaPublic)));
    WH_TEST_ASSERT_RETURN(_dmaAllZero(out_buf + sizeof(_dmaPublic),
                                      sizeof(out_buf) - sizeof(_dmaPublic)));

    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    return WH_ERROR_OK;
}

/* Direct-mapped port (no callback): the transformed pointer is the raw client
 * address, so a 0 address must be refused, not dereferenced by the zero-fill.
 * The shipped client APIs send exactly this when handed a NULL buffer. */
static int _whTest_DmaZeroFillNullAddr(whServerContext* server)
{
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(server, NULL));

    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_PLAIN, 0,
                                          NULL, WH_TEST_DMAZF_REQ_LEN, &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

#ifdef WH_TEST_DMAZF_CERT
    rc = WH_ERROR_OK;
    WH_TEST_RETURN_ON_FAIL(_dmaCertReadTrusted(
        server, WH_TEST_DMAZF_ID_PLAIN, NULL, WH_TEST_DMAZF_REQ_LEN, &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
#endif /* WH_TEST_DMAZF_CERT */

    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(server, _dmaBounceCb));
    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    return WH_ERROR_OK;
}

/* A read the NVM policy refuses must be rejected before the buffer is mapped,
 * so the destination is left exactly as the client had it. */
static int _whTest_DmaZeroFillNvmDenied(whServerContext* server)
{
    uint8_t out_buf[WH_TEST_DMAZF_REQ_LEN];
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(
        _dmaAddObject(server, WH_TEST_DMAZF_ID_DENY,
                      WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_NONEXPORTABLE,
                      _dmaSecret, sizeof(_dmaSecret)));

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_DENY, 0,
                                          out_buf, (uint16_t)sizeof(out_buf),
                                          &rc));

    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);
    WH_TEST_ASSERT_RETURN(_dmaNoMapping());
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    /* ACCESS whatever the offset, so the error code cannot be used to probe
     * the length of an object the client may not read. */
    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_DENY,
                                          WH_TEST_DMAZF_REQ_LEN, out_buf,
                                          (uint16_t)sizeof(out_buf), &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);
    WH_TEST_ASSERT_RETURN(_dmaNoMapping());
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_DENY));
    return WH_ERROR_OK;
}

/* Both pre-mapping refusal paths must leave the destination untouched. */
static int _whTest_DmaZeroFillNvmMissingId(whServerContext* server)
{
    uint8_t       out_buf[WH_TEST_DMAZF_REQ_LEN];
    whNvmMetadata probe;
    int32_t       rc = WH_ERROR_OK;

    /* The id must really be absent, or this passes for the wrong reason. */
    WH_TEST_ASSERT_RETURN(wh_Nvm_GetMetadata(server->nvm,
                                             WH_TEST_DMAZF_ID_ABSENT,
                                             &probe) != WH_ERROR_OK);

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_ABSENT, 0,
                                          out_buf, (uint16_t)sizeof(out_buf),
                                          &rc));

    WH_TEST_ASSERT_RETURN(rc != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(_dmaNoMapping());
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_PLAIN,
                                          sizeof(_dmaPublic), out_buf,
                                          (uint16_t)sizeof(out_buf), &rc));

    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(_dmaNoMapping());
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    return WH_ERROR_OK;
}

/* A mapping that yields no writable pointer must fail the request outright,
 * and the POST still has to pair with the PRE that succeeded. */
static int _whTest_DmaZeroFillNullMapping(whServerContext* server)
{
    uint8_t out_buf[WH_TEST_DMAZF_REQ_LEN];
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(server, _dmaNullMapCb));

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_PLAIN, 0,
                                          out_buf, (uint16_t)sizeof(out_buf),
                                          &rc));

    /* A pointerless PRE must fail without pairing a POST, so the poisoning
     * POST never runs and the destination keeps its fill byte. */
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN((_dmaWritePres == 1) && (_dmaWritePosts == 0));
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    /* A zero-length read maps nothing, so the NVM backends accept a NULL
     * pointer for it. Refusing it here would break that contract. */
    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(
        _dmaNvmReadDma(server, WH_TEST_DMAZF_ID_PLAIN, 0, NULL, 0, &rc));
    WH_TEST_ASSERT_RETURN(rc != WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

#ifdef WH_TEST_DMAZF_CERT
    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_PLAIN,
                                               out_buf, sizeof(out_buf), &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN((_dmaWritePres == 1) && (_dmaWritePosts == 0));
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));
#endif /* WH_TEST_DMAZF_CERT */

    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(server, _dmaBounceCb));
    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    return WH_ERROR_OK;
}

/* The direct-mapped port a default build uses: no callback, so the memset
 * writes straight into client memory and there is no POST copy that could
 * supply the zeros instead. */
static int _whTest_DmaZeroFillDirectShortRead(whServerContext* server)
{
    uint8_t out_buf[WH_TEST_DMAZF_REQ_LEN];
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(server, NULL));

    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_PLAIN, 0,
                                          out_buf, (uint16_t)sizeof(out_buf),
                                          &rc));

    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(0 == memcmp(out_buf, _dmaPublic, sizeof(_dmaPublic)));
    WH_TEST_ASSERT_RETURN(_dmaAllZero(out_buf + sizeof(_dmaPublic),
                                      sizeof(out_buf) - sizeof(_dmaPublic)));

#ifdef WH_TEST_DMAZF_CERT
    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaCertReadTrusted(server, WH_TEST_DMAZF_ID_PLAIN,
                                               out_buf, sizeof(out_buf), &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(0 == memcmp(out_buf, _dmaPublic, sizeof(_dmaPublic)));
    WH_TEST_ASSERT_RETURN(_dmaAllZero(out_buf + sizeof(_dmaPublic),
                                      sizeof(out_buf) - sizeof(_dmaPublic)));
#endif /* WH_TEST_DMAZF_CERT */

    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(server, _dmaBounceCb));
    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    return WH_ERROR_OK;
}

/* File-scope to keep the two 160-byte lists out of the sub-test frame. */
static whDmaAddrAllowList _dmaAllowList;

/* The allowlist is the only bound named in the handler, so exercise both
 * directions: in-range succeeds and zeros the tail; past it is refused
 * before the map, leaving the buffer untouched. */
static int _whTest_DmaZeroFillNvmAllowlist(whServerContext* server)
{
    uint8_t out_buf[WH_TEST_DMAZF_REQ_LEN];
    int32_t rc = WH_ERROR_OK;

    WH_TEST_RETURN_ON_FAIL(_dmaAddObject(server, WH_TEST_DMAZF_ID_PLAIN,
                                         WH_NVM_FLAGS_NONE, _dmaPublic,
                                         sizeof(_dmaPublic)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(server, NULL));

    /* Permit exactly the object's length at out_buf, nothing more. */
    memset(&_dmaAllowList, 0, sizeof(_dmaAllowList));
    _dmaAllowList.writeList[0].addr = out_buf;
    _dmaAllowList.writeList[0].size = sizeof(_dmaPublic);
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_DmaRegisterAllowList(server, &_dmaAllowList));

    /* In range: object length exactly fills the allowed window. */
    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_PLAIN, 0,
                                          out_buf, (uint16_t)sizeof(_dmaPublic),
                                          &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(0 == memcmp(out_buf, _dmaPublic, sizeof(_dmaPublic)));

    /* Past the window: the full request length is validated, so it is refused
     * before the map and the destination keeps its fill byte. */
    _dmaArm(out_buf, sizeof(out_buf));
    WH_TEST_RETURN_ON_FAIL(_dmaNvmReadDma(server, WH_TEST_DMAZF_ID_PLAIN, 0,
                                          out_buf, (uint16_t)sizeof(out_buf),
                                          &rc));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);
    WH_TEST_ASSERT_RETURN(_dmaUntouched(out_buf, sizeof(out_buf)));

    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterAllowList(server, NULL));
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(server, _dmaBounceCb));
    WH_TEST_RETURN_ON_FAIL(_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN));
    return WH_ERROR_OK;
}

/* Run one sub-test, naming it on failure like WH_TEST_RETURN_ON_FAIL does,
 * but without returning early: the callback must be de-registered on the way
 * out, or a later DMA test would be redirected into _dmaScratch. */
#define WH_TEST_DMAZF_STAGE(ret, call)                     \
    do {                                                   \
        if ((ret) == WH_ERROR_OK) {                        \
            (ret) = (call);                                \
            if ((ret) != WH_ERROR_OK) {                    \
                WH_ERROR_PRINT(#call ": ret=%d\n", (ret)); \
            }                                              \
        }                                                  \
    } while (0)

int whTest_DmaWriteZeroFill(whServerContext* server)
{
    whServerDmaClientMemCb prevCb = server->dma.cb;
    int                    ret    = WH_ERROR_OK;

#ifdef WH_TEST_DMAZF_CERT
    /* Idempotent, and every cert sub-test below needs it. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));
#endif /* WH_TEST_DMAZF_CERT */
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(server, _dmaBounceCb));

    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillNvmShortRead(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillNvmDenied(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillNvmMissingId(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillNvmAllowlist(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillNullMapping(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillNullAddr(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillDirectShortRead(server));
#ifdef WH_TEST_DMAZF_CERT
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillCertOversized(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillCertBufferTooSmall(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillCertDenied(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillCertMissingId(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillCertShortRead(server));
    WH_TEST_DMAZF_STAGE(ret, _whTest_DmaZeroFillCertNoCarry(server));
#endif /* WH_TEST_DMAZF_CERT */

    /* Best-effort cleanup: a sub-test that failed mid-way may have left a
     * reserved id provisioned, which would leak into later server-group
     * tests. Restore the callback that was registered on entry. */
    (void)_dmaDestroyObject(server, WH_TEST_DMAZF_ID_PLAIN);
    (void)_dmaDestroyObject(server, WH_TEST_DMAZF_ID_DENY);
    (void)wh_Server_DmaRegisterCb(server, prevCb);

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER && WOLFHSM_CFG_DMA */
