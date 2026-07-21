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
 * test-refactor/client-server/wh_test_keywrap_endian_e2e.c
 *
 * End-to-end byte-order coverage for the key wrap metadata trailer, against a
 * live server over the real transport:
 *
 *   _whTest_KeyWrapE2ERoundTrip - wrap -> unwrap-and-export, and a denied
 *                                 export, whole packet in native and in
 *                                 swapped byte order
 *
 * Packets are hand built and pushed straight at the transport, because
 * wh_CommClient always sends WH_COMM_MAGIC_NATIVE and rejects a non-native
 * response. The hand-written swaps are also an oracle independent of the
 * wh_Message*_Translate* code under test.
 *
 * Reaches what server/wh_test_keywrap_endian.c cannot: the comm layer accepting
 * a non-native magic, and wh_Server_HandleRequestMessage passing one packet
 * buffer as both req_packet and resp_packet, so the egress translation is an
 * in-place swap inside the wrapped blob. The mem transport's own buffers are
 * separate; that aliasing is above it.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_KEYWRAP) && \
    !defined(NO_AES) && defined(HAVE_AESGCM) && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Distinct id range so nothing collides with the other client suites */
#define WH_TEST_KWE2E_KEK_ID 0x72
#define WH_TEST_KWE2E_META_ID 0x26

#define WH_TEST_KWE2E_KEYSIZE 32
#define WH_TEST_KWE2E_WRAPPED_SIZE                            \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(whNvmMetadata) + \
     WH_TEST_KWE2E_KEYSIZE)

/* Non-palindromic access mask: a missed translation changes its value */
#define WH_TEST_KWE2E_ACCESS 0x1234

/* Livelock backstop, not a timeout. Each spin costs a memory fence and two CSR
 * loads; an observed exchange settles under 2000, so this caps a stuck loop
 * below a second */
#define WH_TEST_KWE2E_MAX_SPINS 10000000u

/* The packet is cast to whCommHeader, so give it pointer-grade alignment.
 * Static to keep it off the stack */
static union {
    uint64_t align[WH_COMM_MTU_U64_COUNT];
    uint8_t  bytes[WH_COMM_MTU];
} _pkt;

/* Byte order conversion is its own inverse, so one routine covers both
 * encoding a request and decoding a response */
static uint16_t _Swap16If(int swap, uint16_t val)
{
    if (swap == 0) {
        return val;
    }
    return (uint16_t)(((val & 0xFF00u) >> 8) | ((val & 0x00FFu) << 8));
}

static uint32_t _Swap32If(int swap, uint32_t val)
{
    if (swap == 0) {
        return val;
    }
    return ((val & 0xFF000000u) >> 24) | ((val & 0x00FF0000u) >> 8) |
           ((val & 0x0000FF00u) << 8) | ((val & 0x000000FFu) << 24);
}

static void _SwapMetadataIf(int swap, const whNvmMetadata* src,
                            whNvmMetadata* dest)
{
    dest->id     = _Swap16If(swap, src->id);
    dest->access = _Swap16If(swap, src->access);
    dest->flags  = _Swap16If(swap, src->flags);
    dest->len    = _Swap16If(swap, src->len);
    memcpy(dest->label, src->label, sizeof(dest->label));
}

static int _IsZeroed(const uint8_t* buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* Every 16-bit field takes a value that differs from its byte-swapped self,
 * so an untranslated field cannot pass unnoticed */
static void _FillMetadata(whNvmMetadata* meta, whKeyId id)
{
    size_t i;

    memset(meta, 0, sizeof(*meta));
    meta->id     = id;
    meta->access = WH_TEST_KWE2E_ACCESS;
    meta->flags  = WH_NVM_FLAGS_USAGE_ANY;
    meta->len    = WH_TEST_KWE2E_KEYSIZE;
    for (i = 0; i < sizeof(meta->label); i++) {
        meta->label[i] = (uint8_t)(0xA0 + i);
    }
}

/* Plain client KEK, cached through the ordinary client API. Enough for wrap
 * and unwrap-and-export, which never require a trusted KEK */
static int _CacheKek(whClientContext* client, whKeyId* outKekId)
{
    whKeyId kekId                   = WH_TEST_KWE2E_KEK_ID;
    uint8_t label[WH_NVM_LABEL_LEN] = "KwE2E KEK";
    uint8_t kek[WH_TEST_KWE2E_KEYSIZE];
    size_t  i;

    for (i = 0; i < sizeof(kek); i++) {
        kek[i] = (uint8_t)(0xC2 ^ i);
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_WRAP,
                                              label, (uint16_t)sizeof(label),
                                              kek, sizeof(kek), &kekId));
    *outKekId = kekId;
    return WH_ERROR_OK;
}

/* Frame the payload already in _pkt behind the header, send it, and spin for
 * the reply. seq comes from the caller: this path never advances comm->seq */
static int _Exchange(whClientContext* client, uint16_t magic, uint16_t kind,
                     uint16_t seq, uint16_t reqDataSz, uint16_t* outRespDataSz)
{
    const whTransportClientCb* cb;
    void*                      tctx;
    whCommHeader*              hdr;
    int                        swap;
    int                        rc;
    uint32_t                   spins;
    uint16_t                   size;

    cb   = client->comm->transport_cb;
    tctx = client->comm->transport_context;
    hdr  = (whCommHeader*)_pkt.bytes;
    swap = (magic != WH_COMM_MAGIC_NATIVE);

    if (cb == NULL || cb->Send == NULL || cb->Recv == NULL) {
        return WH_ERROR_BADARGS;
    }

    hdr->magic = magic;
    hdr->kind  = _Swap16If(swap, kind);
    hdr->seq   = _Swap16If(swap, seq);
    hdr->aux   = _Swap16If(swap, WH_COMM_AUX_REQ_NORMAL);

    spins = 0;
    do {
        rc = cb->Send(tctx, (uint16_t)(sizeof(*hdr) + reqDataSz), _pkt.bytes);
        spins++;
    } while (rc == WH_ERROR_NOTREADY && spins < WH_TEST_KWE2E_MAX_SPINS);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("e2e: transport Send failed %d\n", rc);
        return (rc == WH_ERROR_NOTREADY) ? WH_ERROR_ABORTED : rc;
    }

    /* out_size is the destination capacity on the way in, and the true
     * response length on the way out, so reset it before every attempt */
    spins = 0;
    do {
        size = (uint16_t)sizeof(_pkt.bytes);
        rc   = cb->Recv(tctx, &size, _pkt.bytes);
        spins++;
    } while (rc == WH_ERROR_NOTREADY && spins < WH_TEST_KWE2E_MAX_SPINS);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("e2e: transport Recv failed %d\n", rc);
        return (rc == WH_ERROR_NOTREADY) ? WH_ERROR_ABORTED : rc;
    }

    /* Bound the reported length like wh_CommClient_RecvResponse does: the
     * transport clamps its copy but still reports the peer's true length */
    WH_TEST_ASSERT_RETURN(size >= sizeof(*hdr));
    WH_TEST_ASSERT_RETURN(size <= sizeof(_pkt.bytes));

    /* The server must echo the magic it was addressed with, and answer the
     * message it was sent */
    WH_TEST_ASSERT_RETURN(hdr->magic == magic);
    WH_TEST_ASSERT_RETURN(_Swap16If(swap, hdr->kind) == kind);
    WH_TEST_ASSERT_RETURN(_Swap16If(swap, hdr->seq) == seq);

    *outRespDataSz = (uint16_t)(size - sizeof(*hdr));
    return WH_ERROR_OK;
}

/* Wrap a plaintext key, presenting header, metadata trailer and key in the
 * byte order the given magic denotes */
static int _WrapWithMagic(whClientContext* client, uint16_t magic,
                          whKeyId kekId, const whNvmMetadata* metaIn,
                          const uint8_t* keyIn, uint16_t keySz,
                          uint8_t* wrappedOut, uint16_t* wrappedInOutSz)
{
    whMessageKeystore_KeyWrapRequest  wireReq;
    whMessageKeystore_KeyWrapResponse wireResp;
    whNvmMetadata                     wireMeta;
    uint8_t*                          data;
    int                               swap;
    uint16_t                          respDataSz = 0;
    uint16_t                          wrappedSz;

    swap = (magic != WH_COMM_MAGIC_NATIVE);
    data = _pkt.bytes + sizeof(whCommHeader);

    memset(&wireReq, 0, sizeof(wireReq));
    wireReq.keySz       = _Swap16If(swap, keySz);
    wireReq.serverKeyId = _Swap16If(swap, (uint16_t)kekId);
    wireReq.cipherType  = _Swap16If(swap, (uint16_t)WC_CIPHER_AES_GCM);
    _SwapMetadataIf(swap, metaIn, &wireMeta);

    memcpy(data, &wireReq, sizeof(wireReq));
    memcpy(data + sizeof(wireReq), &wireMeta, sizeof(wireMeta));
    memcpy(data + sizeof(wireReq) + sizeof(wireMeta), keyIn, keySz);

    WH_TEST_RETURN_ON_FAIL(_Exchange(
        client, magic, WH_MESSAGE_KIND(WH_MESSAGE_GROUP_KEY, WH_KEY_KEYWRAP),
        (uint16_t)(client->comm->seq + 1),
        (uint16_t)(sizeof(wireReq) + sizeof(wireMeta) + keySz), &respDataSz));

    WH_TEST_ASSERT_RETURN(respDataSz >= sizeof(wireResp));
    memcpy(&wireResp, data, sizeof(wireResp));
    WH_TEST_ASSERT_RETURN((int32_t)_Swap32If(swap, wireResp.rc) == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(_Swap16If(swap, wireResp.cipherType) ==
                          (uint16_t)WC_CIPHER_AES_GCM);

    wrappedSz = _Swap16If(swap, wireResp.wrappedKeySz);
    WH_TEST_ASSERT_RETURN(wrappedSz <= *wrappedInOutSz);
    WH_TEST_ASSERT_RETURN(respDataSz >= sizeof(wireResp) + wrappedSz);

    /* The blob is opaque bytes, so it needs no translation */
    memcpy(wrappedOut, data + sizeof(wireResp), wrappedSz);
    *wrappedInOutSz = wrappedSz;

    return WH_ERROR_OK;
}

/* Unwrap-and-export the blob and decode the metadata trailer the server
 * returns ahead of the key */
static int _UnwrapWithMagic(whClientContext* client, uint16_t magic,
                            whKeyId kekId, const uint8_t* wrappedIn,
                            uint16_t wrappedSz, whNvmMetadata* metaOut,
                            uint8_t* keyOut, uint16_t* keyInOutSz, int expectRc)
{
    whMessageKeystore_KeyUnwrapAndExportRequest  wireReq;
    whMessageKeystore_KeyUnwrapAndExportResponse wireResp;
    whNvmMetadata                                wireMeta;
    uint8_t*                                     data;
    int                                          swap;
    uint16_t                                     respDataSz = 0;
    uint16_t                                     keySz;

    swap = (magic != WH_COMM_MAGIC_NATIVE);
    data = _pkt.bytes + sizeof(whCommHeader);

    memset(&wireReq, 0, sizeof(wireReq));
    wireReq.wrappedKeySz = _Swap16If(swap, wrappedSz);
    wireReq.serverKeyId  = _Swap16If(swap, (uint16_t)kekId);
    wireReq.cipherType   = _Swap16If(swap, (uint16_t)WC_CIPHER_AES_GCM);

    memcpy(data, &wireReq, sizeof(wireReq));
    memcpy(data + sizeof(wireReq), wrappedIn, wrappedSz);

    WH_TEST_RETURN_ON_FAIL(_Exchange(
        client, magic,
        WH_MESSAGE_KIND(WH_MESSAGE_GROUP_KEY, WH_KEY_KEYUNWRAPEXPORT),
        (uint16_t)(client->comm->seq + 1),
        (uint16_t)(sizeof(wireReq) + wrappedSz), &respDataSz));

    WH_TEST_ASSERT_RETURN(respDataSz >= sizeof(wireResp));
    memcpy(&wireResp, data, sizeof(wireResp));
    WH_TEST_ASSERT_RETURN((int32_t)_Swap32If(swap, wireResp.rc) == expectRc);
    WH_TEST_ASSERT_RETURN(_Swap16If(swap, wireResp.cipherType) ==
                          (uint16_t)WC_CIPHER_AES_GCM);

    keySz = _Swap16If(swap, wireResp.keySz);

    if (expectRc != WH_ERROR_OK) {
        /* Over the wire, through the buffer the server uses for both request
         * and response: the trailer ships but must carry nothing */
        WH_TEST_ASSERT_RETURN(keySz == 0);
        WH_TEST_ASSERT_RETURN(respDataSz ==
                              sizeof(wireResp) + sizeof(wireMeta));
        WH_TEST_ASSERT_RETURN(_IsZeroed(data + sizeof(wireResp),
                                        sizeof(wireMeta)));
        return WH_ERROR_OK;
    }

    WH_TEST_ASSERT_RETURN(keySz <= *keyInOutSz);
    WH_TEST_ASSERT_RETURN(respDataSz >=
                          sizeof(wireResp) + sizeof(wireMeta) + keySz);

    memcpy(&wireMeta, data + sizeof(wireResp), sizeof(wireMeta));
    _SwapMetadataIf(swap, &wireMeta, metaOut);
    memcpy(keyOut, data + sizeof(wireResp) + sizeof(wireMeta), keySz);
    *keyInOutSz = keySz;

    return WH_ERROR_OK;
}

static int _RoundTrip(whClientContext* client, uint16_t magic, whKeyId kekId)
{
    whNvmMetadata metaIn;
    whNvmMetadata metaOut;
    uint8_t       keyIn[WH_TEST_KWE2E_KEYSIZE];
    uint8_t       keyOut[WH_TEST_KWE2E_KEYSIZE];
    uint8_t       wrapped[WH_TEST_KWE2E_WRAPPED_SIZE];
    uint16_t      wrappedSz = (uint16_t)sizeof(wrapped);
    uint16_t      keyOutSz  = (uint16_t)sizeof(keyOut);
    size_t        i;

    for (i = 0; i < sizeof(keyIn); i++) {
        keyIn[i] = (uint8_t)(0x7B ^ i);
    }
    memset(&metaOut, 0, sizeof(metaOut));
    memset(keyOut, 0, sizeof(keyOut));
    _FillMetadata(&metaIn, WH_CLIENT_KEYID_MAKE_WRAPPED_META(
                               client->comm->client_id, WH_TEST_KWE2E_META_ID));

    WH_TEST_RETURN_ON_FAIL(_WrapWithMagic(client, magic, kekId, &metaIn, keyIn,
                                          (uint16_t)sizeof(keyIn), wrapped,
                                          &wrappedSz));
    WH_TEST_RETURN_ON_FAIL(_UnwrapWithMagic(client, magic, kekId, wrapped,
                                            wrappedSz, &metaOut, keyOut,
                                            &keyOutSz, WH_ERROR_OK));

    WH_TEST_ASSERT_RETURN(metaOut.id == metaIn.id);
    WH_TEST_ASSERT_RETURN(metaOut.access == metaIn.access);
    WH_TEST_ASSERT_RETURN(metaOut.flags == metaIn.flags);
    WH_TEST_ASSERT_RETURN(metaOut.len == metaIn.len);
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(metaOut.label, metaIn.label, sizeof(metaIn.label)));
    WH_TEST_ASSERT_RETURN(keyOutSz == sizeof(keyIn));
    WH_TEST_ASSERT_RETURN(0 == memcmp(keyOut, keyIn, sizeof(keyIn)));

    return WH_ERROR_OK;
}

/* Wrap a NONEXPORTABLE key and try to export it: the scrub meeting the
 * request/response buffer aliasing the product actually uses */
static int _DeniedExport(whClientContext* client, uint16_t magic, whKeyId kekId)
{
    whNvmMetadata metaIn;
    whNvmMetadata metaOut;
    uint8_t       keyIn[WH_TEST_KWE2E_KEYSIZE];
    uint8_t       keyOut[WH_TEST_KWE2E_KEYSIZE];
    uint8_t       wrapped[WH_TEST_KWE2E_WRAPPED_SIZE];
    uint16_t      wrappedSz = (uint16_t)sizeof(wrapped);
    uint16_t      keyOutSz  = (uint16_t)sizeof(keyOut);
    size_t        i;

    for (i = 0; i < sizeof(keyIn); i++) {
        keyIn[i] = (uint8_t)(0x7B ^ i);
    }
    memset(&metaOut, 0, sizeof(metaOut));
    memset(keyOut, 0, sizeof(keyOut));
    _FillMetadata(&metaIn, WH_CLIENT_KEYID_MAKE_WRAPPED_META(
                               client->comm->client_id, WH_TEST_KWE2E_META_ID));
    metaIn.flags = WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_ENCRYPT;

    WH_TEST_RETURN_ON_FAIL(_WrapWithMagic(client, magic, kekId, &metaIn, keyIn,
                                          (uint16_t)sizeof(keyIn), wrapped,
                                          &wrappedSz));

    return _UnwrapWithMagic(client, magic, kekId, wrapped, wrappedSz, &metaOut,
                            keyOut, &keyOutSz, WH_ERROR_ACCESS);
}

/* Same cases twice: once addressed as a same-endian peer, once as a
 * peer whose byte order differs from the server's */
static int _RunMagic(whClientContext* client, uint16_t magic, whKeyId kekId)
{
    WH_TEST_RETURN_ON_FAIL(_RoundTrip(client, magic, kekId));
    WH_TEST_RETURN_ON_FAIL(_DeniedExport(client, magic, kekId));

    return WH_ERROR_OK;
}

static int _whTest_KeyWrapE2ERoundTrip(whClientContext* client)
{
    int     ret;
    whKeyId kekId = WH_KEYID_ERASED;

    WH_TEST_RETURN_ON_FAIL(_CacheKek(client, &kekId));

    ret = _RunMagic(client, WH_COMM_MAGIC_NATIVE, kekId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("e2e under native magic: ret=%d\n", ret);
    }
    else {
        ret = _RunMagic(client, WH_COMM_MAGIC_SWAP, kekId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("e2e under swapped magic: ret=%d\n", ret);
        }
    }

    /* Reaches here on the assertion-failure paths too, which all follow a
     * completed exchange. Only a server that never replies defeats it */
    (void)wh_Client_KeyEvict(client, kekId);

    return ret;
}

int whTest_KeyWrapEndianE2E(whClientContext* client)
{
    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(_whTest_KeyWrapE2ERoundTrip(client));

    return WH_ERROR_OK;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_KEYWRAP && !NO_AES &&
        * HAVE_AESGCM */
