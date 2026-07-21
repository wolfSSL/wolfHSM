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
 * test-refactor/server/wh_test_keywrap_endian.c
 *
 * Byte-order coverage for the key wrap metadata trailer, which crosses the
 * comm boundary as a raw whNvmMetadata instead of a flattened message:
 *
 *   _whTest_KeyWrapMetadataTranslate    - the translate helper itself
 *   _whTest_KeyWrapRoundTrip            - wrap -> unwrap-and-export, and
 *                                         wrap -> unwrap-and-cache
 *   _whTest_KeyWrapRejectsNonWrappedId  - wrap refuses a non-WRAPPED id
 *   _whTest_KeyWrapRejectsNonExportable - export refuses NONEXPORTABLE
 *   _whTest_KeyWrapMalformedNoResidue   - a failed export ships no residue
 *   _whTest_KeyWrapCrossMagic           - wrap under one byte order, consume
 *                                         the blob under the other
 *
 * All but the first run under native and swapped magic, the latter modelling a
 * client whose endianness differs from the server's. Client and server share a
 * process in every harness here, so the dispatch is driven through
 * wh_Server_HandleKeyRequest to reach that path at all.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_KEYWRAP) && !defined(NO_AES) && defined(HAVE_AESGCM)

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
#include "wolfhsm/wh_message_nvm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Client-facing ids, kept clear of the ranges other suites use */
#define WH_TEST_KWE_KEK_ID 0x71
#define WH_TEST_KWE_TRUSTED_KEK_ID 0x73
#define WH_TEST_KWE_META_ID 0x25

#define WH_TEST_KWE_KEYSIZE 32
#define WH_TEST_KWE_WRAPPED_SIZE                              \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(whNvmMetadata) + \
     WH_TEST_KWE_KEYSIZE)

/* Non-palindromic access mask: a missed translation changes its value */
#define WH_TEST_KWE_ACCESS 0x1234

/* Stand-in keyId for the pure translation test, TYPE=WRAPPED USER=0 ID=0x25 */
#define WH_TEST_KWE_RAW_KEYID 0x4025

/* TYPE=SHE, but byte-reversed it is WH_TEST_KWE_RAW_KEYID (TYPE=WRAPPED) */
#define WH_TEST_KWE_SWAPS_TO_WRAPPED_KEYID 0x2540

/* Packet buffers the server casts to its message structs, so give them
 * pointer-grade alignment. Static to keep 16KB off the stack */
static union {
    uint64_t align[(WOLFHSM_CFG_COMM_DATA_LEN + 7) / 8];
    uint8_t  bytes[WOLFHSM_CFG_COMM_DATA_LEN];
} _req, _resp;

static uint16_t _Swap16(uint16_t val)
{
    return (uint16_t)(((val & 0xFF00u) >> 8) | ((val & 0x00FFu) << 8));
}

/* Wire images are built and decoded with these rather than the library
 * Translate* helpers, so a bug inside those cannot cancel itself out here */
static uint16_t _Swap16If(int swap, uint16_t val)
{
    return (swap != 0) ? _Swap16(val) : val;
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

static int _MagicSwaps(uint16_t magic)
{
    return magic != WH_COMM_MAGIC_NATIVE;
}

/* Every 16-bit field takes a value that differs from its byte-swapped self,
 * so an untranslated field cannot pass unnoticed */
static void _FillMetadata(whNvmMetadata* meta, whKeyId id)
{
    size_t i;

    memset(meta, 0, sizeof(*meta));
    meta->id     = id;
    meta->access = WH_TEST_KWE_ACCESS;
    meta->flags  = WH_NVM_FLAGS_USAGE_ANY;
    meta->len    = WH_TEST_KWE_KEYSIZE;
    for (i = 0; i < sizeof(meta->label); i++) {
        meta->label[i] = (uint8_t)(0xA0 + i);
    }
}

/* Sentinel the response buffer is primed with. Zeroing it instead would make
 * the scrub assertions below pass whether or not the server wrote anything */
#define WH_TEST_KWE_RESP_FILL 0xA5

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

static whKeyId _KekKeyId(whServerContext* server, uint16_t rawId)
{
    return WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id, rawId);
}

/* A wrapped keyId whose two bytes are equal, so it reads the same either way
 * round. Lets a subtest past the wrap-side gate to reach another field */
static whKeyId _PalindromeKeyId(whServerContext* server)
{
    uint16_t hi = (uint16_t)((WH_KEYTYPE_WRAPPED << 4) |
                             (server->comm->client_id & 0xF));

    return WH_MAKE_KEYID(WH_KEYTYPE_WRAPPED, server->comm->client_id, hi);
}

static int _whTest_KeyWrapMetadataTranslate(void)
{
    whNvmMetadata in;
    whNvmMetadata out;
    whNvmMetadata back;

    _FillMetadata(&in, WH_TEST_KWE_RAW_KEYID);

    /* A same-endian peer sees the struct unchanged */
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK == wh_MessageNvm_TranslateMetadata(
                                             WH_COMM_MAGIC_NATIVE, &in, &out));
    WH_TEST_ASSERT_RETURN(0 == memcmp(&in, &out, sizeof(in)));

    /* A swapped peer sees every field byte-reversed, label untouched */
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK == wh_MessageNvm_TranslateMetadata(
                                             WH_COMM_MAGIC_SWAP, &in, &out));
    WH_TEST_ASSERT_RETURN(out.id == _Swap16(in.id));
    WH_TEST_ASSERT_RETURN(out.access == _Swap16(in.access));
    WH_TEST_ASSERT_RETURN(out.flags == _Swap16(in.flags));
    WH_TEST_ASSERT_RETURN(out.len == _Swap16(in.len));
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(out.label, in.label, sizeof(in.label)));

    /* decode(encode(m)) == m, including in place */
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK == wh_MessageNvm_TranslateMetadata(
                                             WH_COMM_MAGIC_SWAP, &out, &back));
    WH_TEST_ASSERT_RETURN(0 == memcmp(&in, &back, sizeof(in)));
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK == wh_MessageNvm_TranslateMetadata(
                                             WH_COMM_MAGIC_SWAP, &out, &out));
    WH_TEST_ASSERT_RETURN(0 == memcmp(&in, &out, sizeof(in)));

    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_MessageNvm_TranslateMetadata(
                              WH_COMM_MAGIC_NATIVE, NULL, &out));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_MessageNvm_TranslateMetadata(
                              WH_COMM_MAGIC_NATIVE, &in, NULL));

    return WH_ERROR_OK;
}

/* Cache a KEK straight into the server keystore. Unwrap-and-cache also demands
 * WH_NVM_FLAGS_TRUSTED, which only the server side can set */
static int _CacheKek(whServerContext* server, uint16_t rawId, whNvmFlags flags)
{
    whNvmMetadata meta;
    uint8_t       kek[WH_TEST_KWE_KEYSIZE];
    size_t        i;

    for (i = 0; i < sizeof(kek); i++) {
        kek[i] = (uint8_t)(0xC2 ^ i);
    }

    memset(&meta, 0, sizeof(meta));
    meta.id    = _KekKeyId(server, rawId);
    meta.len   = sizeof(kek);
    meta.flags = flags;
    memcpy(meta.label, "KwEndian KEK", sizeof("KwEndian KEK"));

    return wh_Server_KeystoreCacheKey(server, &meta, kek);
}

/* Wrap a key, presenting header, metadata trailer and key in the byte order
 * the magic denotes. expectRc lets a caller assert a rejection instead */
static int _WrapWithMagic(whServerContext* server, uint16_t magic,
                          uint16_t kekRawId, const whNvmMetadata* metaIn,
                          const uint8_t* keyIn, uint16_t keySz,
                          uint8_t* wrappedOut, uint16_t* wrappedInOutSz,
                          int expectRc)
{
    int                               ret;
    int                               swap = _MagicSwaps(magic);
    uint16_t                          reqSize;
    uint16_t                          respSize = 0;
    whMessageKeystore_KeyWrapRequest  wireReq;
    whMessageKeystore_KeyWrapResponse resp;
    whMessageKeystore_KeyWrapResponse wireResp;
    whNvmMetadata                     wireMeta;

    memset(_req.bytes, 0, sizeof(_req.bytes));
    memset(_resp.bytes, WH_TEST_KWE_RESP_FILL, sizeof(_resp.bytes));
    memset(&wireReq, 0, sizeof(wireReq));

    wireReq.keySz       = _Swap16If(swap, keySz);
    wireReq.serverKeyId = _Swap16If(swap, kekRawId);
    wireReq.cipherType  = _Swap16If(swap, (uint16_t)WC_CIPHER_AES_GCM);
    _SwapMetadataIf(swap, metaIn, &wireMeta);
    memcpy(_req.bytes, &wireReq, sizeof(wireReq));
    memcpy(_req.bytes + sizeof(wireReq), &wireMeta, sizeof(wireMeta));
    memcpy(_req.bytes + sizeof(wireReq) + sizeof(wireMeta), keyIn, keySz);
    reqSize = (uint16_t)(sizeof(wireReq) + sizeof(wireMeta) + keySz);

    ret = wh_Server_HandleKeyRequest(server, magic, WH_KEY_KEYWRAP, reqSize,
                                     _req.bytes, &respSize, _resp.bytes);
    WH_TEST_ASSERT_RETURN(ret == expectRc);

    memcpy(&wireResp, _resp.bytes, sizeof(wireResp));
    resp.rc           = _Swap32If(swap, wireResp.rc);
    resp.wrappedKeySz = _Swap16If(swap, wireResp.wrappedKeySz);
    resp.cipherType   = _Swap16If(swap, wireResp.cipherType);
    WH_TEST_ASSERT_RETURN((int)resp.rc == expectRc);
    WH_TEST_ASSERT_RETURN(resp.cipherType == (uint16_t)WC_CIPHER_AES_GCM);
    if (expectRc != WH_ERROR_OK) {
        return WH_ERROR_OK;
    }
    WH_TEST_ASSERT_RETURN(resp.wrappedKeySz <= *wrappedInOutSz);

    /* The blob is opaque bytes, so it needs no translation */
    memcpy(wrappedOut, _resp.bytes + sizeof(resp), resp.wrappedKeySz);
    *wrappedInOutSz = resp.wrappedKeySz;

    return WH_ERROR_OK;
}

/* Unwrap-and-export, decoding the metadata trailer returned ahead of the key.
 * expectRc lets a caller assert a policy rejection instead */
static int _UnwrapWithMagic(whServerContext* server, uint16_t magic,
                            uint16_t kekRawId, const uint8_t* wrappedIn,
                            uint16_t wrappedSz, whNvmMetadata* metaOut,
                            uint8_t* keyOut, uint16_t* keyInOutSz, int expectRc)
{
    int                                          ret;
    int                                          swap = _MagicSwaps(magic);
    uint16_t                                     reqSize;
    uint16_t                                     respSize = 0;
    whMessageKeystore_KeyUnwrapAndExportRequest  wireReq;
    whMessageKeystore_KeyUnwrapAndExportResponse resp;
    whMessageKeystore_KeyUnwrapAndExportResponse wireResp;
    whNvmMetadata                                wireMeta;

    memset(_req.bytes, 0, sizeof(_req.bytes));
    memset(_resp.bytes, WH_TEST_KWE_RESP_FILL, sizeof(_resp.bytes));
    memset(&wireReq, 0, sizeof(wireReq));

    wireReq.wrappedKeySz = _Swap16If(swap, wrappedSz);
    wireReq.serverKeyId  = _Swap16If(swap, kekRawId);
    wireReq.cipherType   = _Swap16If(swap, (uint16_t)WC_CIPHER_AES_GCM);
    memcpy(_req.bytes, &wireReq, sizeof(wireReq));
    memcpy(_req.bytes + sizeof(wireReq), wrappedIn, wrappedSz);
    reqSize = (uint16_t)(sizeof(wireReq) + wrappedSz);

    ret = wh_Server_HandleKeyRequest(server, magic, WH_KEY_KEYUNWRAPEXPORT,
                                     reqSize, _req.bytes, &respSize,
                                     _resp.bytes);
    WH_TEST_ASSERT_RETURN(ret == expectRc);

    memcpy(&wireResp, _resp.bytes, sizeof(wireResp));
    resp.rc         = _Swap32If(swap, wireResp.rc);
    resp.keySz      = _Swap16If(swap, wireResp.keySz);
    resp.cipherType = _Swap16If(swap, wireResp.cipherType);
    WH_TEST_ASSERT_RETURN((int)resp.rc == expectRc);
    WH_TEST_ASSERT_RETURN(resp.cipherType == (uint16_t)WC_CIPHER_AES_GCM);

    /* The trailer ships whatever the outcome, even with keySz zeroed */
    WH_TEST_ASSERT_RETURN(respSize ==
                          sizeof(resp) + sizeof(wireMeta) + resp.keySz);

    memcpy(&wireMeta, _resp.bytes + sizeof(resp), sizeof(wireMeta));
    if (expectRc != WH_ERROR_OK) {
        /* A denied request carries back neither metadata nor the plaintext key
         * the server already decrypted into the shared buffer */
        WH_TEST_ASSERT_RETURN(resp.keySz == 0);
        WH_TEST_ASSERT_RETURN(
            _IsZeroed(_resp.bytes + sizeof(resp),
                      sizeof(wireMeta) + WH_TEST_KWE_KEYSIZE));
        return WH_ERROR_OK;
    }
    WH_TEST_ASSERT_RETURN(resp.keySz <= *keyInOutSz);

    _SwapMetadataIf(swap, &wireMeta, metaOut);
    memcpy(keyOut, _resp.bytes + sizeof(resp) + sizeof(wireMeta), resp.keySz);
    *keyInOutSz = resp.keySz;

    return WH_ERROR_OK;
}

/* Unwrap-and-cache under the trusted KEK. It stores what it decrypts without
 * translating: the other half of the blobs-hold-native-metadata invariant */
static int _UnwrapCacheWithMagic(whServerContext* server, uint16_t magic,
                                 const uint8_t* wrappedIn, uint16_t wrappedSz)
{
    int                                         ret;
    int                                         swap = _MagicSwaps(magic);
    uint16_t                                    reqSize;
    uint16_t                                    respSize = 0;
    whMessageKeystore_KeyUnwrapAndCacheRequest  wireReq;
    whMessageKeystore_KeyUnwrapAndCacheResponse resp;
    whMessageKeystore_KeyUnwrapAndCacheResponse wireResp;

    memset(_req.bytes, 0, sizeof(_req.bytes));
    memset(_resp.bytes, WH_TEST_KWE_RESP_FILL, sizeof(_resp.bytes));
    memset(&wireReq, 0, sizeof(wireReq));

    wireReq.wrappedKeySz = _Swap16If(swap, wrappedSz);
    wireReq.serverKeyId  = _Swap16If(swap, WH_TEST_KWE_TRUSTED_KEK_ID);
    wireReq.cipherType   = _Swap16If(swap, (uint16_t)WC_CIPHER_AES_GCM);
    memcpy(_req.bytes, &wireReq, sizeof(wireReq));
    memcpy(_req.bytes + sizeof(wireReq), wrappedIn, wrappedSz);
    reqSize = (uint16_t)(sizeof(wireReq) + wrappedSz);

    ret = wh_Server_HandleKeyRequest(server, magic, WH_KEY_KEYUNWRAPCACHE,
                                     reqSize, _req.bytes, &respSize,
                                     _resp.bytes);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    memcpy(&wireResp, _resp.bytes, sizeof(wireResp));
    resp.rc    = _Swap32If(swap, wireResp.rc);
    resp.keyId = _Swap16If(swap, wireResp.keyId);
    /* A byte-swapped len fails the handler's len-vs-key-size check */
    WH_TEST_ASSERT_RETURN(resp.rc == WH_ERROR_OK);

    return WH_ERROR_OK;
}

/* Wrap under the trusted KEK, prime the cache from that blob, and read the
 * cached key back to confirm native metadata and key material landed */
static int _CacheRoundTrip(whServerContext* server, uint16_t magic,
                           const whNvmMetadata* metaIn, const uint8_t* keyIn,
                           uint16_t keySz)
{
    int           ret;
    whNvmMetadata metaBack;
    uint8_t       keyBack[WH_TEST_KWE_KEYSIZE];
    uint32_t      keyBackSz = sizeof(keyBack);
    uint8_t       wrapped[WH_TEST_KWE_WRAPPED_SIZE];
    uint16_t      wrappedSz = (uint16_t)sizeof(wrapped);

    memset(&metaBack, 0, sizeof(metaBack));
    memset(keyBack, 0, sizeof(keyBack));

    WH_TEST_RETURN_ON_FAIL(_WrapWithMagic(server, magic,
                                          WH_TEST_KWE_TRUSTED_KEK_ID, metaIn,
                                          keyIn, keySz, wrapped, &wrappedSz,
                                          WH_ERROR_OK));
    WH_TEST_RETURN_ON_FAIL(
        _UnwrapCacheWithMagic(server, magic, wrapped, wrappedSz));

    ret = wh_Server_KeystoreReadKey(server, metaIn->id, &metaBack, keyBack,
                                    &keyBackSz);
    (void)wh_Server_KeystoreEvictKey(server, metaIn->id);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    WH_TEST_ASSERT_RETURN(metaBack.id == metaIn->id);
    WH_TEST_ASSERT_RETURN(metaBack.access == metaIn->access);
    WH_TEST_ASSERT_RETURN(metaBack.len == metaIn->len);
    /* The cache path strips server-only bits from the client's flags */
    WH_TEST_ASSERT_RETURN(metaBack.flags ==
                          (metaIn->flags & ~WH_NVM_FLAGS_SERVER_ONLY));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(metaBack.label, metaIn->label, sizeof(metaIn->label)));
    WH_TEST_ASSERT_RETURN(keyBackSz == keySz);
    WH_TEST_ASSERT_RETURN(0 == memcmp(keyBack, keyIn, keySz));

    return WH_ERROR_OK;
}

/* Wrap must refuse a non-WRAPPED keyId. 0x2540 is TYPE=SHE, but byte-reversed
 * it reads 0x4025 = TYPE=WRAPPED, so a missed ingress translation lets it in */
static int _whTest_KeyWrapRejectsNonWrappedId(whServerContext* server,
                                              uint16_t         magic)
{
    whNvmMetadata metaIn;
    uint8_t       keyIn[WH_TEST_KWE_KEYSIZE];
    uint8_t       wrapped[WH_TEST_KWE_WRAPPED_SIZE];
    uint16_t      wrappedSz = (uint16_t)sizeof(wrapped);
    size_t        i;

    for (i = 0; i < sizeof(keyIn); i++) {
        keyIn[i] = (uint8_t)(0x7B ^ i);
    }
    _FillMetadata(&metaIn, WH_TEST_KWE_SWAPS_TO_WRAPPED_KEYID);

    return _WrapWithMagic(server, magic, WH_TEST_KWE_KEK_ID, &metaIn, keyIn,
                          (uint16_t)sizeof(keyIn), wrapped, &wrappedSz,
                          WH_ERROR_BADARGS);
}

/* Unwrap-and-export must refuse a NONEXPORTABLE key. Bit 10 swaps into bit 2,
 * so flags 0x0024, with bit 10 clear, exposes a missed translation */
static int _whTest_KeyWrapRejectsNonExportable(whServerContext* server,
                                               uint16_t         magic)
{
    whNvmMetadata metaIn;
    whNvmMetadata metaOut;
    uint8_t       keyIn[WH_TEST_KWE_KEYSIZE];
    uint8_t       keyOut[WH_TEST_KWE_KEYSIZE];
    uint8_t       wrapped[WH_TEST_KWE_WRAPPED_SIZE];
    uint16_t      wrappedSz = (uint16_t)sizeof(wrapped);
    uint16_t      keyOutSz  = (uint16_t)sizeof(keyOut);
    size_t        i;

    for (i = 0; i < sizeof(keyIn); i++) {
        keyIn[i] = (uint8_t)(0x7B ^ i);
    }
    memset(&metaOut, 0, sizeof(metaOut));
    memset(keyOut, 0, sizeof(keyOut));

    /* A palindromic keyId survives the wrap-side ISWRAPPED gate under either
     * byte order, so the flags check below is what the subtest exercises */
    _FillMetadata(&metaIn, _PalindromeKeyId(server));
    metaIn.flags = WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_ENCRYPT;

    WH_TEST_RETURN_ON_FAIL(_WrapWithMagic(server, magic, WH_TEST_KWE_KEK_ID,
                                          &metaIn, keyIn,
                                          (uint16_t)sizeof(keyIn), wrapped,
                                          &wrappedSz, WH_ERROR_OK));

    return _UnwrapWithMagic(server, magic, WH_TEST_KWE_KEK_ID, wrapped,
                            wrappedSz, &metaOut, keyOut, &keyOutSz,
                            WH_ERROR_ACCESS);
}

/* Wrap as a peer of one byte order, consume the blob as the other: what a
 * mixed-endian deployment sharing a KEK actually does */
static int _whTest_KeyWrapCrossMagic(whServerContext* server,
                                     uint16_t wrapMagic, uint16_t useMagic)
{
    whNvmMetadata metaIn;
    whNvmMetadata metaOut;
    uint8_t       keyIn[WH_TEST_KWE_KEYSIZE];
    uint8_t       keyOut[WH_TEST_KWE_KEYSIZE];
    uint8_t       wrapped[WH_TEST_KWE_WRAPPED_SIZE];
    uint16_t      wrappedSz = (uint16_t)sizeof(wrapped);
    uint16_t      keyOutSz  = (uint16_t)sizeof(keyOut);
    size_t        i;

    for (i = 0; i < sizeof(keyIn); i++) {
        keyIn[i] = (uint8_t)(0x7B ^ i);
    }
    memset(&metaOut, 0, sizeof(metaOut));
    memset(keyOut, 0, sizeof(keyOut));
    _FillMetadata(&metaIn,
                  WH_MAKE_KEYID(WH_KEYTYPE_WRAPPED, server->comm->client_id,
                                WH_TEST_KWE_META_ID));

    /* Export leg: wrap under one magic, unwrap-and-export under the other */
    WH_TEST_RETURN_ON_FAIL(_WrapWithMagic(server, wrapMagic,
                                          WH_TEST_KWE_KEK_ID, &metaIn, keyIn,
                                          (uint16_t)sizeof(keyIn), wrapped,
                                          &wrappedSz, WH_ERROR_OK));
    WH_TEST_RETURN_ON_FAIL(_UnwrapWithMagic(server, useMagic,
                                            WH_TEST_KWE_KEK_ID, wrapped,
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

    /* Cache leg: wrap under one magic, prime the cache under the other */
    wrappedSz = (uint16_t)sizeof(wrapped);
    WH_TEST_RETURN_ON_FAIL(_WrapWithMagic(server, wrapMagic,
                                          WH_TEST_KWE_TRUSTED_KEK_ID, &metaIn,
                                          keyIn, (uint16_t)sizeof(keyIn),
                                          wrapped, &wrappedSz, WH_ERROR_OK));
    WH_TEST_RETURN_ON_FAIL(
        _UnwrapCacheWithMagic(server, useMagic, wrapped, wrappedSz));
    (void)wh_Server_KeystoreEvictKey(server, metaIn.id);

    return WH_ERROR_OK;
}

/* The two paths that fail before any trailer is written. One ships anyway,
 * because *out_resp_size always counts one, so it must not carry residue */
static int _whTest_KeyWrapMalformedNoResidue(whServerContext* server,
                                             uint16_t         magic)
{
    whMessageKeystore_KeyUnwrapAndExportRequest  req;
    whMessageKeystore_KeyUnwrapAndExportRequest  wireReq;
    whMessageKeystore_KeyUnwrapAndExportResponse resp;
    whMessageKeystore_KeyUnwrapAndExportResponse wireResp;
    int                                          ret;
    size_t                                       pass;

    /* pass 0: req_size short of the fixed struct, so the handler never runs.
     * pass 1: wrappedKeySz claims more data than the request carries */
    for (pass = 0; pass < 2; pass++) {
        uint16_t respSize = 0;
        uint16_t reqSize;
        int      expectRc;

        memset(_req.bytes, WH_TEST_KWE_RESP_FILL, sizeof(_req.bytes));
        memset(_resp.bytes, WH_TEST_KWE_RESP_FILL, sizeof(_resp.bytes));
        memset(&req, 0, sizeof(req));

        req.wrappedKeySz = WH_TEST_KWE_KEYSIZE;
        req.serverKeyId  = WH_TEST_KWE_KEK_ID;
        req.cipherType   = WC_CIPHER_AES_GCM;
        (void)wh_MessageKeystore_TranslateKeyUnwrapAndExportRequest(magic, &req,
                                                                    &wireReq);
        memcpy(_req.bytes, &wireReq, sizeof(wireReq));

        if (pass == 0) {
            reqSize  = (uint16_t)(sizeof(wireReq) - 1);
            expectRc = WH_ERROR_BADARGS;
        }
        else {
            reqSize  = (uint16_t)sizeof(wireReq);
            expectRc = WH_ERROR_BUFFER_SIZE;
        }

        ret = wh_Server_HandleKeyRequest(server, magic, WH_KEY_KEYUNWRAPEXPORT,
                                         reqSize, _req.bytes, &respSize,
                                         _resp.bytes);
        WH_TEST_ASSERT_RETURN(ret == expectRc);

        memcpy(&wireResp, _resp.bytes, sizeof(wireResp));
        (void)wh_MessageKeystore_TranslateKeyUnwrapAndExportResponse(
            magic, &wireResp, &resp);
        WH_TEST_ASSERT_RETURN((int)resp.rc == expectRc);
        WH_TEST_ASSERT_RETURN(resp.keySz == 0);

        /* The trailer ships regardless, so it must be zeroed, not the 0xA5
         * the buffer was primed with */
        WH_TEST_ASSERT_RETURN(respSize ==
                              sizeof(resp) + sizeof(whNvmMetadata));
        WH_TEST_ASSERT_RETURN(
            _IsZeroed(_resp.bytes + sizeof(resp), sizeof(whNvmMetadata)));
    }

    return WH_ERROR_OK;
}

static int _whTest_KeyWrapRoundTrip(whServerContext* server, uint16_t magic)
{
    whNvmMetadata metaIn;
    whNvmMetadata metaOut;
    uint8_t       keyIn[WH_TEST_KWE_KEYSIZE];
    uint8_t       keyOut[WH_TEST_KWE_KEYSIZE];
    uint8_t       wrapped[WH_TEST_KWE_WRAPPED_SIZE];
    uint16_t      wrappedSz = (uint16_t)sizeof(wrapped);
    uint16_t      keyOutSz  = (uint16_t)sizeof(keyOut);
    size_t        i;

    for (i = 0; i < sizeof(keyIn); i++) {
        keyIn[i] = (uint8_t)(0x7B ^ i);
    }
    memset(&metaOut, 0, sizeof(metaOut));
    memset(keyOut, 0, sizeof(keyOut));
    _FillMetadata(&metaIn,
                  WH_MAKE_KEYID(WH_KEYTYPE_WRAPPED, server->comm->client_id,
                                WH_TEST_KWE_META_ID));

    WH_TEST_RETURN_ON_FAIL(_WrapWithMagic(server, magic, WH_TEST_KWE_KEK_ID,
                                          &metaIn, keyIn,
                                          (uint16_t)sizeof(keyIn), wrapped,
                                          &wrappedSz, WH_ERROR_OK));
    WH_TEST_RETURN_ON_FAIL(_UnwrapWithMagic(server, magic, WH_TEST_KWE_KEK_ID,
                                            wrapped, wrappedSz, &metaOut,
                                            keyOut, &keyOutSz, WH_ERROR_OK));

    WH_TEST_ASSERT_RETURN(metaOut.id == metaIn.id);
    WH_TEST_ASSERT_RETURN(metaOut.access == metaIn.access);
    WH_TEST_ASSERT_RETURN(metaOut.flags == metaIn.flags);
    WH_TEST_ASSERT_RETURN(metaOut.len == metaIn.len);
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(metaOut.label, metaIn.label, sizeof(metaIn.label)));
    WH_TEST_ASSERT_RETURN(keyOutSz == sizeof(keyIn));
    WH_TEST_ASSERT_RETURN(0 == memcmp(keyOut, keyIn, sizeof(keyIn)));

    WH_TEST_RETURN_ON_FAIL(_CacheRoundTrip(server, magic, &metaIn, keyIn,
                                           (uint16_t)sizeof(keyIn)));

    return WH_ERROR_OK;
}

/* Every case that depends on byte order, run under one magic */
static int _RunMagic(whServerContext* server, uint16_t magic)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_KeyWrapRoundTrip(server, magic));
    WH_TEST_RETURN_ON_FAIL(_whTest_KeyWrapRejectsNonWrappedId(server, magic));
    WH_TEST_RETURN_ON_FAIL(_whTest_KeyWrapRejectsNonExportable(server, magic));
    WH_TEST_RETURN_ON_FAIL(_whTest_KeyWrapMalformedNoResidue(server, magic));

    return WH_ERROR_OK;
}

int whTest_KeyWrapEndian(whServerContext* server)
{
    int ret;

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(_whTest_KeyWrapMetadataTranslate());

    /* Fallthrough from here on, not WH_TEST_RETURN_ON_FAIL: once either KEK is
     * cached it must leave the shared keystore on every exit path */
    ret = _CacheKek(server, WH_TEST_KWE_KEK_ID, WH_NVM_FLAGS_USAGE_WRAP);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("cache plain KEK: ret=%d\n", ret);
    }

    if (ret == WH_ERROR_OK) {
        ret = _CacheKek(server, WH_TEST_KWE_TRUSTED_KEK_ID,
                        WH_NVM_FLAGS_USAGE_WRAP | WH_NVM_FLAGS_TRUSTED);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("cache trusted KEK: ret=%d\n", ret);
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = _RunMagic(server, WH_COMM_MAGIC_NATIVE);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("under native magic: ret=%d\n", ret);
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = _RunMagic(server, WH_COMM_MAGIC_SWAP);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("under swapped magic: ret=%d\n", ret);
        }
    }

    /* The blob is server-native whoever wrapped it, so the two byte orders
     * must interoperate through it in both directions */
    if (ret == WH_ERROR_OK) {
        ret = _whTest_KeyWrapCrossMagic(server, WH_COMM_MAGIC_SWAP,
                                        WH_COMM_MAGIC_NATIVE);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("wrap swapped, use native: ret=%d\n", ret);
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_KeyWrapCrossMagic(server, WH_COMM_MAGIC_NATIVE,
                                        WH_COMM_MAGIC_SWAP);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("wrap native, use swapped: ret=%d\n", ret);
        }
    }

    (void)wh_Server_KeystoreEvictKey(server,
                                     _KekKeyId(server, WH_TEST_KWE_KEK_ID));
    (void)wh_Server_KeystoreEvictKey(
        server, _KekKeyId(server, WH_TEST_KWE_TRUSTED_KEK_ID));

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER && !WOLFHSM_CFG_NO_CRYPTO &&
        * WOLFHSM_CFG_KEYWRAP && !NO_AES && HAVE_AESGCM */
