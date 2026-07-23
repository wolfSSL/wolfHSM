/*
 * Copyright (C) 2024 wolfSSL Inc.
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
 * src/wh_server_keystore.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_ENABLE_SERVER)

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/asn_public.h"

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_log.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_server_she.h"
#include "wolfhsm/wh_she_common.h" /* For wh_She_Label2Meta (counter guard) */
#endif

#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_crypto.h"
#include "wolfhsm/wh_crypto.h"

#ifndef NO_RSA
#include "wolfssl/wolfcrypt/rsa.h"
#endif
#ifdef HAVE_ECC
#include "wolfssl/wolfcrypt/ecc.h"
#endif
#ifdef HAVE_ED25519
#include "wolfssl/wolfcrypt/ed25519.h"
#endif
#ifdef HAVE_CURVE25519
#include "wolfssl/wolfcrypt/curve25519.h"
#endif
#ifdef WOLFSSL_HAVE_MLDSA
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#endif
#ifdef WOLFSSL_HAVE_MLKEM
#include "wolfssl/wolfcrypt/wc_mlkem.h"
#endif
#ifdef WOLFSSL_HAVE_LMS
#include "wolfssl/wolfcrypt/wc_lms.h"
#endif
#ifdef WOLFSSL_HAVE_XMSS
#include "wolfssl/wolfcrypt/wc_xmss.h"
#endif

static int _FindInCache(whServerContext* server, whKeyId keyId, int* out_index,
                        int* out_big, uint8_t** out_buffer,
                        whNvmMetadata** out_meta);

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/*
 * @brief Check if keyId represents a global key (USER == 0)
 */
static int _IsGlobalKey(whKeyId keyId)
{
    return (WH_KEYID_USER(keyId) == WH_KEYUSER_GLOBAL);
}
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

/*
 * @brief Get the appropriate cache context based on keyId
 *
 * When WOLFHSM_CFG_GLOBAL_KEYS is enabled, routes to global cache if keyId
 * has USER == 0, otherwise routes to local cache. When disabled, always
 * routes to local cache.
 *
 * The global cache lives in the NVM context, which is optional. With no NVM
 * there is no global cache, so global keys fall back to the local cache.
 */
static whKeyCacheContext* _GetCacheContext(whServerContext* server,
                                           whKeyId          keyId)
{
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    if (_IsGlobalKey(keyId) && (server->nvm != NULL)) {
        return &server->nvm->globalCache;
    }
#else
    (void)keyId;
#endif
    return &server->localCache;
}

typedef enum {
    WH_KS_OP_CACHE = 0,
    WH_KS_OP_COMMIT,
    WH_KS_OP_EVICT,
    WH_KS_OP_EXPORT,
    WH_KS_OP_REVOKE,
    /* Exporting only the public half of a public-key object is considered
     * non-sensitive and is intentionally not gated by NONEXPORTABLE. */
    WH_KS_OP_EXPORT_PUBLIC,
} whKsOp;

static int _KeyIsCommitted(whServerContext* server, whKeyId keyId)
{
    int ret;
    int big;
    int index;

    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);
    ret = _FindInCache(server, keyId, &index, &big, NULL, NULL);
    if (ret != WH_ERROR_OK) {
        return 0;
    }

    if (big == 0) {
        return ctx->cache[index].committed;
    }
    else {
        return ctx->bigCache[index].committed;
    }
}
/* Centralized cache/NVM policy: enforce NONMODIFIABLE/NONEXPORTABLE at the
 * keystore layer. Usage enforcement remains separate. */
static int _KeystoreCheckPolicy(whServerContext* server, whKsOp op,
                                whKeyId keyId)
{
    whNvmMetadata* cacheMeta = NULL;
    whNvmMetadata  nvmMeta;
    whNvmFlags     flags;
    int            ret;
    int            foundInCache = 0;
    int            foundInNvm   = 0;

    /* Use WH_KEYID_IS_UNASSIGNED (not WH_KEYID_ISERASED) so SHE slot 0
     * (WH_SHE_SECRET_KEY_ID, ID field == 0) is treated as an explicit key id
     * rather than the dynamic-assignment sentinel. This keeps the policy gate
     * consistent with the SHE-aware read path it guards
     * (wh_Server_KeystoreReadKey) so a SHE slot-0 key can be
     * wrap-exported/evicted/etc. */
    if ((server == NULL) || WH_KEYID_IS_UNASSIGNED(keyId)) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only keys are not keystore-managed: no keystore operation is
     * permitted on them. Must be checked before the existence lookup below,
     * since these keys are never in cache or NVM and some callers (e.g.
     * GetCacheSlotChecked) deliberately tolerate WH_ERROR_NOTFOUND */
    if (WH_KEYID_ISHW(keyId)) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    /* Check cache first */
    ret = _FindInCache(server, keyId, NULL, NULL, NULL, &cacheMeta);
    if (ret == WH_ERROR_OK && cacheMeta != NULL) {
        foundInCache = 1;
    }
    else if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    /* Check NVM if not in cache. No NVM means the key can't be there. */
    if (!foundInCache && (server->nvm != NULL)) {
        ret = wh_Nvm_GetMetadata(server->nvm, keyId, &nvmMeta);
        if (ret == WH_ERROR_OK) {
            foundInNvm = 1;
        }
        else if (ret != WH_ERROR_NOTFOUND) {
            return ret;
        }
    }

    /* Key not found */
    if (!foundInCache && !foundInNvm) {
        return WH_ERROR_NOTFOUND;
    }

    /* Get flags from the appropriate source */
    flags = (foundInCache) ? cacheMeta->flags : nvmMeta.flags;

    /* A trusted KEK is frozen against all client keystore ops: it can only be
     * *used* as a KEK by the keywrap path, which freshens it via the unchecked
     * cache-slot path and so bypasses this gate. Mirrors the WH_KEYID_ISHW gate
     * above but flag-based, so the flag is self-protecting regardless of the
     * key's other bits, and blocks a client re-caching over the KEK id to drop
     * the flag. */
    if (flags & WH_NVM_FLAGS_TRUSTED) {
        return WH_ERROR_ACCESS;
    }

    switch (op) {
        case WH_KS_OP_CACHE:
            if (flags & WH_NVM_FLAGS_NONMODIFIABLE) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_KS_OP_EVICT:
            if (_KeyIsCommitted(server, keyId)) {
                /* Committed keys can always be evicted */
                break;
            }
            if (flags &
                (WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONDESTROYABLE)) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_KS_OP_EXPORT:
            if (flags & WH_NVM_FLAGS_NONEXPORTABLE) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_KS_OP_EXPORT_PUBLIC:
            /* Public material is non-sensitive; NONEXPORTABLE does not
             * apply. The key still had to exist (checked above). */
            break;

        case WH_KS_OP_COMMIT:
        case WH_KS_OP_REVOKE:
            /* Always allowed */
            break;
        default:
            /* unknown operation */
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

/* Clear flags a client may never set. Called at every point where
 * client-supplied metadata becomes a whNvmMetadata, so the only way a key can
 * carry a server-only flag is via trusted provisioning (whnvmtool image or
 * server-internal boot code), never through the request handlers. */
static void _SanitizeClientFlags(whNvmMetadata* meta)
{
    meta->flags &= ~WH_NVM_FLAGS_SERVER_ONLY;
}

/**
 * @brief Find a key in the specified cache context
 */
static int _FindInKeyCache(whKeyCacheContext* ctx, whKeyId keyId,
                           int* out_index, int* out_big, uint8_t** out_buffer,
                           whNvmMetadata** out_meta)
{
    int            ret = WH_ERROR_NOTFOUND;
    int            i;
    int            index  = -1;
    int            big    = -1;
    whNvmMetadata* meta   = NULL;
    uint8_t*       buffer = NULL;

    /* Search regular cache */
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        if (ctx->cache[i].meta->id == keyId) {
            big    = 0;
            index  = i;
            meta   = ctx->cache[i].meta;
            buffer = ctx->cache[i].buffer;
            break;
        }
    }

    /* Search big cache if not found */
    if (index == -1) {
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (ctx->bigCache[i].meta->id == keyId) {
                big    = 1;
                index  = i;
                meta   = ctx->bigCache[i].meta;
                buffer = ctx->bigCache[i].buffer;
                break;
            }
        }
    }

    /* Set output parameters if found */
    if (index != -1) {
        if (out_index != NULL)
            *out_index = index;
        if (out_big != NULL)
            *out_big = big;
        if (out_meta != NULL)
            *out_meta = meta;
        if (out_buffer != NULL)
            *out_buffer = buffer;
        ret = WH_ERROR_OK;
    }

    return ret;
}

static int _EvictSlot(uint8_t* buf, whNvmMetadata* meta)
{
    meta->id = WH_KEYID_ERASED;
    memset(buf, 0, meta->len);
    return WH_ERROR_OK;
}

/**
 * @brief Get an available cache slot from the specified cache context
 */
static int _GetKeyCacheSlot(whKeyCacheContext* ctx, uint16_t keySz,
                            uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int foundIndex = -1;
    int i;
    int            evictRet = WH_ERROR_OK;
    uint8_t*       slotBuf  = NULL;
    whNvmMetadata* slotMeta = NULL;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Determine which cache to use based on key size */
    if (keySz <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        /* Search regular cache for empty slot */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (ctx->cache[i].meta->id == WH_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }

        /* If no empty slots, find committed key to evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
                if (ctx->cache[i].committed == 1) {
                    evictRet =
                        _EvictSlot(ctx->cache[i].buffer, ctx->cache[i].meta);
                    if (evictRet == WH_ERROR_OK) {
                        foundIndex = i;
                        break;
                    }
                }
            }
        }

        /* Zero slot and capture pointers */
        if (foundIndex >= 0) {
            memset(&ctx->cache[foundIndex], 0, sizeof(whCacheSlot));
            slotBuf  = ctx->cache[foundIndex].buffer;
            slotMeta = ctx->cache[foundIndex].meta;
        }
    }
    else {
        /* Search big cache for empty slot */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (ctx->bigCache[i].meta->id == WH_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }

        /* If no empty slots, find committed key to evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
                if (ctx->bigCache[i].committed == 1) {
                    evictRet = _EvictSlot(ctx->bigCache[i].buffer,
                                          ctx->bigCache[i].meta);
                    if (evictRet == WH_ERROR_OK) {
                        foundIndex = i;
                        break;
                    }
                }
            }
        }

        /* Zero slot and capture pointers */
        if (foundIndex >= 0) {
            memset(&ctx->bigCache[foundIndex], 0, sizeof(whBigCacheSlot));
            slotBuf  = ctx->bigCache[foundIndex].buffer;
            slotMeta = ctx->bigCache[foundIndex].meta;
        }
    }

    if (foundIndex == -1) {
        return WH_ERROR_NOSPACE;
    }

    /* Copy out pointers only if caller provided non-NULL output parameters */
    if (outBuf != NULL) {
        *outBuf = slotBuf;
    }
    if (outMeta != NULL) {
        *outMeta = slotMeta;
    }

    return WH_ERROR_OK;
}

/**
 * @brief Evict a key from the specified cache context
 * zeroes the buffer
 */
static int _EvictKeyFromCache(whKeyCacheContext* ctx, whKeyId keyId)
{
    whNvmMetadata* meta      = NULL;
    uint8_t*       outBuffer = NULL;

    int ret = _FindInKeyCache(ctx, keyId, NULL, NULL, &outBuffer, &meta);

    if (ret == WH_ERROR_OK && meta != NULL) {
        return _EvictSlot(outBuffer, meta);
    }

    return ret;
}

/**
 * @brief Mark a cached key as committed
 */
static int _MarkKeyCommitted(whKeyCacheContext* ctx, whKeyId keyId,
                             int committed)
{
    int index = -1;
    int big   = -1;
    int ret   = _FindInKeyCache(ctx, keyId, &index, &big, NULL, NULL);

    if (ret == WH_ERROR_OK) {
        if (big == 0) {
            ctx->cache[index].committed = committed;
        }
        else {
            ctx->bigCache[index].committed = committed;
        }
    }

    return ret;
}

#ifndef NO_RSA
static int _ExportRsaPublicKey(whServerContext* server, whKeyId keyId,
    uint8_t* out, uint16_t* outSz)
{
    int    ret = WH_ERROR_OK;
    RsaKey key[1];
    int    pub_ret;

    ret = wc_InitRsaKey_ex(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Server_CacheExportRsaKey(server, keyId, key);
        if (ret == 0) {
            pub_ret = wc_RsaKeyToPublicDer(key, out, (word32)*outSz);
            if (pub_ret > 0) {
                *outSz = (uint16_t)pub_ret;
            }
            else {
                ret = (pub_ret == 0) ? WH_ERROR_ABORTED : pub_ret;
            }
        }
        wc_FreeRsaKey(key);
    }
    return ret;
}
#endif

#ifdef HAVE_ECC

static int _ExportEccPublicKey(whServerContext* server, whKeyId keyId,
    uint8_t* out, uint16_t* outSz)
{
    int     ret = WH_ERROR_OK;
    ecc_key key[1];
    int     pub_ret;

    ret = wc_ecc_init_ex(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Server_EccKeyCacheExport(server, keyId, key);
        if (ret == 0) {
            pub_ret = wc_EccPublicKeyToDer(key, out, (word32)*outSz, 1);
            if (pub_ret > 0) {
                *outSz = (uint16_t)pub_ret;
            }
            else {
                ret = (pub_ret == 0) ? WH_ERROR_ABORTED : pub_ret;
            }
        }
        wc_ecc_free(key);
    }
    return ret;
}
#endif

#ifdef HAVE_ED25519
static int _ExportEd25519PublicKey(whServerContext* server, whKeyId keyId,
    uint8_t* out, uint16_t* outSz)
{
    int         ret = WH_ERROR_OK;
    ed25519_key key[1];
    int         pub_ret;

    ret = wc_ed25519_init_ex(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Server_CacheExportEd25519Key(server, keyId, key);
        if (ret == 0) {
            pub_ret = wc_Ed25519PublicKeyToDer(key, out, (word32)*outSz, 1);
            if (pub_ret > 0) {
                *outSz = (uint16_t)pub_ret;
            }
            else {
                ret = (pub_ret == 0) ? WH_ERROR_ABORTED : pub_ret;
            }
        }
        wc_ed25519_free(key);
    }
    return ret;
}
#endif

#if defined(WOLFSSL_HAVE_MLDSA) && defined(WOLFSSL_MLDSA_PUBLIC_KEY)
static int _ExportMldsaPublicKey(whServerContext* server, whKeyId keyId,
    uint8_t* out, uint16_t* outSz)
{
    int         ret = WH_ERROR_OK;
    wc_MlDsaKey key[1];
    int         pub_ret;

    ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Server_MlDsaKeyCacheExport(server, keyId, key);
        if (ret == 0) {
            pub_ret = wc_MlDsaKey_PublicKeyToDer(key, out, (word32)*outSz, 1);
            if (pub_ret > 0) {
                *outSz = (uint16_t)pub_ret;
            }
            else {
                ret = (pub_ret == 0) ? WH_ERROR_ABORTED : pub_ret;
            }
        }
        wc_MlDsaKey_Free(key);
    }
    return ret;
}
#endif

#ifdef HAVE_CURVE25519
static int _ExportCurve25519PublicKey(whServerContext* server, whKeyId keyId,
    uint8_t* out, uint16_t* outSz)
{
    int            ret = WH_ERROR_OK;
    curve25519_key key[1];
    int            pub_ret;

    ret = wc_curve25519_init_ex(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Server_CacheExportCurve25519Key(server, keyId, key);
        if (ret == 0) {
            pub_ret = wc_Curve25519PublicKeyToDer(key, out, (word32)*outSz, 1);
            if (pub_ret > 0) {
                *outSz = (uint16_t)pub_ret;
            }
            else {
                ret = (pub_ret == 0) ? WH_ERROR_ABORTED : pub_ret;
            }
        }
        wc_curve25519_free(key);
    }
    return ret;
}
#endif

#ifdef WOLFSSL_HAVE_MLKEM
static int _ExportMlkemPublicKey(whServerContext* server, whKeyId keyId,
    uint8_t* out, uint16_t* outSz)
{
    int      ret = WH_ERROR_OK;
    MlKemKey key[1];
    word32   pubSize;
    /* Pick the lowest compiled-in level as the initial hint;
     * wh_Crypto_MlKemDeserializeKey (called via
     * wh_Server_MlKemKeyCacheExport) probes the remaining enabled levels. */
#ifndef WOLFSSL_NO_ML_KEM_512
    const int initLevel = WC_ML_KEM_512;
#elif !defined(WOLFSSL_NO_ML_KEM_768)
    const int initLevel = WC_ML_KEM_768;
#else
    const int initLevel = WC_ML_KEM_1024;
#endif

    ret = wc_MlKemKey_Init(key, initLevel, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Server_MlKemKeyCacheExport(server, keyId, key);
        if (ret == 0) {
            ret = wc_MlKemKey_PublicKeySize(key, &pubSize);
            if (ret == 0) {
                if ((uint32_t)pubSize > (uint32_t)*outSz) {
                    ret = WH_ERROR_NOSPACE;
                }
                else {
                    ret = wc_MlKemKey_EncodePublicKey(key, out, pubSize);
                    if (ret == 0) {
                        *outSz = (uint16_t)pubSize;
                    }
                }
            }
        }
        wc_MlKemKey_Free(key);
    }
    return ret;
}
#endif /* WOLFSSL_HAVE_MLKEM */

#ifdef WOLFSSL_HAVE_LMS
/* Emit the raw LMS public key for a cached/committed key. Stateful private
 * state stays in the HSM; only the public bytes leave. */
static int _ExportLmsPublicKey(whServerContext* server, whKeyId keyId,
    uint8_t* out, uint16_t* outSz)
{
    int    ret;
    LmsKey key[1];
    word32 pubLen = 0;

    ret = wc_LmsKey_Init(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Server_LmsKeyCacheExport(server, keyId, key);
        if (ret == WH_ERROR_OK) {
            ret = wc_LmsKey_GetPubLen(key, &pubLen);
        }
        if (ret == WH_ERROR_OK) {
            if (pubLen > (word32)*outSz) {
                ret = WH_ERROR_NOSPACE;
            }
            else {
                memcpy(out, key->pub, pubLen);
                *outSz = (uint16_t)pubLen;
            }
        }
        wc_LmsKey_Free(key);
    }
    return ret;
}
#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS
static int _ExportXmssPublicKey(whServerContext* server, whKeyId keyId,
    uint8_t* out, uint16_t* outSz)
{
    int     ret;
    XmssKey key[1];
    word32  pubLen = 0;

    ret = wc_XmssKey_Init(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Server_XmssKeyCacheExport(server, keyId, key);
        if (ret == WH_ERROR_OK) {
            ret = wc_XmssKey_GetPubLen(key, &pubLen);
        }
        if (ret == WH_ERROR_OK) {
            if (pubLen > (word32)*outSz) {
                ret = WH_ERROR_NOSPACE;
            }
            else {
                memcpy(out, key->pk, pubLen);
                *outSz = (uint16_t)pubLen;
            }
        }
        wc_XmssKey_Free(key);
    }
    return ret;
}
#endif /* WOLFSSL_HAVE_XMSS */

int wh_Server_KeystoreGetUniqueId(whServerContext* server, whNvmId* inout_id)
{
    int     ret   = WH_ERROR_OK;
    int     found = 0;
    whNvmId id;
    /* apply client_id and type which should be set by caller on outId */
    whKeyId key_id = *inout_id;
    int     type   = WH_KEYID_TYPE(key_id);
    int     user   = WH_KEYID_USER(key_id);
    whNvmId buildId;

    whKeyCacheContext* ctx = _GetCacheContext(server, key_id);

    /* Wrapped keys must be provisioned with explicit identifiers */
    if (type == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only key ids are assigned by the hardware backend */
    if (type == WH_KEYTYPE_HW) {
        return WH_ERROR_BADARGS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    /* try every index until we find a unique one, don't worry about capacity */
    for (id = WH_KEYID_IDMAX; id > WH_KEYID_ERASED; id--) {
        /* id loop var is not an input client ID so we don't need to handle the
         * global case */
        buildId = WH_MAKE_KEYID(type, user, id);

        /* Check against cache keys using unified cache functions */
        ret = _FindInKeyCache(ctx, buildId, NULL, NULL, NULL, NULL);
        if (ret == WH_ERROR_OK) {
            /* Found in cache, try next ID */
            continue;
        }
        else if (ret != WH_ERROR_NOTFOUND) {
            return ret;
        }

        /* Check if keyId exists in NVM. With no NVM, not being in the cache
         * is enough to make this ID unique. */
        if (server->nvm == NULL) {
            found = 1;
            break;
        }
        ret = wh_Nvm_GetMetadata(server->nvm, buildId, NULL);
        if (ret == WH_ERROR_NOTFOUND) {
            /* key doesn't exist in NVM, we found a candidate ID */
            found = 1;
            break;
        }

        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }

    if (!found) {
        return WH_ERROR_NOSPACE;
    }

    /* Return found id */
    *inout_id = buildId;
    return WH_ERROR_OK;
}

/* find a slot to cache a key. If key is already there, is evicted first */
int wh_Server_KeystoreGetCacheSlot(whServerContext* server, whKeyId keyId,
                                   uint16_t keySz, uint8_t** outBuf,
                                   whNvmMetadata** outMeta)
{
    whKeyCacheContext* ctx;
    int                ret;
    int                idx       = -1;
    int                isBig     = -1;
    uint8_t*           buf       = NULL;
    whNvmMetadata*     foundMeta = NULL;

    if (server == NULL || (keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE &&
                           keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE)) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only keys must never occupy a cache slot. This core check is
     * the sole protection for the DMA cache path, which allocates its slot
     * here without going through _KeystoreCacheKey */
    if (WH_KEYID_ISHW(keyId)) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    ret = _FindInCache(server, keyId, &idx, &isBig, &buf, &foundMeta);
    if (ret == WH_ERROR_OK) {
        /* Key is already cached; evict it first */
        ret = wh_Server_KeystoreEvictKey(server, keyId);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }
    else if (ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    ctx = _GetCacheContext(server, keyId);
    return _GetKeyCacheSlot(ctx, keySz, outBuf, outMeta);
}

int wh_Server_KeystoreGetCacheSlotChecked(whServerContext* server,
                                          whKeyId keyId, uint16_t keySz,
                                          uint8_t**       outBuf,
                                          whNvmMetadata** outMeta)
{
    int ret;
    ret = _KeystoreCheckPolicy(server, WH_KS_OP_CACHE, keyId);
    if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTFOUND) {
        return ret;
    }
    return wh_Server_KeystoreGetCacheSlot(server, keyId, keySz, outBuf,
                                          outMeta);
}

static int _KeystoreCacheKey(whServerContext* server, whNvmMetadata* meta,
                             uint8_t* in, int checked)
{
    uint8_t*       slotBuf;
    whNvmMetadata* slotMeta;
    int            ret;

    /* make sure id is valid */
    if ((server == NULL) || (meta == NULL) || (in == NULL) ||
        WH_KEYID_IS_UNASSIGNED(meta->id) ||
        ((meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) &&
         (meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE))) {
        return WH_ERROR_BADARGS;
    }

#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
    /* Checked calls must refuse access to the LMX/XMSS private key */
    if (checked && wh_Crypto_IsStatefulSigPrivBlob(in, (uint16_t)meta->len)) {
        return WH_ERROR_ACCESS;
    }
#endif
#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only keys must never enter the key cache */
    if (WH_KEYID_ISHW(meta->id)) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    if (checked) {
        ret = wh_Server_KeystoreGetCacheSlotChecked(server, meta->id, meta->len,
                                                    &slotBuf, &slotMeta);
    }
    else {
        ret = wh_Server_KeystoreGetCacheSlot(server, meta->id, meta->len,
                                             &slotBuf, &slotMeta);
    }
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    memcpy(slotBuf, in, meta->len);
    memcpy((uint8_t*)slotMeta, (uint8_t*)meta, sizeof(whNvmMetadata));
    _MarkKeyCommitted(_GetCacheContext(server, meta->id), meta->id, 0);

    WH_DEBUG_SERVER_VERBOSE("hsmCacheKey: cached keyid=0x%X, len=%u\n",
                            meta->id, meta->len);
    WH_DEBUG_VERBOSE_HEXDUMP("[server] cacheKey: key=", in, meta->len);

    return WH_ERROR_OK;
}

int wh_Server_KeystoreCacheKey(whServerContext* server, whNvmMetadata* meta,
                               uint8_t* in)
{
    return _KeystoreCacheKey(server, meta, in, 0);
}
int wh_Server_KeystoreCacheKeyChecked(whServerContext* server,
                                      whNvmMetadata* meta, uint8_t* in)
{
    return _KeystoreCacheKey(server, meta, in, 1);
}

#ifndef WC_NO_RNG
static int _KeystoreCacheRandomKey(whServerContext* server, whNvmMetadata* meta)
{
    uint8_t*       slotBuf;
    whNvmMetadata* slotMeta;
    int            ret;

    /* make sure id and length are valid */
    if ((server == NULL) || (meta == NULL) || (meta->len == 0) ||
        WH_KEYID_ISERASED(meta->id) ||
        ((meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) &&
         (meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreGetCacheSlotChecked(server, meta->id, meta->len,
                                                &slotBuf, &slotMeta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Fill the slot directly from the server RNG */
    ret = wc_RNG_GenerateBlock(server->crypto->rng, slotBuf, meta->len);
    if (ret != 0) {
        return ret;
    }

    memcpy((uint8_t*)slotMeta, (uint8_t*)meta, sizeof(whNvmMetadata));
    _MarkKeyCommitted(_GetCacheContext(server, meta->id), meta->id, 0);

    WH_DEBUG_SERVER_VERBOSE("hsmGenerateKey: cached keyid=0x%X, len=%u\n",
                            meta->id, meta->len);

    return WH_ERROR_OK;
}
#endif /* !WC_NO_RNG */

static int _FindInCache(whServerContext* server, whKeyId keyId, int* out_index,
                        int* out_big, uint8_t** out_buffer,
                        whNvmMetadata** out_meta)
{
    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);
    return _FindInKeyCache(ctx, keyId, out_index, out_big, out_buffer,
                           out_meta);
}

#ifdef WOLFHSM_CFG_KEYWRAP
static int _ExistsInCache(whServerContext* server, whKeyId keyId)
{
    int            ret           = 0;
    int            foundIndex    = -1;
    int            foundBigIndex = -1;
    whNvmMetadata* tmpMeta;
    uint8_t*       tmpBuf;

    ret = _FindInCache(server, keyId, &foundIndex, &foundBigIndex, &tmpBuf,
                       &tmpMeta);

    if (ret != WH_ERROR_OK) {
        /* Key doesn't exist in the cache */
        return 0;
    }

    /* Key exists in the cache */
    return 1;
}
#endif /* WOLFHSM_CFG_KEYWRAP */

/* try to put the specified key into cache if it isn't already, return pointers
 * to meta and the cached data*/
int wh_Server_KeystoreFreshenKey(whServerContext* server, whKeyId keyId,
                                 uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int             ret            = 0;
    int             foundIndex     = -1;
    int             foundBigIndex  = -1;
    uint8_t*        cacheBufLocal  = NULL;
    whNvmMetadata*  cacheMetaLocal = NULL;
    uint8_t**       cacheBufOut;
    whNvmMetadata** cacheMetaOut;
    whNvmMetadata   tmpMeta[1];

    if ((server == NULL) || WH_KEYID_IS_UNASSIGNED(keyId)) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only keys are never cached and are not usable through the
     * keystore. The keywrap KEK path fetches them directly from the hardware
     * keystore instead */
    if (WH_KEYID_ISHW(keyId)) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    /* Use local buffers to allow for optional (NULL) output parameters */
    cacheBufOut  = (outBuf != NULL) ? outBuf : (uint8_t**)&cacheBufLocal;
    cacheMetaOut = (outMeta != NULL) ? outMeta : &cacheMetaLocal;

    ret = _FindInCache(server, keyId, &foundIndex, &foundBigIndex, cacheBufOut,
                       cacheMetaOut);
    if (ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    /* key not in the cache */

    /* For wrapped keys, just probe the cache and error if not found. We
     * don't support automatically unwrapping and caching outside of the
     * keywrap API */
    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_NOTFOUND;
    }

    /* No NVM to check, so a cache miss means not found. */
    if (server->nvm == NULL) {
        return WH_ERROR_NOTFOUND;
    }

    /* Not in cache. Check if it is in NVM */
    ret = wh_Nvm_GetMetadata(server->nvm, keyId, tmpMeta);
    if (ret == WH_ERROR_OK) {
        /* Key found in NVM, get a free cache slot */
        ret = wh_Server_KeystoreGetCacheSlot(server, keyId, tmpMeta->len,
                                             cacheBufOut, cacheMetaOut);
        if (ret == WH_ERROR_OK) {
            /* Read the key from NVM into the cache slot */
            ret =
                wh_Nvm_Read(server->nvm, keyId, 0, tmpMeta->len, *cacheBufOut);
            if (ret == WH_ERROR_OK) {
                /* Copy the metadata to the cache slot if key read is
                 * successful*/
                memcpy((uint8_t*)*cacheMetaOut, (uint8_t*)tmpMeta,
                       sizeof(whNvmMetadata));
                _MarkKeyCommitted(_GetCacheContext(server, keyId), keyId, 1);
            }
        }
    }

    return ret;
}

/* Reads key from cache or NVM. If keyId is a wrapped key will attempt to read
 * from cache but NOT from NVM */
int wh_Server_KeystoreReadKey(whServerContext* server, whKeyId keyId,
                              whNvmMetadata* outMeta, uint8_t* out,
                              uint32_t* outSz)
{
    int            ret = 0;
    whNvmMetadata  meta[1];
    whNvmMetadata* cacheMeta   = NULL;
    uint8_t*       cacheBuffer = NULL;

    if ((server == NULL) || (outSz == NULL) || WH_KEYID_IS_UNASSIGNED(keyId)) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only key material must never be read out of the server */
    if (WH_KEYID_ISHW(keyId)) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    /* Check the cache using unified function */
    ret = _FindInCache(server, keyId, NULL, NULL, &cacheBuffer, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        /* Found in cache */
        if (cacheMeta->len > *outSz)
            return WH_ERROR_NOSPACE;
        if (outMeta != NULL) {
            memcpy((uint8_t*)outMeta, (uint8_t*)cacheMeta,
                   sizeof(whNvmMetadata));
        }
        if (out != NULL) {
            memcpy(out, cacheBuffer, cacheMeta->len);
        }
        *outSz = cacheMeta->len;
        return 0;
    }

    /* For wrapped keys, just probe the cache and error if not found. We
     * don't support automatically unwrapping and caching outside of the
     * keywrap API */
    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_NOTFOUND;
    }

    /* Not in cache, try to read the metadata from NVM. With no NVM the key is
     * not found, but the SHE master-ecu fallback below still applies. */
    if (server->nvm != NULL) {
        ret = wh_Nvm_GetMetadata(server->nvm, keyId, meta);
    }
    else {
        ret = WH_ERROR_NOTFOUND;
    }
    if (ret == 0) {
        if (meta->len > *outSz)
            return WH_ERROR_NOSPACE;
        /* set outSz */
        *outSz = meta->len;
        /* read meta */
        if (outMeta != NULL)
            memcpy((uint8_t*)outMeta, (uint8_t*)meta, sizeof(*outMeta));
        /* read the object */
        if (out != NULL)
            ret = wh_Nvm_Read(server->nvm, keyId, 0, *outSz, out);
    }
    /* cache key if free slot, will only kick out other committed keys.
     * Skip SHE SECRET_KEY (slot 0): _KeystoreCacheKey now accepts an id with a
     * zero ID field for SHE keys (so SECRET_KEY can be primed via
     * unwrap-and-cache on a NVM-less server), but auto-caching it here would
     * block a later prime of the same slot (unwrap-and-cache rejects ids
     * already in cache). Keep reading it straight from NVM each time. */
    if (ret == 0 && out != NULL &&
        !((WH_KEYID_TYPE(meta->id) == WH_KEYTYPE_SHE) &&
          (WH_KEYID_ID(meta->id) == WH_KEYID_ERASED))) {
        if (wh_Server_KeystoreCacheKey(server, meta, out) == WH_ERROR_OK) {
            /* Cached key found in NVM. Mark it committed so it can be
               evicted later. */
            _MarkKeyCommitted(_GetCacheContext(server, keyId), keyId, 1);
        }
    }
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    /* use empty key of zeros if we couldn't find the master ecu key */
    if ((ret == WH_ERROR_NOTFOUND) &&
        (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_SHE) &&
        (WH_KEYID_ID(keyId) == WH_SHE_MASTER_ECU_KEY_ID)) {
        if (out != NULL)
            memset(out, 0, WH_SHE_KEY_SZ);
        *outSz = WH_SHE_KEY_SZ;
        if (outMeta != NULL) {
            /* need empty flags and correct length and id */
            memset(outMeta, 0, sizeof(*outMeta));
            outMeta->len = WH_SHE_KEY_SZ;
            outMeta->id  = keyId;
        }
        ret = 0;
    }
#endif
    return ret;
}

int wh_Server_KeystoreReadKeyChecked(whServerContext* server, whKeyId keyId,
                                     whNvmMetadata* outMeta, uint8_t* out,
                                     uint32_t* outSz)
{
    int ret;

    ret = _KeystoreCheckPolicy(server, WH_KS_OP_EXPORT, keyId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    return wh_Server_KeystoreReadKey(server, keyId, outMeta, out, outSz);
}

int wh_Server_KeystoreEvictKey(whServerContext* server, whNvmId keyId)
{
    int                ret = 0;
    whKeyCacheContext* ctx;

    if ((server == NULL) || WH_KEYID_IS_UNASSIGNED(keyId)) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only keys are never cached, so there is nothing to evict */
    if (WH_KEYID_ISHW(keyId)) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    /* Get the appropriate cache context for this key */
    ctx = _GetCacheContext(server, keyId);

    /* Use the unified evict function */
    ret = _EvictKeyFromCache(ctx, keyId);

    if (ret == 0) {
        WH_DEBUG_SERVER_VERBOSE("wh_Server_KeystoreEvictKey: evicted keyid=0x%X\n",
               keyId);
    }

    return ret;
}

int wh_Server_KeystoreEvictKeyChecked(whServerContext* server, whNvmId keyId)
{
    int ret;

    ret = _KeystoreCheckPolicy(server, WH_KS_OP_EVICT, keyId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    return wh_Server_KeystoreEvictKey(server, keyId);
}

int wh_Server_KeystoreCommitKey(whServerContext* server, whNvmId keyId)
{
    uint8_t*           slotBuf;
    whNvmMetadata*     slotMeta;
    whNvmSize          size;
    int                ret;
    whKeyCacheContext* ctx;

    if ((server == NULL) || WH_KEYID_IS_UNASSIGNED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_ABORTED;
    }

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only keys must never be persisted to NVM */
    if (WH_KEYID_ISHW(keyId)) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    /* Get the appropriate cache context for this key */
    ctx = _GetCacheContext(server, keyId);

    /* Find the key in the appropriate cache context obtained above. */
    ret = _FindInKeyCache(ctx, keyId, NULL, NULL, &slotBuf, &slotMeta);
    if (ret == WH_ERROR_OK) {
        size = slotMeta->len;
        /* Committing writes the cached key to NVM. With no NVM there is
         * nowhere to persist it, so wh_Nvm_* returns an error. */
        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, slotMeta, size, slotBuf);
        if (ret == 0) {
            /* Mark key as committed using unified function */
            (void)_MarkKeyCommitted(ctx, keyId, 1);
        }
    }
    return ret;
}

int wh_Server_KeystoreCommitKeyChecked(whServerContext* server, whNvmId keyId)
{
    int ret;

    ret = _KeystoreCheckPolicy(server, WH_KS_OP_COMMIT, keyId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    return wh_Server_KeystoreCommitKey(server, keyId);
}

int wh_Server_KeystoreEraseKey(whServerContext* server, whNvmId keyId)
{
    if ((server == NULL) || (WH_KEYID_IS_UNASSIGNED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_ABORTED;
    }

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only keys are not keystore-managed and cannot be erased */
    if (WH_KEYID_ISHW(keyId)) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    /* remove the key from the cache if present */
    (void)wh_Server_KeystoreEvictKey(server, keyId);

    /* No NVM means there is nothing to destroy, same as erasing a key that
     * was never there. */
    if (server->nvm == NULL) {
        return WH_ERROR_OK;
    }

    /* destroy the object */
    return wh_Nvm_DestroyObjects(server->nvm, 1, &keyId);
}

int wh_Server_KeystoreEraseKeyChecked(whServerContext* server, whNvmId keyId)
{
    int ret;

    if ((server == NULL) || (WH_KEYID_IS_UNASSIGNED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_ABORTED;
    }

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Hardware-only keys are not keystore-managed and cannot be erased */
    if (WH_KEYID_ISHW(keyId)) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    /* NOTFOUND means the key was not cached, whether it is absent entirely or
     * lives only in NVM; both are fine. Any other error must not be masked by
     * the destroy below. */
    ret = wh_Server_KeystoreEvictKeyChecked(server, keyId);
    if ((ret != WH_ERROR_OK) && (ret != WH_ERROR_NOTFOUND)) {
        return ret;
    }

    /* Nothing left to destroy is a successful erase, matching
     * wh_Server_KeystoreEraseKey */
    if (server->nvm == NULL) {
        return WH_ERROR_OK;
    }

    return wh_Nvm_DestroyObjectsChecked(server->nvm, 1, &keyId);
}

static void _revokeKey(whNvmMetadata* meta)
{

    /* Set NONMODIFIABLE flag and clear all usage flags */
    meta->flags |= WH_NVM_FLAGS_NONMODIFIABLE;
    meta->flags &= ~WH_NVM_FLAGS_USAGE_ANY;
}

static int _isKeyRevoked(whNvmMetadata* meta)
{
    if ((meta->flags & WH_NVM_FLAGS_NONMODIFIABLE) &&
        ((meta->flags & WH_NVM_FLAGS_USAGE_ANY) == 0)) {
        return 1;
    }

    return 0;
}

int wh_Server_KeystoreRevokeKey(whServerContext* server, whNvmId keyId)
{
    int            ret;
    int            isInNvm   = 0;
    uint8_t*       cacheBuf  = NULL;
    whNvmMetadata* cacheMeta = NULL;

    if ((server == NULL) || WH_KEYID_IS_UNASSIGNED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _KeystoreCheckPolicy(server, WH_KS_OP_REVOKE, keyId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* No NVM means the key can't be in NVM. */
    if (server->nvm != NULL) {
        ret = wh_Nvm_GetMetadata(server->nvm, keyId, NULL);
        if (ret == WH_ERROR_OK) {
            isInNvm = 1;
        }
        else if (ret != WH_ERROR_NOTFOUND) {
            return ret;
        }
    }

    /* be sure to have the key in the cache */
    ret = wh_Server_KeystoreFreshenKey(server, keyId, &cacheBuf, &cacheMeta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* if already revoked and committed, nothing to do */
    if (_isKeyRevoked(cacheMeta) && _KeyIsCommitted(server, keyId)) {
        return WH_ERROR_OK;
    }

    /* Revoke the key by updating its metadata */
    _revokeKey(cacheMeta);
    /* commit the changes */
    if (isInNvm) {
        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, cacheMeta,
                                          cacheMeta->len, cacheBuf);
        if (ret == WH_ERROR_OK) {
            _MarkKeyCommitted(_GetCacheContext(server, keyId), keyId, 1);
        }
    }

    return ret;
}

#ifdef WOLFHSM_CFG_KEYWRAP

#ifndef NO_AES
#ifdef HAVE_AESGCM

/* Resolve the KEK for a keywrap operation. Hardware-only KEKs (TYPE=HW)
 * are fetched from the server's hardware keystore into hwKekBuf, which the
 * caller must keep local and zeroize after use; they carry no NVM metadata,
 * so usage policy is delegated to the hardware keystore backend. All other
 * KEKs are freshened into the key cache and must carry WH_NVM_FLAGS_USAGE_WRAP.
 *
 * When enforceTrustedKek is nonzero the KEK must be one the client cannot know
 * or set: a hardware key (returned above) or a software key carrying
 * WH_NVM_FLAGS_TRUSTED. This is the unified eligibility predicate
 * isTrustedKek = WH_KEYID_ISHW(id) || (flags & WH_NVM_FLAGS_TRUSTED), required
 * by the ops that move a server secret across the client boundary
 * (KeyWrapExport, KeyUnwrapAndCache). */
static int _KeywrapResolveKek(whServerContext* server, whKeyId serverKeyId,
                              int enforceTrustedKek, uint8_t* hwKekBuf,
                              uint16_t hwKekBufSz, const uint8_t** outKek,
                              uint32_t* outKekSz)
{
    int            ret;
    whNvmMetadata* kekMeta = NULL;
    uint8_t*       kek     = NULL;

#ifdef WOLFHSM_CFG_HWKEYSTORE
    if (WH_KEYID_ISHW(serverKeyId)) {
        uint16_t hwKekSz = hwKekBufSz;
        if (server->hwKeystore == NULL) {
            /* No hardware keystore bound to this server */
            return WH_ERROR_NOTFOUND;
        }
        ret = wh_HwKeystore_GetKey(server->hwKeystore, serverKeyId, hwKekBuf,
                                   &hwKekSz);
        if (ret == WH_ERROR_OK) {
            *outKek   = hwKekBuf;
            *outKekSz = hwKekSz;
        }
        return ret;
    }
#else
    (void)hwKekBuf;
    (void)hwKekBufSz;
#endif /* WOLFHSM_CFG_HWKEYSTORE */

    ret = wh_Server_KeystoreFreshenKey(server, serverKeyId, &kek, &kekMeta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Every KEK must be authorized for wrapping */
    ret = wh_Server_KeystoreEnforceKeyUsage(kekMeta, WH_NVM_FLAGS_USAGE_WRAP);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* A hardware KEK already returned above and is inherently trusted; a
     * software KEK qualifies only if it was provisioned with
     * WH_NVM_FLAGS_TRUSTED (which a client can never set). */
    if (enforceTrustedKek && !(kekMeta->flags & WH_NVM_FLAGS_TRUSTED)) {
        return WH_ERROR_ACCESS;
    }

    *outKek   = kek;
    *outKekSz = kekMeta->len;
    return WH_ERROR_OK;
}

/* Size of the local storage each keywrap helper provides for a hardware-only
 * KEK. Minimal when no hardware keystore is configured, since the resolver
 * then never writes to it */
#ifdef WOLFHSM_CFG_HWKEYSTORE
#define WH_KEYWRAP_HWKEK_BUF_SIZE WOLFHSM_CFG_HWKEYSTORE_MAX_KEY_SIZE
#else
#define WH_KEYWRAP_HWKEK_BUF_SIZE 1
#endif /* WOLFHSM_CFG_HWKEYSTORE */

static const uint8_t WH_KEYWRAP_AAD_KEY[]  = WH_KEYWRAP_AAD_KEY_STR;
static const uint8_t WH_KEYWRAP_AAD_DATA[] = WH_KEYWRAP_AAD_DATA_STR;

static int _AesGcmKeyWrapWithKek(whServerContext* server,
                                 const uint8_t* serverKey, uint32_t serverKeySz,
                                 uint8_t* keyIn, uint16_t keySz,
                                 whNvmMetadata* metadataIn,
                                 uint8_t* wrappedKeyOut, uint16_t wrappedKeySz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t  plainBlob[sizeof(*metadataIn) + WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
    uint32_t plainBlobSz = sizeof(*metadataIn) + keySz;
    uint8_t* encBlob;

    if (server == NULL || keyIn == NULL || metadataIn == NULL ||
        wrappedKeyOut == NULL || plainBlobSz > sizeof(plainBlob)) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the buffer is big enough to hold the wrapped key */
    if (wrappedKeySz <
        sizeof(iv) + sizeof(authTag) + sizeof(*metadataIn) + keySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Generate the IV */
    ret = wc_RNG_GenerateBlock(server->crypto->rng, iv, sizeof(iv));
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Combine key and metadata into one blob */
    memcpy(plainBlob, metadataIn, sizeof(*metadataIn));
    memcpy(plainBlob + sizeof(*metadataIn), keyIn, keySz);

    /* Place the encrypted blob after the IV and Auth Tag */
    encBlob = (uint8_t*)wrappedKeyOut + sizeof(iv) + sizeof(authTag);

    /* Encrypt the blob under the key-wrap domain */
    ret = wc_AesGcmEncrypt(aes, encBlob, plainBlob, plainBlobSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), WH_KEYWRAP_AAD_KEY,
                           WH_KEYWRAP_AAD_KEY_LEN);
    if (ret == 0) {
        /* Prepend IV + authTag to encrypted blob */
        memcpy(wrappedKeyOut, iv, sizeof(iv));
        memcpy(wrappedKeyOut + sizeof(iv), authTag, sizeof(authTag));
    }

    wc_AesFree(aes);

    /* plainBlob held the cleartext metadata+key; wipe the stack copy */
    wh_Utils_ForceZero(plainBlob, sizeof(plainBlob));

    return (ret == 0) ? WH_ERROR_OK : ret;
}

static int _AesGcmKeyWrap(whServerContext* server, whKeyId serverKeyId,
                          int requireTrustedKek, uint8_t* keyIn, uint16_t keySz,
                          whNvmMetadata* metadataIn, uint8_t* wrappedKeyOut,
                          uint16_t wrappedKeySz)
{
    int            ret;
    const uint8_t* serverKey   = NULL;
    uint32_t       serverKeySz = 0;
    uint8_t        hwKek[WH_KEYWRAP_HWKEK_BUF_SIZE];

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get the server side key (KEK) */
    ret = _KeywrapResolveKek(server, serverKeyId, requireTrustedKek, hwKek,
                             (uint16_t)sizeof(hwKek), &serverKey, &serverKeySz);
    if (ret == WH_ERROR_OK) {
        ret =
            _AesGcmKeyWrapWithKek(server, serverKey, serverKeySz, keyIn, keySz,
                                  metadataIn, wrappedKeyOut, wrappedKeySz);
    }

    /* Wipe any hardware KEK material from local storage */
    wh_Utils_ForceZero(hwKek, sizeof(hwKek));

    return ret;
}

static int _AesGcmKeyUnwrapWithKek(whServerContext* server,
                                   const uint8_t*   serverKey,
                                   uint32_t serverKeySz, void* wrappedKeyIn,
                                   uint16_t       wrappedKeySz,
                                   whNvmMetadata* metadataOut, void* keyOut,
                                   uint16_t keySz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t* encBlob;
    uint16_t encBlobSz;
    uint8_t  plainBlob[sizeof(*metadataOut) + WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];

    if (server == NULL || wrappedKeyIn == NULL || metadataOut == NULL ||
        keyOut == NULL || keySz > WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE) {
        return WH_ERROR_BADARGS;
    }

    if (wrappedKeySz < sizeof(iv) + sizeof(authTag)) {
        return WH_ERROR_BADARGS;
    }

    encBlob   = (uint8_t*)wrappedKeyIn + sizeof(iv) + sizeof(authTag);
    encBlobSz = wrappedKeySz - sizeof(iv) - sizeof(authTag);

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Extract IV and authTag from wrappedKeyIn */
    memcpy(iv, wrappedKeyIn, sizeof(iv));
    memcpy(authTag, (const uint8_t*)wrappedKeyIn + sizeof(iv), sizeof(authTag));

    /* Decrypt under the key-wrap domain; a data blob won't authenticate here */
    ret = wc_AesGcmDecrypt(aes, plainBlob, encBlob, encBlobSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), WH_KEYWRAP_AAD_KEY,
                           WH_KEYWRAP_AAD_KEY_LEN);
    if (ret == 0) {
        /* Extract metadata and key from the decrypted blob */
        memcpy(metadataOut, plainBlob, sizeof(*metadataOut));
        memcpy(keyOut, plainBlob + sizeof(*metadataOut), keySz);
    }

    wc_AesFree(aes);

    /* plainBlob held the decrypted metadata+key; wipe the stack copy */
    wh_Utils_ForceZero(plainBlob, sizeof(plainBlob));

    return ret;
}

static int _AesGcmKeyUnwrap(whServerContext* server, uint16_t serverKeyId,
                            int requireTrustedKek, void* wrappedKeyIn,
                            uint16_t wrappedKeySz, whNvmMetadata* metadataOut,
                            void* keyOut, uint16_t keySz)
{
    int            ret;
    const uint8_t* serverKey   = NULL;
    uint32_t       serverKeySz = 0;
    uint8_t        hwKek[WH_KEYWRAP_HWKEK_BUF_SIZE];

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get the server side key (KEK) */
    ret = _KeywrapResolveKek(server, serverKeyId, requireTrustedKek, hwKek,
                             (uint16_t)sizeof(hwKek), &serverKey, &serverKeySz);
    if (ret == WH_ERROR_OK) {
        ret = _AesGcmKeyUnwrapWithKek(server, serverKey, serverKeySz,
                                      wrappedKeyIn, wrappedKeySz, metadataOut,
                                      keyOut, keySz);
    }

    /* Wipe any hardware KEK material from local storage */
    wh_Utils_ForceZero(hwKek, sizeof(hwKek));

    return ret;
}

static int _AesGcmDataWrapWithKek(whServerContext* server,
                                  const uint8_t*   serverKey,
                                  uint32_t serverKeySz, uint8_t* dataIn,
                                  uint16_t dataSz, uint8_t* wrappedDataOut,
                                  uint16_t wrappedDataSz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t* encBlob;

    if (server == NULL || dataIn == NULL || wrappedDataOut == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the buffer is big enough to hold the wrapped data */
    if (wrappedDataSz < sizeof(iv) + sizeof(authTag) + dataSz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Generate the IV */
    ret = wc_RNG_GenerateBlock(server->crypto->rng, iv, sizeof(iv));
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Place the encrypted blob after the IV and Auth Tag */
    encBlob = (uint8_t*)wrappedDataOut + sizeof(iv) + sizeof(authTag);

    /* Encrypt the blob under the data-wrap domain */
    ret = wc_AesGcmEncrypt(aes, encBlob, dataIn, dataSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), WH_KEYWRAP_AAD_DATA,
                           WH_KEYWRAP_AAD_DATA_LEN);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Prepend IV + authTag to encrypted blob */
    memcpy(wrappedDataOut, iv, sizeof(iv));
    memcpy(wrappedDataOut + sizeof(iv), authTag, sizeof(authTag));

    wc_AesFree(aes);

    return WH_ERROR_OK;
}

static int _AesGcmDataWrap(whServerContext* server, whKeyId serverKeyId,
                           uint8_t* dataIn, uint16_t dataSz,
                           uint8_t* wrappedDataOut, uint16_t wrappedDataSz)
{
    int            ret;
    const uint8_t* serverKey   = NULL;
    uint32_t       serverKeySz = 0;
    uint8_t        hwKek[WH_KEYWRAP_HWKEK_BUF_SIZE];

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get the server side key (KEK). Data wrap requires the KEK to carry
     * USAGE_WRAP, but not to be a trusted KEK (no server secret crosses the
     * boundary). */
    ret = _KeywrapResolveKek(server, serverKeyId, 0, hwKek,
                             (uint16_t)sizeof(hwKek), &serverKey, &serverKeySz);
    if (ret == WH_ERROR_OK) {
        ret = _AesGcmDataWrapWithKek(server, serverKey, serverKeySz, dataIn,
                                     dataSz, wrappedDataOut, wrappedDataSz);
    }

    /* Wipe any hardware KEK material from local storage */
    wh_Utils_ForceZero(hwKek, sizeof(hwKek));

    return ret;
}

static int _AesGcmDataUnwrapWithKek(whServerContext* server,
                                    const uint8_t*   serverKey,
                                    uint32_t serverKeySz, void* wrappedDataIn,
                                    uint16_t wrappedDataSz, void* dataOut,
                                    uint16_t dataSz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t* encBlob;
    uint16_t encBlobSz;

    if (server == NULL || wrappedDataIn == NULL || dataOut == NULL ||
        dataSz > WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE) {
        return WH_ERROR_BADARGS;
    }

    if (wrappedDataSz < sizeof(iv) + sizeof(authTag)) {
        return WH_ERROR_BADARGS;
    }

    encBlob   = (uint8_t*)wrappedDataIn + sizeof(iv) + sizeof(authTag);
    encBlobSz = wrappedDataSz - sizeof(iv) - sizeof(authTag);

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Extract IV and authTag from wrappedDataIn */
    memcpy(iv, wrappedDataIn, sizeof(iv));
    memcpy(authTag, (const uint8_t*)wrappedDataIn + sizeof(iv), sizeof(authTag));

    /* Decrypt under the data-wrap domain; a key blob won't authenticate here */
    ret = wc_AesGcmDecrypt(aes, dataOut, encBlob, encBlobSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), WH_KEYWRAP_AAD_DATA,
                           WH_KEYWRAP_AAD_DATA_LEN);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    wc_AesFree(aes);
    return WH_ERROR_OK;
}

static int _AesGcmDataUnwrap(whServerContext* server, uint16_t serverKeyId,
                             void* wrappedDataIn, uint16_t wrappedDataSz,
                             void* dataOut, uint16_t dataSz)
{
    int            ret;
    const uint8_t* serverKey   = NULL;
    uint32_t       serverKeySz = 0;
    uint8_t        hwKek[WH_KEYWRAP_HWKEK_BUF_SIZE];

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get the server side key (KEK). Data unwrap requires the KEK to carry
     * USAGE_WRAP, but not to be a trusted KEK (no server secret crosses the
     * boundary). */
    ret = _KeywrapResolveKek(server, serverKeyId, 0, hwKek,
                             (uint16_t)sizeof(hwKek), &serverKey, &serverKeySz);
    if (ret == WH_ERROR_OK) {
        ret = _AesGcmDataUnwrapWithKek(server, serverKey, serverKeySz,
                                       wrappedDataIn, wrappedDataSz, dataOut,
                                       dataSz);
    }

    /* Wipe any hardware KEK material from local storage */
    wh_Utils_ForceZero(hwKek, sizeof(hwKek));

    return ret;
}

#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

static int _HandleKeyWrapRequest(whServerContext*                  server,
                                 whMessageKeystore_KeyWrapRequest* req,
                                 uint8_t* reqData, uint32_t reqDataSz,
                                 whMessageKeystore_KeyWrapResponse* resp,
                                 uint8_t* respData, uint32_t respDataSz)
{

    int           ret;
    uint8_t*      wrappedKey;
    whNvmMetadata metadata;
    uint8_t       key[WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
    whKeyId       serverKeyId;

    if (server == NULL || req == NULL || reqData == NULL ||
        resp == NULL || respData == NULL ||
        req->keySz > WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE)
    {
        return WH_ERROR_BADARGS;
    }

    /* Check if the reqData is big enough to hold the metadata and key */
    if (reqDataSz < sizeof(metadata) + req->keySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Extract the metadata and key from reqData */
    memcpy(&metadata, reqData, sizeof(metadata));
    memcpy(key, reqData + sizeof(metadata), req->keySz);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Wrapped key size is only passed back to the client on success */
    resp->wrappedKeySz = 0;

    /* Ensure the keyId in the wrapped metadata has the wrapped flag set */
    if (!WH_KEYID_ISWRAPPED(metadata.id)) {
        WH_LOG_F(&server->log, WH_LOG_LEVEL_ERROR,
                 "KeyWrapRequest: keyId:0x%08X is not wrapped", metadata.id);
        return WH_ERROR_BADARGS;
    }

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                               server->comm->client_id,
                                               req->serverKeyId);

    /* Store the wrapped key in the response data */
    wrappedKey = respData;

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t wrappedKeySz =
                WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(metadata) + req->keySz;

            /* Check if the response data can fit the wrapped key */
            if (respDataSz < wrappedKeySz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Wrap the key. The client supplies the plaintext, so no server
             * secret crosses the boundary; the KEK may be any client key. */
            ret = _AesGcmKeyWrap(server, serverKeyId, /*requireTrustedKek=*/0,
                                 key, req->keySz, &metadata, wrappedKey,
                                 wrappedKeySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Tell the client how big the wrapped key is */
            resp->wrappedKeySz = wrappedKeySz;

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

/* Wrap a key the server already holds (identified by id) and return the wrapped
 * blob. The client presents only an id; never plaintext. The blob carries the
 * key's real metadata so it round-trips through unwrap-and-cache. */
static int
_HandleKeyWrapExportRequest(whServerContext*                        server,
                            whMessageKeystore_KeyWrapExportRequest* req,
                            uint8_t* reqData, uint32_t reqDataSz,
                            whMessageKeystore_KeyWrapExportResponse* resp,
                            uint8_t* respData, uint32_t respDataSz)
{
    int           ret;
    uint8_t*      wrappedKey;
    whNvmMetadata metadata = {0};
    uint8_t       key[WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
    uint32_t      keySz = sizeof(key);
    whKeyId       targetKeyId;
    whKeyId       serverKeyId;
    uint16_t      targetKeyType;

    /* reqData/reqDataSz are unused: the key to wrap already lives in the
     * keystore, so there is no inline key payload in the request. */
    (void)reqData;
    (void)reqDataSz;

    if (server == NULL || req == NULL || resp == NULL || respData == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Wrapped key size is only passed back to the client on success */
    resp->wrappedKeySz = 0;

    /* Translate the client-supplied ids. The KEK is always a crypto key; the
     * target key type comes from req->keyType because there is no client flag
     * for SHE keys. */
    targetKeyId = wh_KeyId_TranslateFromClient(
        req->keyType, server->comm->client_id, req->keyId);
    serverKeyId = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, server->comm->client_id, req->serverKeyId);

    /* Validate the *translated* target key type against the allow-list. Using
     * the translated type also closes the gap where a client sets the WRAPPED
     * flag in keyId to override req->keyType. */
    targetKeyType = WH_KEYID_TYPE(targetKeyId);
    switch (targetKeyType) {
        case WH_KEYTYPE_CRYPTO:
        case WH_KEYTYPE_WRAPPED:
#ifdef WOLFHSM_CFG_SHE_EXTENSION
        case WH_KEYTYPE_SHE:
#endif
            break;
        default:
            return WH_ERROR_BADARGS;
    }

    /* Read the key and its real metadata, enforcing export policy
     * (NONEXPORTABLE). For wrapped keys this is a cache-only probe. */
    ret = wh_Server_KeystoreReadKeyChecked(server, targetKeyId, &metadata, key,
                                           &keySz);
    if (ret != WH_ERROR_OK) {
        goto out;
    }

    /* Normalize non-SHE keys into the WRAPPED namespace so the blob round-trips
     * through unwrap-and-cache without colliding with server-managed keyIds.
     * SHE keys must keep TYPE=SHE so the SHE API can find them after caching.
     * USER is preserved for the unwrap-side ownership check. */
    if (WH_KEYID_TYPE(metadata.id) != WH_KEYTYPE_SHE) {
        metadata.id =
            WH_MAKE_KEYID(WH_KEYTYPE_WRAPPED, WH_KEYID_USER(metadata.id),
                          WH_KEYID_ID(metadata.id));
    }

    /* Store the wrapped key in the response data */
    wrappedKey = respData;

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t wrappedKeySz = WH_KEYWRAP_AES_GCM_HEADER_SIZE +
                                    sizeof(metadata) + (uint16_t)keySz;

            /* Check if the response data can fit the wrapped key */
            if (respDataSz < wrappedKeySz) {
                ret = WH_ERROR_BUFFER_SIZE;
                goto out;
            }

            /* Wrap the key with its real metadata. This extracts a server-held
             * secret to the client, so the KEK must be a trusted (HW or
             * WH_NVM_FLAGS_TRUSTED) key the client cannot know. */
            ret = _AesGcmKeyWrap(server, serverKeyId, /*requireTrustedKek=*/1,
                                 key, (uint16_t)keySz, &metadata, wrappedKey,
                                 wrappedKeySz);
            if (ret != WH_ERROR_OK) {
                goto out;
            }

            /* Tell the client how big the wrapped key is */
            resp->wrappedKeySz = wrappedKeySz;

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            ret = WH_ERROR_BADARGS;
            goto out;
    }

    ret = WH_ERROR_OK;

out:
    /* key[] held a cleartext server secret; wipe the stack copy on every exit
     */
    wh_Utils_ForceZero(key, sizeof(key));
    return ret;
}

static int _HandleKeyUnwrapAndExportRequest(
    whServerContext* server, whMessageKeystore_KeyUnwrapAndExportRequest* req,
    uint8_t* reqData, uint32_t reqDataSz,
    whMessageKeystore_KeyUnwrapAndExportResponse* resp, uint8_t* respData,
    uint32_t respDataSz)
{
    int            ret;
    uint8_t*       wrappedKey;
    whNvmMetadata* metadata;
    uint8_t*       key;
    whKeyId        serverKeyId;

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the reqData is big enough to hold the wrapped key */
    if (reqDataSz < req->wrappedKeySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Set the wrapped key to the request data */
    wrappedKey = reqData;

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                               server->comm->client_id,
                                               req->serverKeyId);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Key size is only passed back to the client on success */
    resp->keySz = 0;

    /* Store the metadata and key in the respData */
    metadata = (whNvmMetadata*)respData;
    key      = respData + sizeof(*metadata);

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t keySz;

            if (req->wrappedKeySz < WH_KEYWRAP_AES_GCM_HEADER_SIZE +
                                    sizeof(*metadata)) {
                return WH_ERROR_BADARGS;
            }

            keySz = req->wrappedKeySz -
                    WH_KEYWRAP_AES_GCM_HEADER_SIZE - sizeof(*metadata);

            /* Check if the response data can fit the metadata + key  */
            if (respDataSz < sizeof(*metadata) + keySz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Unwrap the key. The plaintext is handed back to the client, not
             * injected into the server, so the KEK may be any client key. */
            ret = _AesGcmKeyUnwrap(server, serverKeyId,
                                   /*requireTrustedKek=*/0, wrappedKey,
                                   req->wrappedKeySz, metadata, key, keySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Dynamic keyId generation for wrapped keys is not allowed */
            if (WH_KEYID_IS_UNASSIGNED(metadata->id)) {
                /* Wrapped keys must use explicit identifiers */
                return WH_ERROR_BADARGS;
            }

            /* Extract ownership from unwrapped metadata (preserves original
             * owner) */
            uint16_t wrappedKeyUser = WH_KEYID_USER(metadata->id);
            uint16_t wrappedKeyType = WH_KEYID_TYPE(metadata->id);

            /* Require explicit wrapped-key encoding */
            if (wrappedKeyType != WH_KEYTYPE_WRAPPED) {
                return WH_ERROR_ABORTED;
            }

            /* Check if the key is exportable */
            if (metadata->flags & WH_NVM_FLAGS_NONEXPORTABLE) {
                return WH_ERROR_ACCESS;
            }

            /* Validate ownership: USER field must match requesting client.
             * The USER field specifies who owns this wrapped key. */
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
            /* Global keys (USER=0) can be exported by any client */
            if (wrappedKeyUser != WH_KEYUSER_GLOBAL &&
                wrappedKeyUser != server->comm->client_id) {
                return WH_ERROR_ACCESS;
            }
#else
            /* Without global keys, USER must match requesting client */
            if (wrappedKeyUser != server->comm->client_id) {
                return WH_ERROR_ACCESS;
            }
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

            /* Tell the client how big the key is on success */
            resp->keySz = keySz;
        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return ret;
}

static int _HandleKeyUnwrapAndCacheRequest(
    whServerContext* server, whMessageKeystore_KeyUnwrapAndCacheRequest* req,
    uint8_t* reqData, uint32_t reqDataSz,
    whMessageKeystore_KeyUnwrapAndCacheResponse* resp, uint8_t* respData,
    uint32_t respDataSz)
{
    /* The server doesn't have any extra response data to send back to the
     * client */
    (void)respData;
    (void)respDataSz;

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    int           ret;
    uint8_t*      wrappedKey;
    whNvmMetadata metadata = {0};
    uint16_t      keySz = 0;
    uint8_t       key[WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
    whKeyId       serverKeyId;
    uint16_t      wrappedKeyUser;
    uint16_t      wrappedKeyType;

    /* Check if the reqData is big enough to hold the wrapped key */
    if (reqDataSz < req->wrappedKeySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Set the wrapped key to the request data */
    wrappedKey = reqData;

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                               server->comm->client_id,
                                               req->serverKeyId);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Key ID is only passed back to the client on success */
    resp->keyId = WH_KEYID_ERASED;

    /* Unwrap the key based on the cipher type */
    switch (req->cipherType) {
#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            if (req->wrappedKeySz < WH_KEYWRAP_AES_GCM_HEADER_SIZE +
                                    sizeof(metadata)) {
                return WH_ERROR_BADARGS;
            }

            keySz = req->wrappedKeySz - WH_KEYWRAP_AES_GCM_HEADER_SIZE -
                    sizeof(metadata);
            resp->cipherType = WC_CIPHER_AES_GCM;

            /* Unwrap-and-cache injects a key into the server keystore, so the
             * KEK must be a trusted (HW or WH_NVM_FLAGS_TRUSTED) key, else a
             * client could forge a blob under a KEK it knows. */
            ret = _AesGcmKeyUnwrap(server, serverKeyId,
                                   /*requireTrustedKek=*/1, wrappedKey,
                                   req->wrappedKeySz, &metadata, key, keySz);
            if (ret != WH_ERROR_OK) {
                goto out;
            }


        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
        default:
            return WH_ERROR_BADARGS;
    }

    /* Strip server-only flags decoded from the blob. A legitimate blob never
     * carries WH_NVM_FLAGS_TRUSTED (a KEK is rejected as a wrap-export target,
     * so one is never produced), and a forged blob must not be able to mint a
     * KEK, so dropping it here is always safe. */
    _SanitizeClientFlags(&metadata);

    /* Verify the key size argument and key size from the the metadata match */
    if (keySz != metadata.len) {
        ret = WH_ERROR_BADARGS;
        goto out;
    }

    /* Dynamic keyId generation for wrapped keys is not allowed; they must use
     * explicit identifiers. SHE keys are exempt - their ids are fixed slots
     * (slot 0 == SECRET_KEY is a valid explicit id), so they can be primed via
     * unwrap-and-cache on a NVM-less server. */
    if (WH_KEYID_IS_UNASSIGNED(metadata.id)) {
        ret = WH_ERROR_BADARGS;
        goto out;
    }

    /* Extract ownership from unwrapped metadata (preserves original owner) */
    wrappedKeyUser = WH_KEYID_USER(metadata.id);
    wrappedKeyType = WH_KEYID_TYPE(metadata.id);

    /* Require explicit wrapped-key encoding. SHE keys are also permitted so a
     * SHE key blob can be primed into the cache and used via the SHE API. */
    if (wrappedKeyType != WH_KEYTYPE_WRAPPED
#ifdef WOLFHSM_CFG_SHE_EXTENSION
        && wrappedKeyType != WH_KEYTYPE_SHE
#endif
    ) {
        ret = WH_ERROR_ABORTED;
        goto out;
    }

    /* Validate ownership: USER field must match requesting client.
     * The USER field specifies who owns this wrapped key. */
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    /* Global keys (USER=0): any client can unwrap and cache to global cache
     * Local keys (USER!=0): only owning client can unwrap and cache */
    if (wrappedKeyUser != WH_KEYUSER_GLOBAL &&
        wrappedKeyUser != server->comm->client_id) {
        ret = WH_ERROR_ACCESS;
        goto out;
    }
#else
    /* Without global keys, USER must match requesting client */
    if (wrappedKeyUser != server->comm->client_id) {
        ret = WH_ERROR_ACCESS;
        goto out;
    }
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

    /* Ensure a key with the unwrapped ID does not already exist in cache */
    if (_ExistsInCache(server, metadata.id)) {
        ret = WH_ERROR_ABORTED;
        goto out;
    }

#ifdef WOLFHSM_CFG_SHE_EXTENSION
    /* For SHE keys, enforce counter monotonicity (allow-equal) against any
     * committed key in NVM, so a primed blob cannot roll a slot's counter back
     * and shadow the committed key. The slot is known not to be in cache here
     * (checked above), so this consults NVM. A first prime after a cold boot
     * (no stored key) establishes the baseline. With no NVM there is no
     * committed counter to roll back against, so the guard is skipped and the
     * cached blob establishes the baseline. */
    if (wrappedKeyType == WH_KEYTYPE_SHE && server->nvm != NULL) {
        whNvmMetadata storedMeta;
        ret = wh_Nvm_GetMetadata(server->nvm, metadata.id, &storedMeta);
        if (ret == WH_ERROR_OK) {
            uint32_t blobCount   = 0;
            uint32_t storedCount = 0;
            (void)wh_She_Label2Meta(metadata.label, &blobCount, NULL);
            (void)wh_She_Label2Meta(storedMeta.label, &storedCount, NULL);
            if (blobCount < storedCount) {
                ret = WH_ERROR_ACCESS;
                goto out;
            }
        }
        else if (ret != WH_ERROR_NOTFOUND) {
            goto out;
        }
    }
#endif /* WOLFHSM_CFG_SHE_EXTENSION */

    /* Store the assigned key ID in the response, preserving client flags */
    resp->keyId = wh_KeyId_TranslateToClient(metadata.id);

#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
    /* Stateful (LMS/XMSS) private key state must never enter the keystore via
     * unwrap; that would permit a signature-index roll-back. */
    if (wh_Crypto_IsStatefulSigPrivBlob(key, (uint16_t)metadata.len)) {
        ret = WH_ERROR_ACCESS;
        goto out;
    }
#endif

    /* Cache the key */
    ret = wh_Server_KeystoreCacheKey(server, &metadata, key);

out:
    /* key[] held decrypted key material; wipe the stack copy on every exit */
    wh_Utils_ForceZero(key, sizeof(key));
    return ret;
}

static int _HandleDataWrapRequest(whServerContext*                   server,
                                  whMessageKeystore_DataWrapRequest* req,
                                  uint8_t* reqData, uint32_t reqDataSz,
                                  whMessageKeystore_DataWrapResponse* resp,
                                  uint8_t* respData, uint32_t respDataSz)
{

    int      ret;
    uint8_t* wrappedData;
    uint8_t  data[WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE];
    whKeyId  serverKeyId;

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL || req->dataSz > WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the reqData is big enough to hold the data */
    if (reqDataSz < req->dataSz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Extract the metadata and data from reqData */
    memcpy(data, reqData, req->dataSz);

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                               server->comm->client_id,
                                               req->serverKeyId);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Wrapped data size is only passed back to the client on success */
    resp->wrappedDataSz = 0;

    /* Store the wrapped data in the response data */
    wrappedData = respData;

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t wrappedDataSz =
                WH_KEYWRAP_AES_GCM_HEADER_SIZE + req->dataSz;

            /* Check if the response data can fit the wrapped data */
            if (respDataSz < wrappedDataSz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Wrap the data */
            ret = _AesGcmDataWrap(server, serverKeyId, data, req->dataSz,
                                  wrappedData, wrappedDataSz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Tell the client how big the wrapped data is */
            resp->wrappedDataSz = wrappedDataSz;
            resp->cipherType    = WC_CIPHER_AES_GCM;

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static int _HandleDataUnwrapRequest(whServerContext*                     server,
                                    whMessageKeystore_DataUnwrapRequest* req,
                                    uint8_t* reqData, uint32_t reqDataSz,
                                    whMessageKeystore_DataUnwrapResponse* resp,
                                    uint8_t* respData, uint32_t respDataSz)
{
    int      ret;
    uint8_t* wrappedData;
    uint8_t* data;
    whKeyId  serverKeyId;

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the reqData is big enough to hold the data */
    if (reqDataSz < req->wrappedDataSz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Set the wrapped data to the reqData */
    wrappedData = reqData;

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, server->comm->client_id, req->serverKeyId);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Data size is only passed back to the client on success */
    resp->dataSz = 0;

    /* Store the unwrapped data in the respData */
    data = respData;

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t dataSz;

            if (req->wrappedDataSz < WH_KEYWRAP_AES_GCM_HEADER_SIZE) {
                return WH_ERROR_BADARGS;
            }

            dataSz = req->wrappedDataSz - WH_KEYWRAP_AES_GCM_HEADER_SIZE;

            /* Check if the response data can fit the unwrapped data */
            if (respDataSz < dataSz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Unwrap the data */
            ret = _AesGcmDataUnwrap(server, serverKeyId, wrappedData,
                                    req->wrappedDataSz, data, dataSz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Tell the client how big the unwrapped data is */
            resp->dataSz     = dataSz;
            resp->cipherType = WC_CIPHER_AES_GCM;

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_KEYWRAP */

int wh_Server_HandleKeyRequest(whServerContext* server, uint16_t magic,
                               uint16_t action, uint16_t req_size,
                               const void* req_packet, uint16_t* out_resp_size,
                               void* resp_packet)
{
    int           ret = WH_ERROR_OK;
    uint8_t*      in;
    uint8_t*      out;
    whNvmMetadata meta[1] = {{0}};

    /* validate args, even though these functions are only supposed to be
     * called by internal functions */
    if ((server == NULL) || (req_packet == NULL) || (out_resp_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    switch (action) {
        case WH_KEY_CACHE: {
            whMessageKeystore_CacheRequest  req = {0};
            whMessageKeystore_CacheResponse resp = {0};

            /* Validate req_size can hold the fixed request struct */
            if (req_size < sizeof(req)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* translate request */
                (void)wh_MessageKeystore_TranslateCacheRequest(
                    magic, (whMessageKeystore_CacheRequest*)req_packet, &req);

                /* Validate that the variable-length key data fits within the
                 * received packet */
                if (req.sz > req_size - sizeof(req)) {
                    ret = WH_ERROR_BADARGS;
                }
            }

            if (ret == WH_ERROR_OK) {
                /* in is after fixed size fields */
                in = (uint8_t*)req_packet + sizeof(req);

                /* set the metadata fields */
                meta->id = wh_KeyId_TranslateFromClient(
                    WH_KEYTYPE_CRYPTO, server->comm->client_id, req.id);
                meta->access = WH_NVM_ACCESS_ANY;
                meta->flags  = req.flags;
                /* clients can't set server-only flags */
                _SanitizeClientFlags(meta);
                meta->len = req.sz;
                /* truncate label if it's too large */
                if (req.labelSz > WH_NVM_LABEL_LEN) {
                    req.labelSz = WH_NVM_LABEL_LEN;
                }
                memcpy(meta->label, req.label, req.labelSz);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    /* get a new id if one wasn't provided */
                    if (WH_KEYID_IS_UNASSIGNED(meta->id)) {
                        ret =
                            wh_Server_KeystoreGetUniqueId(server, &meta->id);
                    }
                    /* write the key */
                    if (ret == WH_ERROR_OK) {
                        ret = wh_Server_KeystoreCacheKeyChecked(server, meta,
                                                                in);
                    }

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }

            if (ret == WH_ERROR_OK) {
                /* Translate server keyId back to client format with flags */
                resp.id = wh_KeyId_TranslateToClient(meta->id);
            }
            resp.rc = ret;

            (void)wh_MessageKeystore_TranslateCacheResponse(
                magic, &resp, (whMessageKeystore_CacheResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_CACHE_RANDOM: {
            whMessageKeystore_CacheRandomRequest  req  = {0};
            whMessageKeystore_CacheRandomResponse resp = {0};

            /* Validate req_size can hold the fixed request struct */
            if (req_size < sizeof(req)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* translate request */
                (void)wh_MessageKeystore_TranslateCacheRandomRequest(
                    magic, (whMessageKeystore_CacheRandomRequest*)req_packet,
                    &req);

                /* set the metadata fields (no key material is sent) */
                meta->id = wh_KeyId_TranslateFromClient(
                    WH_KEYTYPE_CRYPTO, server->comm->client_id, req.id);
                meta->access = WH_NVM_ACCESS_ANY;
                meta->flags  = req.flags;
                meta->len    = req.sz;
                /* truncate label if it's too large */
                if (req.labelSz > WH_NVM_LABEL_LEN) {
                    req.labelSz = WH_NVM_LABEL_LEN;
                }
                memcpy(meta->label, req.label, req.labelSz);
            }

#ifndef WC_NO_RNG
            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    /* get a new id if one wasn't provided */
                    if (WH_KEYID_ISERASED(meta->id)) {
                        ret = wh_Server_KeystoreGetUniqueId(server, &meta->id);
                    }
                    /* generate the key from the server RNG and cache it */
                    if (ret == WH_ERROR_OK) {
                        ret = _KeystoreCacheRandomKey(server, meta);
                    }

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
#else
            if (ret == WH_ERROR_OK) {
                ret = WH_ERROR_NOTIMPL;
            }
#endif /* !WC_NO_RNG */

            if (ret == WH_ERROR_OK) {
                /* Translate server keyId back to client format with flags */
                resp.id = wh_KeyId_TranslateToClient(meta->id);
            }
            resp.rc = ret;

            (void)wh_MessageKeystore_TranslateCacheRandomResponse(
                magic, &resp, (whMessageKeystore_CacheRandomResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

#ifdef WOLFHSM_CFG_DMA

        case WH_KEY_CACHE_DMA: {
            whMessageKeystore_CacheDmaRequest  req = {0};
            whMessageKeystore_CacheDmaResponse resp = {0};

            if (req_size < sizeof(req)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* translate request */
                (void)wh_MessageKeystore_TranslateCacheDmaRequest(
                    magic, (whMessageKeystore_CacheDmaRequest*)req_packet,
                    &req);

                /* set the metadata fields */
                meta->id = wh_KeyId_TranslateFromClient(
                    WH_KEYTYPE_CRYPTO, server->comm->client_id, req.id);
                meta->access = WH_NVM_ACCESS_ANY;
                meta->flags  = req.flags;
                /* clients can't set server-only flags */
                _SanitizeClientFlags(meta);
                meta->len = req.key.sz;
                /* truncate label if it's too large */
                if (req.labelSz > WH_NVM_LABEL_LEN) {
                    req.labelSz = WH_NVM_LABEL_LEN;
                }
                memcpy(meta->label, req.label, req.labelSz);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    /* get a new id if one wasn't provided */
                    if (WH_KEYID_IS_UNASSIGNED(meta->id)) {
                        ret =
                            wh_Server_KeystoreGetUniqueId(server, &meta->id);
                    }

                    /* write the key using DMA */
                    if (ret == WH_ERROR_OK) {
                        ret = wh_Server_KeystoreCacheKeyDmaChecked(
                            server, meta, req.key.addr);
                        /* propagate bad address to client if DMA operation
                         * failed */
                        if (ret != WH_ERROR_OK) {
                            resp.dmaAddrStatus.badAddr.addr = req.key.addr;
                            resp.dmaAddrStatus.badAddr.sz   = req.key.sz;
                        }
                    }

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }

            if (ret == WH_ERROR_OK) {
                /* Translate server keyId back to client format with flags */
                resp.id = wh_KeyId_TranslateToClient(meta->id);
            }
            resp.rc = ret;

            (void)wh_MessageKeystore_TranslateCacheDmaResponse(
                magic, &resp, (whMessageKeystore_CacheDmaResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_EXPORT_DMA: {
            whMessageKeystore_ExportDmaRequest  req = {0};
            whMessageKeystore_ExportDmaResponse resp = {0};

            if (req_size < sizeof(req)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* translate request */
                (void)wh_MessageKeystore_TranslateExportDmaRequest(
                    magic, (whMessageKeystore_ExportDmaRequest*)req_packet,
                    &req);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = wh_Server_KeystoreExportKeyDmaChecked(
                        server,
                        wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                                     server->comm->client_id,
                                                     req.id),
                        req.key.addr, req.key.sz, meta);

                    /* propagate bad address to client if DMA operation failed
                     */
                    if (ret != WH_ERROR_OK) {
                        resp.dmaAddrStatus.badAddr.addr = req.key.addr;
                        resp.dmaAddrStatus.badAddr.sz   = req.key.sz;
                    }

                    if (ret == WH_ERROR_OK) {
                        resp.len = meta->len;
                        memcpy(resp.label, meta->label, sizeof(meta->label));
                    }

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            resp.rc = ret;

            (void)wh_MessageKeystore_TranslateExportDmaResponse(
                magic, &resp,
                (whMessageKeystore_ExportDmaResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_EXPORT_PUBLIC_DMA: {
            whMessageKeystore_ExportPublicDmaRequest  req;
            whMessageKeystore_ExportPublicDmaResponse resp = {0};
            whKeyId                                   serverKeyId;
            uint8_t*                                  cacheBuf  = NULL;
            whNvmMetadata*                            cacheMeta = NULL;
            uint8_t*                                  stage;
            uint16_t                                  stageMax;
            uint16_t                                  der_len   = 0;

            /* translate request */
            (void)wh_MessageKeystore_TranslateExportPublicDmaRequest(
                magic,
                (whMessageKeystore_ExportPublicDmaRequest*)req_packet, &req);

            /* Reuse the tail of the response comm buffer as a server-local
             * staging area for the public DER. The DMA response itself fits
             * in the struct head, so everything after it is scratch. */
            stage    = (uint8_t*)resp_packet + sizeof(resp);
            stageMax = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN - sizeof(resp));

            serverKeyId = wh_KeyId_TranslateFromClient(
                WH_KEYTYPE_CRYPTO, server->comm->client_id, req.id);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                /* Same policy carve-out as the non-DMA public export. */
                ret = _KeystoreCheckPolicy(server, WH_KS_OP_EXPORT_PUBLIC,
                                           serverKeyId);
                if (ret == WH_ERROR_OK) {
                    ret = wh_Server_KeystoreFreshenKey(server, serverKeyId,
                                                       &cacheBuf, &cacheMeta);
                }
                (void)cacheBuf;
                (void)stage;
                (void)stageMax;

                if (ret == WH_ERROR_OK) {
                    switch (req.algo) {
                    #ifndef NO_RSA
                        case WH_KEY_ALGO_RSA:
                            ret = _ExportRsaPublicKey(server, serverKeyId,
                                                      stage, &stageMax);
                            break;
                    #endif /* !NO_RSA */
                    #ifdef HAVE_ECC
                        case WH_KEY_ALGO_ECC:
                            ret = _ExportEccPublicKey(server, serverKeyId,
                                                      stage, &stageMax);
                            break;
                    #endif /* HAVE_ECC */
                    #ifdef HAVE_ED25519
                        case WH_KEY_ALGO_ED25519:
                            ret = _ExportEd25519PublicKey(server, serverKeyId,
                                                      stage, &stageMax);
                            break;
                    #endif /* HAVE_ED25519 */
                    #if defined(WOLFSSL_HAVE_MLDSA) && defined(WOLFSSL_MLDSA_PUBLIC_KEY)
                        case WH_KEY_ALGO_MLDSA:
                            ret = _ExportMldsaPublicKey(server, serverKeyId,
                                                      stage, &stageMax);
                            break;
                    #endif /* WOLFSSL_HAVE_MLDSA && WOLFSSL_MLDSA_PUBLIC_KEY */
                    #ifdef HAVE_CURVE25519
                        case WH_KEY_ALGO_CURVE25519:
                            ret = _ExportCurve25519PublicKey(server, serverKeyId,
                                                      stage, &stageMax);
                            break;
                    #endif /* HAVE_CURVE25519 */
                    #ifdef WOLFSSL_HAVE_MLKEM
                        case WH_KEY_ALGO_MLKEM:
                            ret = _ExportMlkemPublicKey(server, serverKeyId,
                                                        stage, &stageMax);
                            break;
                    #endif /* WOLFSSL_HAVE_MLKEM */
                    #ifdef WOLFSSL_HAVE_LMS
                        case WH_KEY_ALGO_LMS:
                            ret = _ExportLmsPublicKey(server, serverKeyId,
                                                      stage, &stageMax);
                            break;
                    #endif /* WOLFSSL_HAVE_LMS */
                    #ifdef WOLFSSL_HAVE_XMSS
                        case WH_KEY_ALGO_XMSS:
                            ret = _ExportXmssPublicKey(server, serverKeyId,
                                                       stage, &stageMax);
                            break;
                    #endif /* WOLFSSL_HAVE_XMSS */
                        default:
                            ret = WH_ERROR_BADARGS;
                            break;
                    }
                }
                if (ret == WH_ERROR_OK) {
                    der_len = stageMax;
                }

                /* Confirm client buffer is big enough, then DMA. */
                if (ret == WH_ERROR_OK) {
                    if ((uint64_t)der_len > req.key.sz) {
                        ret = WH_ERROR_NOSPACE;
                    }
                    else {
                        ret = whServerDma_CopyToClient(
                            server, req.key.addr, stage, der_len,
                            (whServerDmaFlags){0});
                        if (ret != WH_ERROR_OK) {
                            resp.dmaAddrStatus.badAddr.addr = req.key.addr;
                            resp.dmaAddrStatus.badAddr.sz   = req.key.sz;
                        }
                    }
                }

                if (ret == WH_ERROR_OK && cacheMeta != NULL) {
                    memcpy(resp.label, cacheMeta->label, WH_NVM_LABEL_LEN);
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */

            resp.len = (ret == WH_ERROR_OK) ? der_len : 0;
            resp.rc  = ret;

            (void)wh_MessageKeystore_TranslateExportPublicDmaResponse(
                magic, &resp,
                (whMessageKeystore_ExportPublicDmaResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;
#endif /* WOLFHSM_CFG_DMA */

        case WH_KEY_EVICT: {
            whMessageKeystore_EvictRequest  req = {0};
            whMessageKeystore_EvictResponse resp = {0};

            if (req_size < sizeof(req)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                (void)wh_MessageKeystore_TranslateEvictRequest(
                    magic, (whMessageKeystore_EvictRequest*)req_packet, &req);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = wh_Server_KeystoreEvictKeyChecked(
                        server,
                        wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                                     server->comm->client_id,
                                                     req.id));
                    resp.ok = 0; /* unused */

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            resp.rc = ret;

            (void)wh_MessageKeystore_TranslateEvictResponse(
                magic, &resp, (whMessageKeystore_EvictResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_EXPORT: {
            whMessageKeystore_ExportRequest  req = {0};
            whMessageKeystore_ExportResponse resp = {0};
            uint32_t                         keySz;

            resp.len = 0;

            if (req_size < sizeof(req)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* translate request */
                (void)wh_MessageKeystore_TranslateExportRequest(
                    magic, (whMessageKeystore_ExportRequest*)req_packet, &req);

                /* out is after fixed size fields */
                out   = (uint8_t*)resp_packet + sizeof(resp);
                keySz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(resp);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    /* read the key */
                    ret = wh_Server_KeystoreReadKeyChecked(
                        server,
                        wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                                     server->comm->client_id,
                                                     req.id),
                        meta, out, &keySz);

                    /* Only provide key output if no error */
                    if (ret == WH_ERROR_OK) {
                        resp.len = keySz;
                        memcpy(resp.label, meta->label, sizeof(meta->label));
                    }

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            resp.rc = ret;

            (void)wh_MessageKeystore_TranslateExportResponse(
                magic, &resp, (whMessageKeystore_ExportResponse*)resp_packet);

            *out_resp_size = sizeof(resp) + resp.len;
        } break;

        case WH_KEY_EXPORT_PUBLIC: {
            whMessageKeystore_ExportPublicRequest  req;
            whMessageKeystore_ExportPublicResponse resp = {0};
            whKeyId                                serverKeyId;
            uint8_t*                               cacheBuf  = NULL;
            whNvmMetadata*                         cacheMeta = NULL;
            uint16_t                               der_len   = 0;
            uint16_t                               max_der;

            /* translate request */
            (void)wh_MessageKeystore_TranslateExportPublicRequest(
                magic,
                (whMessageKeystore_ExportPublicRequest*)req_packet, &req);

            /* out is after fixed size fields */
            out     = (uint8_t*)resp_packet + sizeof(resp);
            max_der = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN - sizeof(resp));

            serverKeyId = wh_KeyId_TranslateFromClient(
                WH_KEYTYPE_CRYPTO, server->comm->client_id, req.id);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                /* Policy check: existence + the public-export carve-out.
                 * NONEXPORTABLE does not apply because public material is
                 * non-sensitive. */
                ret = _KeystoreCheckPolicy(server, WH_KS_OP_EXPORT_PUBLIC,
                                           serverKeyId);
                if (ret == WH_ERROR_OK) {
                    /* Load the cached key DER so we can deserialize directly
                     * below. cacheMeta also supplies the label for the
                     * response. */
                    ret = wh_Server_KeystoreFreshenKey(server, serverKeyId,
                                                       &cacheBuf, &cacheMeta);
                }
                /* out/max_der may be unused if no PK algos are compiled in */
                (void)out;
                (void)max_der;

                if (ret == WH_ERROR_OK) {
                    switch (req.algo) {
                    #ifndef NO_RSA
                        case WH_KEY_ALGO_RSA:
                            ret = _ExportRsaPublicKey(server, serverKeyId,
                                                      out, &max_der);
                            break;
                    #endif /* !NO_RSA */
                    #ifdef HAVE_ECC
                        case WH_KEY_ALGO_ECC:
                            ret = _ExportEccPublicKey(server, serverKeyId,
                                                      out, &max_der);
                            break;
                    #endif /* HAVE_ECC */
                    #ifdef HAVE_ED25519
                        case WH_KEY_ALGO_ED25519:
                            ret = _ExportEd25519PublicKey(server, serverKeyId,
                                                      out, &max_der);
                            break;
                    #endif /* HAVE_ED25519 */
                    #if defined(WOLFSSL_HAVE_MLDSA) && \
                                           defined(WOLFSSL_MLDSA_PUBLIC_KEY)
                        case WH_KEY_ALGO_MLDSA:
                            ret = _ExportMldsaPublicKey(server, serverKeyId,
                                                        out, &max_der);
                            break;
                    #endif /* WOLFSSL_HAVE_MLDSA && WOLFSSL_MLDSA_PUBLIC_KEY */
                    #ifdef HAVE_CURVE25519
                        case WH_KEY_ALGO_CURVE25519:
                            ret = _ExportCurve25519PublicKey(server,
                                    serverKeyId, out, &max_der);
                            break;
                    #endif /* HAVE_CURVE25519 */
                    #ifdef WOLFSSL_HAVE_MLKEM
                        case WH_KEY_ALGO_MLKEM:
                            ret = _ExportMlkemPublicKey(server, serverKeyId,
                                                        out, &max_der);
                            break;
                    #endif /* WOLFSSL_HAVE_MLKEM */
                    #ifdef WOLFSSL_HAVE_LMS
                        case WH_KEY_ALGO_LMS:
                            ret = _ExportLmsPublicKey(server, serverKeyId,
                                                      out, &max_der);
                            break;
                    #endif /* WOLFSSL_HAVE_LMS */
                    #ifdef WOLFSSL_HAVE_XMSS
                        case WH_KEY_ALGO_XMSS:
                            ret = _ExportXmssPublicKey(server, serverKeyId,
                                                       out, &max_der);
                            break;
                    #endif /* WOLFSSL_HAVE_XMSS */
                        default:
                            ret = WH_ERROR_BADARGS;
                            break;
                    }
                }
                if (ret == WH_ERROR_OK) {
                    der_len = max_der;
                }

                /* Only populate the label on full success. On any failure
                 * resp.label stays zeroed (from resp = {0}) so clients cannot
                 * observe partial metadata for a key whose public DER could
                 * not be produced. */
                if (ret == WH_ERROR_OK && cacheMeta != NULL) {
                    memcpy(resp.label, cacheMeta->label, WH_NVM_LABEL_LEN);
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */

            resp.len = der_len;
            resp.rc  = ret;

            (void)wh_MessageKeystore_TranslateExportPublicResponse(
                magic, &resp,
                (whMessageKeystore_ExportPublicResponse*)resp_packet);

            *out_resp_size = sizeof(resp) + resp.len;
        } break;

        case WH_KEY_COMMIT: {
            whMessageKeystore_CommitRequest  req = {0};
            whMessageKeystore_CommitResponse resp = {0};

            if (req_size < sizeof(req)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* translate request */
                (void)wh_MessageKeystore_TranslateCommitRequest(
                    magic, (whMessageKeystore_CommitRequest*)req_packet, &req);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = wh_Server_KeystoreCommitKeyChecked(
                        server,
                        wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                                     server->comm->client_id,
                                                     req.id));
                    resp.ok = 0; /* unused */

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            resp.rc = ret;

            (void)wh_MessageKeystore_TranslateCommitResponse(
                magic, &resp, (whMessageKeystore_CommitResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_ERASE: {
            whMessageKeystore_EraseRequest  req = {0};
            whMessageKeystore_EraseResponse resp = {0};

            if (req_size < sizeof(req)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* translate request */
                (void)wh_MessageKeystore_TranslateEraseRequest(
                    magic, (whMessageKeystore_EraseRequest*)req_packet, &req);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = wh_Server_KeystoreEraseKeyChecked(
                        server,
                        wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                                     server->comm->client_id,
                                                     req.id));
                    resp.ok = 0; /* unused */

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            resp.rc = ret;

            (void)wh_MessageKeystore_TranslateEraseResponse(
                magic, &resp, (whMessageKeystore_EraseResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_REVOKE: {
            whMessageKeystore_RevokeRequest  req = {0};
            whMessageKeystore_RevokeResponse resp = {0};

            if (req_size < sizeof(req)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                (void)wh_MessageKeystore_TranslateRevokeRequest(
                    magic, (whMessageKeystore_RevokeRequest*)req_packet, &req);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = wh_Server_KeystoreRevokeKey(
                        server,
                        wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                                    server->comm->client_id,
                                                    req.id));
                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            resp.rc = ret;

            (void)wh_MessageKeystore_TranslateRevokeResponse(
                magic, &resp, (whMessageKeystore_RevokeResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

#ifdef WOLFHSM_CFG_KEYWRAP
        case WH_KEY_KEYWRAP: {
            whMessageKeystore_KeyWrapRequest  wrapReq  = {0};
            whMessageKeystore_KeyWrapResponse wrapResp = {0};
            uint8_t*                       reqData;
            uint8_t*                       respData;
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapResp);
            uint32_t reqDataSz;

            /* Validate req_size can hold the fixed request struct */
            if (req_size < sizeof(wrapReq)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* Compute actual variable data size from the received packet */
                reqDataSz = req_size - sizeof(wrapReq);

                /* Translate request */
                (void)wh_MessageKeystore_TranslateKeyWrapRequest(
                    magic, req_packet, &wrapReq);

                /* Set the request data pointer directly after the request */
                reqData = (uint8_t*)req_packet +
                          sizeof(whMessageKeystore_KeyWrapRequest);

                /* Set the response data pointer directly after the response */
                respData = (uint8_t*)resp_packet +
                           sizeof(whMessageKeystore_KeyWrapResponse);
            }

            /* Note: Locking here is mega-overkill, as there is only one
             * small section inside this request pipeline that needs to be
             * locked - freshening the server key and checking usage.
             * Consider relocating locking to this section */
            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = _HandleKeyWrapRequest(server, &wrapReq, reqData,
                                                reqDataSz, &wrapResp,
                                                respData, respDataSz);

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            wrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateKeyWrapResponse(magic, &wrapResp,
                                                              resp_packet);
            *out_resp_size = sizeof(wrapResp) + wrapResp.wrappedKeySz;

        } break;

        case WH_KEY_KEYWRAPEXPORT: {
            whMessageKeystore_KeyWrapExportRequest  wrapReq  = {0};
            whMessageKeystore_KeyWrapExportResponse wrapResp = {0};
            uint8_t*                                reqData;
            uint8_t*                                respData;
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapResp);
            uint32_t reqDataSz;

            /* Validate req_size can hold the fixed request struct */
            if (req_size < sizeof(wrapReq)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* Compute actual variable data size from the received packet */
                reqDataSz = req_size - sizeof(wrapReq);

                /* Translate request */
                (void)wh_MessageKeystore_TranslateKeyWrapExportRequest(
                    magic, req_packet, &wrapReq);

                /* Set the request data pointer directly after the request */
                reqData = (uint8_t*)req_packet +
                          sizeof(whMessageKeystore_KeyWrapExportRequest);

                /* Set the response data pointer directly after the response */
                respData = (uint8_t*)resp_packet +
                           sizeof(whMessageKeystore_KeyWrapExportResponse);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = _HandleKeyWrapExportRequest(server, &wrapReq, reqData,
                                                      reqDataSz, &wrapResp,
                                                      respData, respDataSz);

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            wrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateKeyWrapExportResponse(
                magic, &wrapResp, resp_packet);
            *out_resp_size = sizeof(wrapResp) + wrapResp.wrappedKeySz;

        } break;

        case WH_KEY_KEYUNWRAPEXPORT: {
            whMessageKeystore_KeyUnwrapAndExportRequest  unwrapReq  = {0};
            whMessageKeystore_KeyUnwrapAndExportResponse unwrapResp = {0};
            uint8_t*                                  reqData;
            uint8_t*                                  respData;
            uint32_t respDataSz =
                WOLFHSM_CFG_COMM_DATA_LEN - sizeof(unwrapResp);
            uint32_t reqDataSz;

            /* Validate req_size can hold the fixed request struct */
            if (req_size < sizeof(unwrapReq)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* Compute actual variable data size from the received packet */
                reqDataSz = req_size - sizeof(unwrapReq);

                /* Translate request */
                (void)wh_MessageKeystore_TranslateKeyUnwrapAndExportRequest(
                    magic, req_packet, &unwrapReq);

                /* Set the request data pointer directly after the request */
                reqData = (uint8_t*)req_packet +
                          sizeof(whMessageKeystore_KeyUnwrapAndExportRequest);

                /* Set the response data pointer directly after the response */
                respData = (uint8_t*)resp_packet +
                           sizeof(whMessageKeystore_KeyUnwrapAndExportResponse);
            }

            /* Note: Locking here is mega-overkill, as there is only one
             * small section inside this request pipeline that needs to be
             * locked - freshening the server key and checking usage.
             * Consider relocating locking to this section */
            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = _HandleKeyUnwrapAndExportRequest(
                        server, &unwrapReq, reqData, reqDataSz, &unwrapResp,
                        respData, respDataSz);

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            unwrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateKeyUnwrapAndExportResponse(
                magic, &unwrapResp, resp_packet);

            *out_resp_size =
                sizeof(unwrapResp) + sizeof(whNvmMetadata) + unwrapResp.keySz;

        } break;

        case WH_KEY_KEYUNWRAPCACHE: {
            whMessageKeystore_KeyUnwrapAndCacheRequest  cacheReq  = {0};
            whMessageKeystore_KeyUnwrapAndCacheResponse cacheResp = {0};
            uint8_t*                                 reqData;
            uint8_t*                                 respData;
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(cacheResp);
            uint32_t reqDataSz;

            /* Validate req_size can hold the fixed request struct */
            if (req_size < sizeof(cacheReq)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* Compute actual variable data size from the received packet */
                reqDataSz = req_size - sizeof(cacheReq);

                /* Translate request */
                (void)wh_MessageKeystore_TranslateKeyUnwrapAndCacheRequest(
                    magic, req_packet, &cacheReq);

                /* Set the request data pointer directly after the request */
                reqData = (uint8_t*)req_packet +
                          sizeof(whMessageKeystore_KeyUnwrapAndCacheRequest);

                /* Set the response data pointer directly after the response */
                respData = (uint8_t*)resp_packet +
                           sizeof(whMessageKeystore_KeyUnwrapAndCacheResponse);
            }

            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = _HandleKeyUnwrapAndCacheRequest(
                        server, &cacheReq, reqData, reqDataSz, &cacheResp,
                        respData, respDataSz);

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            cacheResp.rc = ret;

            (void)wh_MessageKeystore_TranslateKeyUnwrapAndCacheResponse(
                magic, &cacheResp, resp_packet);

            *out_resp_size = sizeof(cacheResp);

        } break;

        case WH_KEY_DATAWRAP: {
            whMessageKeystore_DataWrapRequest  wrapReq  = {0};
            whMessageKeystore_DataWrapResponse wrapResp = {0};
            uint8_t*                           reqData;
            uint8_t*                           respData;
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapResp);
            uint32_t reqDataSz;

            /* Validate req_size can hold the fixed request struct */
            if (req_size < sizeof(wrapReq)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* Compute actual variable data size from the received packet */
                reqDataSz = req_size - sizeof(wrapReq);

                /* Translate request */
                (void)wh_MessageKeystore_TranslateDataWrapRequest(
                    magic, req_packet, &wrapReq);

                /* Set the request data pointer directly after the request */
                reqData = (uint8_t*)req_packet +
                          sizeof(whMessageKeystore_DataWrapRequest);

                /* Set the response data pointer directly after the response */
                respData = (uint8_t*)resp_packet +
                           sizeof(whMessageKeystore_DataWrapResponse);
            }

            /* Note: Locking here is mega-overkill, as there is only one
             * small section inside this request pipeline that needs to be
             * locked - freshening the server key and checking usage.
             * Consider relocating locking to this section */
            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = _HandleDataWrapRequest(server, &wrapReq, reqData,
                                                 reqDataSz, &wrapResp,
                                                 respData, respDataSz);

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            wrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateDataWrapResponse(magic, &wrapResp,
                                                               resp_packet);
            *out_resp_size = sizeof(wrapResp) + wrapResp.wrappedDataSz;

        } break;

        case WH_KEY_DATAUNWRAP: {
            whMessageKeystore_DataUnwrapRequest  unwrapReq  = {0};
            whMessageKeystore_DataUnwrapResponse unwrapResp = {0};
            uint8_t*                             reqData;
            uint8_t*                             respData;
            uint32_t respDataSz =
                WOLFHSM_CFG_COMM_DATA_LEN - sizeof(unwrapResp);
            uint32_t reqDataSz;

            /* Validate req_size can hold the fixed request struct */
            if (req_size < sizeof(unwrapReq)) {
                ret = WH_ERROR_BADARGS;
            }

            if (ret == WH_ERROR_OK) {
                /* Compute actual variable data size from the received packet */
                reqDataSz = req_size - sizeof(unwrapReq);

                /* Translate request */
                (void)wh_MessageKeystore_TranslateDataUnwrapRequest(
                    magic, req_packet, &unwrapReq);

                /* Set the request data pointer directly after the request */
                reqData = (uint8_t*)req_packet +
                          sizeof(whMessageKeystore_DataUnwrapRequest);

                /* Set the response data pointer directly after the response */
                respData = (uint8_t*)resp_packet +
                           sizeof(whMessageKeystore_DataUnwrapResponse);
            }

            /* Note: Locking here is mega-overkill, as there is only one
             * small section inside this request pipeline that needs to be
             * locked - freshening the server key and checking usage.
             * Consider relocating locking to this section */
            if (ret == WH_ERROR_OK) {
                ret = WH_SERVER_NVM_LOCK(server);
                if (ret == WH_ERROR_OK) {
                    ret = _HandleDataUnwrapRequest(
                        server, &unwrapReq, reqData, reqDataSz, &unwrapResp,
                        respData, respDataSz);

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
            }
            unwrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateDataUnwrapResponse(
                magic, &unwrapResp, resp_packet);
            *out_resp_size = sizeof(unwrapResp) + unwrapResp.dataSz;

        } break;

#endif /* WOLFHSM_CFG_KEYWRAP */

        default:
            ret = WH_ERROR_NOHANDLER;
            break;
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA

int _KeystoreCacheKeyDma(whServerContext* server, whNvmMetadata* meta,
                         uint64_t keyAddr, int checked)
{
    int                ret;
    uint8_t*           buffer;
    whNvmMetadata*     slotMeta;

    /* Get a cache slot */
    if (checked) {
        ret = wh_Server_KeystoreGetCacheSlotChecked(server, meta->id, meta->len,
                                                    &buffer, &slotMeta);
    }
    else {
        ret = wh_Server_KeystoreGetCacheSlot(server, meta->id, meta->len,
                                             &buffer, &slotMeta);
    }
    if (ret != 0) {
        return ret;
    }

    /* Copy metadata */
    memcpy(slotMeta, meta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyFromClient(server, buffer, keyAddr, meta->len,
                                     (whServerDmaFlags){0});
#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
    /* Checked calls must refuse access to the LMX/XMSS private key */
    if ((ret == 0) && checked &&
        wh_Crypto_IsStatefulSigPrivBlob(buffer, (uint16_t)meta->len)) {
        ret = WH_ERROR_ACCESS;
    }
#endif
    if (ret != 0) {
        /* Clear the slot on error */
        memset(buffer, 0, meta->len);
        slotMeta->id = WH_KEYID_ERASED;
    }
    else {
        _MarkKeyCommitted(_GetCacheContext(server, meta->id), meta->id, 0);
    }

    return ret;
}
int wh_Server_KeystoreCacheKeyDma(whServerContext* server, whNvmMetadata* meta,
                                  uint64_t keyAddr)
{
    return _KeystoreCacheKeyDma(server, meta, keyAddr, 0);
}

int wh_Server_KeystoreCacheKeyDmaChecked(whServerContext* server,
                                         whNvmMetadata* meta, uint64_t keyAddr)
{
    return _KeystoreCacheKeyDma(server, meta, keyAddr, 1);
}

int wh_Server_KeystoreExportKeyDma(whServerContext* server, whKeyId keyId,
                                   uint64_t keyAddr, uint64_t keySz,
                                   whNvmMetadata* outMeta)
{
    int            ret;
    uint8_t*       buffer;
    whNvmMetadata* cacheMeta;

    /* bring key in cache */
    ret = wh_Server_KeystoreFreshenKey(server, keyId, &buffer, &cacheMeta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (keySz < cacheMeta->len) {
        return WH_ERROR_NOSPACE;
    }

    memcpy(outMeta, cacheMeta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyToClient(server, keyAddr, buffer, outMeta->len,
                                   (whServerDmaFlags){0});

    return ret;
}
int wh_Server_KeystoreExportKeyDmaChecked(whServerContext* server,
                                          whKeyId keyId, uint64_t keyAddr,
                                          uint64_t       keySz,
                                          whNvmMetadata* outMeta)
{
    int ret;

    ret = _KeystoreCheckPolicy(server, WH_KS_OP_EXPORT, keyId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    return wh_Server_KeystoreExportKeyDma(server, keyId, keyAddr, keySz,
                                          outMeta);
}
#endif /* WOLFHSM_CFG_DMA */

int wh_Server_KeystoreEnforceKeyUsage(const whNvmMetadata* meta,
                                      whNvmFlags           requiredUsage)
{
    whNvmFlags actualFlags;

    /* Validate input parameters */
    if (meta == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* We only care about the usage flags */
    requiredUsage &= WH_NVM_FLAGS_USAGE_ANY;

    /* Check if the key has ALL the required usage flags set */
    actualFlags = meta->flags & WH_NVM_FLAGS_USAGE_ANY;
    if ((actualFlags & requiredUsage) == requiredUsage) {
        return WH_ERROR_OK;
    }

    /* Key does not have ALL the required usage flags */
    return WH_ERROR_USAGE;
}

int wh_Server_KeystoreFindEnforceKeyUsage(whServerContext* server,
                                          whKeyId          keyId,
                                          whNvmFlags       requiredUsage)
{
    int            ret;
    whNvmMetadata* meta = NULL;

    /* Validate input parameters */
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Freshen the key to obtain the metadata */
    ret = wh_Server_KeystoreFreshenKey(server, keyId, NULL, &meta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Enforce the usage policy with the obtained metadata */
    return wh_Server_KeystoreEnforceKeyUsage(meta, requiredUsage);
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_ENABLE_SERVER */
