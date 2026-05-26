/*
 * Copyright (C) 2025 wolfSSL Inc.
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
 * wolfhsm/wh_server_cert_cache.h
 *
 * Server-side cert subsystem types embedded in whServerContext:
 *   - whServerCertContext / whServerCertConfig: hold the user-injectable
 *     verify callback and (optionally) the trusted-cert verify cache.
 *   - whCertVerifyCacheContext: trusted-cert verify-result cache. Records
 *     SHA-256 hashes of DER-encoded CA certificates that have already been
 *     successfully verified, scoped to the set of trusted-root NVM IDs
 *     that were loaded when the verify ran. Hits apply across clients
 *     but require the cached root set to be a subset of the caller's
 *     currently-loaded root set.
 *
 *     Only CA certs are inserted. Caching a leaf would let a future
 *     "leaf alone" verify falsely succeed via cache hit, because the
 *     cache hit bypasses the wolfSSL signature check that would otherwise
 *     have failed (the leaf's issuer is not in the cert manager when the
 *     leaf is supplied without its intermediates). CA caching is sound
 *     because the chain walk loads each verified CA into the cert manager
 *     before the next cert is processed.
 *
 *     Soundness of the subset rule rests on X.509 verify monotonicity:
 *     adding more trusted roots can never invalidate a previously
 *     successful verify, so a chain that validated under set S still
 *     validates under any superset T ⊇ S. A cache hit therefore implies
 *     the cached verify's anchor (whichever root in S actually closed
 *     the chain) is currently trusted, regardless of which element of S
 *     it was — every element of S is in T by hypothesis.
 *
 *     Both single-root and multi-root verifies populate the cache.
 *     Single-root entries have one-element sets (maximum reuse, since
 *     any later caller whose loaded set contains that root will hit).
 *     Multi-root entries have larger sets (narrower reuse — only later
 *     callers whose loaded set is a superset will hit) but capture
 *     verifies that pure single-root traffic would not generate.
 *
 * Lives in its own header to avoid circular dependencies between wh_server.h
 * and wh_server_cert.h.
 */

#ifndef WOLFHSM_WH_SERVER_CERT_CACHE_H_
#define WOLFHSM_WH_SERVER_CERT_CACHE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>

#include "wolfhsm/wh_common.h" /* for whNvmId */
#include "wolfhsm/wh_lock.h"   /* for whLock (global cache lock) */

#include "wolfssl/ssl.h" /* for VerifyCallback */

#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE

#ifndef WOLFHSM_CFG_CERT_VERIFY_CACHE_COUNT
#define WOLFHSM_CFG_CERT_VERIFY_CACHE_COUNT 16
#endif

#define WH_CERT_VERIFY_CACHE_HASH_LEN 32 /* SHA-256 digest size */

typedef struct whCertVerifyCacheSlot {
    uint8_t  committed; /* 0 = empty, 1 = valid */
    uint8_t  WH_PAD[1];
    uint16_t numRoots; /* count of valid entries in rootNvmIds */
    /* Set of trusted root NVM IDs loaded when this cert was verified. A
     * lookup hits when this set is a subset of the caller's currently
     * loaded set (verify monotonicity makes the over-approximation safe). */
    whNvmId rootNvmIds[WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS];
    uint8_t hash[WH_CERT_VERIFY_CACHE_HASH_LEN];
} whCertVerifyCacheSlot;

typedef struct whCertVerifyCacheContext {
    whCertVerifyCacheSlot slots[WOLFHSM_CFG_CERT_VERIFY_CACHE_COUNT];
    uint16_t              writeIdx; /* FIFO ring write position */
    /* Runtime enable flag. When zero, Lookup misses and Insert is a no-op,
     * regardless of slot contents. Toggled by
     * wh_Server_CertVerifyCache_SetEnabled (also reachable from clients via
     * WH_MESSAGE_CERT_ACTION_VERIFY_CACHE_SET_ENABLED). Default is 1;
     * explicitly initialized at server / NVM init so a fresh zero-init context
     * is treated as disabled until init runs. */
    uint8_t enabled;
    uint8_t WH_PAD[5];
#if defined(WOLFHSM_CFG_THREADSAFE) && \
    defined(WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL)
    /* Dedicated lock for the global verify cache. Independent from the NVM
     * lock so cert-cache operations do not serialize behind NVM I/O. Only
     * present when the cache lives in the shared NVM context. */
    whLock lock;
#endif
} whCertVerifyCacheContext;

#endif /* WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE */

/* Per-server cert subsystem config, supplied via whServerConfig.certConfig.
 * The verify callback signature matches wolfSSL's VerifyCallback so the same
 * callback registered with wolfSSL_CertManagerSetVerify can be used here. */
typedef struct {
    VerifyCallback verifyCb; /* user-supplied; NULL = no callback */
} whServerCertConfig;

/* Per-server cert subsystem context, embedded by value in whServerContext.
 * Holds the registered verify callback and (optionally) the per-client verify
 * cache. When WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL is defined the cache
 * is relocated into the shared whNvmContext, so the per-client copy is
 * omitted. */
typedef struct {
    VerifyCallback verifyCb;
#if defined(WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE) && \
    !defined(WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL)
    whCertVerifyCacheContext cache;
#endif
} whServerCertContext;

/* Forward declaration to avoid pulling in wh_server.h */
struct whServerContext_t;

#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
/**
 * @brief Look up a cert hash in the verify cache against a set of loaded
 *        trusted roots.
 *
 * Hits when there exists a committed slot whose stored root set is a
 * subset of the supplied set and whose hash matches. By verify
 * monotonicity, a previously successful verify under the slot's set
 * remains valid under any superset, so the hit is sound.
 *
 * @param server The server context.
 * @param rootNvmIds Array of trusted root NVM IDs currently loaded
 *        (presented set).
 * @param numRoots Number of entries in rootNvmIds (must be > 0).
 * @param hash Pointer to a SHA-256 (32-byte) digest of the DER cert.
 * @return WH_ERROR_OK on hit, WH_ERROR_NOTFOUND on miss,
 *         WH_ERROR_BADARGS on invalid arguments.
 */
int wh_Server_CertVerifyCache_Lookup(struct whServerContext_t* server,
                                     const whNvmId*            rootNvmIds,
                                     uint16_t numRoots, const uint8_t* hash);

/**
 * @brief Insert a cert hash into the verify cache, recording the supplied
 *        root set as the entry's binding.
 *
 * No-op if a slot with the same hash and the same root set already
 * exists. Uses FIFO ring overwrite when full.
 *
 * The supplied set must be the set of roots actually loaded into the
 * cert manager at the time of the verify (post-filtering of any roots
 * absent from NVM); recording roots that were not actually loaded would
 * widen the entry's required-trust set without justification.
 *
 * @param server The server context.
 * @param rootNvmIds Array of trusted root NVM IDs loaded for the verify.
 * @param numRoots Number of entries in rootNvmIds (must be > 0 and
 *        <= WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS).
 * @param hash Pointer to a SHA-256 (32-byte) digest of the DER cert.
 */
void wh_Server_CertVerifyCache_Insert(struct whServerContext_t* server,
                                      const whNvmId*            rootNvmIds,
                                      uint16_t numRoots, const uint8_t* hash);

/**
 * @brief Clear all entries from the verify cache.
 *
 * In per-client mode (default) clears this server's cache only. In global
 * mode (WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL) clears the shared
 * cache for every connected client.
 *
 * @param server The server context.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if server is invalid,
 *         or a lock error if the cache lock could not be acquired.
 */
int wh_Server_CertVerifyCache_Clear(struct whServerContext_t* server);

/**
 * @brief Enable or disable the trusted cert verify cache at runtime.
 *
 * When disabled, all existing entries are cleared and subsequent calls to
 * Lookup miss / Insert are no-ops until the cache is re-enabled. Enabling
 * an already-enabled cache (or disabling an already-disabled one) is a
 * no-op aside from acquiring the lock.
 *
 * In per-client mode (default) this affects this server's cache only. In
 * global mode (WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL) this affects
 * the shared cache observed by every connected client.
 *
 * @param server The server context.
 * @param enable 1 to enable caching, 0 to disable (and flush).
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if server is invalid.
 */
int wh_Server_CertVerifyCache_SetEnabled(struct whServerContext_t* server,
                                         uint8_t                   enable);

/**
 * @brief Evict every cache entry whose stored root set contains the
 *        supplied trusted-root NVM ID.
 *
 * Must be invoked whenever the trusted root at rootNvmId changes (add or
 * erase). Without this, re-using a freed ID for a different root would
 * let stale cache hits short-circuit verifies under a trust anchor that
 * is no longer present at that ID.
 *
 * Entries whose stored set contains the evicted root are dropped
 * entirely rather than stripped of that one root, because the original
 * verify may have been anchored at the now-departed root.
 *
 * @param server The server context.
 * @param rootNvmId NVM ID of the trusted root whose cache entries to drop.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if server is invalid,
 *         or a lock error if the cache lock could not be acquired (in which
 *         case the caller must treat the cache state as suspect).
 */
int wh_Server_CertVerifyCache_EvictRoot(struct whServerContext_t* server,
                                        whNvmId                   rootNvmId);
#endif /* WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE */

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */

#endif /* !WOLFHSM_WH_SERVER_CERT_CACHE_H_ */
