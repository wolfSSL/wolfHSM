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

/* This contains a basic authentication implementation. */


/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_auth.h"
#include "wolfhsm/wh_auth_base.h"
#include "wolfhsm/wh_nvm.h"

/* hash pin with use as credentials */
#ifndef WOLFHSM_CFG_NO_CRYPTO
#include <wolfssl/wolfcrypt/hash.h>
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

/* simple base user list */
#define WH_AUTH_BASE_MAX_USERS 5
#define WH_AUTH_BASE_MAX_CREDENTIALS_LEN 2048

/* RAM-resident user index entry. method/credentials_len are a RAM-only cache
 * (0 = none), rebuilt at load from the credential object (their sole authority). */
typedef struct whAuthBase_User {
    whAuthUser   user;
    whAuthMethod method;
    uint16_t     credentials_len;
} whAuthBase_User;
/* The global users index is protected by the auth context lock when
 * WOLFHSM_CFG_THREADSAFE is defined. Locking is performed by the wh_Auth_*
 * wrapper functions in wh_auth.c. */
static whAuthBase_User users[WH_AUTH_BASE_MAX_USERS];

/* NVM persistence: when non-NULL, the user index and per-user credential
 * objects are stored in NVM */
static whNvmContext* s_auth_base_nvm = NULL;

/* Index format: magic (4) + array of whAuthUser (native layout, device-local).
 * No version/migration: any magic-or-length mismatch on load is fatal. */
#define WH_AUTH_BASE_NVM_MAGIC 0x57484142u /* "WHAB" */
#define WH_AUTH_BASE_NVM_HEADER_SIZE 4
#define WH_AUTH_BASE_NVM_INDEX_SIZE \
    (WH_AUTH_BASE_NVM_HEADER_SIZE + sizeof(whAuthUser) * WH_AUTH_BASE_MAX_USERS)

/* The index size is a size_t but is passed to NVM APIs as whNvmSize (16-bit).
 * Catch at compile time any growth in whAuthUser or WH_AUTH_BASE_MAX_USERS that
 * would silently truncate the length and cause the stored index to be rejected
 * as wrong-size on load. */
WH_UTILS_STATIC_ASSERT(
    WH_AUTH_BASE_NVM_INDEX_SIZE <= (size_t)((whNvmSize)-1),
    "WH_AUTH_BASE_NVM_INDEX_SIZE exceeds whNvmSize range");

/* NVM object ID of the credential blob for a given user_id (1-based). */
#define WH_AUTH_BASE_CRED_ID(user_id) \
    ((whNvmId)(WH_NVM_ID_AUTH_CRED_BASE + ((user_id) - 1)))

/* Self-describing credential object: data length is the credential length, and
 * the method rides in a reserved trailing label byte (kept out of the index). */
#define WH_AUTH_BASE_CRED_LABEL "auth_cred"
#define WH_AUTH_BASE_CRED_LABEL_METHOD_IDX (WH_NVM_LABEL_LEN - 1)

/* Scratch buffer for index (de)serialization and rollback of failed updates.
 * The index carries no credential material, but is force-zeroed after use for
 * uniformity. Protected by the auth context lock along with the users array. */
static uint8_t s_auth_base_index_buf[WH_AUTH_BASE_NVM_INDEX_SIZE];
/* Backup of a single index entry for rolling back a failed index persist. */
static whAuthBase_User s_auth_base_backup;
/* Scratch buffer for reading/writing a single user's credential blob. Holds
 * sensitive credential material and is force-zeroed after every use. Static
 * rather than stack-allocated since it is multiple KB. */
static uint8_t s_auth_base_cred_buf[WH_AUTH_BASE_MAX_CREDENTIALS_LEN];

#ifndef WOLFHSM_CFG_AUTH_BASE_NVM_ONLY
/* Credential storage used when no NVM backend is configured (nvm == NULL), so
 * the in-memory-only configuration still retains credentials. When an NVM
 * backend is present these entries stay zeroed and unused; credentials then
 * live in per-user NVM objects and are read into RAM only for the duration of
 * an authentication or credential-change operation. The stored length for each
 * entry is the matching users[].credentials_len.
 *
 * This fallback table is multiple KB. Builds that always configure an NVM
 * backend can drop it (and remove support for the nvm == NULL configuration)
 * by defining WOLFHSM_CFG_AUTH_BASE_NVM_ONLY. */
static uint8_t s_auth_base_ram_cred[WH_AUTH_BASE_MAX_USERS]
                                   [WH_AUTH_BASE_MAX_CREDENTIALS_LEN];
#endif /* !WOLFHSM_CFG_AUTH_BASE_NVM_ONLY */

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#endif

/* Persist the user index (metadata only, no credential material) to NVM.
 * Caller must hold auth lock. */
static int wh_Auth_BasePersistIndex(void)
{
    whNvmMetadata  meta  = {0};
    uint8_t*       buf   = s_auth_base_index_buf;
    const uint32_t magic = WH_AUTH_BASE_NVM_MAGIC;
    int            rc;
    int            i;

    if (s_auth_base_nvm == NULL) {
        return WH_ERROR_OK;
    }

    /* Serialize magic + a whAuthUser per slot (method/credentials_len live in
     * the credential object). memcpy since buf has no alignment guarantee. */
    memcpy(buf, &magic, sizeof(magic));
    for (i = 0; i < WH_AUTH_BASE_MAX_USERS; i++) {
        size_t off = WH_AUTH_BASE_NVM_HEADER_SIZE +
                     ((size_t)i * sizeof(whAuthUser));
        memcpy(buf + off, &users[i].user, sizeof(whAuthUser));
        /* Clear is_active in the serialized copy; session state is not
         * persisted. */
        buf[off + offsetof(whAuthUser, is_active)] = 0;
    }

    meta.id     = WH_NVM_ID_AUTH_USER_INDEX;
    meta.access = WH_NVM_ACCESS_NONE;
    /* NONEXPORTABLE keeps clients from reading the index through the NVM
     * message group; NONMODIFIABLE keeps clients from overwriting or
     * destroying it. The index carries no credential material but is still
     * marked SENSITIVE so it is not exposed. The unchecked add below is not
     * subject to these policy flags. */
    meta.flags = WH_NVM_FLAGS_SENSITIVE | WH_NVM_FLAGS_NONEXPORTABLE |
                 WH_NVM_FLAGS_NONMODIFIABLE;
    meta.len = (whNvmSize)WH_AUTH_BASE_NVM_INDEX_SIZE;
    memset(meta.label, 0, sizeof(meta.label));
    memcpy(meta.label, "auth_user_idx", 13);

    rc = WH_NVM_LOCK(s_auth_base_nvm);
    if (rc == WH_ERROR_OK) {
        /* Each update adds a duplicate ID; stale copies accumulate until
         * compaction, so use the reclaiming add to compact when space runs
         * low. */
        rc = wh_Nvm_AddObjectWithReclaim(s_auth_base_nvm, &meta,
                                         (whNvmSize)WH_AUTH_BASE_NVM_INDEX_SIZE,
                                         buf);
        (void)WH_NVM_UNLOCK(s_auth_base_nvm);
    } /* LOCK() */

    wh_Utils_ForceZero(buf, WH_AUTH_BASE_NVM_INDEX_SIZE);
    return rc;
}

/* Persist a user's credential blob to its own NVM object (method recorded in the
 * label). Caller holds auth lock and owns zeroing buf (raw bytes, hashed PIN). */
static int wh_Auth_BasePersistCred(uint16_t user_id, whAuthMethod method,
                                   const uint8_t* buf, uint16_t len)
{
    whNvmMetadata meta = {0};
    int           rc;

    if (s_auth_base_nvm == NULL) {
#ifndef WOLFHSM_CFG_AUTH_BASE_NVM_ONLY
        /* In-memory-only mode: keep the credential in the RAM fallback. */
        uint8_t* slot = s_auth_base_ram_cred[user_id - 1];
        wh_Utils_ForceZero(slot, WH_AUTH_BASE_MAX_CREDENTIALS_LEN);
        if (len > 0) {
            memcpy(slot, buf, len);
        }
        return WH_ERROR_OK;
#else
        /* No RAM fallback compiled in; a NULL NVM context is a
         * misconfiguration in NVM-only builds. */
        (void)buf;
        (void)len;
        return WH_ERROR_BADARGS;
#endif /* !WOLFHSM_CFG_AUTH_BASE_NVM_ONLY */
    }

    meta.id     = WH_AUTH_BASE_CRED_ID(user_id);
    meta.access = WH_NVM_ACCESS_NONE;
    /* SENSITIVE and NONEXPORTABLE keep clients from reading credential
     * material through the NVM message group; NONMODIFIABLE keeps clients from
     * overwriting or destroying it. */
    meta.flags = WH_NVM_FLAGS_SENSITIVE | WH_NVM_FLAGS_NONEXPORTABLE |
                 WH_NVM_FLAGS_NONMODIFIABLE;
    meta.len = len;
    memset(meta.label, 0, sizeof(meta.label));
    memcpy(meta.label, WH_AUTH_BASE_CRED_LABEL,
           sizeof(WH_AUTH_BASE_CRED_LABEL) - 1);
    /* Method rides in the reserved trailing label byte (kept out of the index) */
    meta.label[WH_AUTH_BASE_CRED_LABEL_METHOD_IDX] = (uint8_t)method;

    rc = WH_NVM_LOCK(s_auth_base_nvm);
    if (rc == WH_ERROR_OK) {
        rc = wh_Nvm_AddObjectWithReclaim(s_auth_base_nvm, &meta, len, buf);
        (void)WH_NVM_UNLOCK(s_auth_base_nvm);
    } /* LOCK() */
    return rc;
}

/* Read a single user's credential blob from NVM into out (at most
 * WH_AUTH_BASE_MAX_CREDENTIALS_LEN bytes). Caller must hold auth lock and is
 * responsible for zeroing out. Returns WH_ERROR_NOTFOUND if the user has no
 * stored credential object. */
static int wh_Auth_BaseLoadCred(uint16_t user_id, uint8_t* out,
                                uint16_t* out_len)
{
    whNvmMetadata meta = {0};
    whNvmId       id   = WH_AUTH_BASE_CRED_ID(user_id);
    int           rc;

    if (s_auth_base_nvm == NULL) {
#ifndef WOLFHSM_CFG_AUTH_BASE_NVM_ONLY
        /* In-memory-only mode: read from the RAM fallback. The stored length is
         * tracked in the index entry. */
        uint16_t len = users[user_id - 1].credentials_len;
        if (len == 0) {
            return WH_ERROR_NOTFOUND;
        }
        memcpy(out, s_auth_base_ram_cred[user_id - 1], len);
        *out_len = len;
        return WH_ERROR_OK;
#else
        return WH_ERROR_NOTFOUND;
#endif /* !WOLFHSM_CFG_AUTH_BASE_NVM_ONLY */
    }

    rc = WH_NVM_LOCK(s_auth_base_nvm);
    if (rc == WH_ERROR_OK) {
        rc = wh_Nvm_GetMetadata(s_auth_base_nvm, id, &meta);
        if (rc == WH_ERROR_OK) {
            if (meta.len > 0 && meta.len <= WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
                rc = wh_Nvm_Read(s_auth_base_nvm, id, 0, meta.len, out);
                if (rc == WH_ERROR_OK) {
                    *out_len = (uint16_t)meta.len;
                }
            }
            else {
                /* Object exists but length is out of range: corrupt, not absent */
                rc = WH_ERROR_ABORTED;
            }
        }
        (void)WH_NVM_UNLOCK(s_auth_base_nvm);
    } /* LOCK() */
    return rc;
}

/* Read a user's method + credential length from the credential object metadata
 * (no bytes pulled). Used at load; NOTFOUND means a credential-less user. */
static int wh_Auth_BaseLoadCredHeader(uint16_t user_id, whAuthMethod* out_method,
                                      uint16_t* out_len)
{
    whNvmMetadata meta = {0};
    whNvmId       id   = WH_AUTH_BASE_CRED_ID(user_id);
    int           rc;

    if (s_auth_base_nvm == NULL) {
        return WH_ERROR_NOTFOUND;
    }

    rc = WH_NVM_LOCK(s_auth_base_nvm);
    if (rc == WH_ERROR_OK) {
        rc = wh_Nvm_GetMetadata(s_auth_base_nvm, id, &meta);
        (void)WH_NVM_UNLOCK(s_auth_base_nvm);
    } /* LOCK() */
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    *out_method = (whAuthMethod)meta.label[WH_AUTH_BASE_CRED_LABEL_METHOD_IDX];
    *out_len    = (uint16_t)meta.len;
    return WH_ERROR_OK;
}

/* Destroy a single user's credential blob. Caller must hold auth lock. Uses the
 * unchecked destroy so the NONMODIFIABLE policy flag on the object does not
 * block internal removal. */
static int wh_Auth_BaseDestroyCred(uint16_t user_id)
{
    whNvmId id = WH_AUTH_BASE_CRED_ID(user_id);
    int     rc;

    if (s_auth_base_nvm == NULL) {
#ifndef WOLFHSM_CFG_AUTH_BASE_NVM_ONLY
        /* In-memory-only mode: clear the RAM fallback slot. */
        wh_Utils_ForceZero(s_auth_base_ram_cred[user_id - 1],
                           WH_AUTH_BASE_MAX_CREDENTIALS_LEN);
#endif /* !WOLFHSM_CFG_AUTH_BASE_NVM_ONLY */
        return WH_ERROR_OK;
    }

    rc = WH_NVM_LOCK(s_auth_base_nvm);
    if (rc == WH_ERROR_OK) {
        rc = wh_Nvm_DestroyObjects(s_auth_base_nvm, 1, &id);
        (void)WH_NVM_UNLOCK(s_auth_base_nvm);
    } /* LOCK() */
    return rc;
}

/* Load the user index from NVM. Credential material is not read here; it is
 * pulled on demand per user. Caller must hold auth lock. Returns WH_ERROR_OK on
 * success. */
static int wh_Auth_BaseLoadFromNvm(void)
{
    whNvmMetadata meta  = {0};
    uint8_t*      buf   = s_auth_base_index_buf;
    uint32_t      magic = 0;
    int           rc;
    int           i;

    if (s_auth_base_nvm == NULL) {
        return WH_ERROR_OK;
    }

    /* Hold the NVM lock across the metadata/read sequence so it cannot race
     * with other NVM users (keystore, counters, certs) */
    rc = WH_NVM_LOCK(s_auth_base_nvm);
    if (rc == WH_ERROR_OK) {
        rc = wh_Nvm_GetMetadata(s_auth_base_nvm, WH_NVM_ID_AUTH_USER_INDEX, &meta);
        if (rc == WH_ERROR_OK) {
            if (meta.len == WH_AUTH_BASE_NVM_INDEX_SIZE) {
                rc = wh_Nvm_Read(s_auth_base_nvm, WH_NVM_ID_AUTH_USER_INDEX, 0,
                             (whNvmSize)WH_AUTH_BASE_NVM_INDEX_SIZE, buf);
            }
            else {
            /* An index object exists but is the wrong size: corrupt or
             * incompatible format with no migration path. Fatal rather than
             * silently starting with an empty database. */
            rc = WH_ERROR_ABORTED;
            }
        }
        (void)WH_NVM_UNLOCK(s_auth_base_nvm);
    } /* LOCK() */

    if (rc != WH_ERROR_OK) {
        /* Scrub any partially-read index data before returning on error. */
        wh_Utils_ForceZero(buf, WH_AUTH_BASE_NVM_INDEX_SIZE);
        if (rc == WH_ERROR_NOTFOUND) {
            return WH_ERROR_OK; /* No stored index, keep empty */
        }
        return rc; /* Propagate WH_ERROR_ABORTED and read errors */
    }

    /* Validate magic via memcpy into a local integer; buf has no alignment
     * guarantee for wider integer access */
    memcpy(&magic, buf, sizeof(magic));
    if (magic != WH_AUTH_BASE_NVM_MAGIC) {
        /* Unknown format, no migration path: fatal, do not start fresh */
        wh_Utils_ForceZero(buf, WH_AUTH_BASE_NVM_INDEX_SIZE);
        return WH_ERROR_ABORTED;
    }

    /* Clear the RAM cache (method/credentials_len are not persisted) first. */
    memset(users, 0, sizeof(users));

    /* Deserialize each whAuthUser slot. A valid-magic index may still be corrupt,
     * so sanitize/validate each slot and abort on anything UserAdd can't produce. */
    for (i = 0; i < WH_AUTH_BASE_MAX_USERS; i++) {
        whAuthUser*  u           = &users[i].user;
        whAuthMethod cred_method = WH_AUTH_METHOD_NONE;
        uint16_t     cred_len    = 0;
        int          hrc;

        memcpy(u, buf + WH_AUTH_BASE_NVM_HEADER_SIZE + (size_t)i * sizeof(*u),
               sizeof(*u));

        /* Guarantee termination so strcmp() cannot overread the name buffer */
        u->username[sizeof(u->username) - 1] = '\0';

        /* is_active is session state and is not persisted */
        u->is_active = false;

        if (u->user_id == WH_USER_ID_INVALID) {
            /* An empty slot must stay nameless or FindUser() could match it and
             * pass a 0 user_id into the credential path (no cred object here). */
            if (u->username[0] != '\0') {
                rc = WH_ERROR_ABORTED;
                break;
            }
            continue;
        }

        if (u->user_id != (whUserId)(i + 1) ||
            u->permissions.keyIdCount > WH_AUTH_MAX_KEY_IDS) {
            rc = WH_ERROR_ABORTED;
            break;
        }

        /* Rebuild method/credentials_len from the credential object. Missing =
         * credential-less (NONE, 0); a present object must be valid or it aborts. */
        hrc = wh_Auth_BaseLoadCredHeader(u->user_id, &cred_method, &cred_len);
        if (hrc == WH_ERROR_NOTFOUND) {
            cred_method = WH_AUTH_METHOD_NONE;
            cred_len    = 0;
        }
        else if (hrc != WH_ERROR_OK) {
            rc = hrc;
            break;
        }
        else if (cred_len == 0 || cred_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN ||
                 (cred_method != WH_AUTH_METHOD_PIN &&
                  cred_method != WH_AUTH_METHOD_CERTIFICATE)) {
            rc = WH_ERROR_ABORTED;
            break;
        }
        users[i].method          = cred_method;
        users[i].credentials_len = cred_len;
    }

    wh_Utils_ForceZero(buf, WH_AUTH_BASE_NVM_INDEX_SIZE);
    if (rc != WH_ERROR_OK) {
        wh_Utils_ForceZero(users, sizeof(users));
    }
    return rc;
}

int wh_Auth_BaseInit(void* context, const void* config)
{
    (void)context;

    memset(users, 0, sizeof(users));
    s_auth_base_nvm = NULL;

    /* Clear scratch/credential buffers so re-init doesn't leave sensitive data
     * resident in RAM (in RAM-only mode credentials live in s_auth_base_ram_cred). */
    wh_Utils_ForceZero(s_auth_base_index_buf, sizeof(s_auth_base_index_buf));
    wh_Utils_ForceZero(&s_auth_base_backup, sizeof(s_auth_base_backup));
    wh_Utils_ForceZero(s_auth_base_cred_buf, sizeof(s_auth_base_cred_buf));
#ifndef WOLFHSM_CFG_AUTH_BASE_NVM_ONLY
    wh_Utils_ForceZero(s_auth_base_ram_cred, sizeof(s_auth_base_ram_cred));
#endif /* !WOLFHSM_CFG_AUTH_BASE_NVM_ONLY */

    if (config != NULL) {
        const whAuthBaseConfig* base_config = (const whAuthBaseConfig*)config;
        if (base_config->nvm != NULL) {
            s_auth_base_nvm = (whNvmContext*)base_config->nvm;
            return wh_Auth_BaseLoadFromNvm();
        }
    }
    return WH_ERROR_OK;
}

int wh_Auth_BaseCleanup(void* context)
{
    (void)context;
    s_auth_base_nvm = NULL;
    wh_Utils_ForceZero(users, sizeof(users));
    wh_Utils_ForceZero(s_auth_base_index_buf, sizeof(s_auth_base_index_buf));
    wh_Utils_ForceZero(&s_auth_base_backup, sizeof(s_auth_base_backup));
    wh_Utils_ForceZero(s_auth_base_cred_buf, sizeof(s_auth_base_cred_buf));
#ifndef WOLFHSM_CFG_AUTH_BASE_NVM_ONLY
    wh_Utils_ForceZero(s_auth_base_ram_cred, sizeof(s_auth_base_ram_cred));
#endif /* !WOLFHSM_CFG_AUTH_BASE_NVM_ONLY */
    return WH_ERROR_OK;
}

static whAuthBase_User* wh_Auth_BaseFindUser(const char* username)
{
    int i;
    for (i = 0; i < WH_AUTH_BASE_MAX_USERS; i++) {
        if (strcmp(users[i].user.username, username) == 0) {
            return &users[i];
        }
    }
    return NULL;
}

/* Hash PIN credentials using SHA256 (if crypto is available) */
static int wh_Auth_BaseHashPin(const void* pin, uint16_t pin_len,
                               unsigned char* hash_out)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    int ret = wc_Sha256Hash_ex((const unsigned char*)pin, (word32)pin_len,
                               hash_out, NULL, INVALID_DEVID);
    if (ret != 0) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
#else
    /* When crypto is disabled, just copy the PIN as-is */
    if (pin_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
        return WH_ERROR_BUFFER_SIZE;
    }
    memcpy(hash_out, pin, pin_len);
    return WH_ERROR_OK;
#endif /* WOLFHSM_CFG_NO_CRYPTO */
}

/* Sets *out_user to the matched user, or NULL for an ordinary auth failure.
 * Returns a fatal error (out_user NULL) only when hashing or the credential
 * fetch fails for a reason other than a missing credential. */
static int wh_Auth_BaseCheckPin(const char* username, const void* auth_data,
                                uint16_t          auth_data_len,
                                whAuthBase_User** out_user)
{
    whAuthBase_User* found_user = NULL;
    unsigned char    authCheck[WH_AUTH_BASE_MAX_CREDENTIALS_LEN];
    uint16_t         authCheck_len;
    uint16_t         stored_len = 0;
    int              rc;

    *out_user = NULL;

    /* Process auth_data: hash if crypto enabled, copy if disabled */
    rc = wh_Auth_BaseHashPin(auth_data, auth_data_len, authCheck);
    if (rc != WH_ERROR_OK) {
        wh_Utils_ForceZero(authCheck, sizeof(authCheck));
        return rc;
    }
#ifndef WOLFHSM_CFG_NO_CRYPTO
    authCheck_len = WC_SHA256_DIGEST_SIZE;
#else
    authCheck_len = auth_data_len;
#endif /* WOLFHSM_CFG_NO_CRYPTO */

    found_user = wh_Auth_BaseFindUser(username);
    if (found_user != NULL && found_user->method == WH_AUTH_METHOD_PIN &&
        found_user->credentials_len == authCheck_len) {
        /* Pull only this user's credential blob into RAM for the comparison */
        rc = wh_Auth_BaseLoadCred(found_user->user.user_id,
                                  s_auth_base_cred_buf, &stored_len);
        if (rc == WH_ERROR_OK) {
            if (stored_len == authCheck_len &&
                wh_Utils_ConstantCompare(s_auth_base_cred_buf, authCheck,
                                         authCheck_len) == 0) {
                *out_user = found_user;
            }
        }
        else if (rc == WH_ERROR_NOTFOUND) {
            rc = WH_ERROR_OK; /* No stored credential: ordinary auth failure */
        }
        /* else: propagate the storage error */
        wh_Utils_ForceZero(s_auth_base_cred_buf, sizeof(s_auth_base_cred_buf));
    }

    wh_Utils_ForceZero(authCheck, sizeof(authCheck));
    return rc;
}

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
/* Verify a presented certificate against a CA certificate held in ca_cert/
 * ca_cert_len (a credential blob previously read from NVM). */
static int wh_Auth_BaseVerifyCertificate(const uint8_t* ca_cert,
                                         uint16_t       ca_cert_len,
                                         const uint8_t* certificate,
                                         uint16_t       certificate_len)
{
    int                   rc = WH_ERROR_ABORTED;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    cm                       = wolfSSL_CertManagerNew();
    if (cm != NULL) {
        if (wolfSSL_CertManagerLoadCABuffer(
                cm, ca_cert, ca_cert_len,
                WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS) {
            if (wolfSSL_CertManagerVerifyBuffer(
                    cm, certificate, certificate_len, WOLFSSL_FILETYPE_ASN1) ==
                WOLFSSL_SUCCESS) {
                rc = WH_ERROR_OK;
            }
        }
        wolfSSL_CertManagerFree(cm);
    }
    return rc;
}

/* Sets *out_user to the matched user, or NULL for an ordinary auth failure.
 * Returns a fatal error (out_user NULL) only when the CA blob fetch fails for a
 * reason other than a missing credential. */
static int wh_Auth_BaseCheckCertificate(const char* username,
                                        const void* auth_data,
                                        uint16_t    auth_data_len,
                                        whAuthBase_User** out_user)
{
    whAuthBase_User* found_user;
    uint16_t         stored_len = 0;
    int              rc         = WH_ERROR_OK;

    *out_user = NULL;

    found_user = wh_Auth_BaseFindUser(username);
    if (found_user != NULL &&
        found_user->method == WH_AUTH_METHOD_CERTIFICATE &&
        found_user->credentials_len > 0) {
        /* Pull only this user's CA certificate blob into RAM for verification */
        rc = wh_Auth_BaseLoadCred(found_user->user.user_id,
                                  s_auth_base_cred_buf, &stored_len);
        if (rc == WH_ERROR_OK) {
            if (stored_len == found_user->credentials_len &&
                wh_Auth_BaseVerifyCertificate(s_auth_base_cred_buf, stored_len,
                                              auth_data, auth_data_len) ==
                    WH_ERROR_OK) {
                *out_user = found_user;
            }
        }
        else if (rc == WH_ERROR_NOTFOUND) {
            rc = WH_ERROR_OK; /* No stored CA cert: ordinary auth failure */
        }
        /* else: propagate the storage error */
        wh_Utils_ForceZero(s_auth_base_cred_buf, sizeof(s_auth_base_cred_buf));
    }
    return rc;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */

int wh_Auth_BaseLogin(void* context, uint8_t client_id, whAuthMethod method,
                      const char* username, const void* auth_data,
                      uint16_t auth_data_len, whUserId* out_user_id,
                      whAuthPermissions* out_permissions, int* loggedIn)
{
    whAuthBase_User* current_user = NULL;
    int              rc;

    if ((out_user_id == NULL) || (out_permissions == NULL) ||
        (loggedIn == NULL) || (username == NULL)) {
        return WH_ERROR_BADARGS;
    }

    *loggedIn = 0;

    (void)client_id;
    switch (method) {
        case WH_AUTH_METHOD_PIN:
            rc = wh_Auth_BaseCheckPin(username, auth_data, auth_data_len,
                                      &current_user);
            break;
#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
        case WH_AUTH_METHOD_CERTIFICATE:
            rc = wh_Auth_BaseCheckCertificate(username, auth_data,
                                              auth_data_len, &current_user);
            break;
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
        default:
            return WH_ERROR_BADARGS;
    }

    if (rc != WH_ERROR_OK) {
        return rc;
    }

    if (current_user != NULL) {
        if (current_user->user.is_active) {
            /* Can not be logged in if already logged in */
            *loggedIn = 0;
        }
        else {
            *loggedIn                    = 1;
            *out_user_id                 = current_user->user.user_id;
            current_user->user.is_active = true;
            *out_permissions             = current_user->user.permissions;
        }
    }

    (void)context;
    return WH_ERROR_OK;
}

int wh_Auth_BaseLogout(void* context, uint16_t current_user_id,
                       uint16_t user_id)
{
    whAuthBase_User* user;

    if (current_user_id == WH_USER_ID_INVALID ||
        user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_BADARGS;
    }

    if (current_user_id > WH_AUTH_BASE_MAX_USERS ||
        user_id > WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_NOTFOUND;
    }

    if (current_user_id != user_id &&
        !WH_AUTH_IS_ADMIN(users[current_user_id - 1].user.permissions)) {
        return WH_ERROR_ACCESS;
    }

    user                 = &users[user_id - 1];
    user->user.is_active = false;
    (void)context;
    return WH_ERROR_OK;
}


int wh_Auth_BaseUserAdd(void* context, const char* username,
                        whUserId* out_user_id, whAuthPermissions permissions,
                        whAuthMethod method, const void* credentials,
                        uint16_t credentials_len)
{
    whAuthContext*   auth_context = (whAuthContext*)context;
    whAuthBase_User* new_user;
    int              i;
    int              rc;
    int              userId = WH_USER_ID_INVALID;

    if (username == NULL || out_user_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Validate method is supported if credentials are provided */
    if (credentials != NULL && credentials_len > 0) {
        if (method != WH_AUTH_METHOD_PIN
#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
            && method != WH_AUTH_METHOD_CERTIFICATE
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
        ) {
            return WH_ERROR_BADARGS;
        }
    }

    for (i = 0; i < WH_AUTH_BASE_MAX_USERS; i++) {
        if (userId == WH_USER_ID_INVALID &&
            users[i].user.user_id == WH_USER_ID_INVALID) {
            userId = i + 1;
        }

        /* do not allow duplicate users with same name */
        if (strcmp(users[i].user.username, username) == 0) {
            return WH_ERROR_BADARGS;
        }
    }

    if (userId == WH_USER_ID_INVALID) {
        return WH_ERROR_BUFFER_SIZE;
    }
    new_user = &users[userId - 1];

    memset(new_user, 0, sizeof(whAuthBase_User));
    new_user->user.user_id     = userId;
    *out_user_id               = userId;
    new_user->user.permissions = permissions;
    /* Clamp keyIdCount to valid range and zero out unused keyIds */
    if (new_user->user.permissions.keyIdCount > WH_AUTH_MAX_KEY_IDS) {
        new_user->user.permissions.keyIdCount = WH_AUTH_MAX_KEY_IDS;
    }
    /* Zero out unused keyIds beyond keyIdCount */
    if (new_user->user.permissions.keyIdCount < WH_AUTH_MAX_KEY_IDS) {
        int j;
        for (j = new_user->user.permissions.keyIdCount; j < WH_AUTH_MAX_KEY_IDS;
             j++) {
            new_user->user.permissions.keyIds[j] = 0;
        }
    }
    strncpy(new_user->user.username, username,
            sizeof(new_user->user.username) - 1);
    new_user->user.username[sizeof(new_user->user.username) - 1] = '\0';
    new_user->user.is_active                                     = false;

    /* Build the credential blob (if provided) in the scratch buffer. All
     * validation and hashing happens before anything is written to NVM so a
     * failure leaves no partially-committed user. */
    if (credentials != NULL && credentials_len > 0) {
        uint16_t cred_len = 0;
        rc               = WH_ERROR_OK;
        new_user->method = method;
        if (method == WH_AUTH_METHOD_PIN) {
#ifndef WOLFHSM_CFG_NO_CRYPTO
            /* Hash PIN before storing */
            rc = wh_Auth_BaseHashPin(credentials, credentials_len,
                                     s_auth_base_cred_buf);
            if (rc == WH_ERROR_OK) {
                cred_len = WC_SHA256_DIGEST_SIZE;
            }
#else
            if (credentials_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
                rc = WH_ERROR_BUFFER_SIZE;
            }
            else {
                memcpy(s_auth_base_cred_buf, credentials, credentials_len);
                cred_len = credentials_len;
            }
#endif /* WOLFHSM_CFG_NO_CRYPTO */
        }
        else {
            if (credentials_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
                rc = WH_ERROR_BUFFER_SIZE;
            }
            else {
                memcpy(s_auth_base_cred_buf, credentials, credentials_len);
                cred_len = credentials_len;
            }
        }

        if (rc != WH_ERROR_OK) {
            wh_Utils_ForceZero(s_auth_base_cred_buf,
                               sizeof(s_auth_base_cred_buf));
            wh_Utils_ForceZero(new_user, sizeof(whAuthBase_User));
            *out_user_id = WH_USER_ID_INVALID;
            return rc;
        }

        new_user->credentials_len = cred_len;

        /* Write the credential blob before the index. A blob is only reachable
         * once the index entry referencing it is persisted, so committing the
         * blob first means a failure here leaves the index untouched. */
        rc = wh_Auth_BasePersistCred(userId, method, s_auth_base_cred_buf,
                                     cred_len);
        wh_Utils_ForceZero(s_auth_base_cred_buf, sizeof(s_auth_base_cred_buf));
        if (rc != WH_ERROR_OK) {
            /* Blob not written; the index has not been touched yet */
            wh_Utils_ForceZero(new_user, sizeof(whAuthBase_User));
            *out_user_id = WH_USER_ID_INVALID;
            return rc;
        }
    }

    rc = wh_Auth_BasePersistIndex();
    if (rc != WH_ERROR_OK) {
        /* Roll back the in-memory add so a failed persist leaves no
         * partially-committed user. Best-effort destroy any credential blob
         * written above so it does not linger unreferenced. */
        if (new_user->credentials_len > 0) {
            (void)wh_Auth_BaseDestroyCred(userId);
        }
        wh_Utils_ForceZero(new_user, sizeof(whAuthBase_User));
        *out_user_id = WH_USER_ID_INVALID;
    }
    (void)auth_context;
    return rc;
}

int wh_Auth_BaseUserDelete(void* context, uint16_t current_user_id,
                           uint16_t user_id)
{
    whAuthBase_User* user;
    int              rc;

    if (user_id == WH_USER_ID_INVALID || user_id > WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_NOTFOUND;
    }

    if (current_user_id == WH_USER_ID_INVALID ||
        current_user_id > WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_BADARGS;
    }

    /* Only allow an admin user to delete users */
    if (!WH_AUTH_IS_ADMIN(users[current_user_id - 1].user.permissions)) {
        return WH_ERROR_ACCESS;
    }

    user = &users[user_id - 1];
    if (user->user.user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_NOTFOUND;
    }

    /* Save the record so a failed NVM persist can be rolled back, keeping
     * RAM consistent with what is stored in NVM */
    memcpy(&s_auth_base_backup, user, sizeof(whAuthBase_User));
    wh_Utils_ForceZero(user, sizeof(whAuthBase_User));

    /* Persist the index with the entry removed first; the credential blob is
     * only reachable through the index, so once the index no longer references
     * the user the blob can be destroyed. If the index persist fails, restore
     * the record and leave the blob in place. */
    rc = wh_Auth_BasePersistIndex();
    if (rc != WH_ERROR_OK) {
        memcpy(user, &s_auth_base_backup, sizeof(whAuthBase_User));
    }
    else if (s_auth_base_backup.credentials_len > 0) {
        /* A lingering blob could resurrect the credential if the slot is reused,
         * so a destroy failure is fatal: roll the deletion back. */
        rc = wh_Auth_BaseDestroyCred(user_id);
        if (rc != WH_ERROR_OK) {
            memcpy(user, &s_auth_base_backup, sizeof(whAuthBase_User));
            (void)wh_Auth_BasePersistIndex();
        }
    }
    wh_Utils_ForceZero(&s_auth_base_backup, sizeof(whAuthBase_User));
    (void)context;
    return rc;
}

int wh_Auth_BaseUserSetPermissions(void* context, uint16_t current_user_id,
                                   uint16_t          user_id,
                                   whAuthPermissions permissions)
{
    whAuthBase_User*  user;
    whAuthPermissions old_permissions;
    int               rc;

    if (user_id == WH_USER_ID_INVALID || user_id > WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_NOTFOUND;
    }

    if (current_user_id == WH_USER_ID_INVALID ||
        current_user_id > WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_NOTFOUND;
    }

    /* Only allow an admin user to change permissions */
    if (!WH_AUTH_IS_ADMIN(users[current_user_id - 1].user.permissions)) {
        return WH_ERROR_ACCESS;
    }

    user = &users[user_id - 1];
    if (user->user.user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_NOTFOUND;
    }
    old_permissions        = user->user.permissions;
    user->user.permissions = permissions;
    /* Clamp keyIdCount to valid range and zero out unused keyIds */
    if (user->user.permissions.keyIdCount > WH_AUTH_MAX_KEY_IDS) {
        user->user.permissions.keyIdCount = WH_AUTH_MAX_KEY_IDS;
    }
    /* Zero out unused keyIds beyond keyIdCount */
    if (user->user.permissions.keyIdCount < WH_AUTH_MAX_KEY_IDS) {
        int j;
        for (j = user->user.permissions.keyIdCount; j < WH_AUTH_MAX_KEY_IDS;
             j++) {
            user->user.permissions.keyIds[j] = 0;
        }
    }

    /* Permissions live in the index only; no credential blob is touched. */
    rc = wh_Auth_BasePersistIndex();
    if (rc != WH_ERROR_OK) {
        /* Roll back so RAM stays consistent with what is stored in NVM */
        user->user.permissions = old_permissions;
    }
    (void)context;
    return rc;
}


int wh_Auth_BaseUserGet(void* context, const char* username,
                        whUserId*          out_user_id,
                        whAuthPermissions* out_permissions)
{
    whAuthBase_User* user = wh_Auth_BaseFindUser(username);
    if (user == NULL) {
        return WH_ERROR_NOTFOUND;
    }
    *out_user_id     = user->user.user_id;
    *out_permissions = user->user.permissions;
    (void)context;
    return WH_ERROR_OK;
}


int wh_Auth_BaseUserSetCredentials(void* context, uint16_t current_user_id,
                                   uint16_t user_id, whAuthMethod method,
                                   const void*  current_credentials,
                                   uint16_t     current_credentials_len,
                                   const void*  new_credentials,
                                   uint16_t     new_credentials_len)
{
    whAuthContext*   auth_context = (whAuthContext*)context;
    whAuthBase_User* user;
    int              rc         = WH_ERROR_OK;
    uint16_t         old_len    = 0;
    whAuthMethod     old_method = WH_AUTH_METHOD_PIN;
    uint16_t         new_len    = 0;

    if (user_id == WH_USER_ID_INVALID || user_id > WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_BADARGS;
    }

    if (current_user_id == WH_USER_ID_INVALID ||
        current_user_id > WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_BADARGS;
    }

    /* A non-admin caller may only set its own credentials; an admin caller may
     * set credentials for any user. */
    if (current_user_id != user_id &&
        !WH_AUTH_IS_ADMIN(users[current_user_id - 1].user.permissions)) {
        return WH_ERROR_ACCESS;
    }

    /* Validate method is supported */
    if (method != WH_AUTH_METHOD_PIN
#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
        && method != WH_AUTH_METHOD_CERTIFICATE
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
    ) {
        return WH_ERROR_BADARGS;
    }

    user = &users[user_id - 1]; /* subtract 1 to get the index */
    if (user->user.user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_NOTFOUND;
    }

    /* Validate the new credential size up front so all size failures return
     * before any state is read or modified. */
    if (new_credentials_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
        return WH_ERROR_BUFFER_SIZE;
    }

    if (new_credentials_len > 0 && new_credentials == NULL) {
        return WH_ERROR_BADARGS;
    }

    old_len    = user->credentials_len;
    old_method = user->method;

    /* Verify current credentials against the stored blob (pulled into the scratch
     * buffer). No rollback backup: the new value commits atomically below. */
    if (old_len > 0) {
        uint16_t stored_len = 0;

        /* User has existing credentials, so current_credentials must be
         * provided and match */
        if (current_credentials == NULL || current_credentials_len == 0) {
            return WH_ERROR_ACCESS;
        }

        rc = wh_Auth_BaseLoadCred(user_id, s_auth_base_cred_buf, &stored_len);
        if (rc != WH_ERROR_OK || stored_len != old_len) {
            wh_Utils_ForceZero(s_auth_base_cred_buf,
                               sizeof(s_auth_base_cred_buf));
            return WH_ERROR_ACCESS;
        }

        if (old_method == WH_AUTH_METHOD_PIN) {
#ifndef WOLFHSM_CFG_NO_CRYPTO
            /* For PIN, hash the provided credentials before comparing */
            unsigned char hash[WC_SHA256_DIGEST_SIZE];
            rc = wh_Auth_BaseHashPin(current_credentials,
                                     current_credentials_len, hash);
            if (rc == WH_ERROR_OK &&
                (old_len != WC_SHA256_DIGEST_SIZE ||
                 wh_Utils_ConstantCompare(s_auth_base_cred_buf, hash,
                                          WC_SHA256_DIGEST_SIZE) != 0)) {
                rc = WH_ERROR_ACCESS;
            }
            wh_Utils_ForceZero(hash, sizeof(hash));
#else
            /* When crypto is disabled, compare PINs directly */
            if (old_len != current_credentials_len ||
                wh_Utils_ConstantCompare(s_auth_base_cred_buf,
                                         current_credentials,
                                         current_credentials_len) != 0) {
                rc = WH_ERROR_ACCESS;
            }
#endif /* WOLFHSM_CFG_NO_CRYPTO */
        }
        else {
            /* For non-PIN methods, compare as-is */
            if (old_len != current_credentials_len ||
                wh_Utils_ConstantCompare(s_auth_base_cred_buf,
                                         current_credentials,
                                         current_credentials_len) != 0) {
                rc = WH_ERROR_ACCESS;
            }
        }

        /* Done with the old credential; the buffer is reused for the new one
         * below. Scrub it now so a verify failure leaves nothing resident. */
        if (rc != WH_ERROR_OK) {
            wh_Utils_ForceZero(s_auth_base_cred_buf,
                               sizeof(s_auth_base_cred_buf));
            return rc;
        }
    }
    else {
        /* User has no existing credentials, current_credentials should be NULL
         */
        if (current_credentials != NULL && current_credentials_len > 0) {
            return WH_ERROR_BADARGS;
        }
    }

    /* Build the new credential blob in the scratch buffer. Hash/validate before
     * touching NVM so a failure leaves the stored state unchanged. */
    if (new_credentials_len > 0) {
        if (method == WH_AUTH_METHOD_PIN) {
#ifndef WOLFHSM_CFG_NO_CRYPTO
            /* Hash PIN before storing */
            rc = wh_Auth_BaseHashPin(new_credentials, new_credentials_len,
                                     s_auth_base_cred_buf);
            if (rc == WH_ERROR_OK) {
                new_len = WC_SHA256_DIGEST_SIZE;
            }
#else
            memcpy(s_auth_base_cred_buf, new_credentials, new_credentials_len);
            new_len = new_credentials_len;
#endif /* WOLFHSM_CFG_NO_CRYPTO */
        }
        else {
            memcpy(s_auth_base_cred_buf, new_credentials, new_credentials_len);
            new_len = new_credentials_len;
        }
    }

    /* Commit with a single atomic object write (method/credentials_len live in
     * the object, so no second write, no rollback). RAM updates only on success. */
    if (rc == WH_ERROR_OK) {
        if (new_len > 0) {
            rc = wh_Auth_BasePersistCred(user_id, method, s_auth_base_cred_buf,
                                         new_len);
            if (rc == WH_ERROR_OK) {
                user->method          = method;
                user->credentials_len = new_len;
            }
        }
        else if (old_len > 0) {
            /* Clearing removes the object; a credential-less user is method
             * NONE, matching what a reload would rebuild. */
            rc = wh_Auth_BaseDestroyCred(user_id);
            if (rc == WH_ERROR_OK) {
                user->method          = WH_AUTH_METHOD_NONE;
                user->credentials_len = 0;
            }
        }
    }

    wh_Utils_ForceZero(s_auth_base_cred_buf, sizeof(s_auth_base_cred_buf));
    (void)auth_context;
    return rc;
}

#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION */
