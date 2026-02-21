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
typedef struct whAuthBase_User {
    whAuthUser    user;
    whAuthMethod  method;
    unsigned char credentials[WH_AUTH_BASE_MAX_CREDENTIALS_LEN];
    uint16_t      credentials_len;
} whAuthBase_User;
/* The global users array is protected by the auth context lock when
 * WOLFHSM_CFG_THREADSAFE is defined. Locking is performed by the wh_Auth_*
 * wrapper functions in wh_auth.c. */
static whAuthBase_User users[WH_AUTH_BASE_MAX_USERS];

/* NVM persistence: when non-NULL, user database is stored in NVM */
static whNvmContext* s_auth_base_nvm = NULL;

/* Serialization format: magic (4) + version (2) + users array */
#define WH_AUTH_BASE_NVM_MAGIC 0x57484142u /* "WHAB" */
#define WH_AUTH_BASE_NVM_VERSION 1
#define WH_AUTH_BASE_NVM_HEADER_SIZE 6
#define WH_AUTH_BASE_NVM_DATA_SIZE \
    (WH_AUTH_BASE_NVM_HEADER_SIZE + sizeof(whAuthBase_User) * WH_AUTH_BASE_MAX_USERS)

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#endif

/* Persist users array to NVM. Caller must hold auth lock. */
static int wh_Auth_BasePersistToNvm(void)
{
    whNvmMetadata meta = {0};
    uint8_t       buf[WH_AUTH_BASE_NVM_DATA_SIZE];
    int           i;

    if (s_auth_base_nvm == NULL) {
        return WH_ERROR_OK;
    }

    /* Serialize: magic + version + users (clear is_active before storing) */
    ((uint32_t*)buf)[0] = WH_AUTH_BASE_NVM_MAGIC;
    ((uint16_t*)(buf + 4))[0] = WH_AUTH_BASE_NVM_VERSION;
    memcpy(buf + WH_AUTH_BASE_NVM_HEADER_SIZE, users, sizeof(users));
    /* Clear is_active in serialized copy - session state is not persisted */
    for (i = 0; i < WH_AUTH_BASE_MAX_USERS; i++) {
        ((whAuthBase_User*)(buf + WH_AUTH_BASE_NVM_HEADER_SIZE))[i].user.is_active = false;
    }

    meta.id     = WH_NVM_ID_AUTH_USER_DB;
    meta.access = WH_NVM_ACCESS_NONE;
    meta.flags  = WH_NVM_FLAGS_SENSITIVE;
    meta.len    = WH_AUTH_BASE_NVM_DATA_SIZE;
    memset(meta.label, 0, sizeof(meta.label));
    memcpy(meta.label, "auth_user_db", 12);

    return wh_Nvm_AddObject(s_auth_base_nvm, &meta, WH_AUTH_BASE_NVM_DATA_SIZE, buf);
}

/* Load users from NVM. Caller must hold auth lock. Returns WH_ERROR_OK on success. */
static int wh_Auth_BaseLoadFromNvm(void)
{
    whNvmMetadata meta = {0};
    uint8_t       buf[WH_AUTH_BASE_NVM_DATA_SIZE];
    int           rc;

    if (s_auth_base_nvm == NULL) {
        return WH_ERROR_OK;
    }

    rc = wh_Nvm_GetMetadata(s_auth_base_nvm, WH_NVM_ID_AUTH_USER_DB, &meta);
    if (rc == WH_ERROR_NOTFOUND) {
        return WH_ERROR_OK; /* No stored data, keep empty */
    }
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    if (meta.len != WH_AUTH_BASE_NVM_DATA_SIZE) {
        return WH_ERROR_OK; /* Version mismatch, ignore */
    }

    rc = wh_Nvm_Read(s_auth_base_nvm, WH_NVM_ID_AUTH_USER_DB, 0,
                     WH_AUTH_BASE_NVM_DATA_SIZE, buf);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    if (((uint32_t*)buf)[0] != WH_AUTH_BASE_NVM_MAGIC ||
        ((uint16_t*)(buf + 4))[0] != WH_AUTH_BASE_NVM_VERSION) {
        return WH_ERROR_OK; /* Unknown format, start fresh */
    }

    memcpy(users, buf + WH_AUTH_BASE_NVM_HEADER_SIZE, sizeof(users));
    /* Ensure is_active is false after load (session state is not persisted) */
    {
        int i;
        for (i = 0; i < WH_AUTH_BASE_MAX_USERS; i++) {
            users[i].user.is_active = false;
        }
    }
    return WH_ERROR_OK;
}

int wh_Auth_BaseInit(void* context, const void* config)
{
    (void)context;

    memset(users, 0, sizeof(users));
    s_auth_base_nvm = NULL;

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

static whAuthBase_User* wh_Auth_BaseCheckPin(const char* username,
                                             const void* auth_data,
                                             uint16_t    auth_data_len)
{
    whAuthBase_User* found_user;
    unsigned char    authCheck[WH_AUTH_BASE_MAX_CREDENTIALS_LEN];
    uint16_t         authCheck_len;
    int              rc;

    /* Process auth_data: hash if crypto enabled, copy if disabled */
    rc = wh_Auth_BaseHashPin(auth_data, auth_data_len, authCheck);
    if (rc != WH_ERROR_OK) {
        return NULL;
    }
#ifndef WOLFHSM_CFG_NO_CRYPTO
    authCheck_len = WC_SHA256_DIGEST_SIZE;
#else
    authCheck_len = auth_data_len;
#endif /* WOLFHSM_CFG_NO_CRYPTO */

    found_user = wh_Auth_BaseFindUser(username);
    if (found_user != NULL && found_user->method == WH_AUTH_METHOD_PIN &&
        found_user->credentials_len == authCheck_len &&
        wh_Utils_ConstantCompare(found_user->credentials, authCheck,
        authCheck_len) == 0) {
        return found_user;
    }
    return NULL;
}

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
static int wh_Auth_BaseVerifyCertificate(whAuthBase_User* found_user,
                                         const uint8_t*   certificate,
                                         uint16_t         certificate_len)
{
    int                   rc = WH_ERROR_ABORTED;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    cm                       = wolfSSL_CertManagerNew();
    if (cm != NULL) {
        if (wolfSSL_CertManagerLoadCABuffer(cm, found_user->credentials,
                                            found_user->credentials_len,
                                            WOLFSSL_FILETYPE_ASN1) ==
                                            WOLFSSL_SUCCESS) {
            if (wolfSSL_CertManagerVerifyBuffer(cm, certificate,
                    certificate_len, WOLFSSL_FILETYPE_ASN1) ==
                    WOLFSSL_SUCCESS) {
                rc = WH_ERROR_OK;
            }
        }
        wolfSSL_CertManagerFree(cm);
    }
    return rc;
}

static whAuthBase_User* wh_Auth_BaseCheckCertificate(const char* username,
                                                     const void* auth_data,
                                                     uint16_t    auth_data_len)
{
    whAuthBase_User* found_user;
    found_user = wh_Auth_BaseFindUser(username);
    if (found_user != NULL &&
        found_user->method == WH_AUTH_METHOD_CERTIFICATE &&
        found_user->credentials_len > 0) {
        if (wh_Auth_BaseVerifyCertificate(found_user, auth_data,
                                          auth_data_len) == WH_ERROR_OK) {
            return found_user;
        }
    }
    return NULL;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */

int wh_Auth_BaseLogin(void* context, uint8_t client_id, whAuthMethod method,
                      const char* username, const void* auth_data,
                      uint16_t auth_data_len, whUserId* out_user_id,
                      whAuthPermissions* out_permissions, int* loggedIn)
{
    whAuthBase_User* current_user = NULL;

    if ((out_user_id == NULL) || (out_permissions == NULL) ||
        (loggedIn == NULL) || (username == NULL)) {
        return WH_ERROR_BADARGS;
    }

    *loggedIn = 0;

    (void)client_id;
    switch (method) {
        case WH_AUTH_METHOD_PIN:
            current_user =
                wh_Auth_BaseCheckPin(username, auth_data, auth_data_len);
            break;
#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
        case WH_AUTH_METHOD_CERTIFICATE:
            current_user = wh_Auth_BaseCheckCertificate(username, auth_data,
                                                        auth_data_len);
            break;
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
        default:
            return WH_ERROR_BADARGS;
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
        if (users[i].user.user_id == WH_USER_ID_INVALID) {
            break;
        }

        /* do not allow duplicate users with same name */
        if (strcmp(users[i].user.username, username) == 0) {
            return WH_ERROR_BADARGS;
        }
    }

    if (i >= WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_BUFFER_SIZE;
    }
    userId   = i + 1; /* save 0 for WH_USER_ID_INVALID */
    new_user = &users[i];

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

    /* Set credentials if provided */
    if (credentials != NULL && credentials_len > 0) {
        new_user->method = method;
        if (method == WH_AUTH_METHOD_PIN) {
#ifndef WOLFHSM_CFG_NO_CRYPTO
            /* Hash PIN before storing */
            unsigned char hash[WC_SHA256_DIGEST_SIZE];
            int rc = wh_Auth_BaseHashPin(credentials, credentials_len, hash);
            if (rc != WH_ERROR_OK) {
                return rc;
            }
            memcpy(new_user->credentials, hash, WC_SHA256_DIGEST_SIZE);
            new_user->credentials_len = WC_SHA256_DIGEST_SIZE;
#else
            /* When crypto is disabled, store PIN as-is */
            if (credentials_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
                return WH_ERROR_BUFFER_SIZE;
            }
            memcpy(new_user->credentials, credentials, credentials_len);
            new_user->credentials_len = credentials_len;
#endif /* WOLFHSM_CFG_NO_CRYPTO */
        }
        else {
            /* For non-PIN methods (e.g., certificate), store as-is */
            if (credentials_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
                return WH_ERROR_BUFFER_SIZE;
            }
            memcpy(new_user->credentials, credentials, credentials_len);
            new_user->credentials_len = credentials_len;
        }
    }

    rc = wh_Auth_BasePersistToNvm();
    (void)auth_context;
    return rc;
}

int wh_Auth_BaseUserDelete(void* context, uint16_t current_user_id,
                           uint16_t user_id)
{
    whAuthBase_User* user;

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

    memset(user, 0, sizeof(whAuthBase_User));
    (void)context;
    return wh_Auth_BasePersistToNvm();
}

int wh_Auth_BaseUserSetPermissions(void* context, uint16_t current_user_id,
                                   uint16_t          user_id,
                                   whAuthPermissions permissions)
{
    whAuthBase_User* user;

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
    (void)context;
    return wh_Auth_BasePersistToNvm();
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


int wh_Auth_BaseUserSetCredentials(void* context, uint16_t user_id,
                                   whAuthMethod method,
                                   const void*  current_credentials,
                                   uint16_t     current_credentials_len,
                                   const void*  new_credentials,
                                   uint16_t     new_credentials_len)
{
    whAuthContext*   auth_context = (whAuthContext*)context;
    whAuthBase_User* user;
    int              rc = WH_ERROR_OK;

    if (user_id == WH_USER_ID_INVALID || user_id > WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_BADARGS;
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

    /* Verify current credentials if user has existing credentials */
    if (user->credentials_len > 0) {
        /* User has existing credentials, so current_credentials must be
         * provided and match */
        if (current_credentials == NULL || current_credentials_len == 0) {
            return WH_ERROR_ACCESS;
        }
        if (user->method == WH_AUTH_METHOD_PIN) {
#ifndef WOLFHSM_CFG_NO_CRYPTO
            /* For PIN, hash the provided credentials before comparing */
            unsigned char hash[WC_SHA256_DIGEST_SIZE];
            rc = wh_Auth_BaseHashPin(current_credentials,
                                    current_credentials_len, hash);
            if (rc != WH_ERROR_OK) {
                return rc;
            }
            if (user->credentials_len != WC_SHA256_DIGEST_SIZE ||
                wh_Utils_ConstantCompare(user->credentials, hash,
                WC_SHA256_DIGEST_SIZE) != 0) {
                return WH_ERROR_ACCESS;
            }
#else
            /* When crypto is disabled, compare PINs directly */
            if (user->credentials_len != current_credentials_len ||
                wh_Utils_ConstantCompare(user->credentials, current_credentials,
                       current_credentials_len) != 0) {
                return WH_ERROR_ACCESS;
            }
#endif /* WOLFHSM_CFG_NO_CRYPTO */
        }
        else {
            /* For non-PIN methods, compare as-is */
            if (user->credentials_len != current_credentials_len ||
                wh_Utils_ConstantCompare(user->credentials, current_credentials,
                       current_credentials_len) != 0) {
                return WH_ERROR_ACCESS;
            }
        }
    }
    else {
        /* User has no existing credentials, current_credentials should be NULL
         */
        if (current_credentials != NULL && current_credentials_len > 0) {
            return WH_ERROR_BADARGS;
        }
    }

    /* Set new credentials */
    user->method = method;
    if (new_credentials_len > 0) {
        if (method == WH_AUTH_METHOD_PIN) {
#ifndef WOLFHSM_CFG_NO_CRYPTO
            /* Hash PIN before storing */
            unsigned char hash[WC_SHA256_DIGEST_SIZE];
            rc = wh_Auth_BaseHashPin(new_credentials, new_credentials_len, hash);
            if (rc != WH_ERROR_OK) {
                return rc;
            }
            memcpy(user->credentials, hash, WC_SHA256_DIGEST_SIZE);
            user->credentials_len = WC_SHA256_DIGEST_SIZE;
#else
            /* When crypto is disabled, store PIN as-is */
            if (new_credentials_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
                return WH_ERROR_BUFFER_SIZE;
            }
            memcpy(user->credentials, new_credentials, new_credentials_len);
            user->credentials_len = new_credentials_len;
#endif /* WOLFHSM_CFG_NO_CRYPTO */
        }
        else {
            /* For non-PIN methods (e.g., certificate), store as-is */
            if (new_credentials_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
                return WH_ERROR_BUFFER_SIZE;
            }
            memcpy(user->credentials, new_credentials, new_credentials_len);
            user->credentials_len = new_credentials_len;
        }
    }
    else {
        /* Allow clearing credentials by setting length to 0 */
        user->credentials_len = 0;
    }

    if (rc == WH_ERROR_OK) {
        rc = wh_Auth_BasePersistToNvm();
    }
    (void)auth_context;
    return rc;
}
