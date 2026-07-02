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
 * src/wh_client_cert.c
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_cert.h"

/* Helper function to send a certificate verification request */
static int _certVerifyRequest(whClientContext* c, const uint8_t* cert,
                              uint32_t cert_len, whNvmId trustedRootNvmId,
                              uint16_t verifyFlags, whNvmFlags cachedKeyFlags,
                              whKeyId keyId);

/* Helper function to receive a verify response */
static int _certVerifyResponse(whClientContext* c, whKeyId* out_keyId,
                               int32_t* out_rc);

/* Helper function to perform certificate verification */
static int _certVerify(whClientContext* c, const uint8_t* cert,
                       uint32_t cert_len, whNvmId trustedRootNvmId,
                       uint16_t verifyFlags, whNvmFlags cachedKeyFlags,
                       whKeyId* inout_keyId, int32_t* out_rc);


/* Initialize the certificate manager */
int wh_Client_CertInitRequest(whClientContext* c)
{
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* TODO dummy request for now */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_INIT, 0, NULL);
}

int wh_Client_CertInitResponse(whClientContext* c, int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive and validate response */
    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_INIT) || (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
        }
    }

    return rc;
}

int wh_Client_CertInit(whClientContext* c, int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertInitRequest(c);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertInitResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

/* Add a trusted certificate */
int wh_Client_CertAddTrustedRequest(whClientContext* c, whNvmId id,
                                    whNvmAccess access, whNvmFlags flags,
                                    uint8_t* label, whNvmSize label_len,
                                    const uint8_t* cert, uint32_t cert_len)
{
    whMessageCert_AddTrustedRequest req                               = {0};
    uint8_t                         buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t                        hdr_len = sizeof(req);
    uint8_t*                        payload = buffer + hdr_len;

    if ((c == NULL) || (cert == NULL) || (cert_len == 0) ||
        (cert_len > (sizeof(buffer) - hdr_len))) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare request */
    memset(&req, 0, sizeof(req));
    req.id       = id;
    req.access   = access;
    req.flags    = flags;
    req.cert_len = cert_len;
    if (label != NULL && label_len > 0) {
        whNvmSize copy_len =
            (label_len > WH_NVM_LABEL_LEN) ? WH_NVM_LABEL_LEN : label_len;
        memcpy(req.label, label, copy_len);
    }

    /* Copy request struct and certificate data */
    memcpy(buffer, &req, hdr_len);
    memcpy(payload, cert, cert_len);

    /* Send request */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_ADDTRUSTED,
                                 hdr_len + cert_len, buffer);
}

int wh_Client_CertAddTrustedResponse(whClientContext* c, int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive and validate response */
    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_ADDTRUSTED) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
        }
    }

    return rc;
}

int wh_Client_CertAddTrusted(whClientContext* c, whNvmId id, whNvmAccess access,
                             whNvmFlags flags, uint8_t* label,
                             whNvmSize label_len, const uint8_t* cert,
                             uint32_t cert_len, int32_t* out_rc)
{
    int rc = 0;

    if ((c == NULL) || (cert == NULL) || (cert_len == 0)) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertAddTrustedRequest(c, id, access, flags, label,
                                             label_len, cert, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertAddTrustedResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

/* Delete a trusted certificate */
int wh_Client_CertEraseTrustedRequest(whClientContext* c, whNvmId id)
{
    whMessageCert_EraseTrustedRequest req = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.id = id;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_ERASETRUSTED,
                                 sizeof(req), &req);
}

int wh_Client_CertEraseTrustedResponse(whClientContext* c, int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive and validate response */
    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_ERASETRUSTED) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
        }
    }

    return rc;
}

int wh_Client_CertEraseTrusted(whClientContext* c, whNvmId id, int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertEraseTrustedRequest(c, id);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertEraseTrustedResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

/* Get a trusted certificate */
int wh_Client_CertReadTrustedRequest(whClientContext* c, whNvmId id,
                                     uint32_t cert_len)
{
    (void)cert_len;
    whMessageCert_ReadTrustedRequest req = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.id = id;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_READTRUSTED,
                                 sizeof(req), &req);
}

int wh_Client_CertReadTrustedResponse(whClientContext* c, uint8_t* cert,
                                      uint32_t* cert_len, int32_t* out_rc)
{
    int                                rc;
    uint16_t                           group;
    uint16_t                           action;
    uint16_t                           size;
    uint8_t                            buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    whMessageCert_ReadTrustedResponse* resp =
        (whMessageCert_ReadTrustedResponse*)buffer;
    uint8_t* payload = buffer + sizeof(*resp);

    if ((c == NULL) || (cert == NULL) || (cert_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Receive and validate response */
    rc = wh_Client_RecvResponse(c, &group, &action, &size, buffer);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_READTRUSTED) ||
            (size < sizeof(*resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp->rc;
                /* Ensure we return the actual certificate length */
                if (resp->rc == WH_ERROR_BUFFER_SIZE) {
                    *cert_len = resp->cert_len;
                }
            }

            if (resp->rc == WH_ERROR_OK) {
                /* Check that cert_len does not exceed the received data size */
                if (resp->cert_len > size - sizeof(*resp)) {
                    rc = WH_ERROR_ABORTED;
                }
                /* Check that caller buffer is large enough for the cert */
                else if (*cert_len < resp->cert_len) {
                    *cert_len = resp->cert_len;
                    if (out_rc != NULL) {
                        *out_rc = WH_ERROR_BUFFER_SIZE;
                    }
                }
                else {
                    memcpy(cert, payload, resp->cert_len);
                    *cert_len = resp->cert_len;
                }
            }
        }
    }

    return rc;
}

int wh_Client_CertReadTrusted(whClientContext* c, whNvmId id, uint8_t* cert,
                              uint32_t* cert_len, int32_t* out_rc)
{
    int rc = 0;

    if ((c == NULL) || (cert == NULL) || (cert_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertReadTrustedRequest(c, id, *cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertReadTrustedResponse(c, cert, cert_len, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

/* Helper function to send a verify request */
static int _certVerifyRequest(whClientContext* c, const uint8_t* cert,
                              uint32_t cert_len, whNvmId trustedRootNvmId,
                              uint16_t verifyFlags, whNvmFlags cachedKeyFlags,
                              whKeyId keyId)
{
    whMessageCert_VerifyRequest req                               = {0};
    uint8_t                     buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t                    hdr_len                           = sizeof(req);
    uint8_t*                    payload = buffer + hdr_len;

    if ((c == NULL) || (cert == NULL) || (cert_len == 0) ||
        (cert_len > (sizeof(buffer) - hdr_len))) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare request */
    req.cert_len         = cert_len;
    req.trustedRootNvmId = trustedRootNvmId;
    req.flags            = verifyFlags;
    req.cachedKeyFlags   = cachedKeyFlags;
    req.keyId            = keyId;

    /* Copy request struct and certificate data */
    memcpy(buffer, &req, hdr_len);
    memcpy(payload, cert, cert_len);

    /* Send request */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY,
                                 hdr_len + cert_len, buffer);
}

/* Helper function to receive a verify response */
static int _certVerifyResponse(whClientContext* c, whKeyId* out_keyId,
                               int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_VerifyResponse resp;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Receive and validate response */
    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_VERIFY) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
            if (out_keyId != NULL) {
                *out_keyId = resp.keyId;
            }
        }
    }

    return rc;
}

static int _certVerify(whClientContext* c, const uint8_t* cert,
                       uint32_t cert_len, whNvmId trustedRootNvmId,
                       uint16_t verifyFlags, whNvmFlags cachedKeyFlags,
                       whKeyId* inout_keyId, int32_t* out_rc)
{
    int     rc    = 0;
    whKeyId keyId = WH_KEYID_ERASED;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (cert == NULL) || (cert_len == 0) ||
        (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        keyId = *inout_keyId;
    }

    do {
        rc = _certVerifyRequest(c, cert, cert_len, trustedRootNvmId,
                                verifyFlags, cachedKeyFlags, keyId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = _certVerifyResponse(c, inout_keyId, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertVerifyRequest(whClientContext* c, const uint8_t* cert,
                                uint32_t cert_len, whNvmId trustedRootNvmId)
{
    return _certVerifyRequest(c, cert, cert_len, trustedRootNvmId,
                              WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY,
                              WH_KEYID_ERASED);
}

int wh_Client_CertVerifyResponse(whClientContext* c, int32_t* out_rc)
{
    return _certVerifyResponse(c, NULL, out_rc);
}

int wh_Client_CertVerify(whClientContext* c, const uint8_t* cert,
                         uint32_t cert_len, whNvmId trustedRootNvmId,
                         int32_t* out_rc)
{
    return _certVerify(c, cert, cert_len, trustedRootNvmId, WH_CERT_FLAGS_NONE,
                       WH_NVM_FLAGS_USAGE_ANY, NULL, out_rc);
}

int wh_Client_CertVerifyAndCacheLeafPubKeyRequest(
    whClientContext* c, const uint8_t* cert, uint32_t cert_len,
    whNvmId trustedRootNvmId, whNvmFlags cachedKeyFlags, whKeyId keyId)
{
    return _certVerifyRequest(c, cert, cert_len, trustedRootNvmId,
                              WH_CERT_FLAGS_CACHE_LEAF_PUBKEY, cachedKeyFlags,
                              keyId);
}

int wh_Client_CertVerifyAndCacheLeafPubKeyResponse(whClientContext* c,
                                                   whKeyId*         out_keyId,
                                                   int32_t*         out_rc)
{
    return _certVerifyResponse(c, out_keyId, out_rc);
}


int wh_Client_CertVerifyAndCacheLeafPubKey(
    whClientContext* c, const uint8_t* cert, uint32_t cert_len,
    whNvmId trustedRootNvmId, whNvmFlags cachedKeyFlags, whKeyId* inout_keyId,
    int32_t* out_rc)
{
    return _certVerify(c, cert, cert_len, trustedRootNvmId,
                       WH_CERT_FLAGS_CACHE_LEAF_PUBKEY, cachedKeyFlags,
                       inout_keyId, out_rc);
}

/* Helper: send a multi-root verify request */
static int _certVerifyMultiRootRequest(whClientContext* c, const uint8_t* cert,
                                       uint32_t       cert_len,
                                       const whNvmId* trustedRootNvmIds,
                                       uint16_t numRoots, uint16_t verifyFlags,
                                       whNvmFlags cachedKeyFlags, whKeyId keyId)
{
    whMessageCert_VerifyMultiRootRequest req   = {0};
    uint8_t  buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t hdr_len                           = sizeof(req);
    uint32_t roots_bytes = (uint32_t)numRoots * sizeof(whNvmId);
    uint8_t* roots_dst;
    uint8_t* cert_dst;

    if ((c == NULL) || (cert == NULL) || (cert_len == 0) ||
        (trustedRootNvmIds == NULL) || (numRoots == 0) ||
        (numRoots > WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS) ||
        (roots_bytes > sizeof(buffer) - hdr_len) ||
        (cert_len > sizeof(buffer) - hdr_len - roots_bytes)) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare request */
    req.cert_len       = cert_len;
    req.numRoots       = numRoots;
    req.flags          = verifyFlags;
    req.cachedKeyFlags = cachedKeyFlags;
    req.keyId          = keyId;

    /* Pack header, root array, then certificate data */
    memcpy(buffer, &req, hdr_len);
    roots_dst = buffer + hdr_len;
    memcpy(roots_dst, trustedRootNvmIds, roots_bytes);
    cert_dst = roots_dst + roots_bytes;
    memcpy(cert_dst, cert, cert_len);

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY_MULTI_ROOT,
                                 hdr_len + roots_bytes + cert_len, buffer);
}

/* Helper: receive a multi-root verify response */
static int _certVerifyMultiRootResponse(whClientContext* c, whKeyId* out_keyId,
                                        int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_VerifyResponse resp;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_VERIFY_MULTI_ROOT) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
            if (out_keyId != NULL) {
                *out_keyId = resp.keyId;
            }
        }
    }

    return rc;
}

/* Helper: blocking multi-root verify */
static int _certVerifyMultiRoot(whClientContext* c, const uint8_t* cert,
                                uint32_t       cert_len,
                                const whNvmId* trustedRootNvmIds,
                                uint16_t numRoots, uint16_t verifyFlags,
                                whNvmFlags cachedKeyFlags, whKeyId* inout_keyId,
                                int32_t* out_rc)
{
    int     rc    = 0;
    whKeyId keyId = WH_KEYID_ERASED;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (cert == NULL) || (cert_len == 0) ||
        (trustedRootNvmIds == NULL) || (numRoots == 0) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        keyId = *inout_keyId;
    }

    do {
        rc = _certVerifyMultiRootRequest(c, cert, cert_len, trustedRootNvmIds,
                                         numRoots, verifyFlags, cachedKeyFlags,
                                         keyId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = _certVerifyMultiRootResponse(c, inout_keyId, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertVerifyMultiRootRequest(whClientContext* c,
                                         const uint8_t* cert, uint32_t cert_len,
                                         const whNvmId* trustedRootNvmIds,
                                         uint16_t       numRoots)
{
    return _certVerifyMultiRootRequest(c, cert, cert_len, trustedRootNvmIds,
                                       numRoots, WH_CERT_FLAGS_NONE,
                                       WH_NVM_FLAGS_USAGE_ANY, WH_KEYID_ERASED);
}

int wh_Client_CertVerifyMultiRootResponse(whClientContext* c, int32_t* out_rc)
{
    return _certVerifyMultiRootResponse(c, NULL, out_rc);
}

int wh_Client_CertVerifyMultiRoot(whClientContext* c, const uint8_t* cert,
                                  uint32_t       cert_len,
                                  const whNvmId* trustedRootNvmIds,
                                  uint16_t numRoots, int32_t* out_rc)
{
    return _certVerifyMultiRoot(c, cert, cert_len, trustedRootNvmIds, numRoots,
                                WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY,
                                NULL, out_rc);
}

int wh_Client_CertVerifyMultiRootAndCacheLeafPubKeyRequest(
    whClientContext* c, const uint8_t* cert, uint32_t cert_len,
    const whNvmId* trustedRootNvmIds, uint16_t numRoots,
    whNvmFlags cachedKeyFlags, whKeyId keyId)
{
    return _certVerifyMultiRootRequest(
        c, cert, cert_len, trustedRootNvmIds, numRoots,
        WH_CERT_FLAGS_CACHE_LEAF_PUBKEY, cachedKeyFlags, keyId);
}

int wh_Client_CertVerifyMultiRootAndCacheLeafPubKeyResponse(whClientContext* c,
                                                            whKeyId* out_keyId,
                                                            int32_t* out_rc)
{
    return _certVerifyMultiRootResponse(c, out_keyId, out_rc);
}

int wh_Client_CertVerifyMultiRootAndCacheLeafPubKey(
    whClientContext* c, const uint8_t* cert, uint32_t cert_len,
    const whNvmId* trustedRootNvmIds, uint16_t numRoots,
    whNvmFlags cachedKeyFlags, whKeyId* inout_keyId, int32_t* out_rc)
{
    return _certVerifyMultiRoot(c, cert, cert_len, trustedRootNvmIds, numRoots,
                                WH_CERT_FLAGS_CACHE_LEAF_PUBKEY, cachedKeyFlags,
                                inout_keyId, out_rc);
}

#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
int wh_Client_CertVerifyCacheClearRequest(whClientContext* c)
{
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY_CACHE_CLEAR, 0,
                                 NULL);
}

int wh_Client_CertVerifyCacheClearResponse(whClientContext* c, int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == WH_ERROR_OK) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_VERIFY_CACHE_CLEAR) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else if (out_rc != NULL) {
            *out_rc = resp.rc;
        }
    }
    return rc;
}

int wh_Client_CertVerifyCacheClear(whClientContext* c, int32_t* out_rc)
{
    int rc = WH_ERROR_OK;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertVerifyCacheClearRequest(c);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == WH_ERROR_OK) {
        do {
            rc = wh_Client_CertVerifyCacheClearResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertVerifyCacheSetEnabledRequest(whClientContext* c,
                                               uint8_t          enable)
{
    whMessageCert_SetEnabledRequest req = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req.enable = enable ? 1 : 0;

    return wh_Client_SendRequest(
        c, WH_MESSAGE_GROUP_CERT,
        WH_MESSAGE_CERT_ACTION_VERIFY_CACHE_SET_ENABLED, sizeof(req),
        (uint8_t*)&req);
}

int wh_Client_CertVerifyCacheSetEnabledResponse(whClientContext* c,
                                                int32_t*         out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == WH_ERROR_OK) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_VERIFY_CACHE_SET_ENABLED) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else if (out_rc != NULL) {
            *out_rc = resp.rc;
        }
    }
    return rc;
}

int wh_Client_CertVerifyCacheSetEnabled(whClientContext* c, uint8_t enable,
                                        int32_t* out_rc)
{
    int rc = WH_ERROR_OK;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertVerifyCacheSetEnabledRequest(c, enable);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == WH_ERROR_OK) {
        do {
            rc = wh_Client_CertVerifyCacheSetEnabledResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE */

#ifdef WOLFHSM_CFG_DMA

int wh_Client_CertAddTrustedDmaRequest(whClientContext* c, whNvmId id,
                                       whNvmAccess access, whNvmFlags flags,
                                       uint8_t* label, whNvmSize label_len,
                                       const void* cert, uint32_t cert_len)
{
    whMessageCert_AddTrustedDmaRequest req = {0};

    if (c == NULL || cert_len > WOLFHSM_CFG_MAX_CERT_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    memset(&req, 0, sizeof(req));
    req.id        = id;
    req.access    = access;
    req.flags     = flags;
    req.cert_addr = (uint64_t)(uintptr_t)cert;
    req.cert_len  = cert_len;
    if (label != NULL && label_len > 0) {
        whNvmSize copy_len =
            (label_len > WH_NVM_LABEL_LEN) ? WH_NVM_LABEL_LEN : label_len;
        memcpy(req.label, label, copy_len);
    }
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA,
                                 sizeof(req), &req);
}

int wh_Client_CertAddTrustedDmaResponse(whClientContext* c, int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive and validate response */
    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
        }
    }

    return rc;
}

int wh_Client_CertAddTrustedDma(whClientContext* c, whNvmId id,
                                whNvmAccess access, whNvmFlags flags,
                                uint8_t* label, whNvmSize label_len,
                                const void* cert, uint32_t cert_len,
                                int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertAddTrustedDmaRequest(c, id, access, flags, label,
                                                label_len, cert, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertAddTrustedDmaResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertReadTrustedDmaRequest(whClientContext* c, whNvmId id,
                                        void* cert, uint32_t cert_len)
{
    whMessageCert_ReadTrustedDmaRequest req = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.id        = id;
    req.cert_addr = (uint64_t)(uintptr_t)cert;
    req.cert_len  = cert_len;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_READTRUSTED_DMA,
                                 sizeof(req), &req);
}

int wh_Client_CertReadTrustedDmaResponse(whClientContext* c, int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_SimpleResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive and validate response */
    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_READTRUSTED_DMA) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
        }
    }

    return rc;
}

int wh_Client_CertReadTrustedDma(whClientContext* c, whNvmId id, void* cert,
                                 uint32_t cert_len, int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertReadTrustedDmaRequest(c, id, cert, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertReadTrustedDmaResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

static int _certVerifyDmaRequest(whClientContext* c, const void* cert,
                                 uint32_t cert_len, whNvmId trustedRootNvmId,
                                 uint16_t flags, whNvmFlags cachedKeyFlags,
                                 whKeyId keyId)
{
    whMessageCert_VerifyDmaRequest req = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.cert_addr        = (uint64_t)(uintptr_t)cert;
    req.cert_len         = cert_len;
    req.trustedRootNvmId = trustedRootNvmId;
    req.flags            = flags;
    req.cachedKeyFlags   = cachedKeyFlags;
    req.keyId            = keyId;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY_DMA, sizeof(req),
                                 &req);
}

static int _certVerifyDmaResponse(whClientContext* c, whKeyId* out_keyId,
                                  int32_t* out_rc)
{
    int                             rc;
    uint16_t                        group;
    uint16_t                        action;
    uint16_t                        size;
    whMessageCert_VerifyDmaResponse resp;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Receive and validate response */
    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_VERIFY_DMA) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
            if (out_keyId != NULL) {
                *out_keyId = resp.keyId;
            }
        }
    }

    return rc;
}

static int _certVerifyDma(whClientContext* c, const void* cert,
                          uint32_t cert_len, whNvmId trustedRootNvmId,
                          uint16_t flags, whNvmFlags cachedKeyFlags,
                          whKeyId* inout_keyId, int32_t* out_rc)
{
    int     rc    = 0;
    whKeyId keyId = WH_KEYID_ERASED;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        keyId = *inout_keyId;
    }
    else {
        keyId = WH_KEYID_ERASED;
    }

    do {
        rc = _certVerifyDmaRequest(c, cert, cert_len, trustedRootNvmId, flags,
                                   cachedKeyFlags, keyId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = _certVerifyDmaResponse(c, inout_keyId, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertVerifyDmaRequest(whClientContext* c, const void* cert,
                                   uint32_t cert_len, whNvmId trustedRootNvmId)
{
    return _certVerifyDmaRequest(c, cert, cert_len, trustedRootNvmId,
                                 WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY,
                                 WH_KEYID_ERASED);
}

int wh_Client_CertVerifyDmaResponse(whClientContext* c, int32_t* out_rc)
{
    return _certVerifyDmaResponse(c, NULL, out_rc);
}

int wh_Client_CertVerifyDma(whClientContext* c, const void* cert,
                            uint32_t cert_len, whNvmId trustedRootNvmId,
                            int32_t* out_rc)
{
    return _certVerifyDma(c, cert, cert_len, trustedRootNvmId,
                          WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL,
                          out_rc);
}

int wh_Client_CertVerifyDmaAndCacheLeafPubKeyRequest(
    whClientContext* c, const void* cert, uint32_t cert_len,
    whNvmId trustedRootNvmId, whNvmFlags cachedKeyFlags, whKeyId keyId)
{
    return _certVerifyDmaRequest(c, cert, cert_len, trustedRootNvmId,
                                 WH_CERT_FLAGS_CACHE_LEAF_PUBKEY,
                                 cachedKeyFlags, keyId);
}

int wh_Client_CertVerifyDmaAndCacheLeafPubKeyResponse(whClientContext* c,
                                                      whKeyId* out_keyId,
                                                      int32_t* out_rc)
{
    return _certVerifyDmaResponse(c, out_keyId, out_rc);
}

int wh_Client_CertVerifyDmaAndCacheLeafPubKey(
    whClientContext* c, const void* cert, uint32_t cert_len,
    whNvmId trustedRootNvmId, whNvmFlags cachedKeyFlags, whKeyId* inout_keyId,
    int32_t* out_rc)
{
    return _certVerifyDma(c, cert, cert_len, trustedRootNvmId,
                          WH_CERT_FLAGS_CACHE_LEAF_PUBKEY, cachedKeyFlags,
                          inout_keyId, out_rc);
}

/* Helper: send a multi-root DMA verify request */
static int _certVerifyMultiRootDmaRequest(
    whClientContext* c, const void* cert, uint32_t cert_len,
    const whNvmId* trustedRootNvmIds, uint16_t numRoots, uint16_t verifyFlags,
    whNvmFlags cachedKeyFlags, whKeyId keyId)
{
    whMessageCert_VerifyMultiRootDmaRequest req = {0};

    if ((c == NULL) || (trustedRootNvmIds == NULL) || (numRoots == 0) ||
        (numRoots > WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS)) {
        return WH_ERROR_BADARGS;
    }

    req.cert_addr      = (uint64_t)(uintptr_t)cert;
    req.cert_len       = cert_len;
    req.numRoots       = numRoots;
    req.flags          = verifyFlags;
    req.cachedKeyFlags = cachedKeyFlags;
    req.keyId          = keyId;
    /* Only the first numRoots entries are meaningful; remaining slots stay
     * zeroed by the initializer above. */
    memcpy(req.trustedRootNvmIds, trustedRootNvmIds,
           (size_t)numRoots * sizeof(whNvmId));

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY_MULTI_ROOT_DMA,
                                 sizeof(req), &req);
}

/* Helper: receive a multi-root DMA verify response */
static int _certVerifyMultiRootDmaResponse(whClientContext* c,
                                           whKeyId* out_keyId, int32_t* out_rc)
{
    int                             rc;
    uint16_t                        group;
    uint16_t                        action;
    uint16_t                        size;
    whMessageCert_VerifyDmaResponse resp;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_VERIFY_MULTI_ROOT_DMA) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
            if (out_keyId != NULL) {
                *out_keyId = resp.keyId;
            }
        }
    }

    return rc;
}

/* Helper: blocking multi-root DMA verify */
static int _certVerifyMultiRootDma(whClientContext* c, const void* cert,
                                   uint32_t       cert_len,
                                   const whNvmId* trustedRootNvmIds,
                                   uint16_t numRoots, uint16_t verifyFlags,
                                   whNvmFlags cachedKeyFlags,
                                   whKeyId* inout_keyId, int32_t* out_rc)
{
    int     rc    = 0;
    whKeyId keyId = WH_KEYID_ERASED;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        keyId = *inout_keyId;
    }

    do {
        rc = _certVerifyMultiRootDmaRequest(c, cert, cert_len,
                                            trustedRootNvmIds, numRoots,
                                            verifyFlags, cachedKeyFlags, keyId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = _certVerifyMultiRootDmaResponse(c, inout_keyId, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertVerifyMultiRootDmaRequest(whClientContext* c,
                                            const void* cert, uint32_t cert_len,
                                            const whNvmId* trustedRootNvmIds,
                                            uint16_t       numRoots)
{
    return _certVerifyMultiRootDmaRequest(
        c, cert, cert_len, trustedRootNvmIds, numRoots, WH_CERT_FLAGS_NONE,
        WH_NVM_FLAGS_USAGE_ANY, WH_KEYID_ERASED);
}

int wh_Client_CertVerifyMultiRootDmaResponse(whClientContext* c,
                                             int32_t*         out_rc)
{
    return _certVerifyMultiRootDmaResponse(c, NULL, out_rc);
}

int wh_Client_CertVerifyMultiRootDma(whClientContext* c, const void* cert,
                                     uint32_t       cert_len,
                                     const whNvmId* trustedRootNvmIds,
                                     uint16_t numRoots, int32_t* out_rc)
{
    return _certVerifyMultiRootDma(c, cert, cert_len, trustedRootNvmIds,
                                   numRoots, WH_CERT_FLAGS_NONE,
                                   WH_NVM_FLAGS_USAGE_ANY, NULL, out_rc);
}

int wh_Client_CertVerifyMultiRootDmaAndCacheLeafPubKeyRequest(
    whClientContext* c, const void* cert, uint32_t cert_len,
    const whNvmId* trustedRootNvmIds, uint16_t numRoots,
    whNvmFlags cachedKeyFlags, whKeyId keyId)
{
    return _certVerifyMultiRootDmaRequest(
        c, cert, cert_len, trustedRootNvmIds, numRoots,
        WH_CERT_FLAGS_CACHE_LEAF_PUBKEY, cachedKeyFlags, keyId);
}

int wh_Client_CertVerifyMultiRootDmaAndCacheLeafPubKeyResponse(
    whClientContext* c, whKeyId* out_keyId, int32_t* out_rc)
{
    return _certVerifyMultiRootDmaResponse(c, out_keyId, out_rc);
}

int wh_Client_CertVerifyMultiRootDmaAndCacheLeafPubKey(
    whClientContext* c, const void* cert, uint32_t cert_len,
    const whNvmId* trustedRootNvmIds, uint16_t numRoots,
    whNvmFlags cachedKeyFlags, whKeyId* inout_keyId, int32_t* out_rc)
{
    return _certVerifyMultiRootDma(c, cert, cert_len, trustedRootNvmIds,
                                   numRoots, WH_CERT_FLAGS_CACHE_LEAF_PUBKEY,
                                   cachedKeyFlags, inout_keyId, out_rc);
}

#endif /* WOLFHSM_CFG_DMA */

#ifdef WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT


int wh_Client_CertVerifyAcertRequest(whClientContext* c, const void* cert,
                                     uint32_t cert_len,
                                     whNvmId  trustedRootNvmId)
{
    whMessageCert_VerifyAcertRequest req = {0};
    uint8_t                          buffer[WOLFHSM_CFG_COMM_DATA_LEN];
    size_t                           hdr_len = sizeof(req);
    uint8_t*                         payload = buffer + hdr_len;


    if ((c == NULL) || (trustedRootNvmId == WH_NVM_ID_INVALID) ||
        (cert == NULL) || (cert_len == 0) ||
        (cert_len > (sizeof(buffer) - hdr_len))) {
        return WH_ERROR_BADARGS;
    }

    req.cert_len         = cert_len;
    req.trustedRootNvmId = trustedRootNvmId;

    memcpy(buffer, &req, sizeof(req));
    memcpy(payload, cert, cert_len);

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY_ACERT,
                                 hdr_len + cert_len, buffer);
}

int wh_Client_CertVerifyAcertResponse(whClientContext* c, int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_SimpleResponse resp;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_VERIFY_ACERT) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
        }
    }

    return rc;
}

int wh_Client_CertVerifyAcert(whClientContext* c, const void* cert,
                              uint32_t cert_len, whNvmId trustedRootNvmId,
                              int32_t* out_rc)
{
    int rc = 0;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertVerifyAcertRequest(c, cert, cert_len,
                                              trustedRootNvmId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertVerifyAcertResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

#if defined(WOLFHSM_CFG_DMA)

int wh_Client_CertVerifyAcertDmaRequest(whClientContext* c, const void* cert,
                                        uint32_t cert_len,
                                        whNvmId  trustedRootNvmId)
{
    whMessageCert_VerifyDmaRequest req = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req.cert_addr        = (uint64_t)(intptr_t)cert;
    req.cert_len         = cert_len;
    req.trustedRootNvmId = trustedRootNvmId;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY_ACERT_DMA,
                                 sizeof(req), &req);
}

int wh_Client_CertVerifyAcertDmaResponse(whClientContext* c, int32_t* out_rc)
{
    int                          rc;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     size;
    whMessageCert_SimpleResponse resp;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c, &group, &action, &size, &resp);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_VERIFY_ACERT_DMA) ||
            (size != sizeof(resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp.rc;
            }
        }
    }

    return rc;
}

int wh_Client_CertVerifyAcertDma(whClientContext* c, const void* cert,
                                 uint32_t cert_len, whNvmId trustedRootNvmId,
                                 int32_t* out_rc)
{
    int rc = 0;

    /* out_rc is mandatory; it carries the verification verdict */
    if ((c == NULL) || (out_rc == NULL)) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertVerifyAcertDmaRequest(c, cert, cert_len,
                                                 trustedRootNvmId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertVerifyAcertDmaResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT */

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
