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
 * src/wh_client_cert.c
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_cert.h"

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
                                    const uint8_t* cert, uint32_t cert_len)
{
    whMessageCert_AddTrustedRequest req;
    uint8_t                         buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t                        hdr_len = sizeof(req);
    uint8_t*                        payload = buffer + hdr_len;

    if ((c == NULL) || (cert == NULL) || (cert_len == 0) ||
        (cert_len > (sizeof(buffer) - hdr_len))) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare request */
    req.id       = id;
    req.cert_len = cert_len;

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

int wh_Client_CertAddTrusted(whClientContext* c, whNvmId id,
                             const uint8_t* cert, uint32_t cert_len,
                             int32_t* out_rc)
{
    int rc = 0;

    if ((c == NULL) || (cert == NULL) || (cert_len == 0)) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertAddTrustedRequest(c, id, cert, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertAddTrustedResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

/* Delete a trusted certificate */
int wh_Client_CertDeleteTrustedRequest(whClientContext* c, whNvmId id)
{
    whMessageCert_DeleteTrustedRequest req;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.id = id;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_DELETETRUSTED,
                                 sizeof(req), &req);
}

int wh_Client_CertDeleteTrustedResponse(whClientContext* c, int32_t* out_rc)
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
            (action != WH_MESSAGE_CERT_ACTION_DELETETRUSTED) ||
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

int wh_Client_CertDeleteTrusted(whClientContext* c, whNvmId id, int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertDeleteTrustedRequest(c, id);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertDeleteTrustedResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

/* Get a trusted certificate */
int wh_Client_CertGetTrustedRequest(whClientContext* c, whNvmId id,
                                    uint32_t cert_len)
{
    whMessageCert_GetTrustedRequest req;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.id = id;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_GETTRUSTED, sizeof(req),
                                 &req);
}

int wh_Client_CertGetTrustedResponse(whClientContext* c, uint8_t* cert,
                                     uint32_t* cert_len, int32_t* out_rc)
{
    int                               rc;
    uint16_t                          group;
    uint16_t                          action;
    uint16_t                          size;
    uint8_t                           buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    whMessageCert_GetTrustedResponse* resp =
        (whMessageCert_GetTrustedResponse*)buffer;
    uint8_t* payload = buffer + sizeof(*resp);

    if ((c == NULL) || (cert == NULL) || (cert_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Receive and validate response */
    rc = wh_Client_RecvResponse(c, &group, &action, &size, buffer);
    if (rc == 0) {
        if ((group != WH_MESSAGE_GROUP_CERT) ||
            (action != WH_MESSAGE_CERT_ACTION_GETTRUSTED) ||
            (size < sizeof(*resp))) {
            rc = WH_ERROR_ABORTED;
        }
        else {
            if (out_rc != NULL) {
                *out_rc = resp->rc;
            }

            if (resp->rc == 0) {
                /* Copy certificate data if buffer is large enough */
                if (*cert_len >= resp->cert_len) {
                    memcpy(cert, payload, resp->cert_len);
                    *cert_len = resp->cert_len;
                }
            }
        }
    }

    return rc;
}

int wh_Client_CertGetTrusted(whClientContext* c, whNvmId id, uint8_t* cert,
                             uint32_t* cert_len, int32_t* out_rc)
{
    int rc = 0;

    if ((c == NULL) || (cert == NULL) || (cert_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertGetTrustedRequest(c, id, *cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertGetTrustedResponse(c, cert, cert_len, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

/* Verify a certificate */
int wh_Client_CertVerifyRequest(whClientContext* c, const uint8_t* cert,
                                uint32_t cert_len, whNvmId trustedRootNvmId)
{
    whMessageCert_VerifyRequest req;
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

    /* Copy request struct and certificate data */
    memcpy(buffer, &req, hdr_len);
    memcpy(payload, cert, cert_len);

    /* Send request */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY,
                                 hdr_len + cert_len, buffer);
}

int wh_Client_CertVerifyResponse(whClientContext* c, int32_t* out_rc)
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
            (action != WH_MESSAGE_CERT_ACTION_VERIFY) ||
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

int wh_Client_CertVerify(whClientContext* c, const uint8_t* cert,
                         uint32_t cert_len, whNvmId trustedRootNvmId,
                         int32_t* out_rc)
{
    int rc = 0;

    if ((c == NULL) || (cert == NULL) || (cert_len == 0)) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertVerifyRequest(c, cert, cert_len, trustedRootNvmId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertVerifyResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

#ifdef WOLFHSM_CFG_DMA
#if WH_DMA_IS_32BIT
/* DMA 32-bit variants */
int wh_Client_CertAddTrustedDma32Request(whClientContext* c, whNvmId id,
                                         uint32_t cert_addr, uint32_t cert_len)
{
    whMessageCert_AddTrustedDma32Request req;

    if (c == NULL || cert_len > WOLFHSM_CFG_MAX_CERT_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.id        = id;
    req.cert_addr = cert_addr;
    req.cert_len  = cert_len;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA32,
                                 sizeof(req), &req);
}

int wh_Client_CertAddTrustedDma32Response(whClientContext* c, int32_t* out_rc)
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
            (action != WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA32) ||
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

int wh_Client_CertAddTrustedDma32(whClientContext* c, whNvmId id,
                                  uint32_t cert_addr, uint32_t cert_len,
                                  int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertAddTrustedDma32Request(c, id, cert_addr, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertAddTrustedDma32Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertGetTrustedDma32Request(whClientContext* c, whNvmId id,
                                         uint32_t cert_addr, uint32_t cert_len)
{
    whMessageCert_GetTrustedDma32Request req;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.id        = id;
    req.cert_addr = cert_addr;
    req.cert_len  = cert_len;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_GETTRUSTED_DMA32,
                                 sizeof(req), &req);
}

int wh_Client_CertGetTrustedDma32Response(whClientContext* c, int32_t* out_rc)
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
            (action != WH_MESSAGE_CERT_ACTION_GETTRUSTED_DMA32) ||
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

int wh_Client_CertGetTrustedDma32(whClientContext* c, whNvmId id,
                                  uint32_t cert_addr, uint32_t cert_len,
                                  int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertGetTrustedDma32Request(c, id, cert_addr, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertGetTrustedDma32Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertVerifyDma32Request(whClientContext* c, uint32_t cert_addr,
                                     uint32_t cert_len,
                                     whNvmId  trustedRootNvmId)
{
    whMessageCert_VerifyDma32Request req;

    if (c == NULL || cert_len > WOLFHSM_CFG_MAX_CERT_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.cert_addr        = cert_addr;
    req.cert_len         = cert_len;
    req.trustedRootNvmId = trustedRootNvmId;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY_DMA32,
                                 sizeof(req), &req);
}

int wh_Client_CertVerifyDma32Response(whClientContext* c, int32_t* out_rc)
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
            (action != WH_MESSAGE_CERT_ACTION_VERIFY_DMA32) ||
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

int wh_Client_CertVerifyDma32(whClientContext* c, uint32_t cert_addr,
                              uint32_t cert_len, whNvmId trustedRootNvmId,
                              int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertVerifyDma32Request(c, cert_addr, cert_len,
                                              trustedRootNvmId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertVerifyDma32Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}
#endif /* WH_DMA_IS_32BIT */

#if WH_DMA_IS_64BIT
/* DMA 64-bit variants */
int wh_Client_CertAddTrustedDma64Request(whClientContext* c, whNvmId id,
                                         uint64_t cert_addr, uint32_t cert_len)
{
    whMessageCert_AddTrustedDma64Request req;

    if (c == NULL || cert_len > WOLFHSM_CFG_MAX_CERT_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.id        = id;
    req.cert_addr = cert_addr;
    req.cert_len  = cert_len;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA64,
                                 sizeof(req), &req);
}

int wh_Client_CertAddTrustedDma64Response(whClientContext* c, int32_t* out_rc)
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
            (action != WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA64) ||
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

int wh_Client_CertAddTrustedDma64(whClientContext* c, whNvmId id,
                                  uint64_t cert_addr, uint32_t cert_len,
                                  int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertAddTrustedDma64Request(c, id, cert_addr, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertAddTrustedDma64Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertGetTrustedDma64Request(whClientContext* c, whNvmId id,
                                         uint64_t cert_addr, uint32_t cert_len)
{
    whMessageCert_GetTrustedDma64Request req;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.id        = id;
    req.cert_addr = cert_addr;
    req.cert_len  = cert_len;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_GETTRUSTED_DMA64,
                                 sizeof(req), &req);
}

int wh_Client_CertGetTrustedDma64Response(whClientContext* c, int32_t* out_rc)
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
            (action != WH_MESSAGE_CERT_ACTION_GETTRUSTED_DMA64) ||
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

int wh_Client_CertGetTrustedDma64(whClientContext* c, whNvmId id,
                                  uint64_t cert_addr, uint32_t cert_len,
                                  int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertGetTrustedDma64Request(c, id, cert_addr, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertGetTrustedDma64Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertVerifyDma64Request(whClientContext* c, uint64_t cert_addr,
                                     uint32_t cert_len,
                                     whNvmId  trustedRootNvmId)
{
    whMessageCert_VerifyDma64Request req;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare and send request */
    req.cert_addr        = cert_addr;
    req.cert_len         = cert_len;
    req.trustedRootNvmId = trustedRootNvmId;
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CERT,
                                 WH_MESSAGE_CERT_ACTION_VERIFY_DMA64,
                                 sizeof(req), &req);
}

int wh_Client_CertVerifyDma64Response(whClientContext* c, int32_t* out_rc)
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
            (action != WH_MESSAGE_CERT_ACTION_VERIFY_DMA64) ||
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

int wh_Client_CertVerifyDma64(whClientContext* c, uint64_t cert_addr,
                              uint32_t cert_len, whNvmId trustedRootNvmId,
                              int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertVerifyDma64Request(c, cert_addr, cert_len,
                                              trustedRootNvmId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertVerifyDma64Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}
#endif /* WH_DMA_IS_64BIT */

/** Cert Verify DMA Helper functions */

/** Cert Add Trusted DMA Helper functions */
int wh_Client_CertAddTrustedDmaRequest(whClientContext* c, whNvmId id,
                                       const uint8_t* cert, uint32_t cert_len)
{
#if WH_DMA_IS_32BIT
    return wh_Client_CertAddTrustedDma32Request(c, id, (uint32_t)(intptr_t)cert,
                                                cert_len);
#else
    return wh_Client_CertAddTrustedDma64Request(c, id, (uint64_t)(intptr_t)cert,
                                                cert_len);
#endif
}

int wh_Client_CertAddTrustedDmaResponse(whClientContext* c, int32_t* out_rc)
{
#if WH_DMA_IS_32BIT
    return wh_Client_CertAddTrustedDma32Response(c, out_rc);
#else
    return wh_Client_CertAddTrustedDma64Response(c, out_rc);
#endif
}

int wh_Client_CertAddTrustedDma(whClientContext* c, whNvmId id,
                                const uint8_t* cert, uint32_t cert_len,
                                int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertAddTrustedDmaRequest(c, id, cert, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertAddTrustedDmaResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

/** Cert Get Trusted DMA Helper functions */
int wh_Client_CertGetTrustedDmaRequest(whClientContext* c, whNvmId id,
                                       uint8_t* cert, uint32_t cert_len)
{
#if WH_DMA_IS_32BIT
    return wh_Client_CertGetTrustedDma32Request(c, id, (uint32_t)(intptr_t)cert,
                                                cert_len);
#else
    return wh_Client_CertGetTrustedDma64Request(c, id, (uint64_t)(intptr_t)cert,
                                                cert_len);
#endif
}

int wh_Client_CertGetTrustedDmaResponse(whClientContext* c, int32_t* out_rc)
{
#if WH_DMA_IS_32BIT
    return wh_Client_CertGetTrustedDma32Response(c, out_rc);
#else
    return wh_Client_CertGetTrustedDma64Response(c, out_rc);
#endif
}

int wh_Client_CertGetTrustedDma(whClientContext* c, whNvmId id, uint8_t* cert,
                                uint32_t cert_len, int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertGetTrustedDmaRequest(c, id, cert, cert_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertGetTrustedDmaResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

int wh_Client_CertVerifyDmaRequest(whClientContext* c, const uint8_t* cert,
                                   uint32_t cert_len, whNvmId trustedRootNvmId)
{
#if WH_DMA_IS_32BIT
    return wh_Client_CertVerifyDma32Request(c, (uint32_t)(intptr_t)cert, cert_len,
                                            trustedRootNvmId);
#else
    return wh_Client_CertVerifyDma64Request(c, (uint64_t)(intptr_t)cert, cert_len,
                                            trustedRootNvmId);
#endif
}

int wh_Client_CertVerifyDmaResponse(whClientContext* c, int32_t* out_rc)
{
#if WH_DMA_IS_32BIT
    return wh_Client_CertVerifyDma32Response(c, out_rc);
#else
    return wh_Client_CertVerifyDma64Response(c, out_rc);
#endif
}

int wh_Client_CertVerifyDma(whClientContext* c, const uint8_t* cert,
                            uint32_t cert_len, whNvmId trustedRootNvmId,
                            int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CertVerifyDmaRequest(c, cert, cert_len, trustedRootNvmId);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CertVerifyDmaResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}

#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */