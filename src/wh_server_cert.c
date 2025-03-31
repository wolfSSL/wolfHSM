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
 * src/wh_server_cert.c
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_cert.h"
#include "wolfhsm/wh_server_nvm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_cert.h"

#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"


static int _verifyChainAgainstCmStore(WOLFSSL_CERT_MANAGER *cm,
                                      const uint8_t *chain, uint32_t chain_len)
{
    int            rc            = 0;
    const uint8_t* cert_ptr      = chain;
    uint32_t       remaining_len = chain_len;
    int            cert_len      = 0;
    word32         idx           = 0;

    if (cm == NULL || chain == NULL || chain_len == 0) {
        return WH_ERROR_BADARGS;
    }

    /* Iterate through each certificate in the chain */
    while (remaining_len > 0) {
        /* Reset index for each certificate */
        idx = 0;

        /* Get the length of the current certificate */
        rc = GetSequence(cert_ptr, &idx, &cert_len, remaining_len);
        if (rc < 0) {
            return rc;
        }

        /* Ensure the certificate length is valid */
        if (cert_len + idx > remaining_len) {
            return WH_ERROR_ABORTED;
        }

        /* Verify the current certificate */
        rc = wolfSSL_CertManagerVerifyBuffer(cm, cert_ptr, cert_len + idx,
                                             WOLFSSL_FILETYPE_ASN1);


        /* If this is not the leaf certificate and it's trusted, add it to the
         * CM store */
        if (rc == WOLFSSL_SUCCESS) {
            /* Decode (again) to determine if it's a CA (so we know when we hit
             * the leaf in the chain. Unfortunately this means we decode twice
             * but there is no other way to facilitate "Full" cert verification
             * including CRLs, as wc_ParseCert verification doesn't do this. */
            DecodedCert dc;
            wc_InitDecodedCert(&dc, cert_ptr, cert_len + idx, NULL);
            rc = wc_ParseCert(&dc, CERT_TYPE, 0, NULL);
            /* wolfCrypt API returns 0 on success */
            if (rc != 0) {
                wc_FreeDecodedCert(&dc);
                return rc;
            }
            if (dc.isCA) {
                /* Add the certificate to the CM store as trusted */
                rc = wolfSSL_CertManagerLoadCABuffer(
                    cm, cert_ptr, cert_len + idx, WOLFSSL_FILETYPE_ASN1);
                if (rc != WOLFSSL_SUCCESS) {
                    wc_FreeDecodedCert(&dc);
                    return rc;
                }
            }
            wc_FreeDecodedCert(&dc);
        }
        else {
            return rc;
        }

        /* Move to the next certificate in the chain */
        cert_ptr += (cert_len + idx);
        remaining_len -= (cert_len + idx);
    }

    return (rc == WOLFSSL_SUCCESS) ? WH_ERROR_OK : rc;
}

/* Initialize the certificate manager */
int wh_Server_CertInit(whServerContext* server)
{
    /* TODO: Anything to do here? */
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif
    (void)server;
    return WH_ERROR_OK;
}

/* Add a trusted certificate to NVM storage */
int wh_Server_CertAddTrusted(whServerContext* server, whNvmId id,
                             const uint8_t* cert, uint32_t cert_len)
{
    int rc;
    /* TODO: Properly set access and flags */
    whNvmAccess   access                  = WH_NVM_ACCESS_ANY;
    whNvmFlags    flags                   = WH_NVM_FLAGS_IMMUTABLE;
    uint8_t       label[WH_NVM_LABEL_LEN] = "trusted_cert";
    whNvmMetadata metadata;

    if ((server == NULL) || (cert == NULL) || (cert_len == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare metadata */
    metadata.id     = id;
    metadata.access = access;
    metadata.flags  = flags;
    metadata.len    = cert_len;
    memcpy(metadata.label, label, sizeof(label));

    rc = wh_Nvm_AddObject(server->nvm, &metadata, cert_len, cert);

    return rc;
}

/* Delete a trusted certificate from NVM storage */
int wh_Server_CertEraseTrusted(whServerContext* server, whNvmId id)
{
    int     rc;
    whNvmId id_list[1];

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    id_list[0] = id;
    rc         = wh_Nvm_DestroyObjects(server->nvm, 1, id_list);

    return rc;
}

/* Get a trusted certificate from NVM storage */
int wh_Server_CertReadTrusted(whServerContext* server, whNvmId id, uint8_t* cert,
                             uint32_t* inout_cert_len)
{
    int           rc;
    whNvmSize     userLen;
    whNvmMetadata meta;

    if ((server == NULL) || (cert == NULL) || (inout_cert_len == NULL) ||
        (*inout_cert_len > WOLFHSM_CFG_MAX_CERT_SIZE)) {
        return WH_ERROR_BADARGS;
    }


    /* Get metadata to check the certificate size */
    rc = wh_Nvm_GetMetadata(server->nvm, id, &meta);
    if (rc != 0) {
        return rc;
    }

    /* Clamp the input length to the actual length of the certificate. This will
     * be reflected back to the user on length mismatch failure */
    userLen = *inout_cert_len;
    *inout_cert_len = meta.len;

    /* Check if the provided buffer is large enough */
    if (meta.len > userLen) {
        return WH_ERROR_BUFFER_SIZE;
    }

    return wh_Nvm_Read(server->nvm, id, 0, userLen, cert);
}

/* Verify a certificate against trusted certificates */
int wh_Server_CertVerify(whServerContext* server, const uint8_t* cert,
                         uint32_t cert_len, whNvmId trustedRootNvmId)
{
    WOLFSSL_CERT_MANAGER *cm = NULL;

    /* Stack-based buffer for root certificate */
    uint8_t root_cert[WOLFHSM_CFG_MAX_CERT_SIZE];
    uint32_t root_cert_len = sizeof(root_cert);
    int      rc;

    if ((server == NULL) || (cert == NULL) || (cert_len == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize the certificate manager */
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Get the trusted root certificate */
    rc = wh_Server_CertReadTrusted(server, trustedRootNvmId, root_cert,
                                  &root_cert_len);
    if (rc == WH_ERROR_OK) {
        /* Load the trusted root certificate */
        rc = wolfSSL_CertManagerLoadCABuffer(cm, root_cert, root_cert_len,
                                             WOLFSSL_FILETYPE_ASN1);
        if (rc == WOLFSSL_SUCCESS) {
            /* Verify the certificate */
            rc = _verifyChainAgainstCmStore(cm, cert, cert_len);
            if (rc != WH_ERROR_OK) {
                rc = WH_ERROR_CERT_VERIFY;
            }
        }
        else {
            printf("Failed to load trusted root certificate: %d\n", rc);
        }
    }

    /* Clean up */
    (void)wolfSSL_CertManagerFree(cm);

    return rc;
}

/* Handle a certificate request and generate a response */
int wh_Server_HandleCertRequest(whServerContext* server, uint16_t magic,
                                uint16_t action, uint16_t seq,
                                uint16_t req_size, const void* req_packet,
                                uint16_t* out_resp_size, void* resp_packet)
{
    int rc = 0;

    if ((server == NULL) || (req_packet == NULL) || (resp_packet == NULL) ||
        (out_resp_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    switch (action) {
        case WH_MESSAGE_CERT_ACTION_INIT: {
            whMessageCert_SimpleResponse resp = {0};

            /* Process the init action */
            rc      = wh_Server_CertInit(server);
            resp.rc = rc;

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_ADDTRUSTED: {
            whMessageCert_AddTrustedRequest req  = {0};
            whMessageCert_SimpleResponse    resp = {0};
            const uint8_t*                  cert_data;

            /* Convert request struct */
            wh_MessageCert_TranslateAddTrustedRequest(
                magic, (whMessageCert_AddTrustedRequest*)req_packet, &req);

            /* Get pointer to certificate data */
            cert_data = (const uint8_t*)req_packet + sizeof(req);

            /* Process the add trusted action */
            rc      = wh_Server_CertAddTrusted(server, req.id, cert_data,
                                               req.cert_len);
            resp.rc = rc;

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_ERASETRUSTED: {
            whMessageCert_EraseTrustedRequest req  = {0};
            whMessageCert_SimpleResponse       resp = {0};

            /* Convert request struct */
            wh_MessageCert_TranslateEraseTrustedRequest(
                magic, (whMessageCert_EraseTrustedRequest*)req_packet, &req);

            /* Process the delete trusted action */
            rc      = wh_Server_CertEraseTrusted(server, req.id);
            resp.rc = rc;

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_READTRUSTED: {
            whMessageCert_ReadTrustedRequest  req  = {0};
            whMessageCert_ReadTrustedResponse resp = {0};
            uint8_t*                         cert_data;
            uint32_t                         cert_len;

            /* Convert request struct */
            wh_MessageCert_TranslateReadTrustedRequest(
                magic, (whMessageCert_ReadTrustedRequest*)req_packet, &req);

            /* Get pointer to certificate data buffer */
            cert_data = (uint8_t*)resp_packet + sizeof(resp);
            cert_len  = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(resp);

            /* Process the get trusted action */
            rc = wh_Server_CertReadTrusted(server, req.id, cert_data, &cert_len);
            resp.rc       = rc;
            resp.cert_len = cert_len;

            /* Convert the response struct */
            wh_MessageCert_TranslateReadTrustedResponse(
                magic, &resp, (whMessageCert_ReadTrustedResponse*)resp_packet);
            *out_resp_size = sizeof(resp) + cert_len;
        }; break;

        case WH_MESSAGE_CERT_ACTION_VERIFY: {
            whMessageCert_VerifyRequest  req  = {0};
            whMessageCert_SimpleResponse resp = {0};
            const uint8_t*               cert_data;

            if (req_size < sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            else {
                /* Convert request struct */
                wh_MessageCert_TranslateVerifyRequest(
                    magic, (whMessageCert_VerifyRequest*)req_packet, &req);

                /* Get pointer to certificate data */
                cert_data = (const uint8_t*)req_packet + sizeof(req);

                /* Process the verify action */
                resp.rc = wh_Server_CertVerify(server, cert_data, req.cert_len,
                                               req.trustedRootNvmId);
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

#ifdef WOLFHSM_CFG_DMA
#if WH_DMA_IS_32BIT
        case WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA32: {
            whMessageCert_AddTrustedDma32Request req       = {0};
            whMessageCert_SimpleResponse         resp      = {0};
            void*                                cert_data = NULL;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            if (resp.rc == 0) {
                /* Convert request struct */
                wh_MessageCert_TranslateAddTrustedDma32Request(
                    magic, (whMessageCert_AddTrustedDma32Request*)req_packet,
                    &req);

                /* Process client address */
                resp.rc = wh_Server_DmaProcessClientAddress32(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            }
            if (resp.rc == 0) {
                /* Process the add trusted action */
                resp.rc = wh_Server_CertAddTrusted(server, req.id, cert_data,
                                                   req.cert_len);
            }
            if (resp.rc == 0) {
                /* Post-process client address */
                resp.rc = wh_Server_DmaProcessClientAddress32(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_READTRUSTED_DMA32: {
            whMessageCert_ReadTrustedDma32Request req       = {0};
            whMessageCert_SimpleResponse         resp      = {0};
            void*                                cert_data = NULL;
            uint32_t                             cert_len;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            if (resp.rc == 0) {
                /* Convert request struct */
                wh_MessageCert_TranslateReadTrustedDma32Request(
                    magic, (whMessageCert_ReadTrustedDma32Request*)req_packet,
                    &req);

                /* Process client address */
                resp.rc = wh_Server_DmaProcessClientAddress32(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
            }
            if (resp.rc == 0) {
                /* Process the get trusted action */
                cert_len = req.cert_len;
                resp.rc  = wh_Server_CertReadTrusted(server, req.id, cert_data,
                                                    &cert_len);
            }
            if (resp.rc == 0) {
                /* Post-process client address */
                resp.rc = wh_Server_DmaProcessClientAddress32(
                    server, req.cert_addr, &cert_data, cert_len,
                    WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_VERIFY_DMA32: {
            whMessageCert_VerifyDma32Request req       = {0};
            whMessageCert_SimpleResponse     resp      = {0};
            void*                            cert_data = NULL;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            if (resp.rc == 0) {
                /* Convert request struct */
                wh_MessageCert_TranslateVerifyDma32Request(
                    magic, (whMessageCert_VerifyDma32Request*)req_packet, &req);

                /* Process client address */
                resp.rc = wh_Server_DmaProcessClientAddress32(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            }
            if (resp.rc == 0) {
                /* Process the verify action */
                resp.rc = wh_Server_CertVerify(server, cert_data, req.cert_len,
                                               req.trustedRootNvmId);
            }
            if (resp.rc == 0) {
                /* Post-process client address */
                resp.rc = wh_Server_DmaProcessClientAddress32(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;
#endif /* WH_DMA_IS_32BIT */

#if WH_DMA_IS_64BIT
        case WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA64: {
            whMessageCert_AddTrustedDma64Request req       = {0};
            whMessageCert_SimpleResponse         resp      = {0};
            void*                                cert_data = NULL;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            if (resp.rc == 0) {
                /* Convert request struct */
                wh_MessageCert_TranslateAddTrustedDma64Request(
                    magic, (whMessageCert_AddTrustedDma64Request*)req_packet,
                    &req);

                /* Process client address */
                resp.rc = wh_Server_DmaProcessClientAddress64(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            }
            if (resp.rc == 0) {
                /* Process the add trusted action */
                resp.rc = wh_Server_CertAddTrusted(server, req.id, cert_data,
                                                   req.cert_len);
            }
            if (resp.rc == 0) {
                /* Post-process client address */
                resp.rc = wh_Server_DmaProcessClientAddress64(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_READTRUSTED_DMA64: {
            whMessageCert_ReadTrustedDma64Request req       = {0};
            whMessageCert_SimpleResponse         resp      = {0};
            void*                                cert_data = NULL;
            uint32_t                             cert_len;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            if (resp.rc == 0) {
                /* Convert request struct */
                wh_MessageCert_TranslateReadTrustedDma64Request(
                    magic, (whMessageCert_ReadTrustedDma64Request*)req_packet,
                    &req);

                /* Process client address */
                resp.rc = wh_Server_DmaProcessClientAddress64(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
            }
            if (resp.rc == 0) {
                /* Process the get trusted action */
                cert_len = req.cert_len;
                resp.rc  = wh_Server_CertReadTrusted(server, req.id, cert_data,
                                                    &cert_len);
            }
            if (resp.rc == 0) {
                /* Post-process client address */
                resp.rc = wh_Server_DmaProcessClientAddress64(
                    server, req.cert_addr, &cert_data, cert_len,
                    WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_VERIFY_DMA64: {
            whMessageCert_VerifyDma64Request req       = {0};
            whMessageCert_SimpleResponse     resp      = {0};
            void*                            cert_data = NULL;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            if (resp.rc == 0) {
                /* Convert request struct */
                wh_MessageCert_TranslateVerifyDma64Request(
                    magic, (whMessageCert_VerifyDma64Request*)req_packet, &req);

                /* Process client address */
                resp.rc = wh_Server_DmaProcessClientAddress64(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            }
            if (resp.rc == 0) {
                /* Process the verify action */
                resp.rc = wh_Server_CertVerify(server, cert_data, req.cert_len,
                                               req.trustedRootNvmId);
            }
            if (resp.rc == 0) {
                /* Post-process client address */
                resp.rc = wh_Server_DmaProcessClientAddress64(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;
#endif /* WH_DMA_IS_64BIT */
#endif /* WOLFHSM_CFG_DMA */

        default:
            /* Unknown request. Respond with empty packet */
            *out_resp_size = 0;
    }

    return rc;
}

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
