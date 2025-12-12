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

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && \
    !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_cert.h"
#include "wolfhsm/wh_server_nvm.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_cert.h"

#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"


static int _verifyChainAgainstCmStore(whServerContext*      server,
                                      WOLFSSL_CERT_MANAGER* cm,
                                      const uint8_t* chain, uint32_t chain_len,
                                      whCertFlags flags,
                                      whNvmFlags  cachedKeyFlags,
                                      whKeyId*    inout_keyId)
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
            /* This is the leaf cert, so if requested, cache the public key */
            else if (flags & WH_CERT_FLAGS_CACHE_LEAF_PUBKEY) {
                /* If the keyId is erased, get a unique key id for the public
                 * key. Otherwise cache the key using the provided keyId */
                if (WH_KEYID_ISERASED(*inout_keyId)) {
                    rc = wh_Server_KeystoreGetUniqueId(server, inout_keyId);
                    if (rc != WH_ERROR_OK) {
                        return rc;
                    }
                }

                if (rc == WH_ERROR_OK) {
                    whNvmMetadata* cacheMeta;
                    uint8_t*       cacheBuf;
                    word32         cacheBufSize =
                        WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE;

                    /* Grab the cache slot and dump the public key from the cert
                     * into it */
                    rc = wh_Server_KeystoreGetCacheSlot(server, *inout_keyId,
                                                        cacheBufSize, &cacheBuf,
                                                        &cacheMeta);
                    if (rc == WH_ERROR_OK) {
                        rc = wc_GetSubjectPubKeyInfoDerFromCert(
                            cert_ptr, cert_len + idx, cacheBuf, &cacheBufSize);

                        /* Populate the metadata to seal the deal */
                        if (rc == 0) {
                            const char label[] = "cert_pubkey";
                            cacheMeta->len     = (whNvmSize)cacheBufSize;
                            cacheMeta->flags   = cachedKeyFlags;
                            cacheMeta->access  = WH_NVM_ACCESS_ANY;
                            cacheMeta->id      = *inout_keyId;
                            memset(cacheMeta->label, 0,
                                   sizeof(cacheMeta->label));
                            strncpy((char*)cacheMeta->label, label,
                                    sizeof(cacheMeta->label));
                        }
                    }
                }

                if (rc != WH_ERROR_OK) {
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
                             whNvmAccess access, whNvmFlags flags,
                             const uint8_t* label, whNvmSize label_len,
                             const uint8_t* cert, uint32_t cert_len)
{
    int           rc;
    whNvmMetadata metadata;

    if ((server == NULL) || (cert == NULL) || (cert_len == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare metadata */
    metadata.id     = id;
    metadata.access = access;
    metadata.flags  = flags;
    metadata.len    = cert_len;
    memset(metadata.label, 0, WH_NVM_LABEL_LEN);
    if (label != NULL && label_len > 0) {
        whNvmSize copy_len =
            (label_len > WH_NVM_LABEL_LEN) ? WH_NVM_LABEL_LEN : label_len;
        memcpy(metadata.label, label, copy_len);
    }
    else {
        /* Default label if none provided */
        memcpy(metadata.label, "trusted_cert", sizeof("trusted_cert"));
    }

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
int wh_Server_CertReadTrusted(whServerContext* server, whNvmId id,
                              uint8_t* cert, uint32_t* inout_cert_len)
{
    int           rc;
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

    /* Check if the provided buffer is large enough */
    if (meta.len > *inout_cert_len) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Clamp the input length to the actual length of the certificate. This will
     * be reflected back to the user on length mismatch failure */
    *inout_cert_len = meta.len;

    return wh_Nvm_Read(server->nvm, id, 0, meta.len, cert);
}

/* Verify a certificate against trusted certificates */
int wh_Server_CertVerify(whServerContext* server, const uint8_t* cert,
                         uint32_t cert_len, whNvmId trustedRootNvmId,
                         whCertFlags flags, whNvmFlags cachedKeyFlags,
                         whKeyId* inout_keyId)
{
    WOLFSSL_CERT_MANAGER* cm = NULL;

    /* Stack-based buffer for root certificate */
    uint8_t  root_cert[WOLFHSM_CFG_MAX_CERT_SIZE];
    uint32_t root_cert_len = sizeof(root_cert);
    int      rc;

    if ((server == NULL) || (cert == NULL) || (cert_len == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* If the leaf public key is to be cached, then the user must provide a
     * keyId */
    if ((flags & WH_CERT_FLAGS_CACHE_LEAF_PUBKEY) && (inout_keyId == NULL)) {
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
            rc = _verifyChainAgainstCmStore(server, cm, cert, cert_len, flags,
                                            cachedKeyFlags, inout_keyId);
            if (rc != WH_ERROR_OK) {
                rc = WH_ERROR_CERT_VERIFY;
            }
        }
        else {
            WH_DEBUG_SERVER_VERBOSE("Failed to load trusted root certificate: %d\n", rc);
        }
    }

    /* Clean up */
    (void)wolfSSL_CertManagerFree(cm);

    return rc;
}

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
int wh_Server_CertVerifyAcert(whServerContext* server, const uint8_t* cert,
                              uint32_t cert_len, whNvmId trustedRootNvmId)
{
    int rc;

    /* Stack-based buffer for root certificate */
    uint8_t  root_cert[WOLFHSM_CFG_MAX_CERT_SIZE];
    uint32_t root_cert_len = sizeof(root_cert);

    /* Load the trusted root certificate into the buffer */
    rc = wh_Server_CertReadTrusted(server, trustedRootNvmId, root_cert,
                                   &root_cert_len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Decode and parse the root certificate */
    DecodedCert dc;
    wc_InitDecodedCert(&dc, root_cert, root_cert_len, NULL);
    rc = wc_ParseCert(&dc, CERT_TYPE, 0, NULL);
    if (rc != 0) {
        wc_FreeDecodedCert(&dc);
        return rc;
    }

    /* Ensure wolfCrypt was able to decode the certificate and store the
     * public key */
    if (dc.pubKeyStored == 0) {
        wc_FreeDecodedCert(&dc);
        return WH_ERROR_ABORTED;
    }

    /* Verify the Acert against the root certificate public key */
    rc = wc_VerifyX509Acert(cert, cert_len, dc.publicKey, dc.pubKeySize,
                            dc.keyOID, NULL);

    wc_FreeDecodedCert(&dc);
    return rc;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT */

/* Handle a certificate request and generate a response */
int wh_Server_HandleCertRequest(whServerContext* server, uint16_t magic,
                                uint16_t action, uint16_t seq,
                                uint16_t req_size, const void* req_packet,
                                uint16_t* out_resp_size, void* resp_packet)
{
    (void)seq;

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

            /* Validate minimum size */
            if (req_size < sizeof(whMessageCert_AddTrustedRequest)) {
                resp.rc = WH_ERROR_BADARGS;
                wh_MessageCert_TranslateSimpleResponse(
                    magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
                *out_resp_size = sizeof(resp);
                break;
            }

            /* Convert request struct */
            wh_MessageCert_TranslateAddTrustedRequest(
                magic, (whMessageCert_AddTrustedRequest*)req_packet, &req);

            /* Validate certificate data fits within request */
            if (req.cert_len > req_size - sizeof(req)) {
                resp.rc = WH_ERROR_BADARGS;
                wh_MessageCert_TranslateSimpleResponse(
                    magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
                *out_resp_size = sizeof(resp);
                break;
            }

            /* Get pointer to certificate data */
            cert_data = (const uint8_t*)req_packet + sizeof(req);

            /* Process the add trusted action */
            rc = wh_Server_CertAddTrusted(server, req.id, req.access, req.flags,
                                          req.label, WH_NVM_LABEL_LEN,
                                          cert_data, req.cert_len);
            resp.rc = rc;

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_ERASETRUSTED: {
            whMessageCert_EraseTrustedRequest req  = {0};
            whMessageCert_SimpleResponse      resp = {0};

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
            const uint32_t max_transport_cert_len =
                WOLFHSM_CFG_COMM_DATA_LEN -
                sizeof(whMessageCert_ReadTrustedResponse);
            whMessageCert_ReadTrustedRequest  req  = {0};
            whMessageCert_ReadTrustedResponse resp = {0};
            uint8_t*                          cert_data;
            uint32_t                          cert_len;
            whNvmMetadata                     meta;

            /* Convert request struct */
            wh_MessageCert_TranslateReadTrustedRequest(
                magic, (whMessageCert_ReadTrustedRequest*)req_packet, &req);

            /* Get pointer to certificate data buffer */
            cert_data = (uint8_t*)resp_packet + sizeof(resp);
            cert_len  = WOLFHSM_CFG_MAX_CERT_SIZE > max_transport_cert_len
                            ? max_transport_cert_len
                            : WOLFHSM_CFG_MAX_CERT_SIZE;

            /* Check metadata to check if the certificate is non-exportable.
             * This is unfortunately redundant since metadata is checked in
             * wh_Server_CertReadTrusted(). */
            rc = wh_Nvm_GetMetadata(server->nvm, req.id, &meta);
            if (rc == WH_ERROR_OK) {
                /* Check if the certificate is non-exportable */
                if (meta.flags & WH_NVM_FLAGS_NONEXPORTABLE) {
                    resp.rc = WH_ERROR_ACCESS;
                }
                else {
                    rc = wh_Server_CertReadTrusted(server, req.id, cert_data,
                                                   &cert_len);
                    resp.rc       = rc;
                    resp.cert_len = cert_len;
                }
            }
            else {
                resp.rc       = rc;
                resp.cert_len = 0;
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateReadTrustedResponse(
                magic, &resp, (whMessageCert_ReadTrustedResponse*)resp_packet);
            *out_resp_size = sizeof(resp) + resp.cert_len;
        }; break;

        case WH_MESSAGE_CERT_ACTION_VERIFY: {
            whMessageCert_VerifyRequest  req  = {0};
            whMessageCert_VerifyResponse resp = {0};
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

                /* Map client keyId to server keyId space */
                whKeyId keyId = wh_KeyId_TranslateFromClient(
                    WH_KEYTYPE_CRYPTO, server->comm->client_id, req.keyId);

                /* Process the verify action */
                resp.rc = wh_Server_CertVerify(server, cert_data, req.cert_len,
                                               req.trustedRootNvmId, req.flags,
                                               req.cachedKeyFlags, &keyId);

                /* Propagate the keyId back to the client with flags preserved
                 */
                resp.keyId = wh_KeyId_TranslateToClient(keyId);
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateVerifyResponse(
                magic, &resp, (whMessageCert_VerifyResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

#ifdef WOLFHSM_CFG_DMA
        case WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA: {
            whMessageCert_AddTrustedDmaRequest req       = {0};
            whMessageCert_SimpleResponse       resp      = {0};
            void*                              cert_data = NULL;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            if (resp.rc == WH_ERROR_OK) {
                /* Convert request struct */
                wh_MessageCert_TranslateAddTrustedDmaRequest(
                    magic, (whMessageCert_AddTrustedDmaRequest*)req_packet,
                    &req);

                /* Process client address */
                resp.rc = wh_Server_DmaProcessClientAddress(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            }
            if (resp.rc == WH_ERROR_OK) {
                /* Process the add trusted action */
                resp.rc = wh_Server_CertAddTrusted(
                    server, req.id, req.access, req.flags, req.label,
                    WH_NVM_LABEL_LEN, cert_data, req.cert_len);
            }
            if (resp.rc == WH_ERROR_OK) {
                /* Post-process client address */
                resp.rc = wh_Server_DmaProcessClientAddress(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_READTRUSTED_DMA: {
            whMessageCert_ReadTrustedDmaRequest req       = {0};
            whMessageCert_SimpleResponse        resp      = {0};
            void*                               cert_data = NULL;
            uint32_t                            cert_len;
            whNvmMetadata                       meta;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            if (resp.rc == WH_ERROR_OK) {
                /* Convert request struct */
                wh_MessageCert_TranslateReadTrustedDmaRequest(
                    magic, (whMessageCert_ReadTrustedDmaRequest*)req_packet,
                    &req);

                /* Process client address */
                resp.rc = wh_Server_DmaProcessClientAddress(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
            }
            if (resp.rc == WH_ERROR_OK) {
                /* Check metadata to see if the certificate is non-exportable */
                resp.rc = wh_Nvm_GetMetadata(server->nvm, req.id, &meta);
                if (resp.rc == WH_ERROR_OK) {
                    if ((meta.flags & WH_NVM_FLAGS_NONEXPORTABLE) != 0) {
                        resp.rc = WH_ERROR_ACCESS;
                    }
                    else {
                        /* Clamp cert_len to actual stored length */
                        cert_len = req.cert_len;
                        resp.rc  = wh_Server_CertReadTrusted(
                             server, req.id, cert_data, &cert_len);
                    }
                }
            }
            if (resp.rc == WH_ERROR_OK) {
                /* Post-process client address */
                resp.rc = wh_Server_DmaProcessClientAddress(
                    server, req.cert_addr, &cert_data, cert_len,
                    WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

        case WH_MESSAGE_CERT_ACTION_VERIFY_DMA: {
            whMessageCert_VerifyDmaRequest req       = {0};
            whMessageCert_VerifyDmaResponse resp      = {0};
            void*                          cert_data = NULL;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                resp.rc = WH_ERROR_ABORTED;
            }
            if (resp.rc == WH_ERROR_OK) {
                /* Convert request struct */
                wh_MessageCert_TranslateVerifyDmaRequest(
                    magic, (whMessageCert_VerifyDmaRequest*)req_packet, &req);

                /* Process client address */
                resp.rc = wh_Server_DmaProcessClientAddress(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            }
            if (resp.rc == WH_ERROR_OK) {
                /* Map client keyId to server keyId space */
                whKeyId keyId = wh_KeyId_TranslateFromClient(
                    WH_KEYTYPE_CRYPTO, server->comm->client_id, req.keyId);

                /* Process the verify action */
                resp.rc = wh_Server_CertVerify(server, cert_data, req.cert_len,
                                               req.trustedRootNvmId, req.flags,
                                               req.cachedKeyFlags, &keyId);

                /* Propagate the keyId back to the client with flags preserved
                 */
                resp.keyId = wh_KeyId_TranslateToClient(keyId);
            }
            if (resp.rc == WH_ERROR_OK) {
                /* Post-process client address */
                resp.rc = wh_Server_DmaProcessClientAddress(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateVerifyDmaResponse(
                magic, &resp, (whMessageCert_VerifyDmaResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;
#endif /* WOLFHSM_CFG_DMA */

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
        case WH_MESSAGE_CERT_ACTION_VERIFY_ACERT: {
            whMessageCert_VerifyAcertRequest req       = {0};
            whMessageCert_SimpleResponse     resp      = {0};
            const uint8_t*                   cert_data = NULL;

            /* Convert request struct */
            wh_MessageCert_TranslateVerifyAcertRequest(
                magic, (whMessageCert_VerifyAcertRequest*)req_packet, &req);

            cert_data = (const uint8_t*)req_packet + sizeof(req);

            /* Process the verify action */
            rc = wh_Server_CertVerifyAcert(server, cert_data, req.cert_len,
                                           req.trustedRootNvmId);

            /* Signature confirmation error is not an error for the server, so
             * propagate this error to the client in the response, otherwise
             * return the error code from the verify action */
            if (rc == ASN_SIG_CONFIRM_E) {
                resp.rc = WH_ERROR_CERT_VERIFY;
                rc      = WH_ERROR_OK;
            }
            else {
                resp.rc = rc;
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        }; break;

#if defined(WOLFHSM_CFG_DMA)
        case WH_MESSAGE_CERT_ACTION_VERIFY_ACERT_DMA: {
            /* Acert verify request uses standard cert verify request struct */
            whMessageCert_VerifyDmaRequest req       = {0};
            whMessageCert_SimpleResponse   resp      = {0};
            void*                          cert_data = NULL;

            if (req_size != sizeof(req)) {
                /* Request is malformed */
                rc = WH_ERROR_ABORTED;
            }
            if (rc == WH_ERROR_OK) {
                /* Convert request struct */
                wh_MessageCert_TranslateVerifyDmaRequest(
                    magic, (whMessageCert_VerifyDmaRequest*)req_packet, &req);

                /* Process client address */
                rc = wh_Server_DmaProcessClientAddress(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            }
            if (rc == WH_ERROR_OK) {
                /* Process the verify action */
                rc = wh_Server_CertVerifyAcert(server, cert_data, req.cert_len,
                                               req.trustedRootNvmId);
                /* Signature confirmation error is not an error for the server,
                 * so propagate this error to the client in the response,
                 * otherwise return the error code from the verify action */
                if (rc == ASN_SIG_CONFIRM_E) {
                    resp.rc = WH_ERROR_CERT_VERIFY;
                    rc      = WH_ERROR_OK;
                }
                else {
                    resp.rc = rc;
                }
            }
            if (rc == WH_ERROR_OK) {
                /* Post-process client address */
                rc = wh_Server_DmaProcessClientAddress(
                    server, req.cert_addr, &cert_data, req.cert_len,
                    WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
            }

            /* Convert the response struct */
            wh_MessageCert_TranslateSimpleResponse(
                magic, &resp, (whMessageCert_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);

            /* If there was an error, return it in the response */
            if (rc != WH_ERROR_OK) {
                resp.rc = rc;
            }
        } break;
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT */

        default:
            /* Unknown request. Respond with empty packet */
            *out_resp_size = 0;
    }

    return rc;
}

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO && \
          WOLFHSM_CFG_ENABLE_SERVER */
