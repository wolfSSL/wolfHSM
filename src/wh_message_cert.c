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
 * src/wh_message_cert.c
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_cert.h"

int wh_MessageCert_TranslateSimpleResponse(
    uint16_t magic, const whMessageCert_SimpleResponse* src,
    whMessageCert_SimpleResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}

int wh_MessageCert_TranslateAddTrustedRequest(
    uint16_t magic, const whMessageCert_AddTrustedRequest* src,
    whMessageCert_AddTrustedRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    WH_T32(magic, dest, src, cert_len);
    return 0;
}

int wh_MessageCert_TranslateEraseTrustedRequest(
    uint16_t magic, const whMessageCert_EraseTrustedRequest* src,
    whMessageCert_EraseTrustedRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    return 0;
}

int wh_MessageCert_TranslateReadTrustedRequest(
    uint16_t magic, const whMessageCert_ReadTrustedRequest* src,
    whMessageCert_ReadTrustedRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    return 0;
}

int wh_MessageCert_TranslateReadTrustedResponse(
    uint16_t magic, const whMessageCert_ReadTrustedResponse* src,
    whMessageCert_ReadTrustedResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, cert_len);
    return 0;
}

int wh_MessageCert_TranslateVerifyRequest(
    uint16_t magic, const whMessageCert_VerifyRequest* src,
    whMessageCert_VerifyRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, cert_len);
    WH_T16(magic, dest, src, trustedRootNvmId);
    return 0;
}

#ifdef WOLFHSM_CFG_DMA
int wh_MessageCert_TranslateAddTrustedDma32Request(
    uint16_t magic, const whMessageCert_AddTrustedDma32Request* src,
    whMessageCert_AddTrustedDma32Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    WH_T32(magic, dest, src, cert_addr);
    WH_T32(magic, dest, src, cert_len);
    return 0;
}

int wh_MessageCert_TranslateReadTrustedDma32Request(
    uint16_t magic, const whMessageCert_ReadTrustedDma32Request* src,
    whMessageCert_ReadTrustedDma32Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    WH_T32(magic, dest, src, cert_addr);
    WH_T32(magic, dest, src, cert_len);
    return 0;
}

int wh_MessageCert_TranslateVerifyDma32Request(
    uint16_t magic, const whMessageCert_VerifyDma32Request* src,
    whMessageCert_VerifyDma32Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, cert_addr);
    WH_T32(magic, dest, src, cert_len);
    WH_T16(magic, dest, src, trustedRootNvmId);
    return 0;
}

int wh_MessageCert_TranslateAddTrustedDma64Request(
    uint16_t magic, const whMessageCert_AddTrustedDma64Request* src,
    whMessageCert_AddTrustedDma64Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    WH_T64(magic, dest, src, cert_addr);
    WH_T32(magic, dest, src, cert_len);
    return 0;
}

int wh_MessageCert_TranslateReadTrustedDma64Request(
    uint16_t magic, const whMessageCert_ReadTrustedDma64Request* src,
    whMessageCert_ReadTrustedDma64Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    WH_T64(magic, dest, src, cert_addr);
    WH_T32(magic, dest, src, cert_len);
    return 0;
}

int wh_MessageCert_TranslateVerifyDma64Request(
    uint16_t magic, const whMessageCert_VerifyDma64Request* src,
    whMessageCert_VerifyDma64Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T64(magic, dest, src, cert_addr);
    WH_T32(magic, dest, src, cert_len);
    WH_T16(magic, dest, src, trustedRootNvmId);
    return 0;
}
#endif /* WOLFHSM_CFG_DMA */

#ifdef WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT
int wh_MessageCert_TranslateVerifyAcertRequest(
    uint16_t magic, const whMessageCert_VerifyAcertRequest* src,
    whMessageCert_VerifyAcertRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, cert_len);
    WH_T16(magic, dest, src, trustedRootNvmId);
    return 0;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT */
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */