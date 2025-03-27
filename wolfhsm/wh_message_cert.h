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
 * wolfhsm/wh_message_cert.h
 */

#ifndef WOLFHSM_WH_MESSAGE_CERT_H_
#define WOLFHSM_WH_MESSAGE_CERT_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_nvm.h"

enum WH_MESSAGE_CERT_ACTION_ENUM {
    WH_MESSAGE_CERT_ACTION_INIT             = 0x1,
    WH_MESSAGE_CERT_ACTION_ADDTRUSTED       = 0x2,
    WH_MESSAGE_CERT_ACTION_DELETETRUSTED    = 0x3,
    WH_MESSAGE_CERT_ACTION_GETTRUSTED       = 0x4,
    WH_MESSAGE_CERT_ACTION_VERIFY           = 0x5,
    WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA32 = 0x12,
    WH_MESSAGE_CERT_ACTION_GETTRUSTED_DMA32 = 0x14,
    WH_MESSAGE_CERT_ACTION_VERIFY_DMA32     = 0x15,
    WH_MESSAGE_CERT_ACTION_ADDTRUSTED_DMA64 = 0x22,
    WH_MESSAGE_CERT_ACTION_GETTRUSTED_DMA64 = 0x24,
    WH_MESSAGE_CERT_ACTION_VERIFY_DMA64     = 0x25,
};

/* Simple reusable response message */
typedef struct {
    int32_t rc;
    uint8_t WH_PAD[4];
} whMessageCert_SimpleResponse;

int wh_MessageCert_TranslateSimpleResponse(
    uint16_t magic, const whMessageCert_SimpleResponse* src,
    whMessageCert_SimpleResponse* dest);

/* Init Request/Response */
/* Empty request message */
/* Use SimpleResponse */

/* AddTrusted Request */
typedef struct {
    uint32_t cert_len;
    whNvmId  id;
    uint8_t  WH_PAD[2];
    /* Certificate data follows */
} whMessageCert_AddTrustedRequest;

int wh_MessageCert_TranslateAddTrustedRequest(
    uint16_t magic, const whMessageCert_AddTrustedRequest* src,
    whMessageCert_AddTrustedRequest* dest);

/* AddTrusted Response */
/* Use SimpleResponse */

/* DeleteTrusted Request */
typedef struct {
    whNvmId id;
    uint8_t WH_PAD[6];
} whMessageCert_DeleteTrustedRequest;

int wh_MessageCert_TranslateDeleteTrustedRequest(
    uint16_t magic, const whMessageCert_DeleteTrustedRequest* src,
    whMessageCert_DeleteTrustedRequest* dest);

/* DeleteTrusted Response */
/* Use SimpleResponse */

/* GetTrusted Request */
typedef struct {
    whNvmId id;
    uint8_t WH_PAD[6];
} whMessageCert_GetTrustedRequest;

int wh_MessageCert_TranslateGetTrustedRequest(
    uint16_t magic, const whMessageCert_GetTrustedRequest* src,
    whMessageCert_GetTrustedRequest* dest);

/* GetTrusted Response */
typedef struct {
    int32_t  rc;
    uint32_t cert_len;
    /* Certificate data follows */
} whMessageCert_GetTrustedResponse;

int wh_MessageCert_TranslateGetTrustedResponse(
    uint16_t magic, const whMessageCert_GetTrustedResponse* src,
    whMessageCert_GetTrustedResponse* dest);

/* Verify Request */
typedef struct {
    uint32_t cert_len;
    whNvmId  trustedRootNvmId;
    uint8_t  WH_PAD[2];
    /* Certificate data follows */
} whMessageCert_VerifyRequest;

int wh_MessageCert_TranslateVerifyRequest(
    uint16_t magic, const whMessageCert_VerifyRequest* src,
    whMessageCert_VerifyRequest* dest);

/* Verify Response */
/* Use SimpleResponse */

#ifdef WOLFHSM_CFG_DMA
#if WH_DMA_IS_32BIT
/* AddTrusted DMA32 Request */
typedef struct {
    uint32_t cert_addr;
    uint32_t cert_len;
    whNvmId  id;
    uint8_t  WH_PAD[2];
} whMessageCert_AddTrustedDma32Request;

int wh_MessageCert_TranslateAddTrustedDma32Request(
    uint16_t magic, const whMessageCert_AddTrustedDma32Request* src,
    whMessageCert_AddTrustedDma32Request* dest);

/* GetTrusted DMA32 Request */
typedef struct {
    uint32_t cert_addr;
    uint32_t cert_len;
    whNvmId  id;
    uint8_t  WH_PAD[2];
} whMessageCert_GetTrustedDma32Request;

int wh_MessageCert_TranslateGetTrustedDma32Request(
    uint16_t magic, const whMessageCert_GetTrustedDma32Request* src,
    whMessageCert_GetTrustedDma32Request* dest);

/* Verify DMA32 Request */
typedef struct {
    uint32_t cert_addr;
    uint32_t cert_len;
    whNvmId  trustedRootNvmId;
    uint8_t  WH_PAD[2];
} whMessageCert_VerifyDma32Request;

int wh_MessageCert_TranslateVerifyDma32Request(
    uint16_t magic, const whMessageCert_VerifyDma32Request* src,
    whMessageCert_VerifyDma32Request* dest);
#endif /* WH_DMA_IS_32BIT */

#if WH_DMA_IS_64BIT
/* AddTrusted DMA64 Request */
typedef struct {
    uint64_t cert_addr;
    uint32_t cert_len;
    whNvmId  id;
    uint8_t  WH_PAD[2];
} whMessageCert_AddTrustedDma64Request;

int wh_MessageCert_TranslateAddTrustedDma64Request(
    uint16_t magic, const whMessageCert_AddTrustedDma64Request* src,
    whMessageCert_AddTrustedDma64Request* dest);

/* GetTrusted DMA64 Request */
typedef struct {
    uint64_t cert_addr;
    uint32_t cert_len;
    whNvmId  id;
    uint8_t  WH_PAD[2];
} whMessageCert_GetTrustedDma64Request;

int wh_MessageCert_TranslateGetTrustedDma64Request(
    uint16_t magic, const whMessageCert_GetTrustedDma64Request* src,
    whMessageCert_GetTrustedDma64Request* dest);

/* Verify DMA64 Request */
typedef struct {
    uint64_t cert_addr;
    uint32_t cert_len;
    whNvmId  trustedRootNvmId;
    uint8_t  WH_PAD[2];
} whMessageCert_VerifyDma64Request;

int wh_MessageCert_TranslateVerifyDma64Request(
    uint16_t magic, const whMessageCert_VerifyDma64Request* src,
    whMessageCert_VerifyDma64Request* dest);
#endif /* WH_DMA_IS_64BIT */
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_WH_MESSAGE_CERT_H_ */