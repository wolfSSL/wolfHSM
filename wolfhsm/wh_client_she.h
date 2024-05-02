/* wh_client_she.h
 *
 * Copyright (C) 2006-2023 wolfHSM Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFHSM_WH_CLIENT_SHE_H_
#define WOLFHSM_WH_CLIENT_SHE_H_
/* System libraries */
#include <stdint.h>

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"

/* Component includes */
#include "wolfhsm/wh_comm.h"

int wh_Client_SheSetUidRequest(whClientContext* c, uint8_t* uid,
    uint32_t uidSz);
int wh_Client_SheSetUidResponse(whClientContext* c);
int wh_Client_SheSetUid(whClientContext* c, uint8_t* uid, uint32_t uidSz);
int wh_Client_SheSecureBoot(whClientContext* c, uint8_t* bootloader,
    uint32_t bootloaderLen);
int wh_Client_SheGetStatusRequest(whClientContext* c);
int wh_Client_SheGetStatusResponse(whClientContext* c, uint8_t* sreg);
int wh_Client_SheGetStatus(whClientContext* c, uint8_t* sreg);
int wh_Client_SheLoadKeyRequest(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree);
int wh_Client_SheLoadKeyResponse(whClientContext* c, uint8_t* messageFour,
    uint8_t* messageFive);
int wh_Client_SheLoadKey(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree, uint8_t* messageFour,
    uint8_t* messageFive);
int wh_Client_SheExportRamKeyRequest(whClientContext* c);
int wh_Client_SheExportRamKeyResponse(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree, uint8_t* messageFour,
    uint8_t* messageFive);
int wh_Client_SheExportRamKey(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree, uint8_t* messageFour,
    uint8_t* messageFive);
int wh_Client_SheInitRndRequest(whClientContext* c);
int wh_Client_SheInitRndResponse(whClientContext* c);
int wh_Client_SheInitRnd(whClientContext* c);
int wh_Client_SheRndRequest(whClientContext* c);
int wh_Client_SheRndResponse(whClientContext* c, uint8_t* out, uint32_t* outSz);
int wh_Client_SheRnd(whClientContext* c, uint8_t* out, uint32_t* outSz);
int wh_Client_SheExtendSeedRequest(whClientContext* c, uint8_t* entropy,
    uint32_t entropySz);
int wh_Client_SheExtendSeedResponse(whClientContext* c);
int wh_Client_SheExtendSeed(whClientContext* c, uint8_t* entropy,
    uint32_t entropySz);
#endif
