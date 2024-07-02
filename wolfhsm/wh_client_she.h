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
 * wolfhsm/wh_client_she.h
 *
 */

#ifndef WOLFHSM_WH_CLIENT_SHE_H_
#define WOLFHSM_WH_CLIENT_SHE_H_
/* System libraries */
#include <stdint.h>

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"

/* Component includes */
#include "wolfhsm/wh_client.h"

int wh_Client_ShePreProgramKey(whClientContext* c, whNvmId keyId,
    whNvmFlags flags, uint8_t* key, whNvmSize keySz);
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
int wh_Client_SheLoadPlainKeyRequest(whClientContext* c, uint8_t* key,
    uint32_t keySz);
int wh_Client_SheLoadPlainKeyResponse(whClientContext* c);
int wh_Client_SheLoadPlainKey(whClientContext* c, uint8_t* key, uint32_t keySz);
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
int wh_Client_SheEncEcbRequest(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint32_t sz);
int wh_Client_SheEncEcbResponse(whClientContext* c, uint8_t* out, uint32_t sz);
int wh_Client_SheEncEcb(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint8_t* out, uint32_t sz);
int wh_Client_SheEncCbcRequest(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint32_t sz);
int wh_Client_SheEncCbcResponse(whClientContext* c, uint8_t* out, uint32_t sz);
int wh_Client_SheEncCbc(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint8_t* out, uint32_t sz);
int wh_Client_SheDecEcbRequest(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint32_t sz);
int wh_Client_SheDecEcbResponse(whClientContext* c, uint8_t* out, uint32_t sz);
int wh_Client_SheDecEcb(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint8_t* out, uint32_t sz);
int wh_Client_SheDecCbcRequest(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint32_t sz);
int wh_Client_SheDecCbcResponse(whClientContext* c, uint8_t* out, uint32_t sz);
int wh_Client_SheDecCbc(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint8_t* out, uint32_t sz);
int wh_Client_SheGenerateMacRequest(whClientContext* c, uint8_t keyId,
    uint8_t* in, uint32_t sz);
int wh_Client_SheGenerateMacResponse(whClientContext* c, uint8_t* out,
    uint32_t sz);
int wh_Client_SheGenerateMac(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint32_t inSz, uint8_t* out, uint32_t outSz);
int wh_Client_SheVerifyMacRequest(whClientContext* c, uint8_t keyId,
    uint8_t* message, uint32_t messageLen, uint8_t* mac, uint32_t macLen);
int wh_Client_SheVerifyMacResponse(whClientContext* c, uint8_t* outStatus);
int wh_Client_SheVerifyMac(whClientContext* c, uint8_t keyId, uint8_t* message,
    uint32_t messageLen, uint8_t* mac, uint32_t macLen, uint8_t* outStatus);
#endif
