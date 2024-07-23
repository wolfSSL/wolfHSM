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
 * wolfhsm/wh_server_she.h
 *
 */

#ifndef WOLFHSM_WH_SERVER_SHE_H
#define WOLFHSM_WH_SERVER_SHE_H

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_server.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#if defined(WOLFHSM_CFG_SHE_EXTENSION)

typedef struct {
    uint8_t  sbState;
    uint8_t  cmacKeyFound;
    uint8_t  ramKeyPlain;
    uint8_t  uidSet;
    uint32_t blSize;
    uint32_t blSizeReceived;
    uint32_t rndInited;

#ifndef WOLFHSM_CFG_NO_CRYPTO
#ifndef NO_AES
    Aes sheAes[1];
#endif /* !NO_AES*/
#ifdef WOLFSSL_CMAC
    Cmac sheCmac[1];
#endif /* WOLFSSL_CMAC */
#endif /* !WOLFHSM_CFG_NO_CRYPTO*/

    uint8_t  prngState[WH_SHE_KEY_SZ];
    uint8_t  prngKey[WH_SHE_KEY_SZ];
    uint8_t  uid[WH_SHE_UID_SZ];
} whServerSheContext;

int wh_Server_HandleSheRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size);

#endif /* WOLFHSM_CFG_SHE_EXTENSION */

#endif /* !WOLFHSM_WH_SERVER_SHE_H */
