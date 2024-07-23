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
 * wolfhsm/wh_she_crypto.h
 *
 */

#ifndef WOLFHSM_WH_SHE_CRYPTO_H_
#define WOLFHSM_WH_SHE_CRYPTO_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#ifndef WOLFHSM_CFG_NO_CRYPTO

#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"

int wh_She_AesMp16_ex(Aes* aes, void* heap, int devid,
        uint8_t* in, word32 inSz, uint8_t* out);

int wh_She_GenerateLoadableKey(uint8_t keyId,
    uint8_t authKeyId, uint32_t count, uint32_t flags, uint8_t* uid,
    uint8_t* key, uint8_t* authKey, uint8_t* messageOne, uint8_t* messageTwo,
    uint8_t* messageThree, uint8_t* messageFour, uint8_t* messageFive);

#endif /* !WOLFHSM_CFG_NO_CRYPTO*/
#endif /* WOLFHSM_CFG_SHE_EXTENSION */

#endif /* !WOLFHSM_WH_SHE_CRYPTO_H_ */
