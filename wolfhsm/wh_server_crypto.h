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
 * wolfhsm/wh_server_crypto.h
 *
 */

#ifndef WOLFHSM_WH_SERVER_CRYPTO_H_
#define WOLFHSM_WH_SERVER_CRYPTO_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include "wolfhsm/wh_server.h"

int wh_Server_HandleCryptoRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size, uint16_t seq);

int wh_Server_HandleCryptoDmaRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size, uint16_t seq);

#ifdef HAVE_ECC
int wh_Server_EccKeyCacheImport(whServerContext* ctx, ecc_key* key,
        whKeyId keyId, whNvmFlags flags, uint16_t label_len, uint8_t* label);

int wh_Server_EccKeyCacheExport(whServerContext* ctx, whKeyId keyId,
        ecc_key* key);
#endif

#ifdef HAVE_CURVE25519

/* Store a curve25519_key into a server key cache with optional metadata */
int wh_Server_CacheImportCurve25519Key(whServerContext* ctx,
        curve25519_key* key,
        whKeyId keyId, whNvmFlags flags, uint16_t label_len, uint8_t* label);
/* Restore a curve25519_key from a server key cache */
int wh_Server_CacheExportCurve25519Key(whServerContext* ctx, whKeyId keyId,
        curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* !WOLFHSM_WH_SERVER_CRYPTO_H_ */
