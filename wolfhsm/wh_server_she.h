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

struct whServerContext_t;

/* Reads WH_SHE_UID_SZ bytes into outUid. Returns 0, WH_ERROR_NOTFOUND if no UID
 * is provisioned, or another wolfHSM error. Called on every gated SHE request,
 * so it must be cheap and idempotent. */
typedef int (*whServerSheGetUidCb)(struct whServerContext_t* server, void* ctx,
                                   uint8_t* outUid);

/* Persists the WH_SHE_UID_SZ byte UID provisioned by WH_SHE_SET_UID. */
typedef int (*whServerSheSetUidCb)(struct whServerContext_t* server, void* ctx,
                                   const uint8_t* uid);

typedef struct {
    whServerSheGetUidCb getUidCb; /* NULL = use in-context uid[]/uidSet */
    whServerSheSetUidCb setUidCb; /* NULL = UID is read-only */
    void*               uidCtx;   /* opaque, passed back to both callbacks */
} whServerSheConfig;

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

    /* When getUidCb is set, the uid[] and uidSet fields above are unused. */
    whServerSheGetUidCb getUidCb;
    whServerSheSetUidCb setUidCb;
    void*               uidCtx;
} whServerSheContext;

int wh_Server_HandleSheRequest(whServerContext* server, uint16_t magic,
                               uint16_t action, uint16_t req_size,
                               const void* req_packet, uint16_t* out_resp_size,
                               void* resp_packet);

/**
 * @brief Register SHE UID storage callbacks at runtime.
 *
 * Replaces callbacks previously set via whServerConfig.sheConfig or by a prior
 * call to this function.
 *
 * @param server Server context.
 * @param getCb  UID read callback, or NULL to use in-context uid[]/uidSet.
 * @param setCb  UID write callback, or NULL for a read-only UID, which makes
 *               WH_SHE_SET_UID return WH_SHE_ERC_WRITE_PROTECTED.
 * @param ctx    Opaque context passed to both callbacks.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if server or server->she is
 *         NULL.
 */
int wh_Server_SheSetUidCb(whServerContext* server, whServerSheGetUidCb getCb,
                          whServerSheSetUidCb setCb, void* ctx);
#endif /* WOLFHSM_CFG_SHE_EXTENSION */

#endif /* !WOLFHSM_WH_SERVER_SHE_H */
