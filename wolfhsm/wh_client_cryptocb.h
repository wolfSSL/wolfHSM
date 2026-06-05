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
 *
 */
/*
 * wolfhsm/wh_client_cryptocb.h
 *
 */

#ifndef WOLFHSM_CLIENT_CRYPTOCB_H_
#define WOLFHSM_CLIENT_CRYPTOCB_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

#include "wolfhsm/wh_client.h"

/* Unified cryptoCb, registered for WH_DEV_ID and the client's configured
 * devId. Dispatches to the DMA path when the client's DMA mode is set (see
 * wh_Client_SetDmaMode), falling back to the standard path for algorithms
 * without a DMA variant; otherwise uses the standard path directly. */
int wh_Client_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx);

/* Standard (non-DMA) cryptoCb */
int wh_Client_CryptoCbStd(int devId, wc_CryptoInfo* info, void* ctx);

#ifdef WOLFHSM_CFG_DMA
/* DMA-only cryptoCb, registered for WH_DEV_ID_DMA. No standard-path fallback:
 * algorithms without a DMA variant return CRYPTOCB_UNAVAILABLE.
 */
int wh_Client_CryptoCbDma(int devId, wc_CryptoInfo* info, void* inCtx);
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* !WOLFHSM_CLIENT_CRYPTOCB_H_ */
