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

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

int wolfHSM_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx);

#endif /* !WOLFHSM_CLIENT_CRYPTOCB_H_ */
