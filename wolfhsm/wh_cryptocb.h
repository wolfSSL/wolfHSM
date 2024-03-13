/* cryptocb.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
#ifndef WOLFHSM_CRYPTOCB_H
#define WOLFHSM_CRYPTOCB_H
#include <wolfhsm/common.h>

#ifdef __cplusplus
    extern "C" {
#endif

int wolfHSM_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* !WOLFHSM_CRYPTOCB_H */
