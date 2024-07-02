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
 * wolfhsm/wh_utils.h
 *
 */

#ifndef WOLFHSM_WH_UTILS_H_
#define WOLFHSM_WH_UTILS_H_

#include <stdint.h>

/** Byteswap functions */
uint16_t wh_Utils_Swap16(uint16_t val);
uint32_t wh_Utils_Swap32(uint32_t val);
uint64_t wh_Utils_Swap64(uint64_t val);

uint32_t wh_Utils_htonl(uint32_t hostlong);
uint32_t wh_Utils_ntohl(uint32_t networklong);

int wh_Utils_memeqzero(uint8_t* buffer, uint32_t size);

#endif /* WOLFHSM_WH_UTILS_H_ */
