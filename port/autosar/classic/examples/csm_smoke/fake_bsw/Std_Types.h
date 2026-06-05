/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * port/autosar/classic/examples/csm_smoke/fake_bsw/Std_Types.h
 *
 * Minimal AUTOSAR Std_Types.h sufficient to build the Crypto Driver
 * standalone in the csm_smoke harness. A real BSW project replaces this
 * with the vendor-supplied header. NOT part of the public port API.
 */

#ifndef STD_TYPES_H_
#define STD_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t  uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef int8_t   sint8;
typedef int16_t  sint16;
typedef int32_t  sint32;
typedef int64_t  sint64;
typedef uint8_t  boolean;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define STD_ON 1
#define STD_OFF 0

typedef uint8 Std_ReturnType;
#define E_OK ((Std_ReturnType)0x00u)
#define E_NOT_OK ((Std_ReturnType)0x01u)

typedef struct {
    uint16 vendorID;
    uint16 moduleID;
    uint8  sw_major_version;
    uint8  sw_minor_version;
    uint8  sw_patch_version;
} Std_VersionInfoType;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* STD_TYPES_H_ */
