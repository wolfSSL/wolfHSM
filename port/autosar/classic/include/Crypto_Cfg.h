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
 * port/autosar/classic/include/Crypto_Cfg.h
 *
 * Compile-time configuration for the wolfHSM Crypto Driver. In a full
 * AUTOSAR Classic project this would be a generator output produced by
 * DaVinci / ISOLAR / tresos from the project's ARXML. For tool-free
 * builds (csm_smoke), the template under config/ produces the same
 * symbol set with defaults.
 */

#ifndef CRYPTO_CFG_H_
#define CRYPTO_CFG_H_

#include "Std_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Number of Crypto Driver Objects. Each maps to one wolfHSM client
 * context. Override via -DCRYPTO_DRIVER_OBJECT_COUNT=N. */
#ifndef CRYPTO_DRIVER_OBJECT_COUNT
#define CRYPTO_DRIVER_OBJECT_COUNT 1u
#endif

/* Maximum outstanding async jobs per driver object. */
#ifndef CRYPTO_MAX_ASYNC_JOBS
#define CRYPTO_MAX_ASYNC_JOBS 4u
#endif

/* Enable / disable DET reporting at compile time. */
#ifndef CRYPTO_DEV_ERROR_DETECT
#define CRYPTO_DEV_ERROR_DETECT STD_ON
#endif

/* Per-driver-object configuration. The implementation provides a default
 * configuration suitable for the csm_smoke harness; replace with a
 * generator-produced Crypto_PBcfg.c in a real BSW project. */
typedef struct {
    uint32 objectId;
    uint32 maxQueueSize;
} Crypto_DriverObjectConfigType;

typedef struct {
    const Crypto_DriverObjectConfigType* objects;
    uint32                               objectCount;
} Crypto_ConfigType;

extern const Crypto_ConfigType Crypto_DefaultConfig;

/* The key-descriptor table is also part of the post-build configuration.
 * Its type and lookup helper live in wh_autosar_classic_internal.h to
 * avoid pulling wolfHSM headers into Crypto_Cfg.h. The Crypto_PBcfg.c
 * file shipped with the port supplies a (possibly empty) default table;
 * integrators replace it with their generator output. */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CRYPTO_CFG_H_ */
