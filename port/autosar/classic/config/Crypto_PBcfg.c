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
 * port/autosar/classic/config/Crypto_PBcfg.c
 *
 * Default post-build configuration for builds without generator output.
 */

#include "Crypto_Cfg.h"
#include "wh_autosar_classic_internal.h"

static const Crypto_DriverObjectConfigType
    s_objects[CRYPTO_DRIVER_OBJECT_COUNT] = {{0u, 8u}};

const Crypto_ConfigType Crypto_DefaultConfig = {s_objects,
                                                CRYPTO_DRIVER_OBJECT_COUNT};

/* Empty and weak so a generated or test configuration can override it. */
WH_AUTOSAR_WEAK const Crypto_KeyDescriptorType* const
                             Crypto_KeyDescriptorTable = NULL;
WH_AUTOSAR_WEAK const uint32 Crypto_KeyDescriptorCount = 0u;
