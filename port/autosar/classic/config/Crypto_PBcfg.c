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
 * Default post-build configuration used when no generator output is
 * provided (csm_smoke and other tool-free builds). Real BSW projects
 * replace this file with the generator output from DaVinci / ISOLAR /
 * tresos.
 *
 * Descriptor table symbols are weak so the smoke harness can install
 * its own strong overrides without editing this file. Both symbols are
 * const-protected — neither the table pointer nor the count is
 * runtime-writable on a real target (they live in .rodata).
 */

#include "Crypto_Cfg.h"
#include "wh_autosar_classic_internal.h"

static const Crypto_DriverObjectConfigType
    s_objects[CRYPTO_DRIVER_OBJECT_COUNT] = {{0u, 8u}};

const Crypto_ConfigType Crypto_DefaultConfig = {s_objects,
                                                CRYPTO_DRIVER_OBJECT_COUNT};

/* No descriptors by default. KeyGenerate / KeyDerive / KeyExchange*
 * therefore return E_NOT_OK until the integrator's Crypto_PBcfg.c
 * installs a real table. */
WH_AUTOSAR_WEAK const Crypto_KeyDescriptorType* const
                             Crypto_KeyDescriptorTable = NULL;
WH_AUTOSAR_WEAK const uint32 Crypto_KeyDescriptorCount = 0u;
