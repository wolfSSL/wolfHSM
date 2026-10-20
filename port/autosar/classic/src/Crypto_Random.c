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
 * port/autosar/classic/src/Crypto_Random.c
 *
 * Crypto_RandomSeed — wolfHSM exposes no client-side reseed today, so the
 * call is rejected (E_NOT_OK). Random generation goes through
 * Crypto_ProcessJob with service=CRYPTO_RANDOMGENERATE.
 */

#include "Crypto.h"

Std_ReturnType Crypto_RandomSeed(uint32 cryptoKeyId, const uint8* seedPtr,
                                 uint32 seedLength)
{
    (void)cryptoKeyId;
    (void)seedPtr;
    (void)seedLength;
    return E_NOT_OK;
}
