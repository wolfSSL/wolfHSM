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
 * src/wh_utils.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h> /* For size_t */
#include <string.h> /* For memset/cpy */

#if defined(WOLFHSM_CFG_HEXDUMP)
#include <stdio.h>
#endif

#include "wolfhsm/wh_utils.h"

/** Byteswap functions */
uint16_t wh_Utils_Swap16(uint16_t val)
{
    return (val >> 8) | (val << 8);
}

uint32_t wh_Utils_Swap32(uint32_t val)
{
    return  ((val & 0xFF000000ul) >> 24) |
            ((val & 0x00FF0000ul) >> 8) |
            ((val & 0x0000FF00ul) << 8) |
            ((val & 0x000000FFul) << 24);
}

uint64_t wh_Utils_Swap64(uint64_t val)
{
    return  ((val & 0xFF00000000000000ull) >> 56) |
            ((val & 0xFF000000000000ull) >> 40) |
            ((val & 0xFF0000000000ull) >> 24) |
            ((val & 0xFF00000000ull) >> 8)|
            ((val & 0xFF000000ull) << 8) |
            ((val & 0xFF0000ull) << 24 ) |
            ((val & 0xFF00ull) << 40) |
            ((val & 0xFFull) << 56);
}

static int isLittleEndian(void) {
    unsigned int x = 1; /* 0x00000001 */
    char *c = (char*)&x;
    return (int)*c;
}

/* Converts a 32-bit value from host to network byte order */
uint32_t wh_Utils_htonl(uint32_t hostlong) {
    if (isLittleEndian()) {
        return wh_Utils_Swap32(hostlong);
    }
    return hostlong; /* No conversion needed if not little endian */
}

uint32_t wh_Utils_ntohl(uint32_t networklong) {
    /* same operation */
    return wh_Utils_htonl(networklong);
}



int wh_Utils_memeqzero(uint8_t* buffer, uint32_t size)
{
    while (size > 1) {
        size--;
        if (buffer[size] != 0)
            return 0;
    }
    return 1;
}

/* Secure zeroization that resists compiler optimization.
 * Uses volatile to prevent the compiler from optimizing away the writes. */
void wh_Utils_ForceZero(void* mem, uint32_t size)
{
    volatile uint8_t* p = (volatile uint8_t*)mem;
    while (size > 0) {
        *p = 0;
        p++;
        size--;
    }
}

/** Constant time compare of two buffers to mitigate side channel leaks
 * returns 0 on success where buffer a is equal to buffer b for length bytes */
int wh_Utils_ConstantCompare(const uint8_t* a, const uint8_t* b, size_t length)
{
    size_t i;
    size_t ret = 0;

    for (i = 0; i < length; i++) {
        ret |= a[i] ^ b[i];
    }

    return (int)ret;
}

/** Cache helper functions */
const void* wh_Utils_CacheInvalidate(const void* p, size_t n)
{
    int len = (int)n;
    const uint8_t* ptr = (const uint8_t*)p;
    do {
        XCACHEINVLD(ptr);
        ptr += XCACHELINE;
        len -= XCACHELINE;
    } while (len > 0);
    return p;
}

void* wh_Utils_CacheFlush(void* p, size_t n)
{
    int len = (int)n;
    uint8_t* ptr = (uint8_t*)p;
    do {
        XCACHEFLUSH(ptr);
        ptr += XCACHELINE;
        len -= XCACHELINE;
    } while (len > 0);
    return p;
}

void* wh_Utils_memset_flush(void* p, int c, size_t n)
{
    memset(p, c, n);
    XMEMFENCE();
    return XCACHEFLUSHBLK(p, n);
}

void* wh_Utils_memcpy_invalidate(void* dst, const void* src, size_t n)
{
    return memcpy(dst, XCACHEINVLDBLK(src, n), n);
}

void* wh_Utils_memcpy_flush(void* dst, const void* src , size_t n)
{
    memcpy(dst,src,n);
    XMEMFENCE();
    return XCACHEFLUSHBLK(dst, n);
}


#if defined(WOLFHSM_CFG_HEXDUMP)
void wh_Utils_Hexdump(const char* initial, const uint8_t* ptr, size_t size)
{
#define HEXDUMP_BYTES_PER_LINE 16
    int count = 0;
    if(initial != NULL)
        WOLFHSM_CFG_PRINTF("%s",initial);
    while(size > 0) {
        WOLFHSM_CFG_PRINTF("%02X ", *ptr);
        ptr++;
        size --;
        count++;
        if (count % HEXDUMP_BYTES_PER_LINE == 0) {
            WOLFHSM_CFG_PRINTF("\n");
        }
    }
    if((count % HEXDUMP_BYTES_PER_LINE) != 0) {
        WOLFHSM_CFG_PRINTF("\n");
    }
}
#endif

