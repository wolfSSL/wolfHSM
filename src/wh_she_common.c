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
 * src/wh_she_common.c
 *
 */
/* System libraries */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION

#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#include "wolfhsm/wh_she_common.h"

typedef struct {
    uint32_t count;
    uint32_t flags;
} whSheMetadata;

int wh_She_Label2Meta(const uint8_t* label, uint32_t *out_count,
        uint32_t *out_flags)
{
    whSheMetadata* meta = (whSheMetadata*)label;

    if (label == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (out_count != NULL) {
        *out_count = wh_Utils_ntohl(meta->count);
    }
    if (out_flags != NULL) {
        *out_flags = wh_Utils_ntohl(meta->flags);
    }
    return 0;
}

int wh_She_Meta2Label(uint32_t count, uint32_t flags, uint8_t* label)
{
    whSheMetadata* meta = (whSheMetadata*)label;
    if (label == NULL) {
        return WH_ERROR_BADARGS;
    }

    meta->count = wh_Utils_htonl(count);
    meta->flags = wh_Utils_htonl(flags);

    return 0;
}

#endif /* WOLFHSM_CFG_SHE_EXTENSION */

