/*
 * Copyright (C) 2025 wolfSSL Inc.
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
 * wolfhsm/wh_message_counter.c
 *
 * Message translation functions for counter operations.
 */

#include "wolfhsm/wh_message_counter.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include <string.h>

/* Counter Init Request translation */
int wh_MessageCounter_TranslateInitRequest(
    uint16_t magic, const whMessageCounter_InitRequest* src,
    whMessageCounter_InitRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, counter);
    WH_T16(magic, dest, src, counterId);
    return 0;
}

/* Counter Init Response translation */
int wh_MessageCounter_TranslateInitResponse(
    uint16_t magic, const whMessageCounter_InitResponse* src,
    whMessageCounter_InitResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, counter);
    return 0;
}

/* Counter Increment Request translation */
int wh_MessageCounter_TranslateIncrementRequest(
    uint16_t magic, const whMessageCounter_IncrementRequest* src,
    whMessageCounter_IncrementRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, counterId);
    return 0;
}

/* Counter Increment Response translation */
int wh_MessageCounter_TranslateIncrementResponse(
    uint16_t magic, const whMessageCounter_IncrementResponse* src,
    whMessageCounter_IncrementResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, counter);
    return 0;
}

/* Counter Read Request translation */
int wh_MessageCounter_TranslateReadRequest(
    uint16_t magic, const whMessageCounter_ReadRequest* src,
    whMessageCounter_ReadRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, counterId);
    return 0;
}

/* Counter Read Response translation */
int wh_MessageCounter_TranslateReadResponse(
    uint16_t magic, const whMessageCounter_ReadResponse* src,
    whMessageCounter_ReadResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, counter);
    return 0;
}

/* Counter Destroy Request translation */
int wh_MessageCounter_TranslateDestroyRequest(
    uint16_t magic, const whMessageCounter_DestroyRequest* src,
    whMessageCounter_DestroyRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, counterId);
    return 0;
}

/* Counter Destroy Response translation */
int wh_MessageCounter_TranslateDestroyResponse(
    uint16_t magic, const whMessageCounter_DestroyResponse* src,
    whMessageCounter_DestroyResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}