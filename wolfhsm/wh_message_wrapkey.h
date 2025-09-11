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

#ifndef WOLFHSM_WH_MESSAGE_WRAPKEY_H_
#define WOLFHSM_WH_MESSAGE_WRAPKEY_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"

/* Wrap Key Request */
typedef struct {
    uint16_t keySz;
    uint16_t serverKeyId;
    uint16_t cipherType;
    /* Data follows:
     * whNvmMetadata metadata
     * uint8_t key[keySz]
     */
} whMessageWrapKey_WrapRequest;

/* Wrap Key Response */
typedef struct {
    uint32_t rc;
    uint16_t wrappedKeySz;
    uint16_t cipherType;
    /* Data follows:
     * uint8_t wrappedKey[wrappedKeySz]
     */
} whMessageWrapKey_WrapResponse;

/* Key Cache translation functions */
int wh_MessageWrapKey_TranslateWrapRequest(
    uint16_t magic, const whMessageWrapKey_WrapRequest* src,
    whMessageWrapKey_WrapRequest* dest);

int wh_MessageWrapKey_TranslateWrapResponse(
    uint16_t magic, const whMessageWrapKey_WrapResponse* src,
    whMessageWrapKey_WrapResponse* dest);

/* Unwrap Key Request */
typedef struct {
    uint16_t wrappedKeySz;
    uint16_t serverKeyId;
    uint16_t cipherType;
    uint8_t  WH_PAD[2];
    /* Data follows:
     * uint8_t wrappedKey[wrappedKeySz]
     */
} whMessageWrapKey_UnwrapRequest;

/* Unwrap Key Response*/
typedef struct {
    uint32_t rc;
    uint16_t keySz;
    uint16_t cipherType;
    /* Data follows:
     * whNvmMetadata metadata
     * uint8_t key[keySz]
     */
} whMessageWrapKey_UnwrapResponse;


/* Unwrap Key translation functions */
int wh_MessageWrapKey_TranslateUnwrapRequest(
    uint16_t magic, const whMessageWrapKey_UnwrapRequest* src,
    whMessageWrapKey_UnwrapRequest* dest);

int wh_MessageWrapKey_TranslateUnwrapResponse(
    uint16_t magic, const whMessageWrapKey_UnwrapResponse* src,
    whMessageWrapKey_UnwrapResponse* dest);

/* Wrap Key Cache Request */
typedef struct {
    uint16_t wrappedKeySz;
    uint16_t serverKeyId;
    uint16_t cipherType;
    uint8_t  WH_PAD[2];
    /* Data follows:
     * uint8_t wrappedKey[wrappedKeySz]
     */
} whMessageWrapKey_CacheRequest;

/* Wrap Key Cache Response*/
typedef struct {
    uint32_t rc;
    uint16_t keyId;
    uint16_t cipherType;
} whMessageWrapKey_CacheResponse;

/* Wrap Key Cache translation functions */
int wh_MessageWrapKey_TranslateCacheRequest(
    uint16_t magic, const whMessageWrapKey_CacheRequest* src,
    whMessageWrapKey_CacheRequest* dest);

int wh_MessageWrapKey_TranslateCacheResponse(
    uint16_t magic, const whMessageWrapKey_CacheResponse* src,
    whMessageWrapKey_CacheResponse* dest);

#endif /* !WOLFHSM_WH_MESSAGE_WRAPKEY_H_ */
