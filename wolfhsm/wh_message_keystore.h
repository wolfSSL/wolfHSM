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
 * wolfhsm/wh_message_keystore.h
 *
 * Message structures and translation functions for keystore operations.
 */

#ifndef WOLFHSM_WH_MESSAGE_KEYSTORE_H_
#define WOLFHSM_WH_MESSAGE_KEYSTORE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"

/* Key Cache Request */
typedef struct {
    uint32_t flags;
    uint32_t sz;
    uint32_t labelSz;
    uint16_t id;
    uint8_t  WH_PAD[2];
    uint8_t  label[WH_NVM_LABEL_LEN];
    /* Data follows:
     * uint8_t in[sz]
     */
} whMessageKeystore_CacheRequest;

/* Key Cache Response */
typedef struct {
    uint32_t rc;
    uint16_t id;
    uint8_t  WH_PAD[6];
} whMessageKeystore_CacheResponse;

/* Key Cache translation functions */
int wh_MessageKeystore_TranslateCacheRequest(
    uint16_t magic, const whMessageKeystore_CacheRequest* src,
    whMessageKeystore_CacheRequest* dest);

int wh_MessageKeystore_TranslateCacheResponse(
    uint16_t magic, const whMessageKeystore_CacheResponse* src,
    whMessageKeystore_CacheResponse* dest);

/* Key Evict Request */
typedef struct {
    uint16_t id;
    uint8_t  WH_PAD[6];
} whMessageKeystore_EvictRequest;

/* Key Evict Response */
typedef struct {
    uint32_t rc;
    uint32_t ok;
    uint8_t  WH_PAD[4];
} whMessageKeystore_EvictResponse;

/* Key Evict translation functions */
int wh_MessageKeystore_TranslateEvictRequest(
    uint16_t magic, const whMessageKeystore_EvictRequest* src,
    whMessageKeystore_EvictRequest* dest);

int wh_MessageKeystore_TranslateEvictResponse(
    uint16_t magic, const whMessageKeystore_EvictResponse* src,
    whMessageKeystore_EvictResponse* dest);

/* Key Commit Request */
typedef struct {
    uint16_t id;
    uint8_t  WH_PAD[6];
} whMessageKeystore_CommitRequest;

/* Key Commit Response */
typedef struct {
    uint32_t rc;
    uint32_t ok;
    uint8_t  WH_PAD[4];
} whMessageKeystore_CommitResponse;

/* Key Commit translation functions */
int wh_MessageKeystore_TranslateCommitRequest(
    uint16_t magic, const whMessageKeystore_CommitRequest* src,
    whMessageKeystore_CommitRequest* dest);

int wh_MessageKeystore_TranslateCommitResponse(
    uint16_t magic, const whMessageKeystore_CommitResponse* src,
    whMessageKeystore_CommitResponse* dest);

/* Key Export Request */
typedef struct {
    uint16_t id;
    uint8_t  WH_PAD[6];
} whMessageKeystore_ExportRequest;

/* Key Export Response */
typedef struct {
    uint32_t rc;
    uint32_t len;
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint8_t  WH_PAD[4];
    /* Data follows:
     * uint8_t out[len]
     */
} whMessageKeystore_ExportResponse;

/* Key Export translation functions */
int wh_MessageKeystore_TranslateExportRequest(
    uint16_t magic, const whMessageKeystore_ExportRequest* src,
    whMessageKeystore_ExportRequest* dest);

int wh_MessageKeystore_TranslateExportResponse(
    uint16_t magic, const whMessageKeystore_ExportResponse* src,
    whMessageKeystore_ExportResponse* dest);

/* Key Erase Request */
typedef struct {
    uint16_t id;
    uint8_t  WH_PAD[6];
} whMessageKeystore_EraseRequest;

/* Key Erase Response */
typedef struct {
    uint32_t rc;
    uint32_t ok;
    uint8_t  WH_PAD[4];
} whMessageKeystore_EraseResponse;

/* Key Erase translation functions */
int wh_MessageKeystore_TranslateEraseRequest(
    uint16_t magic, const whMessageKeystore_EraseRequest* src,
    whMessageKeystore_EraseRequest* dest);

int wh_MessageKeystore_TranslateEraseResponse(
    uint16_t magic, const whMessageKeystore_EraseResponse* src,
    whMessageKeystore_EraseResponse* dest);

/*
 * DMA-based keystore operations
 */

/* DMA buffer structure */
typedef struct {
    uint64_t addr;
    uint64_t sz;
} whMessageKeystore_DmaBuffer;

/* DMA address status structure */
typedef struct {
    /* If packet->rc == WH_ERROR_ACCESS, this field will contain the offending
     * address/size pair. Invalid otherwise. */
    whMessageKeystore_DmaBuffer badAddr;
} whMessageKeystore_DmaAddrStatus;

/* Key Cache DMA Request */
typedef struct {
    whMessageKeystore_DmaBuffer
             key; /* Client memory buffer containing key data */
    uint32_t flags;
    uint32_t labelSz;
    uint16_t id;
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint8_t  WH_PAD[6]; /* Pad to 8-byte alignment */
} whMessageKeystore_CacheDmaRequest;

/* Key Cache DMA Response */
typedef struct {
    whMessageKeystore_DmaAddrStatus dmaAddrStatus;
    uint32_t                        rc;
    uint16_t                        id;
    uint8_t                         WH_PAD[2]; /* Pad to 8-byte alignment */
} whMessageKeystore_CacheDmaResponse;

/* Key Cache DMA translation functions */
int wh_MessageKeystore_TranslateCacheDmaRequest(
    uint16_t magic, const whMessageKeystore_CacheDmaRequest* src,
    whMessageKeystore_CacheDmaRequest* dest);

int wh_MessageKeystore_TranslateCacheDmaResponse(
    uint16_t magic, const whMessageKeystore_CacheDmaResponse* src,
    whMessageKeystore_CacheDmaResponse* dest);

/* Key Export DMA Request */
typedef struct {
    whMessageKeystore_DmaBuffer
             key; /* Client memory buffer to receive key data */
    uint16_t id;
    uint8_t  WH_PAD[6]; /* Pad to 8-byte alignment */
} whMessageKeystore_ExportDmaRequest;

/* Key Export DMA Response */
typedef struct {
    whMessageKeystore_DmaAddrStatus dmaAddrStatus;
    uint32_t                        rc;
    uint32_t                        len;
    uint8_t                         label[WH_NVM_LABEL_LEN];
} whMessageKeystore_ExportDmaResponse;

/* Key Export DMA translation functions */
int wh_MessageKeystore_TranslateExportDmaRequest(
    uint16_t magic, const whMessageKeystore_ExportDmaRequest* src,
    whMessageKeystore_ExportDmaRequest* dest);

int wh_MessageKeystore_TranslateExportDmaResponse(
    uint16_t magic, const whMessageKeystore_ExportDmaResponse* src,
    whMessageKeystore_ExportDmaResponse* dest);

/* Wrap Key Request */
typedef struct {
    uint16_t keySz;
    uint16_t serverKeyId;
    uint16_t cipherType;
    /* Data follows:
     * whNvmMetadata metadata
     * uint8_t key[keySz]
     */
} whMessageKeystore_KeyWrapRequest;

/* Wrap Key Response */
typedef struct {
    uint32_t rc;
    uint16_t wrappedKeySz;
    uint16_t cipherType;
    /* Data follows:
     * uint8_t wrappedKey[wrappedKeySz]
     */
} whMessageKeystore_KeyWrapResponse;

/* Wrap key translation functions */
int wh_MessageKeystore_TranslateKeyWrapRequest(
    uint16_t magic, const whMessageKeystore_KeyWrapRequest* src,
    whMessageKeystore_KeyWrapRequest* dest);

int wh_MessageKeystore_TranslateKeyWrapResponse(
    uint16_t magic, const whMessageKeystore_KeyWrapResponse* src,
    whMessageKeystore_KeyWrapResponse* dest);

/* Unwrap Key export Request */
typedef struct {
    uint16_t wrappedKeySz;
    uint16_t serverKeyId;
    uint16_t cipherType;
    uint8_t  WH_PAD[2];
    /* Data follows:
     * uint8_t wrappedKey[wrappedKeySz]
     */
} whMessageKeystore_KeyUnwrapAndExportRequest;

/* Unwrap Key export Response*/
typedef struct {
    uint32_t rc;
    uint16_t keySz;
    uint16_t cipherType;
    /* Data follows:
     * whNvmMetadata metadata
     * uint8_t key[keySz]
     */
} whMessageKeystore_KeyUnwrapAndExportResponse;


/* Unwrap Key export translation functions */
int wh_MessageKeystore_TranslateKeyUnwrapAndExportRequest(
    uint16_t magic, const whMessageKeystore_KeyUnwrapAndExportRequest* src,
    whMessageKeystore_KeyUnwrapAndExportRequest* dest);

int wh_MessageKeystore_TranslateKeyUnwrapAndExportResponse(
    uint16_t magic, const whMessageKeystore_KeyUnwrapAndExportResponse* src,
    whMessageKeystore_KeyUnwrapAndExportResponse* dest);

/* Unwrap Key Cache Request */
typedef struct {
    uint16_t wrappedKeySz;
    uint16_t serverKeyId;
    uint16_t cipherType;
    uint8_t  WH_PAD[2];
    /* Data follows:
     * uint8_t wrappedKey[wrappedKeySz]
     */
} whMessageKeystore_KeyUnwrapAndCacheRequest;

/* Unwrap Key Cache Response*/
typedef struct {
    uint32_t rc;
    uint16_t keyId;
    uint16_t cipherType;
} whMessageKeystore_KeyUnwrapAndCacheResponse;

/* Unwrap Key Cache translation functions */
int wh_MessageKeystore_TranslateKeyUnwrapAndCacheRequest(
    uint16_t magic, const whMessageKeystore_KeyUnwrapAndCacheRequest* src,
    whMessageKeystore_KeyUnwrapAndCacheRequest* dest);

int wh_MessageKeystore_TranslateKeyUnwrapAndCacheResponse(
    uint16_t magic, const whMessageKeystore_KeyUnwrapAndCacheResponse* src,
    whMessageKeystore_KeyUnwrapAndCacheResponse* dest);

/* Wrap Data Request */
typedef struct {
    uint32_t dataSz;
    uint16_t serverKeyId;
    uint16_t cipherType;
    /* Data follows:
     * uint8_t data[dataSz]
     */
} whMessageKeystore_DataWrapRequest;

/* Wrap Data Response */
typedef struct {
    uint32_t rc;
    uint32_t wrappedDataSz;
    uint16_t cipherType;
    uint8_t  WH_PAD[2];
    /* Data follows:
     * uint8_t wrappedData[wrappedDataSz]
     */
} whMessageKeystore_DataWrapResponse;

/* Wrap key translation functions */
int wh_MessageKeystore_TranslateDataWrapRequest(
    uint16_t magic, const whMessageKeystore_DataWrapRequest* src,
    whMessageKeystore_DataWrapRequest* dest);

int wh_MessageKeystore_TranslateDataWrapResponse(
    uint16_t magic, const whMessageKeystore_DataWrapResponse* src,
    whMessageKeystore_DataWrapResponse* dest);

/* Unwrap Data export Request */
typedef struct {
    uint32_t wrappedDataSz;
    uint16_t serverKeyId;
    uint16_t cipherType;
    /* Data follows:
     * uint8_t wrappedData[wrappedDataSz]
     */
} whMessageKeystore_DataUnwrapRequest;

/* Unwrap Data Response*/
typedef struct {
    uint32_t rc;
    uint32_t dataSz;
    uint16_t cipherType;
    uint8_t  WH_PAD[2];
    /* Data follows:
     * uint8_t data[dataSz]
     */
} whMessageKeystore_DataUnwrapResponse;


/* Unwrap Data export translation functions */
int wh_MessageKeystore_TranslateDataUnwrapRequest(
    uint16_t magic, const whMessageKeystore_DataUnwrapRequest* src,
    whMessageKeystore_DataUnwrapRequest* dest);

int wh_MessageKeystore_TranslateDataUnwrapResponse(
    uint16_t magic, const whMessageKeystore_DataUnwrapResponse* src,
    whMessageKeystore_DataUnwrapResponse* dest);

#endif /* !WOLFHSM_WH_MESSAGE_KEYSTORE_H_ */
