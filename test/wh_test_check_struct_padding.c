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
#ifndef WH_TEST_CHECK_STRUCT_PADDING_C_
#define WH_TEST_CHECK_STRUCT_PADDING_C_

#include "wolfhsm/wh_settings.h"

/* For each included file, define an instance of every struct for which we want
 * to check padding. Then, when this file is compiled with -Wpadded it will
 * generate an error if padding is wrong */


#include "wolfhsm/wh_message_comm.h"
whMessageComm_ErrorResponse whMessageComm_ErrorResponse_test;
whMessageCommInitRequest    whMessageCommInitRequest_test;
whMessageCommInitResponse   whMessageCommInitResponse_test;
whMessageCommInfoResponse   whMessageCommInfoResponse_test;

#include "wolfhsm/wh_message_customcb.h"
whMessageCustomCb_Request  whMessageCustomCb_Request_test;
whMessageCustomCb_Response whMessageCustomCb_Response_test;

#include "wolfhsm/wh_message_nvm.h"
whMessageNvm_SimpleResponse        whMessageNvm_SimpleResponse_test;
whMessageNvm_InitRequest           whMessageNvm_InitRequest_test;
whMessageNvm_InitResponse          whMessageNvm_InitResponse_test;
whMessageNvm_GetAvailableResponse  whMessageNvm_GetAvailableResponse_test;
whMessageNvm_AddObjectRequest      whMessageNvm_AddObjectRequest_test;
whMessageNvm_ListRequest           whMessageNvm_ListRequest_test;
whMessageNvm_ListResponse          whMessageNvm_ListResponse_test;
whMessageNvm_GetMetadataRequest    whMessageNvm_GetMetadataRequest_test;
whMessageNvm_GetMetadataResponse   whMessageNvm_GetMetadataResponse_test;
whMessageNvm_DestroyObjectsRequest whMessageNvm_DestroyObjectsRequest_test;
whMessageNvm_ReadRequest           whMessageNvm_ReadRequest_test;
whMessageNvm_ReadResponse          whMessageNvm_ReadResponse_test;

#if defined(WOLFHSM_CFG_DMA)
whMessageNvm_AddObjectDmaRequest whMessageNvm_AddObjectDmaRequest_test;
whMessageNvm_ReadDmaRequest      whMessageNvm_ReadDmaRequest_test;
#endif

/* Include keystore message header for new keystore message structures */
#include "wolfhsm/wh_message_keystore.h"
whMessageKeystore_CacheRequest     keyCacheReq;
whMessageKeystore_EvictRequest     keyEvictReq;
whMessageKeystore_CommitRequest    keyCommitReq;
whMessageKeystore_ExportRequest    keyExportReq;
whMessageKeystore_EraseRequest     keyEraseReq;
whMessageKeystore_CacheResponse    keyCacheRes;
whMessageKeystore_EvictResponse    keyEvictRes;
whMessageKeystore_CommitResponse   keyCommitRes;
whMessageKeystore_ExportResponse   keyExportRes;
whMessageKeystore_EraseResponse    keyEraseRes;

/* Include counter message header for new counter message structures */
#include "wolfhsm/wh_message_counter.h"
whMessageCounter_InitRequest       counterInitReq;
whMessageCounter_IncrementRequest  counterIncrementReq;
whMessageCounter_ReadRequest       counterReadReq;
whMessageCounter_DestroyRequest    counterDestroyReq;
whMessageCounter_InitResponse      counterInitRes;
whMessageCounter_IncrementResponse counterIncrementRes;
whMessageCounter_ReadResponse      counterReadRes;
whMessageCounter_DestroyResponse   counterDestroyRes;

/* DMA keystore messages */
whMessageKeystore_CacheDmaRequest   keyCacheDmaReq;
whMessageKeystore_CacheDmaResponse  keyCacheDmaRes;
whMessageKeystore_ExportDmaRequest  keyExportDmaReq;
whMessageKeystore_ExportDmaResponse keyExportDmaRes;

#ifndef WOLFHSM_CFG_NO_CRYPTO
/* Include crypto message header for new crypto message structures */
#include "wolfhsm/wh_message_crypto.h"
whMessageCrypto_GenericRequestHeader  cryptoGenericReqHeader;
whMessageCrypto_GenericResponseHeader cryptoGenericResHeader;
whMessageCrypto_AesCbcRequest        cipherAesCbcReq;
whMessageCrypto_AesGcmRequest        cipherAesGcmReq;
whMessageCrypto_RsaKeyGenRequest     pkRsakgReq;
whMessageCrypto_RsaRequest           pkRsaReq;
whMessageCrypto_RsaGetSizeRequest    pkRsaGetSizeReq;
whMessageCrypto_EccKeyGenRequest     pkEckgReq;
whMessageCrypto_EcdhRequest          pkEcdhReq;
whMessageCrypto_EccSignRequest       pkEccSignReq;
whMessageCrypto_EccVerifyRequest     pkEccVerifyReq;
whMessageCrypto_EccCheckRequest      pkEccCheckReq;
whMessageCrypto_RngRequest           rngReq;
whMessageCrypto_CmacRequest          cmacReq;
whMessageCrypto_AesCbcResponse       cipherAesCbcRes;
whMessageCrypto_AesGcmResponse       cipherAesGcmRes;
whMessageCrypto_RsaKeyGenResponse    pkRsakgRes;
whMessageCrypto_RsaResponse          pkRsaRes;
whMessageCrypto_RsaGetSizeResponse   pkRsaGetSizeRes;
whMessageCrypto_EccKeyGenResponse    pkEckgRes;
whMessageCrypto_EcdhResponse         pkEcdhRes;
whMessageCrypto_EccSignResponse      pkEccSignRes;
whMessageCrypto_EccVerifyResponse    pkEccVerifyRes;
whMessageCrypto_EccCheckResponse     pkEccCheckRes;
whMessageCrypto_RngResponse          rngRes;
whMessageCrypto_CmacResponse         cmacRes;
whMessageCrypto_Sha256Request        hashSha256Req;
whMessageCrypto_Sha512Request        hashSha512Req;
whMessageCrypto_Sha2Response         hashSha2Res;

/* DMA crypto messages */
#if defined(WOLFHSM_CFG_DMA)
whMessageCrypto_Sha2DmaRequest          hashSha2DmaReq;
whMessageCrypto_Sha2DmaResponse         hashSha2DmaRes;
whMessageCrypto_MlDsaKeyGenDmaRequest   pqMldsaKeygenDmaReq;
whMessageCrypto_MlDsaKeyGenDmaResponse  pqMldsaKeygenDmaRes;
whMessageCrypto_MlDsaSignDmaRequest     pqMldsaSignDmaReq;
whMessageCrypto_MlDsaSignDmaResponse    pqMldsaSignDmaRes;
whMessageCrypto_MlDsaVerifyDmaRequest   pqMldsaVerifyDmaReq;
whMessageCrypto_MlDsaVerifyDmaResponse  pqMldsaVerifyDmaRes;
whMessageCrypto_CmacDmaRequest          cmacDmaReq;
whMessageCrypto_CmacDmaResponse         cmacDmaRes;
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#ifdef WOLFHSM_CFG_SHE_EXTENSION
/* Include SHE message header for SHE message structures */
#include "wolfhsm/wh_message_she.h"
whMessageShe_SetUidRequest            sheSetUidReq;
whMessageShe_SetUidResponse           sheSetUidRes;
whMessageShe_SecureBootInitRequest    sheSecureBootInitReq;
whMessageShe_SecureBootInitResponse   sheSecureBootInitRes;
whMessageShe_SecureBootUpdateRequest  sheSecureBootUpdateReq;
whMessageShe_SecureBootUpdateResponse sheSecureBootUpdateRes;
whMessageShe_SecureBootFinishResponse sheSecureBootFinishRes;
whMessageShe_GetStatusResponse        sheGetStatusRes;
whMessageShe_LoadKeyRequest           sheLoadKeyReq;
whMessageShe_LoadKeyResponse          sheLoadKeyRes;
whMessageShe_LoadPlainKeyRequest      sheLoadPlainKeyReq;
whMessageShe_LoadPlainKeyResponse     sheLoadPlainKeyRes;
whMessageShe_ExportRamKeyResponse     sheExportRamKeyRes;
whMessageShe_InitRngResponse          sheInitRngRes;
whMessageShe_RndResponse              sheRndRes;
whMessageShe_ExtendSeedRequest        sheExtendSeedReq;
whMessageShe_ExtendSeedResponse       sheExtendSeedRes;
whMessageShe_EncEcbRequest            sheEncEcbReq;
whMessageShe_EncEcbResponse           sheEncEcbRes;
whMessageShe_EncCbcRequest            sheEncCbcReq;
whMessageShe_EncCbcResponse           sheEncCbcRes;
whMessageShe_DecEcbRequest            sheDecEcbReq;
whMessageShe_DecEcbResponse           sheDecEcbRes;
whMessageShe_DecCbcRequest            sheDecCbcReq;
whMessageShe_DecCbcResponse           sheDecCbcRes;
whMessageShe_GenMacRequest            sheGenMacReq;
whMessageShe_GenMacResponse           sheGenMacRes;
whMessageShe_VerifyMacRequest         sheVerifyMacReq;
whMessageShe_VerifyMacResponse        sheVerifyMacRes;
#endif /* WOLFHSM_CFG_SHE_EXTENSION */

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER)
/* Include certificate manager message header for new certificate manager
 * message structures */
#include "wolfhsm/wh_message_cert.h"
whMessageCert_SimpleResponse      whMessageCert_SimpleResponse_test;
whMessageCert_AddTrustedRequest   whMessageCert_AddTrustedRequest_test;
whMessageCert_EraseTrustedRequest whMessageCert_EraseTrustedRequest_test;
whMessageCert_ReadTrustedRequest  whMessageCert_ReadTrustedRequest_test;
whMessageCert_ReadTrustedResponse whMessageCert_ReadTrustedResponse_test;
whMessageCert_VerifyRequest       whMessageCert_VerifyRequest_test;
whMessageCert_VerifyResponse      whMessageCert_VerifyResponse_test;

#if defined(WOLFHSM_CFG_DMA)
whMessageCert_AddTrustedDmaRequest  whMessageCert_AddTrustedDmaRequest_test;
whMessageCert_ReadTrustedDmaRequest whMessageCert_ReadTrustedDmaRequest_test;
whMessageCert_VerifyDmaRequest      whMessageCert_VerifyDmaRequest_test;
whMessageCert_VerifyDmaResponse     whMessageCert_VerifyDmaResponse_test;
#endif /* WOLFHSM_CFG_DMA */

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
whMessageCert_VerifyAcertRequest whMessageCert_VerifyAcertRequest_test;
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT */
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER */

#endif /* WH_TEST_CHECK_STRUCT_PADDING_C_ */
