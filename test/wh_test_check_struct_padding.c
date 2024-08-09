#ifndef WH_TEST_CHECK_STRUCT_PADDING_C_
#define WH_TEST_CHECK_STRUCT_PADDING_C_

/* For each included file, define an instance of every struct for which we want
 * to check padding. Then, when this file is compiled with -Wpadded it will
 * generate an error if padding is wrong */


#include "wolfhsm/wh_message_comm.h"
whMessageComm_ErrorResponse whMessageComm_ErrorResponse_test;
whMessageCommLenData        whMessageCommLenData_test;
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
whMessageNvm_AddObjectDma32Request whMessageNvm_AddObjectDma32Request_test;
whMessageNvm_ReadDma32Request      whMessageNvm_ReadDma32Request_test;
whMessageNvm_AddObjectDma64Request whMessageNvm_AddObjectDma64Request_test;
whMessageNvm_ReadDma64Request      whMessageNvm_ReadDma64Request_test;

#include "wolfhsm/wh_packet.h"
whPacket whPacket_test;
/* Test every variant of the nested union */
wh_Packet_version_exchange           versionExchange;
wh_Packet_key_cache_req              keyCacheReq;
wh_Packet_key_evict_req              keyEvictReq;
wh_Packet_key_commit_req             keyCommitReq;
wh_Packet_key_export_req             keyExportReq;
wh_Packet_key_erase_req              keyEraseReq;
wh_Packet_counter_init_req           counterInitReq;
wh_Packet_counter_increment_req      counterIncrementReq;
wh_Packet_counter_read_req           counterReadReq;
wh_Packet_counter_destroy_req        counterDestroyReq;
wh_Packet_key_cache_res              keyCacheRes;
wh_Packet_key_evict_res              keyEvictRes;
wh_Packet_key_commit_res             keyCommitRes;
wh_Packet_key_export_res             keyExportRes;
wh_Packet_key_erase_res              keyEraseRes;
wh_Packet_counter_init_res           counterInitRes;
wh_Packet_counter_increment_res      counterIncrementRes;
wh_Packet_counter_read_res           counterReadRes;
#ifndef WOLFHSM_CFG_NO_CRYPTO
wh_Packet_cipher_any_req             cipherAnyReq;
wh_Packet_cipher_aescbc_req          cipherAesCbcReq;
wh_Packet_cipher_aesgcm_req          cipherAesGcmReq;
wh_Packet_pk_any_req                 pkAnyReq;
wh_Packet_pk_rsakg_req               pkRsakgReq;
wh_Packet_pk_rsa_req                 pkRsaReq;
wh_Packet_pk_rsa_get_size_req        pkRsaGetSizeReq;
wh_Packet_pk_eckg_req                pkEckgReq;
wh_Packet_pk_ecdh_req                pkEcdhReq;
wh_Packet_pk_ecc_sign_req            pkEccSignReq;
wh_Packet_pk_ecc_verify_req          pkEccVerifyReq;
wh_Packet_pk_ecc_check_req           pkEccCheckReq;
wh_Packet_pk_curve25519kg_req        pkCurve25519kgReq;
wh_Packet_pk_curve25519kg_res        pkCurve25519kgRes;
wh_Packet_pk_curve25519_req          pkCurve25519Req;
wh_Packet_pk_curve25519_res          pkCurve25519Res;
wh_Packet_rng_req                    rngReq;
wh_Packet_cmac_req                   cmacReq;
wh_Packet_cipher_aescbc_res          cipherAesCbcRes;
wh_Packet_cipher_aesgcm_res          cipherAesGcmRes;
wh_Packet_pk_rsakg_res               pkRsakgRes;
wh_Packet_pk_rsa_res                 pkRsaRes;
wh_Packet_pk_rsa_get_size_res        pkRsaGetSizeRes;
wh_Packet_pk_eckg_res                pkEckgRes;
wh_Packet_pk_ecdh_res                pkEcdhRes;
wh_Packet_pk_ecc_sign_res            pkEccSignRes;
wh_Packet_pk_ecc_verify_res          pkEccVerifyRes;
wh_Packet_pk_ecc_check_res           pkEccCheckRes;
wh_Packet_rng_res                    rngRes;
wh_Packet_cmac_res                   cmacRes;
wh_Packet_hash_any_req               hashAnyReq;
wh_Packet_hash_sha256_req            hashSha256Req;
wh_Packet_hash_sha256_res            hashSha256Res;
#endif /* !WOLFHSM_CFG_NO_CRYPTO */
#ifdef WOLFHSM_CFG_SHE_EXTENSION
wh_Packet_she_set_uid_req            sheSetUidReq;
wh_Packet_she_secure_boot_init_req   sheSecureBootInitReq;
wh_Packet_she_secure_boot_init_res   sheSecureBootInitRes;
wh_Packet_she_secure_boot_update_req sheSecureBootUpdateReq;
wh_Packet_she_secure_boot_update_res sheSecureBootUpdateRes;
wh_Packet_she_secure_boot_finish_res sheSecureBootFinishRes;
wh_Packet_she_get_status_res         sheGetStatusRes;
wh_Packet_she_load_key_req           sheLoadKeyReq;
wh_Packet_she_load_key_res           sheLoadKeyRes;
wh_Packet_she_load_plain_key_req     sheLoadPlainKeyReq;
wh_Packet_she_export_ram_key_res     sheExportRamKeyRes;
wh_Packet_she_init_rng_res           sheInitRngRes;
wh_Packet_she_rnd_res                sheRndRes;
wh_Packet_she_extend_seed_req        sheExtendSeedReq;
wh_Packet_she_extend_seed_res        sheExtendSeedRes;
wh_Packet_she_enc_ecb_req            sheEncEcbReq;
wh_Packet_she_enc_ecb_res            sheEncEcbRes;
wh_Packet_she_enc_cbc_req            sheEncCbcReq;
wh_Packet_she_enc_cbc_res            sheEncCbcRes;
wh_Packet_she_enc_ecb_req            sheDecEcbReq;
wh_Packet_she_enc_ecb_res            sheDecEcbRes;
wh_Packet_she_enc_cbc_req            sheDecCbcReq;
wh_Packet_she_enc_cbc_res            sheDecCbcRes;
wh_Packet_she_gen_mac_req            sheGenMacReq;
wh_Packet_she_gen_mac_res            sheGenMacRes;
wh_Packet_she_verify_mac_req         sheVerifyMacReq;
wh_Packet_she_verify_mac_res         sheVerifyMacRes;
#endif /* WOLFHSM_CFG_SHE_EXTENSION */


#endif /* WH_TEST_CHECK_STRUCT_PADDING_C_ */
