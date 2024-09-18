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
 * wolfhsm/wh_packet.h
 *
 */

#ifndef WOLFHSM_WH_PACKET_H_
#define WOLFHSM_WH_PACKET_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_she_common.h"
#endif

/** Management Packets */
typedef struct  wh_Packet_version_exchange
{
    uint32_t version;
    uint8_t WH_PAD[4];
} wh_Packet_version_exchange;


/** Cipher Packets */
typedef struct  wh_Packet_cipher_any_req
{
    uint32_t type;
    uint32_t enc;
} wh_Packet_cipher_any_req;

typedef struct  wh_Packet_cipher_aescbc_req
{
    uint32_t type;
    uint32_t enc;
    uint32_t keyLen;
    uint32_t sz;
    uint16_t keyId;
    uint8_t WH_PAD[6];
    /* key[keyLen] | iv[AES_IV_SIZE] | in[sz] */
} wh_Packet_cipher_aescbc_req;

typedef struct  wh_Packet_cipher_aescbc_res
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t out[]; */
} wh_Packet_cipher_aescbc_res;

typedef struct  wh_Packet_cipher_aesgcm_req
{
    uint32_t type;
    uint32_t enc;
    uint32_t keyLen;
    uint32_t sz;
    uint32_t ivSz;
    uint32_t authInSz;
    uint32_t authTagSz;
    uint16_t keyId;
    uint8_t WH_PAD[2];
    /* key[keyLen] | iv[ivSz] | in[sz] | authIn[authInSz] | authTag[authTagSz] */
} wh_Packet_cipher_aesgcm_req;

typedef struct  wh_Packet_cipher_aesgcm_res
{
    uint32_t sz;
    uint32_t authTagSz;
    /* uint8_t out[sz]; */
    /* uint8_t authTag[authTagSz] */
} wh_Packet_cipher_aesgcm_res;


/** PKI Packets */
typedef struct  wh_Packet_pk_any_req
{
    uint32_t type;
    uint8_t WH_PAD[4];
} wh_Packet_pk_any_req;

typedef struct  wh_Packet_pk_rsakg_req
{
    uint32_t type;
    uint32_t size;
    uint32_t e;
    uint8_t WH_PAD[4];
} wh_Packet_pk_rsakg_req;

typedef struct  wh_Packet_pk_rsakg_res
{
    uint32_t keyId;
    uint8_t WH_PAD[4];
} wh_Packet_pk_rsakg_res;

typedef struct  wh_Packet_pk_rsa_req
{
    uint32_t type;
    uint32_t opType;
    uint32_t keyId;
    uint32_t inLen;
    uint32_t outLen;
    uint8_t WH_PAD[4];
    /* uint8_t in[]; */
} wh_Packet_pk_rsa_req;

typedef struct  wh_Packet_pk_rsa_res
{
    uint32_t outLen;
    uint8_t WH_PAD[4];
    /* uint8_t out[]; */
} wh_Packet_pk_rsa_res;

typedef struct  wh_Packet_pk_rsa_get_size_req
{
    uint32_t type;
    uint32_t keyId;
} wh_Packet_pk_rsa_get_size_req;

typedef struct  wh_Packet_pk_rsa_get_size_res
{
    uint32_t keySize;
    uint8_t WH_PAD[4];
} wh_Packet_pk_rsa_get_size_res;

typedef struct  wh_Packet_pk_eckg_req
{
    uint32_t type;
    uint32_t sz;
    uint32_t curveId;
    uint32_t keyId;
    uint32_t flags;
    uint32_t access;
    uint8_t label[WH_NVM_LABEL_LEN];
} wh_Packet_pk_eckg_req;

typedef struct  wh_Packet_pk_eckg_res
{
    uint32_t keyId;
    uint32_t len;
    /* uint8_t out[] */
} wh_Packet_pk_eckg_res;

typedef struct  wh_Packet_pk_ecdh_req
{
    uint32_t type;
    uint32_t options;
#define WH_PACKET_PK_ECDH_OPTIONS_EVICTPUB  (1 << 0)
#define WH_PACKET_PK_ECDH_OPTIONS_EVICTPRV (1 << 1)
    uint32_t privateKeyId;
    uint32_t publicKeyId;
} wh_Packet_pk_ecdh_req;

typedef struct  wh_Packet_pk_ecdh_res
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t out[] */
} wh_Packet_pk_ecdh_res;

typedef struct  wh_Packet_pk_ecc_sign_req
{
    uint32_t type;
    uint32_t options;
#define WH_PACKET_PK_ECCSIGN_OPTIONS_EVICT  (1 << 0)
    uint32_t keyId;
    uint32_t sz;
    /* uint8_t in[] */
} wh_Packet_pk_ecc_sign_req;

typedef struct  wh_Packet_pk_ecc_sign_res
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t out[] */
} wh_Packet_pk_ecc_sign_res;

typedef struct  wh_Packet_pk_ecc_verify_req
{
    uint32_t type;
    uint32_t options;
#define WH_PACKET_PK_ECCVERIFY_OPTIONS_EVICT  (1 << 0)
#define WH_PACKET_PK_ECCVERIFY_OPTIONS_EXPORTPUB (1 << 1)
    uint32_t keyId;
    uint32_t sigSz;
    uint32_t hashSz;
    uint8_t WH_PAD[4];
    /* uint8_t sig[] */
    /* uint8_t hash[] */
} wh_Packet_pk_ecc_verify_req;

typedef struct  wh_Packet_pk_ecc_verify_res
{
    uint32_t res;
    uint32_t pubSz;
    /* uint8_t pub[] */
} wh_Packet_pk_ecc_verify_res;

typedef struct  wh_Packet_pk_ecc_check_req
{
    uint32_t type;
    uint32_t keyId;
    uint32_t curveId;
    uint8_t WH_PAD[4];
} wh_Packet_pk_ecc_check_req;

typedef struct  wh_Packet_pk_ecc_check_res
{
    uint32_t ok;
    uint8_t WH_PAD[4];
} wh_Packet_pk_ecc_check_res;

typedef struct  wh_Packet_pk_curve25519kg_req
{
    uint32_t type;
    uint32_t sz;
    uint32_t flags;
    uint32_t keyId;
    uint8_t label[WH_NVM_LABEL_LEN];
} wh_Packet_pk_curve25519kg_req;

typedef struct  wh_Packet_pk_curve25519kg_res
{
    uint32_t keyId;
    uint32_t len;
    /* uint8_t out[len]; */
} wh_Packet_pk_curve25519kg_res;

typedef struct  wh_Packet_pk_curve25519_req
{
    uint32_t type;
    uint32_t options;
#define WH_PACKET_PK_CURVE25519_OPTIONS_EVICTPUB (1 << 0)
#define WH_PACKET_PK_CURVE25519_OPTIONS_EVICTPRV (1 << 1)
    uint32_t privateKeyId;
    uint32_t publicKeyId;
    uint32_t endian;
} wh_Packet_pk_curve25519_req;

typedef struct  wh_Packet_pk_curve25519_res
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t out[]; */
} wh_Packet_pk_curve25519_res;


/* RNG Messages */
typedef struct  wh_Packet_rng_req
{
    uint32_t sz;
    uint8_t WH_PAD[4];
} wh_Packet_rng_req;

typedef struct  wh_Packet_rng_res
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t out[]; */
} wh_Packet_rng_res;


/** CMAC Packets */
typedef struct  wh_Packet_cmac_req
{
    uint32_t outSz;
    uint32_t inSz;
    uint32_t keySz;
    uint32_t type;
    uint16_t keyId;
    uint8_t WH_PAD[6];
    /* uint8_t in[inSz] */
    /* uint8_t key[keySz] */
} wh_Packet_cmac_req;

typedef struct  wh_Packet_cmac_res
{
    uint32_t outSz;
    uint16_t keyId;
    uint8_t WH_PAD[2];
    /* uint8_t out[]; */
} wh_Packet_cmac_res;

typedef struct wh_Packet_hash_any_req {
    uint32_t type; /* enum wc_HashType */
    uint8_t WH_PAD[4];
} wh_Packet_hash_any_req;

typedef struct wh_Packet_hash_sha256_req {
    /* TODO change to "wh_Packet_hash_any_req header" */
    uint32_t type; /* enum wc_HashType */
    struct {
        uint32_t hiLen;
        uint32_t loLen;
        /* intermediate hash value */
        uint8_t hash[32]; /* TODO (BRN) WC_SHA256_DIGEST_SIZE */
    } resumeState;
    /* Flag indicating to the server that this is the last block and it should
     * finalize the hash. If set, inBlock may be only partially full*/
    uint32_t isLastBlock;
    /* Length of the last input block of data. Only valid if isLastBlock=1 */
    uint32_t lastBlockLen;
    /* Full sha256 input block to hash */
    uint8_t inBlock[64]; /* TODO (BRN) WC_SHA256_BLOCK_SIZE */
    uint8_t WH_PAD[4];
} wh_Packet_hash_sha256_req;

typedef struct wh_Packet_hash_sha256_res {
    /* Resulting hash value */
    uint32_t hiLen;
    uint32_t loLen;
    uint8_t  hash[32]; /* TODO WC_SHA256_DIGEST_SIZE */
} wh_Packet_hash_sha256_res;


/** Key Management Packets */
typedef struct  wh_Packet_key_cache_req
{
    uint32_t flags;
    uint32_t sz;
    uint32_t labelSz;
    uint16_t id;
    uint8_t WH_PAD[2];
    uint8_t label[WH_NVM_LABEL_LEN];
    /* uint8_t in[]; */
} wh_Packet_key_cache_req;

typedef struct  wh_Packet_key_cache_res
{
    uint16_t id;
    uint8_t WH_PAD[6];
} wh_Packet_key_cache_res;

typedef struct  wh_Packet_key_evict_req
{
    uint32_t id;
    uint8_t WH_PAD[4];
} wh_Packet_key_evict_req;

typedef struct  wh_Packet_key_evict_res
{
    uint32_t ok;
    uint8_t WH_PAD[4];
} wh_Packet_key_evict_res;

typedef struct  wh_Packet_key_commit_req
{
    uint32_t id;
    uint8_t WH_PAD[4];
} wh_Packet_key_commit_req;

typedef struct  wh_Packet_key_commit_res
{
    uint32_t ok;
    uint8_t WH_PAD[4];
} wh_Packet_key_commit_res;

typedef struct  wh_Packet_key_export_req
{
    uint32_t id;
    uint8_t WH_PAD[4];
} wh_Packet_key_export_req;

typedef struct  wh_Packet_key_export_res
{
    uint32_t len;
    uint8_t label[WH_NVM_LABEL_LEN];
    uint8_t WH_PAD[4];
    /* uint8_t out[len]; */
} wh_Packet_key_export_res;

typedef struct  wh_Packet_key_erase_req
{
    uint32_t id;
    uint8_t WH_PAD[4];
} wh_Packet_key_erase_req;

typedef struct  wh_Packet_key_erase_res
{
    uint32_t ok;
    uint8_t WH_PAD[4];
} wh_Packet_key_erase_res;


/** NVM Counter packets */
typedef struct  wh_Packet_counter_init_req
{
    uint32_t counter;
    uint16_t counterId;
    uint8_t WH_PAD[2];
} wh_Packet_counter_init_req;

typedef struct  wh_Packet_counter_init_res
{
    uint32_t counter;
    uint8_t WH_PAD[4];
} wh_Packet_counter_init_res;

typedef struct  wh_Packet_counter_increment_req
{
    uint16_t counterId;
    uint8_t WH_PAD[6];
} wh_Packet_counter_increment_req;

typedef struct  wh_Packet_counter_increment_res
{
    uint32_t counter;
    uint8_t WH_PAD[4];
} wh_Packet_counter_increment_res;

typedef struct  wh_Packet_counter_read_req
{
    uint16_t counterId;
    uint8_t WH_PAD[6];
} wh_Packet_counter_read_req;

typedef struct  wh_Packet_counter_read_res
{
    uint32_t counter;
    uint8_t WH_PAD[4];
} wh_Packet_counter_read_res;

typedef struct  wh_Packet_counter_destroy_req
{
    uint16_t counterId;
    uint8_t WH_PAD[6];
} wh_Packet_counter_destroy_req;

/* DMA-based crypto messages */
typedef struct {
    uint32_t addr;
    uint32_t sz;
} wh_Packet_Dma32_buffer;

typedef struct {
    uint64_t addr;
    uint64_t sz;
} wh_Packet_Dma64_buffer;

typedef struct {
    /* If packet->rc == WH_ERROR_ACCESS, this field will contain the offending
     * address/size pair. Invalid otherwise. */
    wh_Packet_Dma32_buffer badAddr;
} wh_Packet_Dma32_crypto_res;

typedef struct {
    /* If packet->rc == WH_ERROR_ACCESS, this field will contain the offending
     * address/size pair. Invalid otherwise. */
    wh_Packet_Dma64_buffer badAddr;
} wh_Packet_Dma64_crypto_res;

/* SHA256 DMA messages */
typedef struct wh_Packet_hash_sha256_Dma32_req {
    uint32_t type;
    /* Since client addresses are subject to DMA checking, we can't use them to
     * determine the requested operation (update/final). Therefore we need to
     * indicate to the server which SHA256 operation to perform */
    uint32_t finalize;
    wh_Packet_Dma32_buffer input;
    wh_Packet_Dma32_buffer state;
    wh_Packet_Dma32_buffer output;
} wh_Packet_hash_sha256_Dma32_req;

typedef struct wh_Packet_hash_sha256_Dma64_req {
    uint64_t type;
    /* Since client addresses are subject to DMA checking, we can't use them to
     * determine the requested operation (update/final). Therefore we need to
     * indicate to the server which SHA256 operation to perform */
    uint64_t finalize;
    wh_Packet_Dma64_buffer input;
    wh_Packet_Dma64_buffer state;
    wh_Packet_Dma64_buffer output;
} wh_Packet_hash_sha256_Dma64_req;

typedef struct wh_Packet_hash_sha256_Dma32_res {
    wh_Packet_Dma32_crypto_res dmaCryptoRes;
} wh_Packet_hash_sha256_Dma32_res;

typedef struct wh_Packet_hash_sha256_Dma64_res {
    wh_Packet_Dma64_crypto_res dmaCryptoRes;
} wh_Packet_hash_sha256_Dma64_res;


/** SHE Packets */
#ifdef WOLFHSM_CFG_SHE_EXTENSION
typedef struct  wh_Packet_she_set_uid_req
{
    uint8_t uid[WH_SHE_UID_SZ];
    uint8_t WH_PAD[1];
} wh_Packet_she_set_uid_req;

typedef struct  wh_Packet_she_secure_boot_init_req
{
    uint32_t sz;
    uint8_t WH_PAD[4];
} wh_Packet_she_secure_boot_init_req;

typedef struct  wh_Packet_she_secure_boot_init_res
{
    uint32_t status;
    uint8_t WH_PAD[4];
} wh_Packet_she_secure_boot_init_res;

typedef struct  wh_Packet_she_secure_boot_update_req
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t in[sz] */
} wh_Packet_she_secure_boot_update_req;

typedef struct  wh_Packet_she_secure_boot_update_res
{
    uint32_t status;
    uint8_t WH_PAD[4];
} wh_Packet_she_secure_boot_update_res;

/* no req body for a finish request */
typedef struct  wh_Packet_she_secure_boot_finish_res
{
    uint32_t status;
    uint8_t WH_PAD[4];
} wh_Packet_she_secure_boot_finish_res;

/* no req body for get status */
typedef struct  wh_Packet_she_get_status_res
{
    uint8_t sreg;
    uint8_t WH_PAD[7];
} wh_Packet_she_get_status_res;

typedef struct wh_Packet_she_load_key_req
{
    uint8_t messageOne[WH_SHE_M1_SZ];
    uint8_t messageTwo[WH_SHE_M2_SZ];
    uint8_t messageThree[WH_SHE_M3_SZ];
} wh_Packet_she_load_key_req;

typedef struct  wh_Packet_she_load_key_res
{
    uint8_t messageFour[WH_SHE_M4_SZ];
    uint8_t messageFive[WH_SHE_M5_SZ];
} wh_Packet_she_load_key_res;

typedef struct  wh_Packet_she_load_plain_key_req
{
    uint8_t key[WH_SHE_KEY_SZ];
} wh_Packet_she_load_plain_key_req;

typedef struct wh_Packet_she_export_ram_key_res
{
    uint8_t messageOne[WH_SHE_M1_SZ];
    uint8_t messageTwo[WH_SHE_M2_SZ];
    uint8_t messageThree[WH_SHE_M3_SZ];
    uint8_t messageFour[WH_SHE_M4_SZ];
    uint8_t messageFive[WH_SHE_M5_SZ];
} wh_Packet_she_export_ram_key_res;

typedef struct  wh_Packet_she_init_rng_res
{
    uint32_t status;
    uint8_t WH_PAD[4];
} wh_Packet_she_init_rng_res;

typedef struct  wh_Packet_she_rnd_res
{
    uint8_t rnd[WH_SHE_KEY_SZ];
} wh_Packet_she_rnd_res;

typedef struct  wh_Packet_she_extend_seed_req
{
    uint8_t entropy[WH_SHE_KEY_SZ];
} wh_Packet_she_extend_seed_req;

typedef struct  wh_Packet_she_extend_seed_res
{
    uint32_t status;
    uint8_t WH_PAD[4];
} wh_Packet_she_extend_seed_res;

typedef struct  wh_Packet_she_enc_ecb_req
{
    uint32_t sz;
    uint8_t keyId;
    uint8_t WH_PAD[3];
    /* uint8_t in[sz] */
} wh_Packet_she_enc_ecb_req;

typedef struct  wh_Packet_she_enc_ecb_res
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t out[sz] */
} wh_Packet_she_enc_ecb_res;

typedef struct  wh_Packet_she_enc_cbc_req
{
    uint32_t sz;
    uint8_t keyId;
    uint8_t WH_PAD[3];
    uint8_t iv[WH_SHE_KEY_SZ];
    /* uint8_t in[sz] */
} wh_Packet_she_enc_cbc_req;

typedef struct  wh_Packet_she_enc_cbc_res
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t out[sz] */
} wh_Packet_she_enc_cbc_res;

typedef struct  wh_Packet_she_dec_ecb_req
{
    uint32_t sz;
    uint8_t keyId;
    uint8_t WH_PAD[3];
    /* uint8_t in[sz] */
} wh_Packet_she_dec_ecb_req;

typedef struct  wh_Packet_she_dec_ecb_res
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t out[sz] */
} wh_Packet_she_dec_ecb_res;

typedef struct  wh_Packet_she_dec_cbc_req
{
    uint32_t sz;
    uint8_t keyId;
    uint8_t WH_PAD[3];
    uint8_t iv[WH_SHE_KEY_SZ];
    /* uint8_t in[sz] */
} wh_Packet_she_dec_cbc_req;

typedef struct  wh_Packet_she_dec_cbc_res
{
    uint32_t sz;
    uint8_t WH_PAD[4];
    /* uint8_t out[sz] */
} wh_Packet_she_dec_cbc_res;

typedef struct  wh_Packet_she_gen_mac_req
{
    uint32_t keyId;
    uint32_t sz;
    /* uint8_t in[sz] */
} wh_Packet_she_gen_mac_req;

typedef struct  wh_Packet_she_gen_mac_res
{
    uint8_t mac[WH_SHE_KEY_SZ];
} wh_Packet_she_gen_mac_res;

typedef struct  wh_Packet_she_verify_mac_req
{
    uint32_t keyId;
    uint32_t messageLen;
    uint32_t macLen;
    uint8_t WH_PAD[4];
    /* uint8_t message[messageLen] */
    /* uint8_t mac[macLen] */
} wh_Packet_she_verify_mac_req;

typedef struct  wh_Packet_she_verify_mac_res
{
    uint8_t status;
    uint8_t WH_PAD[7];
} wh_Packet_she_verify_mac_res;
#endif  /*WOLFHSM_CFG_SHE_EXTENSION */

/** Union of all packet types with common header
 * NOTE: This union, and therefore all structures within it, must be padded out
 * such that they are 8-byte aligned
 */
typedef struct whPacket
{
    /* header */
    int32_t rc;
    uint16_t flags;
    uint8_t WH_PAD[2];

#define WH_PACKET_STUB_SIZE 8
   /* body, will be either a request or a response */
    union {
        wh_Packet_version_exchange versionExchange;
        /* FIXED SIZE REQUESTS */
        /* cipher */
        wh_Packet_cipher_any_req cipherAnyReq;
        /* AES CBC */
        wh_Packet_cipher_aescbc_req cipherAesCbcReq;
        /* AES GCM */
        wh_Packet_cipher_aesgcm_req cipherAesGcmReq;
        /* pk */
        wh_Packet_pk_any_req pkAnyReq;
        /* RSA */
        wh_Packet_pk_rsakg_req pkRsakgReq;
        wh_Packet_pk_rsa_req pkRsaReq;
        wh_Packet_pk_rsa_get_size_req pkRsaGetSizeReq;
        /* ECC */
        wh_Packet_pk_eckg_req pkEckgReq;
        wh_Packet_pk_ecdh_req pkEcdhReq;
        wh_Packet_pk_ecc_sign_req pkEccSignReq;
        wh_Packet_pk_ecc_verify_req pkEccVerifyReq;
        wh_Packet_pk_ecc_check_req pkEccCheckReq;
        /* curve25519 */
        wh_Packet_pk_curve25519kg_req pkCurve25519kgReq;
        wh_Packet_pk_curve25519kg_res pkCurve25519kgRes;
        wh_Packet_pk_curve25519_req pkCurve25519Req;
        wh_Packet_pk_curve25519_res pkCurve25519Res;
        /* rng */
        wh_Packet_rng_req rngReq;
        /* cmac */
        wh_Packet_cmac_req cmacReq;
        /* Hash */
        wh_Packet_hash_any_req hashAnyReq;
        /* Hash: SHA256*/
        wh_Packet_hash_sha256_req hashSha256Req;
        /* key cache */
        wh_Packet_key_cache_req keyCacheReq;
        /* key evict */
        wh_Packet_key_evict_req keyEvictReq;
        /* key commit */
        wh_Packet_key_commit_req keyCommitReq;
        /* key export */
        wh_Packet_key_export_req keyExportReq;
        /* key erase */
        wh_Packet_key_erase_req keyEraseReq;
        /* counters */
        wh_Packet_counter_init_req counterInitReq;
        wh_Packet_counter_increment_req counterIncrementReq;
        wh_Packet_counter_read_req counterReadReq;
        wh_Packet_counter_destroy_req counterDestroyReq;

        /* FIXED SIZE RESPONSES */
        /* cipher */
        /* AES CBC */
        wh_Packet_cipher_aescbc_res cipherAesCbcRes;
        /* AES GCM */
        wh_Packet_cipher_aesgcm_res cipherAesGcmRes;
        /* pk */
        /* RSA */
        wh_Packet_pk_rsakg_res pkRsakgRes;
        wh_Packet_pk_rsa_res pkRsaRes;
        wh_Packet_pk_rsa_get_size_res pkRsaGetSizeRes;
        /* ECC */
        wh_Packet_pk_eckg_res pkEckgRes;
        wh_Packet_pk_ecdh_res pkEcdhRes;
        wh_Packet_pk_ecc_sign_res pkEccSignRes;
        wh_Packet_pk_ecc_verify_res pkEccVerifyRes;
        wh_Packet_pk_ecc_check_res pkEccCheckRes;
        /* rng */
        wh_Packet_rng_res rngRes;
        /* cmac */
        wh_Packet_cmac_res cmacRes;
        /* hash: SHA256 */
        wh_Packet_hash_sha256_res hashSha256Res;
        /* key cache */
        wh_Packet_key_cache_res keyCacheRes;
        /* key evict */
        wh_Packet_key_evict_res keyEvictRes;
        /* key commit */
        wh_Packet_key_commit_res keyCommitRes;
        /* key export */
        wh_Packet_key_export_res keyExportRes;
        /* key erase */
        wh_Packet_key_erase_res keyEraseRes;
        /* counters */
        wh_Packet_counter_init_res counterInitRes;
        wh_Packet_counter_increment_res counterIncrementRes;
        wh_Packet_counter_read_res counterReadRes;

        /* DMA messages*/
#if defined(WOLFHSM_CFG_DMA) && WH_DMA_IS_32BIT
        wh_Packet_hash_sha256_Dma32_req hashSha256Dma32Req;
        wh_Packet_hash_sha256_Dma32_res hashSha256Dma32Res;
#elif defined(WOLFHSM_CFG_DMA) && WH_DMA_IS_64BIT
        wh_Packet_hash_sha256_Dma64_req hashSha256Dma64Req;
        wh_Packet_hash_sha256_Dma64_res hashSha256Dma64Res;
#endif

#ifdef WOLFHSM_CFG_SHE_EXTENSION
        wh_Packet_she_set_uid_req sheSetUidReq;
        wh_Packet_she_secure_boot_init_req sheSecureBootInitReq;
        wh_Packet_she_secure_boot_init_res sheSecureBootInitRes;
        wh_Packet_she_secure_boot_update_req sheSecureBootUpdateReq;
        wh_Packet_she_secure_boot_update_res sheSecureBootUpdateRes;
        wh_Packet_she_secure_boot_finish_res sheSecureBootFinishRes;
        wh_Packet_she_get_status_res sheGetStatusRes;
        wh_Packet_she_load_key_req sheLoadKeyReq;
        wh_Packet_she_load_key_res sheLoadKeyRes;
        wh_Packet_she_load_plain_key_req sheLoadPlainKeyReq;
        wh_Packet_she_export_ram_key_res sheExportRamKeyRes;
        wh_Packet_she_init_rng_res sheInitRngRes;
        wh_Packet_she_rnd_res sheRndRes;
        wh_Packet_she_extend_seed_req sheExtendSeedReq;
        wh_Packet_she_extend_seed_res sheExtendSeedRes;
        wh_Packet_she_enc_ecb_req sheEncEcbReq;
        wh_Packet_she_enc_ecb_res sheEncEcbRes;
        wh_Packet_she_enc_cbc_req sheEncCbcReq;
        wh_Packet_she_enc_cbc_res sheEncCbcRes;
        wh_Packet_she_enc_ecb_req sheDecEcbReq;
        wh_Packet_she_enc_ecb_res sheDecEcbRes;
        wh_Packet_she_enc_cbc_req sheDecCbcReq;
        wh_Packet_she_enc_cbc_res sheDecCbcRes;
        wh_Packet_she_gen_mac_req sheGenMacReq;
        wh_Packet_she_gen_mac_res sheGenMacRes;
        wh_Packet_she_verify_mac_req sheVerifyMacReq;
        wh_Packet_she_verify_mac_res sheVerifyMacRes;
#endif  /* WOLFHSM_CFG_SHE_EXTENSION */

    };
} whPacket;

#endif /* !WOLFHSM_WH_PACKET_H_ */
