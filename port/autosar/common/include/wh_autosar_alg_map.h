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
 * port/autosar/common/include/wh_autosar_alg_map.h
 *
 * Mapping between AUTOSAR R22-11 Crypto identifiers and wolfHSM primitives.
 */

#ifndef WH_AUTOSAR_ALG_MAP_H_
#define WH_AUTOSAR_ALG_MAP_H_

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

/* AUTOSAR CP R22-11 Crypto_AlgorithmFamilyType values (subset). */
typedef enum {
    WH_AUTOSAR_ALGOFAM_NOT_SET  = 0x00,
    WH_AUTOSAR_ALGOFAM_SHA1     = 0x01,
    WH_AUTOSAR_ALGOFAM_SHA2_224 = 0x02,
    WH_AUTOSAR_ALGOFAM_SHA2_256 = 0x03,
    WH_AUTOSAR_ALGOFAM_SHA2_384 = 0x04,
    WH_AUTOSAR_ALGOFAM_SHA2_512 = 0x05,
    WH_AUTOSAR_ALGOFAM_AES      = 0x14,
    WH_AUTOSAR_ALGOFAM_RSA      = 0x16,
    WH_AUTOSAR_ALGOFAM_ED25519  = 0x17,
    WH_AUTOSAR_ALGOFAM_ECCNIST  = 0x19,
    WH_AUTOSAR_ALGOFAM_RNG      = 0x1B,
    WH_AUTOSAR_ALGOFAM_HKDF     = 0x2B,
    WH_AUTOSAR_ALGOFAM_ECDSA    = 0x2C,
    WH_AUTOSAR_ALGOFAM_X25519   = 0x2E,
    WH_AUTOSAR_ALGOFAM_ECDH     = 0x2F,
    WH_AUTOSAR_ALGOFAM_CUSTOM   = 0xFF
} wh_AutosarAlgoFam;

/* Families R22-11 does not define; integrators may remap them. */
#ifndef WH_AUTOSAR_ALGOFAM_MLDSA
#define WH_AUTOSAR_ALGOFAM_MLDSA 0x80u
#endif
#ifndef WH_AUTOSAR_ALGOFAM_CMAC_KDF
#define WH_AUTOSAR_ALGOFAM_CMAC_KDF 0x81u
#endif

/* AUTOSAR CP R22-11 Crypto_AlgorithmModeType values (subset). */
typedef enum {
    WH_AUTOSAR_ALGOMODE_NOT_SET    = 0x00,
    WH_AUTOSAR_ALGOMODE_ECB        = 0x01,
    WH_AUTOSAR_ALGOMODE_CBC        = 0x02,
    WH_AUTOSAR_ALGOMODE_CTR        = 0x05,
    WH_AUTOSAR_ALGOMODE_GCM        = 0x06,
    WH_AUTOSAR_ALGOMODE_PSS        = 0x0A,
    WH_AUTOSAR_ALGOMODE_PKCS1_V1_5 = 0x0B,
    WH_AUTOSAR_ALGOMODE_CMAC       = 0x10
} wh_AutosarAlgoMode;

/* AUTOSAR CP R22-11 Crypto_ServiceInfoType values (subset). */
typedef enum {
    WH_AUTOSAR_SERVICE_HASH               = 0x00,
    WH_AUTOSAR_SERVICE_MAC_GENERATE       = 0x01,
    WH_AUTOSAR_SERVICE_MAC_VERIFY         = 0x02,
    WH_AUTOSAR_SERVICE_ENCRYPT            = 0x03,
    WH_AUTOSAR_SERVICE_DECRYPT            = 0x04,
    WH_AUTOSAR_SERVICE_AEAD_ENCRYPT       = 0x05,
    WH_AUTOSAR_SERVICE_AEAD_DECRYPT       = 0x06,
    WH_AUTOSAR_SERVICE_SIGNATURE_GENERATE = 0x07,
    WH_AUTOSAR_SERVICE_SIGNATURE_VERIFY   = 0x08,
    WH_AUTOSAR_SERVICE_RANDOM             = 0x0B,
    WH_AUTOSAR_SERVICE_RANDOM_SEED        = 0x0C,
    WH_AUTOSAR_SERVICE_KEY_GENERATE       = 0x0D,
    WH_AUTOSAR_SERVICE_KEY_DERIVE         = 0x0E,
    WH_AUTOSAR_SERVICE_KEY_EXCHANGE_PUB   = 0x0F,
    WH_AUTOSAR_SERVICE_KEY_EXCHANGE_SEC   = 0x10,
    WH_AUTOSAR_SERVICE_KEY_SET_VALID      = 0x13,
    WH_AUTOSAR_SERVICE_KEY_SET_INVALID    = 0x14
} wh_AutosarService;

int wh_AutosarMap_HashType(wh_AutosarAlgoFam fam);

/* Dispatcher operation for a (service, family, mode, secondary) tuple. */
typedef enum {
    WH_AUTOSAR_OP_INVALID = -1,
    WH_AUTOSAR_OP_HASH_SHA256,
    WH_AUTOSAR_OP_HASH_SHA384,
    WH_AUTOSAR_OP_HASH_SHA512,
    WH_AUTOSAR_OP_MAC_CMAC_AES,
    WH_AUTOSAR_OP_CIPHER_AES_ECB,
    WH_AUTOSAR_OP_CIPHER_AES_CBC,
    WH_AUTOSAR_OP_CIPHER_AES_CTR,
    WH_AUTOSAR_OP_AEAD_AES_GCM,
    WH_AUTOSAR_OP_SIG_RSA_PKCS1_V1_5,
    WH_AUTOSAR_OP_SIG_RSA_PSS,
    WH_AUTOSAR_OP_SIG_ECDSA,
    WH_AUTOSAR_OP_SIG_ED25519,
    WH_AUTOSAR_OP_SIG_MLDSA,
    WH_AUTOSAR_OP_RNG_GENERATE,
    WH_AUTOSAR_OP_KEY_GENERATE,
    WH_AUTOSAR_OP_KEY_DERIVE,
    WH_AUTOSAR_OP_KEY_EXCHANGE_PUB,
    WH_AUTOSAR_OP_KEY_EXCHANGE_SEC,
    WH_AUTOSAR_OP_KEY_SET_VALID,
    WH_AUTOSAR_OP_KEY_SET_INVALID,
    WH_AUTOSAR_OP_RANDOM_SEED
} wh_AutosarOpKind;

int wh_AutosarMap_OpKind(uint32_t service, uint32_t family, uint32_t mode,
                         uint32_t secondaryFamily, wh_AutosarOpKind* outOp);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WH_AUTOSAR_ALG_MAP_H_ */
