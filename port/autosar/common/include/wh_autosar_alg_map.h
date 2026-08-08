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
 *
 * Used by both the Classic Crypto Driver and the Adaptive CryptoProvider so
 * the two stay in sync on which (family, mode) combinations are supported.
 */

#ifndef WH_AUTOSAR_ALG_MAP_H_
#define WH_AUTOSAR_ALG_MAP_H_

#include <stdint.h>

#include "wolfhsm/wh_keyid.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AUTOSAR R22-11 algorithm family codes (subset). Values match the SWS so
 * generator-produced config can pass these through unmodified.
 */
typedef enum {
    WH_AUTOSAR_ALGOFAM_NOT_SET  = 0x00,
    WH_AUTOSAR_ALGOFAM_SHA1     = 0x01,
    WH_AUTOSAR_ALGOFAM_SHA2_224 = 0x05,
    WH_AUTOSAR_ALGOFAM_SHA2_256 = 0x06,
    WH_AUTOSAR_ALGOFAM_SHA2_384 = 0x07,
    WH_AUTOSAR_ALGOFAM_SHA2_512 = 0x08,
    WH_AUTOSAR_ALGOFAM_SHA3_256 = 0x0C,
    WH_AUTOSAR_ALGOFAM_SHA3_384 = 0x0D,
    WH_AUTOSAR_ALGOFAM_SHA3_512 = 0x0E,
    WH_AUTOSAR_ALGOFAM_AES      = 0x21,
    WH_AUTOSAR_ALGOFAM_HMAC     = 0x33,
    WH_AUTOSAR_ALGOFAM_CMAC     = 0x34,
    WH_AUTOSAR_ALGOFAM_GMAC     = 0x35,
    WH_AUTOSAR_ALGOFAM_RSA      = 0x47,
    WH_AUTOSAR_ALGOFAM_ECCNIST  = 0x49,
    WH_AUTOSAR_ALGOFAM_ED25519  = 0x4D,
    WH_AUTOSAR_ALGOFAM_X25519   = 0x4E,
    WH_AUTOSAR_ALGOFAM_MLDSA    = 0x60,
    WH_AUTOSAR_ALGOFAM_HKDF     = 0x71,
    WH_AUTOSAR_ALGOFAM_CMAC_KDF = 0x72,
    WH_AUTOSAR_ALGOFAM_RNG      = 0x80
} wh_AutosarAlgoFam;

/*
 * AUTOSAR R22-11 algorithm mode codes (subset).
 */
typedef enum {
    WH_AUTOSAR_ALGOMODE_NOT_SET    = 0x00,
    WH_AUTOSAR_ALGOMODE_ECB        = 0x01,
    WH_AUTOSAR_ALGOMODE_CBC        = 0x02,
    WH_AUTOSAR_ALGOMODE_CTR        = 0x06,
    WH_AUTOSAR_ALGOMODE_GCM        = 0x09,
    WH_AUTOSAR_ALGOMODE_PKCS1_V1_5 = 0x33,
    WH_AUTOSAR_ALGOMODE_PSS        = 0x34,
    WH_AUTOSAR_ALGOMODE_OAEP       = 0x35,
    WH_AUTOSAR_ALGOMODE_ECDSA      = 0x40,
    WH_AUTOSAR_ALGOMODE_ECDH       = 0x41
} wh_AutosarAlgoMode;

/*
 * Crypto service classes carried in Crypto_JobPrimitiveInfo.service.
 * Mirrors Crypto_ServiceInfoType values from R22-11 SWS.
 */
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
    WH_AUTOSAR_SERVICE_RANDOM             = 0x0D,
    WH_AUTOSAR_SERVICE_KEY_GENERATE       = 0x0E,
    WH_AUTOSAR_SERVICE_KEY_DERIVE         = 0x0F,
    WH_AUTOSAR_SERVICE_KEY_EXCHANGE_PUB   = 0x10,
    WH_AUTOSAR_SERVICE_KEY_EXCHANGE_SEC   = 0x11
} wh_AutosarService;

/*
 * Crypto_OperationModeType bitmask from R22-11.
 */
#define WH_AUTOSAR_OPMODE_START 0x01u
#define WH_AUTOSAR_OPMODE_UPDATE 0x02u
#define WH_AUTOSAR_OPMODE_FINISH 0x04u
#define WH_AUTOSAR_OPMODE_SINGLE                          \
    (WH_AUTOSAR_OPMODE_START | WH_AUTOSAR_OPMODE_UPDATE | \
     WH_AUTOSAR_OPMODE_FINISH)

/*
 * Mapped wolfHSM-side identifier for a hash algorithm. Values match the
 * wc_HashType enum from wolfCrypt; -1 means unsupported.
 */
int wh_AutosarMap_HashType(wh_AutosarAlgoFam fam);

/*
 * Resolve a Crypto_AlgorithmInfoType (family, mode, secondaryFam) triple to
 * a single wolfHSM-side "operation kind" code used by the dispatcher. Returns
 * a negative value if the combination is unsupported.
 */
typedef enum {
    WH_AUTOSAR_OP_INVALID = -1,
    WH_AUTOSAR_OP_HASH_SHA224,
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
    WH_AUTOSAR_OP_KEYAGREE_ECDH,
    WH_AUTOSAR_OP_KEYAGREE_X25519,
    WH_AUTOSAR_OP_KDF_HKDF,
    WH_AUTOSAR_OP_KDF_CMAC,
    WH_AUTOSAR_OP_RNG_GENERATE
} wh_AutosarOpKind;

int wh_AutosarMap_OpKind(uint32_t service, uint32_t family, uint32_t mode,
                         uint32_t secondaryFamily, wh_AutosarOpKind* outOp);

/*
 * AUTOSAR uses a 32-bit cryptoKeyId. wolfHSM uses a 16-bit whKeyId. We pack
 * the wolfHSM type/user/id into the low 16 bits and reserve the upper 16
 * bits for AUTOSAR-side bookkeeping (driver object, validity bit). The
 * mapping is reversible.
 */
whKeyId  wh_AutosarMap_KeyIdToWh(uint32_t autosarKeyId);
uint32_t wh_AutosarMap_KeyIdFromWh(whKeyId whId);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WH_AUTOSAR_ALG_MAP_H_ */
