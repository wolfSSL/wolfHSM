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
 * port/autosar/common/src/wh_autosar_alg_map.c
 */

#include "wh_autosar_alg_map.h"

#include "wolfhsm/wh_error.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/hash.h"
#endif

int wh_AutosarMap_HashType(wh_AutosarAlgoFam fam)
{
#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)fam;
    return -1;
#else
    switch (fam) {
        case WH_AUTOSAR_ALGOFAM_SHA2_256:
            return WC_HASH_TYPE_SHA256;
        case WH_AUTOSAR_ALGOFAM_SHA2_384:
            return WC_HASH_TYPE_SHA384;
        case WH_AUTOSAR_ALGOFAM_SHA2_512:
            return WC_HASH_TYPE_SHA512;
        default:
            return -1;
    }
#endif
}

int wh_AutosarMap_OpKind(uint32_t service, uint32_t family, uint32_t mode,
                         uint32_t secondaryFamily, wh_AutosarOpKind* outOp)
{
    wh_AutosarOpKind op = WH_AUTOSAR_OP_INVALID;

    if (outOp == NULL) {
        return WH_ERROR_BADARGS;
    }

    (void)secondaryFamily;

    switch (service) {
        case WH_AUTOSAR_SERVICE_HASH:
            switch (family) {
                case WH_AUTOSAR_ALGOFAM_SHA2_256:
                    op = WH_AUTOSAR_OP_HASH_SHA256;
                    break;
                case WH_AUTOSAR_ALGOFAM_SHA2_384:
                    op = WH_AUTOSAR_OP_HASH_SHA384;
                    break;
                case WH_AUTOSAR_ALGOFAM_SHA2_512:
                    op = WH_AUTOSAR_OP_HASH_SHA512;
                    break;
                default:
                    break;
            }
            break;

        case WH_AUTOSAR_SERVICE_MAC_GENERATE:
        case WH_AUTOSAR_SERVICE_MAC_VERIFY:
            if (family == WH_AUTOSAR_ALGOFAM_AES &&
                mode == WH_AUTOSAR_ALGOMODE_CMAC) {
                op = WH_AUTOSAR_OP_MAC_CMAC_AES;
            }
            break;

        case WH_AUTOSAR_SERVICE_ENCRYPT:
        case WH_AUTOSAR_SERVICE_DECRYPT:
            if (family == WH_AUTOSAR_ALGOFAM_AES) {
                switch (mode) {
                    case WH_AUTOSAR_ALGOMODE_ECB:
                        op = WH_AUTOSAR_OP_CIPHER_AES_ECB;
                        break;
                    case WH_AUTOSAR_ALGOMODE_CBC:
                        op = WH_AUTOSAR_OP_CIPHER_AES_CBC;
                        break;
                    case WH_AUTOSAR_ALGOMODE_CTR:
                        op = WH_AUTOSAR_OP_CIPHER_AES_CTR;
                        break;
                    default:
                        break;
                }
            }
            break;

        case WH_AUTOSAR_SERVICE_AEAD_ENCRYPT:
        case WH_AUTOSAR_SERVICE_AEAD_DECRYPT:
            if (family == WH_AUTOSAR_ALGOFAM_AES &&
                mode == WH_AUTOSAR_ALGOMODE_GCM) {
                op = WH_AUTOSAR_OP_AEAD_AES_GCM;
            }
            break;

        case WH_AUTOSAR_SERVICE_SIGNATURE_GENERATE:
        case WH_AUTOSAR_SERVICE_SIGNATURE_VERIFY:
            if (family == WH_AUTOSAR_ALGOFAM_RSA) {
                if (mode == WH_AUTOSAR_ALGOMODE_PSS) {
                    op = WH_AUTOSAR_OP_SIG_RSA_PSS;
                }
                else if (mode == WH_AUTOSAR_ALGOMODE_PKCS1_V1_5) {
                    op = WH_AUTOSAR_OP_SIG_RSA_PKCS1_V1_5;
                }
            }
            else if (family == WH_AUTOSAR_ALGOFAM_ECCNIST ||
                     family == WH_AUTOSAR_ALGOFAM_ECDSA) {
                op = WH_AUTOSAR_OP_SIG_ECDSA;
            }
            else if (family == WH_AUTOSAR_ALGOFAM_ED25519) {
                op = WH_AUTOSAR_OP_SIG_ED25519;
            }
            else if (family == WH_AUTOSAR_ALGOFAM_MLDSA) {
                op = WH_AUTOSAR_OP_SIG_MLDSA;
            }
            break;

        case WH_AUTOSAR_SERVICE_RANDOM:
            op = WH_AUTOSAR_OP_RNG_GENERATE;
            break;

        /* Key management jobs take their algorithm from the key's
         * descriptor, not from the job's primitive info. */
        case WH_AUTOSAR_SERVICE_RANDOM_SEED:
            op = WH_AUTOSAR_OP_RANDOM_SEED;
            break;
        case WH_AUTOSAR_SERVICE_KEY_GENERATE:
            op = WH_AUTOSAR_OP_KEY_GENERATE;
            break;
        case WH_AUTOSAR_SERVICE_KEY_DERIVE:
            op = WH_AUTOSAR_OP_KEY_DERIVE;
            break;
        case WH_AUTOSAR_SERVICE_KEY_EXCHANGE_PUB:
            op = WH_AUTOSAR_OP_KEY_EXCHANGE_PUB;
            break;
        case WH_AUTOSAR_SERVICE_KEY_EXCHANGE_SEC:
            op = WH_AUTOSAR_OP_KEY_EXCHANGE_SEC;
            break;
        case WH_AUTOSAR_SERVICE_KEY_SET_VALID:
            op = WH_AUTOSAR_OP_KEY_SET_VALID;
            break;
        case WH_AUTOSAR_SERVICE_KEY_SET_INVALID:
            op = WH_AUTOSAR_OP_KEY_SET_INVALID;
            break;

        default:
            break;
    }

    *outOp = op;
    return (op == WH_AUTOSAR_OP_INVALID) ? WH_ERROR_NOTIMPL : WH_ERROR_OK;
}
