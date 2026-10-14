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
 * test-refactor/client-server/wh_test_crypto_sm2.c
 *
 * SM2 sign, verify and key agreement routed through the server.
 *
 * Sign and verify are checked against software in both directions rather
 * than only against each other: a signature made on the HSM is verified in
 * software, and one made in software is verified on the HSM. Checking them
 * only against themselves would pass even if both sides shared a fault.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/asn.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFSSL_SM2) && defined(HAVE_ECC)

#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
/* Copy an SM2 key so the same key material can be driven through a second
 * context bound to a different devId. */
static int _Sm2CopyKey(ecc_key* dst, ecc_key* src)
{
    byte   der[ECC_BUFSIZE];
    word32 derSz = (word32)sizeof(der);
    int    ret;

    ret = wc_EccKeyToDer(src, der, derSz);
    if (ret < 0) {
        return ret;
    }
    derSz = (word32)ret;

    {
        word32 idx = 0;
        ret        = wc_EccPrivateKeyDecode(der, &idx, dst, derSz);
    }
    return ret;
}

static int _whTest_Sm2SignVerify(WC_RNG* rng, ecc_key* hsmKey)
{
    int     ret;
    int     i;
    ecc_key swKey[1];
    byte    hash[32];
    byte    sig[ECC_MAX_SIG_SIZE];
    word32  sigLen   = sizeof(sig);
    int     verified = 0;

    memset(hash, 0x7C, sizeof(hash));

    /* The same key material in a software-only context, so each side can
     * check the other's work. */
    ret = wc_ecc_init_ex(swKey, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = _Sm2CopyKey(swKey, hsmKey);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to copy the SM2 key to software: %d\n", ret);
        goto done;
    }

    /* Sign on the HSM, verify in software */
    ret = wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, hsmKey);
    if (ret != 0) {
        WH_ERROR_PRINT("SM2 HSM sign failed: %d\n", ret);
        goto done;
    }
    ret = wc_ecc_sm2_verify_hash(sig, sigLen, hash, sizeof(hash), &verified,
                                 swKey);
    if (ret != 0) {
        WH_ERROR_PRINT("Software verify of an HSM signature failed: %d\n", ret);
        goto done;
    }
    if (!verified) {
        WH_ERROR_PRINT("Software rejected an HSM-produced SM2 signature\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    /* Sign in software, verify on the HSM */
    sigLen   = sizeof(sig);
    verified = 0;
    ret = wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, swKey);
    if (ret != 0) {
        WH_ERROR_PRINT("SM2 software sign failed: %d\n", ret);
        goto done;
    }
    ret = wc_ecc_sm2_verify_hash(sig, sigLen, hash, sizeof(hash), &verified,
                                 hsmKey);
    if (ret != 0) {
        WH_ERROR_PRINT("HSM verify of a software signature failed: %d\n", ret);
        goto done;
    }
    if (!verified) {
        WH_ERROR_PRINT("HSM rejected a software-produced SM2 signature\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    /* A tampered signature must not verify. Going past the key cache size
     * also shows each rejected request evicts its temporary key. */
    sig[sigLen / 2] ^= 0xFF;
    for (i = 0; i <= WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        verified = 1;
        ret = wc_ecc_sm2_verify_hash(sig, sigLen, hash, sizeof(hash), &verified,
                                     hsmKey);
        if ((ret == 0) && verified) {
            WH_ERROR_PRINT("SM2 verified a tampered signature\n");
            ret = WH_TEST_FAIL;
            goto done;
        }
    }
    sig[sigLen / 2] ^= 0xFF;
    verified = 0;
    ret = wc_ecc_sm2_verify_hash(sig, sigLen, hash, sizeof(hash), &verified,
                                 hsmKey);
    if ((ret != 0) || !verified) {
        WH_ERROR_PRINT("SM2 verify failed after rejected verifies: %d\n", ret);
        ret = WH_TEST_FAIL;
    }

done:
    wc_ecc_free(swKey);
    return ret;
}

/* A short buffer reports the needed length, and a capacity above UINT16_MAX
 * is not truncated to zero */
static int _whTest_Sm2SignSize(WC_RNG* rng, ecc_key* hsmKey)
{
    int    ret;
    byte   hash[32];
    byte   sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = 1;

    memset(hash, 0x7C, sizeof(hash));

    ret = wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, hsmKey);
    if ((ret != BUFFER_E) || (sigLen <= 1) || (sigLen > sizeof(sig))) {
        WH_ERROR_PRINT("SM2 sign into a short buffer: ret %d, len %u\n", ret,
                       (unsigned)sigLen);
        return WH_TEST_FAIL;
    }

    /* Only the signature is written, so the overstated capacity is safe */
    sigLen = (word32)UINT16_MAX + 1;
    ret = wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, hsmKey);
    if ((ret != 0) || (sigLen > sizeof(sig))) {
        WH_ERROR_PRINT("SM2 sign with a large capacity: ret %d, len %u\n", ret,
                       (unsigned)sigLen);
        return WH_TEST_FAIL;
    }
    return 0;
}

/* Sign with a key the client only knows by id */
static int _whTest_Sm2KeyId(whClientContext* ctx, WC_RNG* rng, ecc_key* hsmKey)
{
    int     ret;
    ecc_key idKey[1];
    whKeyId keyId   = WH_KEYID_ERASED;
    uint8_t label[] = "sm2-cached";
    byte    hash[32];
    byte    sig[ECC_MAX_SIG_SIZE];
    word32  sigLen   = sizeof(sig);
    int     verified = 0;

    memset(hash, 0x7C, sizeof(hash));

    ret = wh_Client_EccImportKey(ctx, hsmKey, &keyId,
                                 WH_NVM_FLAGS_USAGE_SIGN |
                                     WH_NVM_FLAGS_USAGE_VERIFY,
                                 sizeof(label), label);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache the SM2 key: %d\n", ret);
        return ret;
    }

    ret = wc_ecc_init_ex(idKey, NULL, WH_CLIENT_DEVID(ctx));
    if (ret == 0) {
        ret = wc_ecc_set_curve(idKey, 32, ECC_SM2P256V1);
        if (ret == 0) {
            ret = wh_Client_EccSetKeyId(idKey, keyId);
        }
        if (ret == 0) {
            ret = wc_ecc_sm2_sign_hash(hash, sizeof(hash), sig, &sigLen, rng,
                                       idKey);
        }
        if (ret == 0) {
            ret = wc_ecc_sm2_verify_hash(sig, sigLen, hash, sizeof(hash),
                                         &verified, hsmKey);
        }
        if ((ret == 0) && !verified) {
            ret = WH_TEST_FAIL;
        }
        wc_ecc_free(idKey);
    }
    (void)wh_Client_KeyEvict(ctx, keyId);

    if (ret != 0) {
        WH_ERROR_PRINT("SM2 sign by key id failed: %d\n", ret);
    }
    return ret;
}
#endif /* HAVE_ECC_SIGN && HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_DHE
/* The HSM result must equal the same agreement computed the other way round,
 * and a short buffer must report the needed length */
static int _whTest_Sm2SharedSecret(WC_RNG* rng, ecc_key* hsmKey)
{
    int     ret;
    ecc_key peer[1];
    byte    hsmSecret[32];
    byte    swSecret[32];
    word32  hsmLen = sizeof(hsmSecret);
    word32  swLen  = sizeof(swSecret);

    ret = wc_ecc_init_ex(peer, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }

    ret = wc_ecc_set_curve(peer, 32, ECC_SM2P256V1);
    if (ret == 0) {
        ret = wc_ecc_make_key_ex(rng, 32, peer, ECC_SM2P256V1);
    }
    if (ret == 0) {
        ret = wc_ecc_set_rng(hsmKey, rng);
    }
    if (ret == 0) {
        ret = wc_ecc_set_rng(peer, rng);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set up the peer SM2 key: %d\n", ret);
        goto done;
    }

    ret = wc_ecc_sm2_shared_secret(hsmKey, peer, hsmSecret, &hsmLen);
    if (ret != 0) {
        WH_ERROR_PRINT("SM2 HSM shared secret failed: %d\n", ret);
        goto done;
    }
    ret = wc_ecc_sm2_shared_secret(peer, hsmKey, swSecret, &swLen);
    if (ret != 0) {
        WH_ERROR_PRINT("SM2 peer shared secret failed: %d\n", ret);
        goto done;
    }
    if ((hsmLen != swLen) || (memcmp(hsmSecret, swSecret, hsmLen) != 0)) {
        WH_ERROR_PRINT("SM2 shared secrets do not match\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    hsmLen = 1;
    ret    = wc_ecc_sm2_shared_secret(hsmKey, peer, hsmSecret, &hsmLen);
    if ((ret != BUFFER_E) || (hsmLen != swLen)) {
        WH_ERROR_PRINT("SM2 shared secret into a short buffer: ret %d, "
                       "len %u\n",
                       ret, (unsigned)hsmLen);
        ret = WH_TEST_FAIL;
        goto done;
    }
    ret = 0;

done:
    wc_ecc_free(peer);
    return ret;
}
#endif /* HAVE_ECC_DHE */

static int _whTest_Sm2(whClientContext* ctx)
{
    int     devId = WH_CLIENT_DEVID(ctx);
    int     ret;
    ecc_key hsmKey[1];
    WC_RNG  rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_ecc_init_ex(hsmKey, NULL, devId);
    if (ret == 0) {
        ret = wc_ecc_set_curve(hsmKey, 32, ECC_SM2P256V1);
        if (ret == 0) {
            ret = wc_ecc_make_key_ex(rng, 32, hsmKey, ECC_SM2P256V1);
        }
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate an SM2 key: %d\n", ret);
        }
#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
        if (ret == 0) {
            ret = _whTest_Sm2SignVerify(rng, hsmKey);
        }
        if (ret == 0) {
            ret = _whTest_Sm2SignSize(rng, hsmKey);
        }
        if (ret == 0) {
            ret = _whTest_Sm2KeyId(ctx, rng, hsmKey);
        }
#endif
#ifdef HAVE_ECC_DHE
        if (ret == 0) {
            ret = _whTest_Sm2SharedSecret(rng, hsmKey);
        }
#endif
        wc_ecc_free(hsmKey);
    }
    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("SM2 SIGN/VERIFY/DH DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

int whTest_Crypto_Sm2(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_Sm2(ctx));
    return 0;
}

#endif /* WOLFSSL_SM2 && HAVE_ECC */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
