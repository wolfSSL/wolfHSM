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
 * test-refactor/client-server/wh_test_crypto_mlkem.c
 *
 * ML-KEM tests routed through the server:
 *   _whTest_CryptoMlKemMakeCacheKeyEphemeral - cache keygen rejects
 *                                              WH_NVM_FLAGS_EPHEMERAL
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef WOLFSSL_HAVE_MLKEM

/* Cache keygen must reject WH_NVM_FLAGS_EPHEMERAL */
static int _whTest_CryptoMlKemMakeCacheKeyEphemeral(whClientContext* ctx)
{
    whKeyId keyId = WH_KEYID_ERASED;
    int     ret;
    /* Valid level so the server level check cannot mask the gate */
    const int level =
#if !defined(WOLFSSL_NO_ML_KEM_512)
        WC_ML_KEM_512;
#elif !defined(WOLFSSL_NO_ML_KEM_768)
        WC_ML_KEM_768;
#else
        WC_ML_KEM_1024;
#endif

    ret = wh_Client_MlKemMakeCacheKey(ctx, level, &keyId,
                                      WH_NVM_FLAGS_EPHEMERAL, 0, NULL);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("MlKemMakeCacheKey with EPHEMERAL returned %d "
                       "(expected BADARGS)\n",
                       ret);
        return WH_TEST_FAIL;
    }
    WH_TEST_PRINT("ML-KEM CACHE-KEY EPHEMERAL REJECT SUCCESS\n");
    return 0;
}

int whTest_Crypto_MlKem(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoMlKemMakeCacheKeyEphemeral(ctx));
    return 0;
}

#endif /* WOLFSSL_HAVE_MLKEM */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
