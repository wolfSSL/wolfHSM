#include "wh_demo_client_wctest.h"
#include "wh_demo_client_wcbench.h"
#include "wh_demo_client_nvm.h"
#include "wh_demo_client_auth.h"
#include "wh_demo_client_keystore.h"
#include "wh_demo_client_crypto.h"
#include "wh_demo_client_secboot.h"
#include "wh_demo_client_keywrap.h"
#include "wh_demo_client_all.h"

int wh_DemoClient_All(whClientContext* clientContext)
{
    int rc = 0;
    whUserId userId = WH_USER_ID_INVALID;
    whAuthPermissions permissions;

    /* Auth demos */
    rc = wh_DemoClient_Auth(clientContext);
    if (rc != 0) {
        return rc;
    }

    /* Log in as an admin user for the rest of the tests */
    if (wh_Client_AuthLogin(clientContext, WH_AUTH_METHOD_PIN, "admin", "1234",
        4, &rc, &userId, &permissions) != 0) {
        return -1;
    }
    if (rc != 0) {
        return rc;
    }

    /* wolfCrypt test and benchmark */
#ifdef WH_DEMO_WCTEST
    rc = wh_DemoClient_wcTest(clientContext);
    if (rc != 0) {
            return rc;
    }
#endif
#ifdef WH_DEMO_WCBENCH
    rc = wh_DemoClient_wcBench(clientContext);
    if (rc != 0) {
            return rc;
    }
#endif
    /* NVM demos */
    rc = wh_DemoClient_Nvm(clientContext);
    if (rc != 0) {
        return rc;
    }

    /* Keystore demos */
    rc = wh_DemoClient_KeystoreBasic(clientContext);
    if (rc != 0) {
        return rc;
    }
    rc = wh_DemoClient_KeystoreCommitKey(clientContext);
    if (rc != 0) {
        return rc;
    }

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && !defined(NO_AES)
    rc = wh_DemoClient_KeystoreAes(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif

#ifdef WOLFHSM_CFG_KEYWRAP
    rc = wh_DemoClient_KeyWrap(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif /* WOLFHSM_CFG_KEYWRAP */

    /**Crypto demos */
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && !defined(NO_RSA)
    rc = wh_DemoClient_CryptoRsa(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoRsaImport(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif /* !NO_RSA */

#ifdef HAVE_CURVE25519
    rc = wh_DemoClient_CryptoCurve25519(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCurve25519Import(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ECC
    rc = wh_DemoClient_CryptoEcc(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoEccImport(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif /* HAVE_ECC */

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    rc = wh_DemoClient_CryptoAesCbc(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoAesCbcImport(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif /* !NO_AES && HAVE_AES_CBC */

    #if !defined(NO_AES) && defined(HAVE_AESGCM)
    rc = wh_DemoClient_CryptoAesGcm(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoAesGcmImport(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif /* !NO_AES && HAVE_AESGCM */

#ifdef HAVE_HKDF
    rc = wh_DemoClient_CryptoHkdfExport(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoHkdfCache(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoHkdfCacheInputKey(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif /* HAVE_HKDF */

#if defined(HAVE_CMAC_KDF) && defined(WOLFSSL_CMAC)
    rc = wh_DemoClient_CryptoCmacKdfExport(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCmacKdfCache(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCmacKdfCacheInputs(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif /* HAVE_CMAC_KDF && WOLFSSL_CMAC */

#if defined(WOLFSSL_CMAC)
    rc = wh_DemoClient_CryptoCmac(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCmacImport(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCmacOneshotImport(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_SecBoot_Provision(clientContext);
    if (rc != 0) {
        return rc;
    }
    rc = wh_DemoClient_SecBoot_Boot(clientContext);
    if (rc != 0) {
        return rc;
    }
    rc = wh_DemoClient_SecBoot_Zeroize(clientContext);
    if (rc != 0) {
        return rc;
    }

#endif /* WOLFSSL_CMAC */

    return rc;
}
