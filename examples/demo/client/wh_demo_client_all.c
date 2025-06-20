#include "wh_demo_client_all.h"
#include "wh_demo_client_nvm.h"
#include "wh_demo_client_keystore.h"
#include "wh_demo_client_crypto.h"
#include "wh_demo_client_wctest.h"
#include "wh_demo_client_wcbench.h"

int wh_DemoClient_All(whClientContext* clientContext)
{
    int rc = 0;

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
#ifndef NO_AES
    rc = wh_DemoClient_KeystoreAes(clientContext);
    if (rc != 0) {
        return rc;
    }
#endif

    /**Crypto demos */
#ifndef NO_RSA
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
#endif /* WOLFSSL_CMAC */

    return rc;
}
