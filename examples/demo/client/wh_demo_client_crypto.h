#ifndef CLIENT_CRYPTO_H_
#define CLIENT_CRYPTO_H_
#include "wolfhsm/wh_client.h"

#if !defined(NO_RSA)
int wh_DemoClient_CryptoRsa(whClientContext* clientContext);
int wh_DemoClient_CryptoRsaImport(whClientContext* clientContext);
#endif

#ifdef HAVE_CURVE25519
int wh_DemoClient_CryptoCurve25519(whClientContext* clientContext);
int wh_DemoClient_CryptoCurve25519Import(whClientContext* clientContext);
#endif /* HAVE_CURVE25519 */

#if defined(HAVE_ECC)
int wh_DemoClient_CryptoEcc(whClientContext* clientContext);
int wh_DemoClient_CryptoEccImport(whClientContext* clientContext);
#endif /* !NO_ECC && HAVE_ECC */

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
int wh_DemoClient_CryptoAesCbc(whClientContext* clientContext);
int wh_DemoClient_CryptoAesCbcImport(whClientContext* clientContext);
#endif /* !NO_AES && HAVE_AES */

#if !defined(NO_AES) && defined(HAVE_AESGCM)
int wh_DemoClient_CryptoAesGcm(whClientContext* clientContext);
int wh_DemoClient_CryptoAesGcmImport(whClientContext* clientContext);
#endif /* !NOAES && HAVE_AES && HAVE_ASEGCM */

#ifdef WOLFSSL_CMAC
int wh_DemoClient_CryptoCmac(whClientContext* clientContext);
int wh_DemoClient_CryptoCmacImport(whClientContext* clientContext);
int wh_DemoClient_CryptoCmacOneshotImport(whClientContext* clientContext);
#endif /* WOLFSSL_CMAC */

#endif /* CLIENT_CRYPTO_H_ */
