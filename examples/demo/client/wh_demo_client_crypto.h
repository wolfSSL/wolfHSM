#ifndef DEMO_CLIENT_CRYPTO_H_
#define DEMO_CLIENT_CRYPTO_H_

#include "wolfhsm/wh_client.h"

int wh_DemoClient_CryptoRsa(whClientContext* clientContext);
int wh_DemoClient_CryptoRsaImport(whClientContext* clientContext);

int wh_DemoClient_CryptoCurve25519(whClientContext* clientContext);
int wh_DemoClient_CryptoCurve25519Import(whClientContext* clientContext);

int wh_DemoClient_CryptoEcc(whClientContext* clientContext);
int wh_DemoClient_CryptoEccImport(whClientContext* clientContext);

int wh_DemoClient_CryptoAesCbc(whClientContext* clientContext);
int wh_DemoClient_CryptoAesCbcImport(whClientContext* clientContext);

int wh_DemoClient_CryptoAesGcm(whClientContext* clientContext);
int wh_DemoClient_CryptoAesGcmImport(whClientContext* clientContext);

int wh_DemoClient_CryptoCmac(whClientContext* clientContext);
int wh_DemoClient_CryptoCmacImport(whClientContext* clientContext);
int wh_DemoClient_CryptoCmacOneshotImport(whClientContext* clientContext);

int wh_DemoClient_CryptoHkdfExport(whClientContext* clientContext);
int wh_DemoClient_CryptoHkdfCache(whClientContext* clientContext);
int wh_DemoClient_CryptoHkdfCacheInputKey(whClientContext* clientContext);

int wh_DemoClient_CryptoCmacKdfExport(whClientContext* clientContext);
int wh_DemoClient_CryptoCmacKdfCache(whClientContext* clientContext);
int wh_DemoClient_CryptoCmacKdfCacheInputs(whClientContext* clientContext);

#endif /* !DEMO_CLIENT_CRYPTO_H_ */
