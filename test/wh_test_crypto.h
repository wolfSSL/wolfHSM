#ifndef WH_TEST_CRYPTO_H_
#define WH_TEST_CRYPTO_H_

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

int whTest_Crypto(void);
int whTest_CryptoClientConfig(whClientConfig* cf);
int whTest_CryptoServerConfig(whServerConfig* cfg);



#endif /* WH_TEST_COMM_H_ */
