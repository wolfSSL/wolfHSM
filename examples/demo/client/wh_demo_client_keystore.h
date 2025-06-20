#ifndef CLIENT_KEYSTORE_H_
#define CLIENT_KEYSTORE_H_
#include "wolfhsm/wh_client.h"

int wh_DemoClient_KeystoreBasic(whClientContext* clientContext);
int wh_DemoClient_KeystoreCommitKey(whClientContext* clientContext);
int wh_DemoClient_KeystoreAes(whClientContext* clientContext);

#endif /* CLIENT_KEYSTORE_H_ */