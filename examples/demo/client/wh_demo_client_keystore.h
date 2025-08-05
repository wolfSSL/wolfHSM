#ifndef DEMO_CLIENT_KEYSTORE_H_
#define DEMO_CLIENT_KEYSTORE_H_

#include "wolfhsm/wh_client.h"

int wh_DemoClient_KeystoreBasic(whClientContext* clientContext);
int wh_DemoClient_KeystoreCommitKey(whClientContext* clientContext);
int wh_DemoClient_KeystoreAes(whClientContext* clientContext);

#endif /* !DEMO_CLIENT_KEYSTORE_H_ */