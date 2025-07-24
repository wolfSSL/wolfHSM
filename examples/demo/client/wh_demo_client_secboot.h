#ifndef DEMO_CLIENT_SECBOOT_H_
#define DEMO_CLIENT_SECBOOT_H_

#include "wolfhsm/wh_client.h"

int wh_DemoClient_SecBoot_Provision(whClientContext* clientContext);
int wh_DemoClient_SecBoot_Boot(whClientContext* clientContext);
int wh_DemoClient_SecBoot_Zeroize(whClientContext* clientContext);

#endif /* !DEMO_CLIENT_SECBOOT_H_ */