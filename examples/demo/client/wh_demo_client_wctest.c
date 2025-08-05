#include "wolfhsm/wh_client.h"

#include "wolfcrypt/test/test.h"

#include "wh_demo_client_counter.h"

int wh_DemoClient_wcTest(whClientContext* clientContext)
{
    (void)clientContext;
    return wolfcrypt_test(NULL);
}
