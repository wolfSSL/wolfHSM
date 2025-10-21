#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_error.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfcrypt/test/test.h"
#endif

#include "wh_demo_client_wctest.h"

int wh_DemoClient_wcTest(whClientContext* clientContext)
{
    (void)clientContext;
#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    return wolfcrypt_test(NULL);
#else
    return WH_ERROR_NOTIMPL;
#endif
}
