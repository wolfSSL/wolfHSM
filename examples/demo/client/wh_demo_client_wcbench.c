#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_error.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfcrypt/benchmark/benchmark.h"
#endif

#include "wh_demo_client_wcbench.h"

int wh_DemoClient_wcBench(whClientContext* clientContext)
{
    (void)clientContext;
#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    return benchmark_test(NULL);
#else
    return WH_ERROR_NOTIMPL;
#endif
}
