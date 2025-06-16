#include "wolfhsm/wh_client.h"

#include "wolfcrypt/benchmark/benchmark.h"

#include "wh_demo_client_wcbench.h"

int wh_DemoClient_wcBench(whClientContext* clientContext)
{
    return benchmark_test(NULL);
}
