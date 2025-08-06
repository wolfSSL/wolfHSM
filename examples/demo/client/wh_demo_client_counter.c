#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wh_demo_client_counter.h"

int wh_DemoClient_Counter(whClientContext* clientContext)
{
    (void)clientContext;
    return WH_ERROR_OK;
}