#ifndef DEMO_CLIENT_AUTH_H_
#define DEMO_CLIENT_AUTH_H_

#include "wolfhsm/wh_client.h"

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
#include "wolfhsm/wh_auth.h"

/*
 * Simple Auth Manager demo entry point.
 */
int wh_DemoClient_Auth(whClientContext* clientContext);
#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION */

#endif /* !DEMO_CLIENT_AUTH_H_ */
