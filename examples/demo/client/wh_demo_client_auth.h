#ifndef DEMO_CLIENT_AUTH_H_
#define DEMO_CLIENT_AUTH_H_

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_auth.h"

/*
 * Simple Auth Manager demo entry point.
 *
 * This is intentionally a thin wrapper around the conceptual auth client
 * APIs. It is expected to evolve as the Auth Manager is implemented.
 * For now, it is primarily a place to experiment with control flow and
 * logging without enforcing any particular backend design.
 */
int wh_DemoClient_Auth(whClientContext* clientContext);

#endif /* !DEMO_CLIENT_AUTH_H_ */
