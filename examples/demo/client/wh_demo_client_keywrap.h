#ifndef DEMO_CLIENT_KEYWRAP_H_
#define DEMO_CLIENT_KEYWRAP_H_

#include "wolfhsm/wh_client.h"

/* Exposed in header so the demo server can obtain the ID for registration */
#define WH_DEMO_KEYWRAP_AESGCM_WRAPKEY_ID 8

int wh_DemoClient_KeyWrap(whClientContext* clientContext);

#endif /* !DEMO_CLIENT_KEYWRAP_H_ */
