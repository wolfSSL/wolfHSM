#ifndef DEMO_CLIENT_KEYWRAP_H_
#define DEMO_CLIENT_KEYWRAP_H_

#include "wolfhsm/wh_client.h"

/* Exposed in header so the demo server can obtain the ID for registration */
#define WH_DEMO_KEYWRAP_AESGCM_WRAPKEY_ID 8

/* Id of the trusted key-encryption key (KEK) the demo names in wrap/unwrap
 * requests. A client cannot create a trusted KEK, so the server must
 * provision one at this id before the demo runs. Exposed in header so server
 * provisioning code uses the same id. */
#define WH_DEMO_KEYWRAP_KEK_ID 9

int wh_DemoClient_KeyWrap(whClientContext* clientContext);

#endif /* !DEMO_CLIENT_KEYWRAP_H_ */
