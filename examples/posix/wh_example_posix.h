/* contains function decleration for transport types */


#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

int wh_Client_ExampleSHMConfig(whClientConfig* c_conf);
int wh_Server_ExampleSHMConfig(whServerConfig* s_conf);

int wh_Client_ExampleTCPConfig(whClientConfig* c_conf);
int wh_Server_ExampleTCPConfig(whServerConfig* s_conf);
