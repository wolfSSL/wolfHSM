#ifndef WOLFHSM_WH_SERVER_CRYPTO_H
#define WOLFHSM_WH_SERVER_CRYPTO_H
#include "wolfhsm/wh_server.h"
int _wh_Server_HandleCryptoRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size);
#endif
