#ifndef WOLFHSM_WH_SERVER_KEYSTORE_H
#define WOLFHSM_WH_SERVER_KEYSTORE_H

#include "wolfhsm/wh_server.h"

int hsmGetUniqueId(whServerContext* server);
int hsmCacheKey(whServerContext* server, whNvmMetadata* meta, uint8_t* in);
int hsmReadKey(whServerContext* server, whKeyId keyId, whNvmMetadata* meta,
    uint8_t* out, uint32_t outLen);
int hsmEvictKey(whServerContext* server, uint16_t keyId);
int hsmCommitKey(whServerContext* server, uint16_t keyId);
int hsmEraseKey(whServerContext* server, whNvmId keyId);
int wh_Server_HandleKeyRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint8_t* data, uint16_t* size);

#endif
