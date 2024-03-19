/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"
#include "wolfhsm/wh_server_she.h"

int wh_Server_Init(whServerContext* server, whServerConfig* config)
{
    int rc = 0;
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(server, 0, sizeof(*server));
    if (
/*            ((rc = wh_Nvm_Init(server->nvm_device, config->nvm_device)) == 0) && */
        ((rc = wh_CommServer_Init(server->comm, config->comm)) == 0) &&
        ((rc = wolfCrypt_Init()) == 0) &&
        ((rc = wc_InitRng_ex(server->crypto->rng, NULL, INVALID_DEVID)) == 0) &&
/*        ((rc = server->nvm->cb->Init(server->nvm, config->nvm)) == 0) && */
        1) {
        /* All good */
    } else {
        wh_Server_Cleanup(server);
    }
    /* WC_INIT_E, WC_HW_E*/
    return rc;
}

static int _wh_Server_HandleCommRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t* out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
    case WH_MESSAGE_COMM_ACTION_ECHO:
    {
        whMessageCommLenData req = {0};
        whMessageCommLenData resp = {0};

        /* Convert request struct */
        wh_MessageComm_TranslateLenData(magic,
                (whMessageCommLenData*)req_packet, &req);

        /* Process the echo action */
        resp.len = req.len;
        memcpy(resp.data, req.data, resp.len);

        /* Convert the response struct */
        wh_MessageComm_TranslateLenData(magic,
                &resp, (whMessageCommLenData*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

static int _wh_Server_HandleNvmRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
#if 0
    case WH_MESSAGE_NVM_ACTION_AVAILABLE:
    {
        whMessageNvmAvailableRequest req = {0};
        whMessageNvmAvailableResponse resp = {0};

        /* Convert request struct */
        wh_MessageNvm_TranslateAvailableRequest(magic,
                (whMessageNvmAvailableRequest*)req_packet, &req);

        /* Process the available action */
        resp.rc = server->nvm->cb->GetAvailable(server->nvm,
                &resp.available_objects, &resp.available_bytes,
                &resp.recoverable_object, &resp.recoverable_bytes);

        /* Convert the response struct */
        wh_MessageNvm_TranslateAvailableResponse(magic,
                &resp, (whMessageNvmAvailableResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;
#endif
    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

static int _wh_Server_HandleKeyRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
#if 0
    int ret = 0;
    uint8_t* in;
    uint8_t* out;
    switch (packet->subType)
    {
    case WOLFHSM_KEY_CACHE:
        /* in is after fixed size fields */
        in = (uint8_t*)(&packet->keyCacheReq + 1);
        /* set the metadata fields */
        meta->id = packet->keyCacheReq.id;
        meta->flags = packet->keyCacheReq.flags;
        meta->len = packet->keyCacheReq.len;
        XMEMCPY(meta->label, packet->keyCacheReq.label, WOLFHSM_NVM_LABEL_LEN);
        /* get a new id if one wasn't provided */
        if (meta->id == WOLFHSM_ID_ERASED) {
            ret =  hsmGetUniqueId(ctx);
            if (ret > 0) {
                meta->id = ret;
                ret = 0;
            }
        }
        /* write the key */
        if (ret == 0)
            ret = hsmCacheKey(ctx, meta, in);
        if (ret == 0) {
            packet->subType = WOLFHSM_KEY_CACHE;
            packet->len = sizeof(packet->keyCacheRes);
            packet->keyCacheRes.id = meta->id;
        }
        break;
    case WOLFHSM_KEY_EVICT:
        ret = hsmEvictKey(ctx, packet->keyEvictReq.id);
        if (ret == 0) {
            packet->subType = WOLFHSM_KEY_EVICT;
            packet->len = sizeof(packet->keyEvictRes);
            packet->keyEvictRes.ok = 0;
        }
        break;
    case WOLFHSM_KEY_COMMIT:
        /* commit the cached key */
        ret = hsmCommitKey(ctx, packet->keyCommitReq.id);
        if (ret > 0) {
            packet->subType = WOLFHSM_KEY_COMMIT;
            packet->len = sizeof(packet->keyCommitRes);
            packet->keyCommitRes.ok = 0;
            ret = 0;
        }
        break;
    case WOLFHSM_KEY_EXPORT:
        /* out is after fixed size fields */
        out = (uint8_t*)(&packet->keyExportRes + 1);
        /* set the metadata fields */
        meta->id = packet->keyExportReq.id;
        meta->len = WOLFHSM_KEYSIZE;
        /* read the key */
        ret = hsmReadKey(ctx, meta, out);
        if (ret == 0) {
            packet->subType = WOLFHSM_KEY_EXPORT;
            /* set return len */
            packet->len = sizeof(packet->keyExportRes) + meta->len;
            /* set key len */
            packet->keyExportRes.len = meta->len;
            /* set label */
            XMEMCPY(packet->keyExportRes.label, meta->label, sizeof(meta->label));
        }
        break;
    case WOLFHSM_KEY_ERASE:
        ret = hsmEraseKey(ctx, packet->keyEraseReq.id);
        if (ret == 0) {
            packet->subType = WOLFHSM_KEY_ERASE;
            packet->len = sizeof(packet->keyEraseRes);
            packet->keyEraseRes.ok = 0;
        }
        break;
    case WOLFHSM_VERSION_EXCHANGE:
        /* TODO should the server refuse a connection or should the client
         * decide? */
        packet->subType = WOLFHSM_VERSION_EXCHANGE;
        packet->versionExchange.version = ctx->version;
        packet->len = sizeof(packet->versionExchange);
        break;
    default:
        ret = BAD_FUNC_ARG;
        break;
    }
    /* set type here in case packet was overwritten */
    packet->type = WOLFHSM_MANAGE;
    return ret;
#endif
    (void)server;
    (void)magic;
    (void)action;
    (void)seq;
    (void)req_size;
    (void)req_packet;
    (void)out_resp_size;
    (void)resp_packet;
    return 0;
}

static int _wh_Server_HandlePkcs11Request(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
    /* TODO: Add PKCS11 message handling here */
    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

#ifdef WOLFHSM_SHE_EXTENSION
static int _wh_Server_HandleSheRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
    /* TODO: Add AUTOSAR SHE message handling here */
    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}
#endif

static int _wh_Server_HandleCustomRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
    /* TODO: Add custom/user callback message handling here */
    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

int wh_Server_HandleRequestMessage(whServerContext* server)
{
    uint16_t magic = 0;
    uint16_t kind = 0;
    uint16_t group = 0;
    uint16_t action = 0;
    uint16_t seq = 0;
    uint16_t size = 0;
    uint8_t data[WH_COMM_MTU] = {0};

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }
    int rc = wh_CommServer_RecvRequest(server->comm, &magic, &kind, &seq,
            &size, data);
    /* Got a packet? */
    if (rc == 0) {
        group = WH_MESSAGE_GROUP(kind);
        action = WH_MESSAGE_ACTION(kind);
        switch (group) {
        case WH_MESSAGE_GROUP_COMM: {
            rc = _wh_Server_HandleCommRequest(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
        case WH_MESSAGE_GROUP_NVM: {
            rc = _wh_Server_HandleNvmRequest(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
        case WH_MESSAGE_GROUP_KEY: {
            rc = _wh_Server_HandleKeyRequest(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
        case WH_MESSAGE_GROUP_CRYPTO: {
            rc = _wh_Server_HandleCryptoRequest(server, &action, data, &size);
        }; break;
        case WH_MESSAGE_GROUP_PKCS11: {
            rc = _wh_Server_HandlePkcs11Request(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
#ifdef WOLFHSM_SHE_EXTENSION
        case WOLFHSM_MESSAGE_GROUP_SHE: {
            rc = _wh_Server_HandleSheRequest(data, size);
        }; break;
#endif
        case WH_MESSAGE_GROUP_CUSTOM: {
            rc = _wh_Server_HandleCustomRequest(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
        default:
            /* Unknown group. Return empty packet*/
            /* TODO: Respond with aux error flag */
            size = 0;
        }
    }
    /* Send a response */
    /* TODO: Response with ErrorResponse if handler returns an error */
    if (rc == 0) {
        do {
            rc = wh_CommServer_SendResponse(server->comm, magic, kind, seq,
                size, data);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

int wh_Server_Cleanup(whServerContext* server)
{
    if (server ==NULL) {
         return WH_ERROR_BADARGS;
     }
#if 0
     if (server->nvm != NULL) {
         /*(void)wh_Nvm_Cleanup(server->nvm);*/
     }
#endif
    (void)wh_CommServer_Cleanup(server->comm);
    (void)wolfCrypt_Cleanup();
    memset(server, 0, sizeof(*server));
    return 0;
}

#if 0
/** Non-volatile counters */

int whClient_CounterSet(whCounterId counterId, uint32_t value)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_CounterGet(whCounterId counterId, uint32_t* outValue)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_CounterErase(whCounterId counterId)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}


/** Key Management */
int whClient_ImportKey(whKeyId keyId, const uint8_t* inKey, uint16_t inSize)
{
    /* BAD_FUNC_ARGS, MEMORY_E, WC_HW_E */
    return 0;
}

int whClient_EraseKey(whKeyId keyId)
{
    /* BAD_FUNC_ARGS, MEMORY_E, WC_HW_E */
    return 0;
}

int whClient_ExportKey(whKeyId keyId, uint8_t* outKey, uint16_t* inoutSize)
{
    /* BAD_FUNC_ARGS, MEMORY_E, WC_HW_E */
    return 0;
}

int whClient_SetKeyRsa(RsaKey* key, whKeyId keyId)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetKeyAes(Aes* aes, whKeyId keyId)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetKeyHmac(Hmac* hmac, whKeyId keyId)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}


/** NVM Management */

int whClient_NvmList(uint16_t access, uint16_t flags,
    whNvmId start_id, uint16_t* out_count, whNvmId* out_id)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_NvmAvailable(uint16_t* out_size, uint16_t* out_objects)
{
    /* WC_HW_E */
    return 0;
}

int whClient_NvmReclaimable(uint16_t* out_size, uint16_t* out_objects)
{
    /* WC_HW_E */
    return 0;
}

int whClient_NvmGetMetadata(whNvmId id, whNvmMetadata* object)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_NvmAddObject(whNvmMetadata *meta, uint16_t data_len,
        const uint8_t* data)
{
    /* BAD_FUNC_ARGS, MEMORY_E, WC_HW_E */
    return 0;
}

int whClient_NvmDestroyObjects(uint16_t list_count, const whNvmId* id_list)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_NvmRead(whNvmId id, uint16_t offset, uint16_t data_len,
        uint8_t* data)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}


/** Additional HSM Features */

int whClient_SetNvmWriteLock(uint32_t code, int state)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_GetNvmWriteLock(int* outState)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetDebugLock(uint32_t code, int state)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_GetDebugLock(int* outState)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_GetBootImageVerification(uint16_t* inoutLen, uint8_t* outResult)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetBootLoaderDone(uint32_t code)
{
    /* WC_HW_E */
    return 0;
}

int whClient_GetBootLoaderDone(uint32_t* outCode)
{
    /* WC_HW_E */
    return 0;
}

int whClient_SetSheUid(uint16_t len, const uint8_t* uid)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetPause(uint32_t code, int state)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_CompareManifest(const uint8_t* address, int* outResult)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}
#endif
