
/* System libraries */
#include <stdint.h>

#if 0
/* wolfCrypt */
#ifndef WOLFSSL_USER_SETTINGS
    #include "wolfssl/options.h"
#endif
#include "wolfssl/wolfcrypt/settings.h"

#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hmac.h"
#endif

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/error.h"
#include "wolfhsm/comm.h"

#if 0
#include "wolfhsm/nvm.h"
#include "wolfhsm/nvm_remote.h"
#endif

#include "wolfhsm/message.h"
#include "wolfhsm/message_comm.h"
#include "wolfhsm/wh_server.h"

int wh_Server_Init(whServer* server, whServerConfig* config)
{
    int rc = 0;
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(server, 0, sizeof(*server));
    if (
/*            ((rc = wh_Nvm_Init(server->nvm_device, config->nvm_device)) == 0) && */
        ((rc = wh_CommServer_Init(server->comm, config->comm)) == 0) &&
/*        ((rc = wh_NvmServer_Init(server->nvm, config->nvm)) == 0)*/
        1) {
        /* All good */
    } else {
        wh_Server_Cleanup(server);
    }
    /* WC_INIT_E, WC_HW_E*/
    return rc;
}

static int _wh_Server_HandleCommRequest(whServer* server,
        uint16_t magic, uint16_t type, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    switch (type) {
    case WOLFHSM_MESSAGE_TYPE_COMM_ECHO:
    {
        whMessageCommLenData req;
        whMessageCommLenData resp;
        wh_MessageComm_TranslateLenData(magic,
                (whMessageCommLenData*)req_packet, &req);

        resp.len = req.len;
        memcpy(resp.data, req.data, resp.len);

        wh_MessageComm_TranslateLenData(magic,
                &resp, (whMessageCommLenData*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return 0;
}

int wh_Server_HandleRequestMessage(whServer* server)
{
    uint16_t type, magic, seq, size;
    uint8_t data[WOLFHSM_COMM_MTU];

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }
    int rc = wh_CommServer_RecvRequest(server->comm, &magic, &type, &seq,
            &size, data);
    /* Got a packet? */
    if (rc == 0) {
        uint16_t group = type & WOLFHSM_MESSAGE_GROUP_MASK;
        switch (group) {
        case WOLFHSM_MESSAGE_GROUP_COMM: {
            rc = _wh_Server_HandleCommRequest(server, magic, type, seq,
                    size, data,
                    &size, data);
        }; break;
        case WOLFHSM_MESSAGE_GROUP_NVM: {
/*            rc = wh_NvmServer_Handle(server->comm,
                    &type, &flags, &seq, &size, server->comm->packet);
                    */
        }; break;
        case WOLFHSM_MESSAGE_GROUP_KEY: {

        }; break;
        case WOLFHSM_MESSAGE_GROUP_CRYPTO: {

        }; break;
        case WOLFHSM_MESSAGE_GROUP_PKCS11: {

        }; break;
        case WOLFHSM_MESSAGE_GROUP_SHE: {

        }; break;
        case WOLFHSM_MESSAGE_GROUP_CUSTOM: {

        }; break;
        default:
            /* Unknown type. Respond with error flag */
            rc = WH_ERROR_NOTREADY;
        }
    }
    /* Send a response */
    if (rc == 0) {
        do {
            rc = wh_CommServer_SendResponse(server->comm, magic, type, seq,
                size, data);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

int wh_Server_Cleanup(whServer* server)
{
    if (server ==NULL) {
         return WH_ERROR_BADARGS;
     }
     if (server->nvm != NULL) {
         /*(void)wh_Nvm_Cleanup(server->nvm);*/
     }
     (void)wh_CommServer_Cleanup(server->comm);
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

