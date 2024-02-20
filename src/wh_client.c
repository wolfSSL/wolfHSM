/*
 * src/wh_client.c
 */

/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */


#if 0
/* wolfCrypt */
#ifndef WOLFSSL_USER_SETTINGS
    #include "wolfssl/options.h"
#endif
#include "wolfssl/wolfcrypt/settings.h"

/* Common error return values reused by wolfHSM */
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hmac.h"
#endif

/* Common WolfHSM types and defines shared with the server */
#include <wolfhsm/wh_error.h>
#include <wolfhsm/wh_comm.h>

#if 0
#include "wolfhsm/nvm.h"
#include "wolfhsm/nvm_remote.h"
#endif

#include <wolfhsm/wh_message_comm.h>
#include "wolfhsm/wh_client.h"

int wh_Client_Init(whClient* c, const whClientConfig* config)
{
    int rc = 0;
    if((c == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(c, 0, sizeof(*c));
    if (    ((rc = wh_CommClient_Init(c->comm, config->comm))==0) &&
/*            ((rc = wh_NvmClient_Init(c->nvm, config->nvm))==0) && */
            1) {
        /* All good */
        c->inited = 1;

#if 0
        /* Now sequentially send/recv init messages for each component */
        uint8_t buffer[WOLFHSM_COMM_MTU];
        uint16_t req_size =sizeof(buffer);
        uint16_t req_type = 0;
        uint16_t req_seq = 0;
        uint16_t res_flags = 0;
        uint16_t res_size = sizeof(buffer);
        uint16_t res_type = 0;
        uint16_t res_seq = 0;
        wh_CommClient_InitRequest(c->nvm,
                WH_COMM_MAGIC_NATIVE,
                &req_type,
                &req_size,
                buffer);
        do {
            rc = wh_CommClient_SendRequest(c->comm,
                    WH_COMM_MAGIC_NATIVE,
                    req_type,
                    &req_seq,
                    req_size,
                    buffer);
        } while (rc == WH_ERROR_NOTREADY);
        if (rc == 0) {
            do {
                rc = wh_CommClient_RecvResponse(c->comm,
                        &res_flags,
                        &res_type,
                        &res_seq,
                        &res_size,
                        buffer);
            } while (rc == WH_ERROR_NOTREADY);
            if (rc == 0) {
                if (    (res_seq == req_seq) &&
                        (res_type == req_type)) {
                    rc = wh_CommClient_InitResponse(c->comm,
                            res_flags,
                            res_type,
                            res_size,
                            buffer);
                } else {
                   /* Mismatched response */
                    rc = WH_ERROR_ABORTED;
                }

            }
        }
#endif

    }
    if (rc != 0) {
        wh_Client_Cleanup(c);
    }
    return rc;
}

int wh_Client_Cleanup(whClient* c)
{
    if (c ==NULL) {
        return WH_ERROR_BADARGS;
    }
#if 0
    if (c->nvm != NULL) {
        (void)wh_NvmClient_Cleanup(c->nvm);
    }
#endif
    (void)wh_CommClient_Cleanup(c->comm);
    memset(c, 0, sizeof(*c));
    return 0;
}

int wh_Client_EchoRequest(whClient* c, uint16_t size, const void* data)
{
    int rc = 0;
    whMessageCommLenData msg;
    uint16_t req_id = 0;
    uint16_t req_type = WOLFHSM_MESSAGE_TYPE_COMM_ECHO;

    if (    (c == NULL) ||
            ((size > 0) && (data == NULL)) ){
        return WH_ERROR_BADARGS;
    }

    if (size > sizeof(msg.data)) size = sizeof(msg.data);
    msg.len = size;
    memcpy(msg.data, data, size);

    rc = wh_CommClient_SendRequest(c->comm,
            WH_COMM_MAGIC_NATIVE, req_type, &req_id,
            sizeof(msg), &msg);
    if (rc == 0) {
        c->last_req_id = req_id;
        c->last_type = req_type;
    }
    return rc;
}

int wh_Client_EchoResponse(whClient* c, uint16_t *out_size, void* data)
{
    int rc = 0;
    whMessageCommLenData msg;
    uint16_t resp_magic = 0;
    uint16_t resp_id = 0;
    uint16_t resp_type = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_CommClient_RecvResponse(c->comm,
            &resp_magic, &resp_type, &resp_id,
            &resp_size, &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_magic != WH_COMM_MAGIC_NATIVE) ||
                (resp_type != WOLFHSM_MESSAGE_TYPE_COMM_ECHO) ||
                (resp_id != c->last_req_id) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            return WH_ERROR_ABORTED;
        }

        if (out_size != NULL) {
            *out_size = msg.len;
        }
        if (data != NULL) {
            memcpy(data, msg.data, msg.len);
        }
        c->last_req_id = 0;
        c->last_type = 0;
    }
    return rc;
}

int wh_Client_Echo(whClient* c, uint16_t snd_len, const void* snd_data,
        uint16_t *out_rcv_len, void* rcv_data)
{
    int rc = 0;
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_EchoRequest(c, snd_len, snd_data);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_EchoResponse(c, out_rcv_len, rcv_data);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

#if 0
/** Static singleton API */

/* Singleton client context */
static whClient _clientContext;

/* Target-supplied configuration */
extern whClientConfig whClient_Configuration;

int whClient_Init()
{
    /* WC_INIT_E, WC_HW_E*/
    return wh_Client_Init(&_clientContext, &whClient_Configuration);
}

int whClient_Cleanup()
{
    /* WC_HW_E */
    return wh_Client_Cleanup(&_clientContext);
    return 0;
}


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
