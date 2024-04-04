/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines*/
#include "wolfhsm/wh_error.h"

/* Server Components */
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_message_nvm.h"
#include "wolfhsm/wh_packet.h"

/* Server API's */
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_internal.h"
#include "wolfhsm/wh_server_crypto.h"
#if defined(WOLFHSM_SHE_EXTENSION)
#include "wolfhsm/wh_server_she.h"
#endif

/** Forward declarations. */
/* TODO: Move these out to separate C files */
static int _wh_Server_HandleCommRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet);
static int _wh_Server_HandleKeyRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet);
static int _wh_Server_HandlePkcs11Request(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet);
#ifdef WOLFHSM_SHE_EXTENSION
static int _wh_Server_HandleSheRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet);
#endif

int wh_Server_Init(whServerContext* server, whServerConfig* config)
{
    int rc = 0;

    if ((server == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(server, 0, sizeof(*server));

    rc = wolfCrypt_Init();
    if (rc != 0) {
        (void)wh_Server_Cleanup(server);
        return WH_ERROR_ABORTED;
    }
    server->flags.wcInitFlag = true;

#if defined(WOLF_CRYPTO_CB)
    server->crypto->devId = config->devId;
    if (config->cryptocb != NULL) {
        /* register the crypto callback with wolSSL */
        rc = wc_CryptoCb_RegisterDevice(server->crypto->devId,
                                        config->cryptocb,
                                        NULL);
        if (rc != 0) {
            (void)wh_Server_Cleanup(server);
            return WH_ERROR_ABORTED;
        }
    }
#else
    server->crypto->devId = INVALID_DEVID;
#endif
    server->flags.wcDevIdInitFlag = true;

    rc = wc_InitRng_ex(server->crypto->rng, NULL, server->crypto->devId);
    if (rc != 0) {
        (void)wh_Server_Cleanup(server);
        return WH_ERROR_ABORTED;
    }
    server->flags.wcRngInitFlag = true;

    rc = wh_Nvm_Init(server->nvm, config->nvm_config);
    if (rc != 0) {
        (void)wh_Server_Cleanup(server);
        return WH_ERROR_ABORTED;
    }

    rc = wh_CommServer_Init(server->comm, config->comm_config);
    if (rc != 0) {
        (void)wh_Server_Cleanup(server);
        return WH_ERROR_ABORTED;
    }
    return rc;
}

int wh_Server_Cleanup(whServerContext* server)
{
    if (server ==NULL) {
        return WH_ERROR_BADARGS;
    }

    (void)wh_CommServer_Cleanup(server->comm);
    (void)wh_Nvm_Cleanup(server->nvm);

#if defined(WOLF_CRYPTO_CB)
    if (server->flags.wcDevIdInitFlag &&
        server->crypto->devId != INVALID_DEVID) {
        (void)wc_CryptoCb_UnRegisterDevice(server->crypto->devId);
    }
#endif

    if (server->flags.wcRngInitFlag) {
        (void)wc_FreeRng(server->crypto->rng);
    }

    if (server->flags.wcInitFlag) {
        (void)wolfCrypt_Cleanup();
    }

    memset(server, 0, sizeof(*server));

    return 0;
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

static int _wh_Server_HandleKeyRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
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

        case WH_MESSAGE_GROUP_COMM:
            rc = _wh_Server_HandleCommRequest(server, magic, action, seq,
                    size, data, &size, data);
            break;

        case WH_MESSAGE_GROUP_NVM:
            rc = wh_Server_HandleNvmRequest(server, magic, action, seq,
                    size, data, &size, data);
            break;

        case WH_MESSAGE_GROUP_KEY:
            rc = _wh_Server_HandleKeyRequest(server, magic, action, seq,
                    size, data, &size, data);
        break;

        case WH_MESSAGE_GROUP_CRYPTO:
            rc = wh_Server_HandleCryptoRequest(server, action, data, &size);
        break;

        case WH_MESSAGE_GROUP_PKCS11:
            rc = _wh_Server_HandlePkcs11Request(server, magic, action, seq,
                    size, data, &size, data);
        break;

#ifdef WOLFHSM_SHE_EXTENSION
        case WOLFHSM_MESSAGE_GROUP_SHE:
            rc = _wh_Server_HandleSheRequest(data, size);
        break;
#endif

        case WH_MESSAGE_GROUP_CUSTOM:
            rc = wh_Server_HandleCustomCbRequest(server, magic, action, seq,
                    size, data, &size, data);
            break;

        default:
            /* Unknown group. Return empty packet*/
            /* TODO: Respond with aux error flag */
            size = 0;
        }

        /* Send a response */
        /* TODO: Respond with ErrorResponse if handler returns an error */
        if (rc == 0) {
            do {
                rc = wh_CommServer_SendResponse(server->comm, magic, kind, seq,
                    size, data);
            } while (rc == WH_ERROR_NOTREADY);
        }
    }
    return rc;
}

