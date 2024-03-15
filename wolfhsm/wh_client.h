/*
 * wolfhsm/wh_client.h
 *
 * Base WolfHSM Client Library API
 *
 * The WolfHSM Client provides a single context and connection to a
 * WolfHSM Server.  All communications and state are internally managed by
 * registering a crypto callback function to be invoked synchronously when
 * wolfCrypt functions are called.  In order to specify to use the WolfHSM
 * Server for cryptographic operations, the device id WOLFHSM_DEV_ID should be
 * passed into any of the wolfCrypt init functions.
 *
 * In addition to the offload of cryptographic functions, the WolfHSM Client
 * also exposes WolfHSM Server key management, non-volatile memory, and protocol
 * functions.
 */

#ifndef WOLFHSM_WH_CLIENT_H_
#define WOLFHSM_WH_CLIENT_H_

/* System libraries */
#include <stdint.h>

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
#include "wolfhsm/wh_common.h"

/* Component includes */
#include "wolfhsm/wh_comm.h"

#if 0
#include "wolfhsm/key_remote.h"
#include "wolfhsm/crypto_remote.h"
#include "wolfhsm/image_remote.h"
#endif

/* Abstract context class */
struct whClientContext_t {
    int inited;
    whCommClient comm[1];
    uint16_t last_req_id;
    uint16_t last_req_kind;
#if 0
    whKeyClient* key;
    whCryptoClient* crypto;
    whImageClient* image;
#endif

#ifdef HAVE_WOLFHSM_PROTOCOL_PKCS11
    whPkcs11Client* pkcs11;
#endif

#ifdef HAVE_WOLFHSM_PROTOCOL_SHE
    whSheClient* she;
#endif

};
typedef struct whClientContext_t whClientContext;

struct whClientConfig_t {
    whCommClientConfig* comm;
#if 0
    whKeyClientConfig* key;
    whCryptoClientConfig* crypto;
    whImageClientConfig* image;
#endif

#ifdef HAVE_WOLFHSM_PROTOCOL_PKCS11
    whPkcs11ClientConfig* pkcs11;
#endif

#ifdef HAVE_WOLFHSM_PROTOCOL_SHE
    whSheClientConfig* she;
#endif
};
typedef struct whClientConfig_t whClientConfig;

int wh_Client_Init(whClientContext* c, const whClientConfig* config);
int wh_Client_Cleanup(whClientContext* c);

int wh_Client_SendRequest(whClientContext* c,
        uint16_t group, uint16_t action,
        uint16_t data_size, const void* data);
int wh_Client_RecvResponse(whClientContext *c,
        uint16_t *out_group, uint16_t *out_action,
        uint16_t *out_size, void* data);

int wh_Client_EchoRequest(whClientContext* c, uint16_t size, const void* data);
int wh_Client_EchoResponse(whClientContext* c, uint16_t *out_size, void* data);
int wh_Client_Echo(whClientContext* c, uint16_t snd_len, const void* snd_data,
        uint16_t *out_rcv_len, void* rcv_data);

/* NVM Functions */
int wh_Client_NvmInitRequest(whClientContext* c);
int wh_Client_NvmInitResponse(whClientContext* c,
        uint32_t *out_clientnvm_id, uint32_t *out_servernvm_id);
int wh_Client_NvmInit(whClientContext* c,
        uint32_t *out_clientnvm_id, uint32_t *out_servernvm_id);

int wh_Client_NvmGetAvailableRequest(whClientContext* c);
int wh_Client_NvmGetAvailableResponse(whClientContext* c,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects);
int wh_Client_NvmGetAvailable(whClientContext* c,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects);

#endif /* WOLFHSM_WH_CLIENT_H_ */
