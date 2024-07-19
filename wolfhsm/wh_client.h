/*
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
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

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"

/* Component includes */
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message_customcb.h"

#ifndef WOLFHSM_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"
#endif

/**
 * Out of band callback function to inform the server to cancel a request,
 *    internal logic is provided by the port code.
 *
 * @param cancelSeq The sequence of the request to cancel.
 * @return Returns 0 on success, or a negative value indicating an error.
 */
typedef int (*whClientCancelCb)(uint16_t cancelSeq);

/* Client context */
struct whClientContext_t {
    uint16_t     last_req_id;
    uint16_t     last_req_kind;
    uint8_t      cancelable;
    uint8_t      WH_PAD[3];
    whCommClient comm[1];
    whClientCancelCb cancelCb;
};
typedef struct whClientContext_t whClientContext;

struct whClientConfig_t {
    whCommClientConfig* comm;
    whClientCancelCb cancelCb;
};
typedef struct whClientConfig_t whClientConfig;


/** Context initialization and shutdown functions */

/**
 * Initializes a whClientContext object with the provided configuration.
 *
 * @param c The pointer to the whClientContext object to be initialized.
 * @param config The pointer to the whClientConfig object containing the
 * configuration settings.
 * @return Returns 0 on success, or a negative value indicating an error.
 */
int wh_Client_Init(whClientContext* c, const whClientConfig* config);

/**
 * @brief Disconnects from the server and releases client context resources
 *
 * This function frees any resources allocated during the initialization
 * of the whClientContext. It should be called when the client is no longer
 * needed
 *
 * @param c A pointer to the whClientContext structure to be cleaned up.
 * @return Returns 0 on success, or a negative value on failure.
 */
int wh_Client_Cleanup(whClientContext* c);


/** Generic request/response functions */
/* TODO: Move these to internal API */


/**
 * Sends a request to the server using the specified client context.
 *
 * @param c The client context.
 * @param group The group identifier.
 * @param action The action identifier.
 * @param data_size The size of the data to be sent. Zero is allowed in the case
 * of NULL data.
 * @param data A pointer to the data to be sent. NULL is allowed in the case of
 * zero-sized data.
 * @return Returns 0 on success, or a negative value on failure.
 */
int wh_Client_SendRequest(whClientContext* c, uint16_t group, uint16_t action,
                          uint16_t data_size, const void* data);
/**
 * Receives a response from the server and extracts the group, action, size, and
 * data.
 *
 * @param c The client context.
 * @param out_group Pointer to store the received group value.
 * @param out_action Pointer to store the received action value.
 * @param out_size Pointer to store the received size value.
 * @param data Pointer to store the received data.
 * @return 0 if successful, a negative value if an error occurred.
 */
int wh_Client_RecvResponse(whClientContext* c, uint16_t* out_group,
                           uint16_t* out_action, uint16_t* out_size,
                           void* data);


/** Comm component functions */

/**
 * @brief Sends a communication initialization request to the server.
 *
 * This function prepares and sends a communication initialization request
 * message to the server. It populates the message with the client's ID
 * (initialized from the config struct at client initialization) and sends it
 * using the communication context.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CommInitRequest(whClientContext* c);

/**
 * @brief Receives a communication initialization response from the server.
 *
 * This function waits for and processes a communication initialization
 * response message from the server. It validates the response and extracts
 * the client and server IDs from the message.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_clientid Pointer to store the client ID from the response.
 * @param[out] out_serverid Pointer to store the server ID from the response.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CommInitResponse(whClientContext* c, uint32_t* out_clientid,
                               uint32_t* out_serverid);

/**
 * @brief Initializes communication with the server with a blocking call.
 *
 * This function handles the complete process of initializing communication
 * with the server. It sends an initialization request and waits for a valid
 * response, extracting the client and server IDs from the response.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_clientid Pointer to store the client ID from the response.
 * @param[out] out_serverid Pointer to store the server ID from the response.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CommInit(whClientContext* c, uint32_t* out_clientid,
                       uint32_t* out_serverid);

/**
 * @brief Sends a communication close request to the server.
 *
 * This function prepares and sends a communication close request
 * message to the server. It signals the server to close the communication
 * channel with the client.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CommCloseRequest(whClientContext* c);

/**
 * @brief Enables request cancellation.
 *
 * This function allows subsequent requests to be canceled, the responses that
 * are normally handled by automatically by wolfCrypt must be handled with a
 * wolfHSM specific function call.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_EnableCancel(whClientContext* c);

/**
 * @brief Disables request cancellation.
 *
 * This function disables request cancellation, making wolfCrypt automatically
 * handle responses again.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_DisableCancel(whClientContext* c);

/**
 * @brief Cancels the previous request, currently only supports CMAC. Async
 * Request
 *
 * This function sends a cancellation request to the server to cancel the
 * previous request made. Does not wait for the response which must be handled
 * seperately
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CancelRequest(whClientContext* c);
/**
 * @brief Handles the response for a cancellation the previous request, currently
 * only supports CMAC. Async response handler.
 *
 * This function handles the response for a request cancellation previously sent
 * to the server. Blocks to wait for the response.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 or WH_ERROR_CANCEL_LATE on success, or a negative
 *    error code on failure.
 */
int wh_Client_CancelResponse(whClientContext* c);
/**
 * @brief Cancels the previous request, currently only supports CMAC.
 *
 * This function sends a cancellation request to the server and waits for the
 * response to cancel the previous request made.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 or WH_ERROR_CANCEL_LATE on success, or a negative
 *    error code on failure.
 */
int wh_Client_Cancel(whClientContext* c);

/**
 * @brief Receives a communication close response from the server.
 *
 * This function checks for and processes a communication close response
 * message from the server.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CommCloseResponse(whClientContext* c);

/**
 * @brief Closes communication with the server.
 *
 * This function handles the complete process of closing communication
 * with the server. It sends a close request and waits for a valid response
 * to confirm that the communication channel has been closed.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CommClose(whClientContext* c);

/**
 * @brief Sends an echo request to the server.
 *
 * This function prepares and sends an echo request message to the server.
 * The message contains a data payload of the specified size. This function
 * does not block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] size Size of the data payload.
 * @param[in] data Pointer to the data payload.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_EchoRequest(whClientContext* c, uint16_t size, const void* data);

/**
 * @brief Receives an echo response from the server.
 *
 * This function attempts to process an echo response message from the server.
 * It validates the response and extracts the data payload. This function does
 * not block; it returns WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_size Pointer to store the size of the received data payload.
 * @param[out] data Pointer to store the received data payload.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_EchoResponse(whClientContext* c, uint16_t* out_size, void* data);

/**
 * @brief Sends an echo request to the server and receives the response.
 *
 * This function handles the complete process of sending an echo request to the
 * server and receiving the response. It sends the request and repeatedly
 * attempts to receive a valid response, extracting the data payload from the
 * response once received. This function blocks until the entire operation is
 * complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] snd_len Size of the data payload to send.
 * @param[in] snd_data Pointer to the data payload to send.
 * @param[out] out_rcv_len Pointer to store the size of the received data
 * payload.
 * @param[out] rcv_data Pointer to store the received data payload.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_Echo(whClientContext* c, uint16_t snd_len, const void* snd_data,
                   uint16_t* out_rcv_len, void* rcv_data);

/** Key functions
 *
 * For client-side key data to be used, it must first be brought into the key
 * cache (RAM) of the HSM server.  Key cache requests instruct the server to
 * transfer key data from client memory and allocate space in the HSM server RAM
 * to hold this key.  Key eviction requests instruct the HSM server to remove
 * the key from the cache so that the RAM may be reused.  Key export requests
 * instruct the server to send back the cached key data to client RAM.  Key
 * commit requests instruct the HSM server to write the cached key into the HSM
 * NVM. Key erase requests instruct the HSM server to remove a previously
 * committed key from NVM.
 */


#ifndef WOLFHSM_NO_CRYPTO
/**
 * @brief Sends a key cache request to the server.
 *
 * This function prepares and sends a key cache request message to the server.
 * The message contains the specified flags, label, and input data. This
 * function does not block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] flags Flags for the key cache request.
 * @param[in] label Pointer to the label associated with the key.
 * @param[in] labelSz Size of the label.
 * @param[in] in Pointer to the key data to be cached.
 * @param[in] inSz Size of the key data.
 * @param[in] keyId Key ID to be used for caching. If set to
 * WOLFHSM_KEYID_ERASED, a new ID will be generated.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyCacheRequest_ex(whClientContext* c, uint32_t flags,
                                 uint8_t* label, uint32_t labelSz, uint8_t* in,
                                 uint32_t inSz, uint16_t keyId);

/**
 * @brief Sends a key cache request to the server.
 *
 * This function prepares and sends a key cache request message to the server.
 * The message contains the specified flags, label, and input data. This
 * function does not block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] flags Flags for the key cache request.
 * @param[in] label Pointer to the label associated with the key.
 * @param[in] labelSz Size of the label.
 * @param[in] in Pointer to the key data to be cached.
 * @param[in] inSz Size of the key data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyCacheRequest(whClientContext* c, uint32_t flags,
                              uint8_t* label, uint32_t labelSz, uint8_t* in,
                              uint32_t inSz);

/**
 * @brief Receives a key cache response from the server.
 *
 * This function attempts to process a key cache response message from the
 * server. It validates the response and extracts the key ID. This function does
 * not block; it returns WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] keyId Pointer to store the key ID assigned by the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_KeyCacheResponse(whClientContext* c, uint16_t* keyId);

/**
 * @brief Sends a key cache request to the server and receives the response.
 *
 * This function handles the complete process of sending a key cache request to
 * the server and receiving the response. It sends the request and repeatedly
 * attempts to receive a valid response, extracting the key ID from the response
 * once received. This function blocks until the entire operation is complete or
 * an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] flags Flags for the key cache request.
 * @param[in] label Pointer to the label associated with the key.
 * @param[in] labelSz Size of the label.
 * @param[in] in Pointer to the key data to be cached.
 * @param[in] inSz Size of the key data.
 * @param[out] keyId Pointer to store the key ID assigned by the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyCache(whClientContext* c, uint32_t flags, uint8_t* label,
                       uint32_t labelSz, uint8_t* in, uint32_t inSz,
                       uint16_t* keyId);

/**
 * @brief Sends a key eviction request to the server.
 *
 * This function prepares and sends a key eviction request message to the
 * server. The message contains the specified key ID. This function does not
 * block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId Key ID to be evicted.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyEvictRequest(whClientContext* c, uint16_t keyId);

/**
 * @brief Receives a key eviction response from the server.
 *
 * This function attempts to process a key eviction response message from the
 * server. It validates the response. This function does not block; it returns
 * WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_KeyEvictResponse(whClientContext* c);

/**
 * @brief Sends a key eviction request to the server and receives the response.
 *
 * This function handles the complete process of sending a key eviction request
 * to the server and receiving the response. It sends the request and repeatedly
 * attempts to receive a valid response. This function blocks until the entire
 * operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId Key ID to be evicted.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyEvict(whClientContext* c, uint16_t keyId);

/**
 * @brief Sends a key export request to the server.
 *
 * This function prepares and sends a key export request message to the server.
 * The message contains the specified key ID. This function does not block;
 * it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId Key ID to be exported.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyExportRequest(whClientContext* c, uint16_t keyId);

/**
 * @brief Receives a key export response from the server.
 *
 * This function attempts to process a key export response message from the
 * server. It validates the response and extracts the label and key data. This
 * function does not block; it returns WH_ERROR_NOTREADY if a response has not
 * been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] label Pointer to store the label associated with the key.
 * @param[in] labelSz Size of the label buffer.
 * @param[out] out Pointer to store the exported key data.
 * @param[out] outSz Pointer to store the size of the exported key data.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_KeyExportResponse(whClientContext* c, uint8_t* label,
                                uint32_t labelSz, uint8_t* out,
                                uint32_t* outSz);

/**
 * @brief Sends a key export request to the server and receives the response.
 *
 * This function handles the complete process of sending a key export request to
 * the server and receiving the response. It sends the request and repeatedly
 * attempts to receive a valid response, extracting the label and key data from
 * the response once received. This function blocks until the entire operation
 * is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId Key ID to be exported.
 * @param[out] label Pointer to store the label associated with the key.
 * @param[in] labelSz Size of the label buffer.
 * @param[out] out Pointer to store the exported key data.
 * @param[out] outSz Pointer to store the size of the exported key data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyExport(whClientContext* c, uint16_t keyId, uint8_t* label,
                        uint32_t labelSz, uint8_t* out, uint32_t* outSz);

/**
 * @brief Sends a key commit request to the server.
 *
 * This function prepares and sends a key commit request message to the server.
 * The message contains the specified key ID. This function does not block;
 * it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId Key ID to be committed. Committing a key means making it
 * persistent in non-volatile memory.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyCommitRequest(whClientContext* c, whNvmId keyId);

/**
 * @brief Receives a key commit response from the server.
 *
 * This function attempts to process a key commit response message from the
 * server. It validates the response. This function does not block; it returns
 * WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_KeyCommitResponse(whClientContext* c);

/**
 * @brief Sends a key commit request to the server and receives the response.
 *
 * This function handles the complete process of sending a key commit request to
 * the server and receiving the response. It sends the request and repeatedly
 * attempts to receive a valid response. This function blocks until the entire
 * operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId Key ID to be committed. Committing a key means making it
 * persistent in non-volatile memory.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyCommit(whClientContext* c, whNvmId keyId);

/**
 * @brief Sends a key erase request to the server.
 *
 * This function prepares and sends a key erase request message to the server.
 * The message contains the specified key ID. This function does not block;
 * it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId Key ID to be erased.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyEraseRequest(whClientContext* c, whNvmId keyId);

/**
 * @brief Receives a key erase response from the server.
 *
 * This function attempts to process a key erase response message from the
 * server. It validates the response. This function does not block; it returns
 * WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_KeyEraseResponse(whClientContext* c);

/**
 * @brief Sends a key erase request to the server and receives the response.
 *
 * This function handles the complete process of sending a key erase request to
 * the server and receiving the response. It sends the request and repeatedly
 * attempts to receive a valid response. This function blocks until the entire
 * operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId Key ID to be erased.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_KeyErase(whClientContext* c, whNvmId keyId);

#ifdef HAVE_CURVE25519
/**
 * @brief Associates a Curve25519 key with a specific key ID.
 *
 * This function sets the device context of a Curve25519 key to the specified
 * key ID. On the server side, this key ID is used to reference the key stored
 * in the HSM
 *
 * @param[in] key Pointer to the Curve25519 key structure.
 * @param[in] keyId Key ID to be associated with the Curve25519 key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_SetKeyIdCurve25519(curve25519_key* key, whNvmId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a Curve25519 key that was previously
 * set by either the crypto callback layer or wh_Client_SetKeyCurve25519.
 *
 * @param[in] key Pointer to the Curve25519 key structure.
 * @param[out] keyId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_GetKeyIdCurve25519(curve25519_key* key, whNvmId* outId);
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ECC
/**
 * @brief Associates a Ecc key with a specific key ID.
 *
 * This function sets the device context of a Ecc key to the specified
 * key ID. On the server side, this key ID is used to reference the key stored
 * in the HSM
 *
 * @param[in] key Pointer to the Ecc key structure.
 * @param[in] keyId Key ID to be associated with the Ecc key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_SetKeyIdEcc(ecc_key* key, whNvmId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a Ecc key that was previously
 * set by either the crypto callback layer or wh_Client_SetKeyIdEcc.
 *
 * @param[in] key Pointer to the Ecc key structure.
 * @param[out] keyId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_GetKeyIdEcc(ecc_key* key, whNvmId* outId);
#endif /* HAVE_ECC */

#ifndef NO_RSA
/**
 * @brief Associates an RSA key with a specific key ID.
 *
 * This function sets the device context of an RSA key to the specified key ID.
 * On the server side, this key ID is used to reference the key stored in the
 * HSM.
 *
 * @param[in] key Pointer to the RSA key structure.
 * @param[in] keyId Key ID to be associated with the RSA key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_SetKeyIdRsa(RsaKey* key, whNvmId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a RSA key that was previously
 * set by either the crypto callback layer or wh_Client_SetKeyRsa.
 *
 * @param[in] key Pointer to the RSA key structure.
 * @param[out] keyId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_GetKeyIdRsa(RsaKey* key, whNvmId* outId);
#endif /* !NO_RSA */

#ifndef NO_AES
/**
 * @brief Associates an AES key with a specific key ID.
 *
 * This function sets the device context of an AES key to the specified key ID.
 * On the server side, this key ID is used to reference the key stored in the
 * HSM
 *
 * @param[in] aes Pointer to the AES key structure.
 * @param[in] keyId Key ID to be associated with the AES key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_SetKeyIdAes(Aes* key, whNvmId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a AES key that was previously
 * set by either the crypto callback layer or wh_Client_SetKeyAes.
 *
 * @param[in] key Pointer to the AES key structure.
 * @param[out] keyId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_GetKeyIdAes(Aes* key, whNvmId* outId);

#ifdef WOLFSSL_CMAC
/**
 * @brief Runs the AES CMAC operation in a single call with a wolfHSM keyId.
 *
 * This function does entire cmac operation in one function call with a key
 * already stored in the HSM. This operation evicts the key from the HSM cache
 * after the operation though it will still be in the HSM's NVM if it was
 * commited
 *
 * @param[in] cmac Pointer to the CMAC key structure.
 * @param[out] out Output buffer for the CMAC tag.
 * @param[out] outSz Size of the output buffer in bytes.
 * @param[in] in Input buffer to be hashed.
 * @param[in] inSz Size of the input buffer in bytes.
 * @param[in] keyId ID of the key inside the HSM.
 * @param[in] heap Heap pointer for the cmac struct.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_AesCmacGenerate(Cmac* cmac, byte* out, word32* outSz,
    const byte* in, word32 inSz, whNvmId keyId, void* heap);

/**
 * @brief Verifies a AES CMAC tag in a single call with a wolfHSM keyId.
 *
 * This function does entire cmac verify in one function call with a key
 * already stored in the HSM. This operation evicts the key from the HSM cache
 * after the operation though it will still be in the HSM's NVM if it was
 * commited
 *
 * @param[in] cmac Pointer to the CMAC key structure.
 * @param[out] check Cmac tag to check against.
 * @param[out] checkSz Size of the check buffer in bytes.
 * @param[in] in Input buffer to be hashed.
 * @param[in] inSz Size of the input buffer in bytes.
 * @param[in] keyId ID of the key inside the HSM.
 * @param[in] heap Heap pointer for the cmac struct.
 * @return int Returns 0 on success, 1 on tag mismatch, or a negative error
 *    code on failure.
 */
int wh_Client_AesCmacVerify(Cmac* cmac, const byte* check, word32 checkSz,
    const byte* in, word32 inSz, whNvmId keyId, void* heap);

/**
 * @brief Handle cancelable CMAC response.
 *
 * This function handles a CMAC operation response from the server when
 * cancellation has been enabled, since wolfCrypt won't automatically block and
 * wait for the response.
 *
 * @param[in] c Pointer to the client context structure.
 * @param[in] cmac Pointer to the CMAC key structure.
 * @param[out] out Buffer to store the CMAC result, only required after
 *    wc_CmacFinal.
 * @param[in/out] outSz Pointer to the size of the out buffer in bytes, will be
 *    set to the size returned by the server on return.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CmacCancelableResponse(whClientContext* c, Cmac* cmac,
    uint8_t* out, uint32_t* outSz);

/**
 * @brief Associates a CMAC key with a specific key ID.
 *
 * This function sets the device context of a CMAC key to the specified key ID.
 * On the server side, this key ID is used to reference the key stored in the
 * HSM
 *
 * @param[in] key Pointer to the CMAC key structure.
 * @param[in] keyId Key ID to be associated with the CMAC key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_SetKeyIdCmac(Cmac* key, whNvmId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a CMAC key that was previously
 * set by either the crypto callback layer or wh_Client_SetKeyCmac.
 *
 * @param[in] key Pointer to the CMAC key structure.
 * @param[out] keyId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_GetKeyIdCmac(Cmac* key, whNvmId* outId);
#endif /* WOLFSSL_CMAC */
#endif /* !NO_AES */
#endif /* ! WOLFHSM_NO_CRYPTO */

/* Counter functions */
int wh_Client_CounterInitRequest(whClientContext* c, whNvmId counterId,
    uint32_t counter);
int wh_Client_CounterInitResponse(whClientContext* c, uint32_t* counter);
/**
 * @brief Creates and initializes a counter with the value set in counter.
 *
 * This function creates/resets a counter with the supplied counterId and gives
 * it the value stored in counter at the start of the call.
 *
 * @param[in] c Pointer to the whClientContext structure.
 * @param[in] counterId counter ID to be associated with the counter.
 * @param[in/out] counter Value to initialize the counter with, retruns with
 * the value set by the HSM for confirmation.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CounterInit(whClientContext* c, whNvmId counterId,
    uint32_t* counter);

int wh_Client_CounterResetRequest(whClientContext* c, whNvmId counterId);
int wh_Client_CounterResetResponse(whClientContext* c, uint32_t* counter);
/**
 * @brief Creates and initializes a counter with to 0.
 *
 * This function creates/resets a counter with the supplied counterId and gives
 * it the value of 0.
 *
 * @param[in] c Pointer to the whClientContext structure.
 * @param[in] counterId Counter ID to be associated with the counter.
 * @param[out] counter Value set by the HSM for confirmation.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CounterReset(whClientContext* c, whNvmId counterId,
    uint32_t* counter);

int wh_Client_CounterIncrementRequest(whClientContext* c, whNvmId counterId);
int wh_Client_CounterIncrementResponse(whClientContext* c, uint32_t* counter);
/**
 * @brief Increments a counter.
 *
 * This function increments a counter created previously. If the counter would
 * roll over the HSM will saturate the value, keeping it at the uint32_t max.
 *
 * @param[in] c Pointer to the whClientContext structure.
 * @param[in] counterId Counter ID to be associated with the counter.
 * @param[out] counter Value set by the HSM for confirmation.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CounterIncrement(whClientContext* c, whNvmId counterId,
    uint32_t* counter);

int wh_Client_CounterReadRequest(whClientContext* c, whNvmId counterId);
int wh_Client_CounterReadResponse(whClientContext* c, uint32_t* counter);
/**
 * @brief Read a counter.
 *
 * This function read a counter created previously.
 *
 * @param[in] c Pointer to the whClientContext structure.
 * @param[in] counterId Counter ID to be associated with the counter.
 * @param[out] counter Value set by the HSM.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CounterRead(whClientContext* c, whNvmId counterId,
    uint32_t* counter);

int wh_Client_CounterDestroyRequest(whClientContext* c, whNvmId counterId);
int wh_Client_CounterDestroyResponse(whClientContext* c);
/**
 * @brief Destroy a counter.
 *
 * This function destroys an NVM counter created previously.
 *
 * @param[in] c Pointer to the whClientContext structure.
 * @param[in] counterId Counter ID to be associated with the counter.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CounterDestroy(whClientContext* c, whNvmId counterId);

/** NVM functions */
/**
 * @brief Sends a non-volatile memory (NVM) initialization request to the
 * server.
 *
 * This function prepares and sends an NVM initialization request message to the
 * server. The message contains the client NVM ID. This function does not block;
 * it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmInitRequest(whClientContext* c);

/**
 * @brief Receives a non-volatile memory (NVM) initialization response from the
 * server.
 *
 * This function attempts to process an NVM initialization response message from
 * the server. It validates the response and extracts the client and server NVM
 * IDs. This function does not block; it returns WH_ERROR_NOTREADY if a response
 * has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_clientnvm_id Pointer to store the client NVM ID assigned by
 * the server.
 * @param[out] out_servernvm_id Pointer to store the server NVM ID assigned by
 * the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmInitResponse(whClientContext* c, int32_t* out_rc,
                              uint32_t* out_clientnvm_id,
                              uint32_t* out_servernvm_id);

/**
 * @brief Sends a non-volatile memory (NVM) initialization request to the server
 * and receives the response.
 *
 * This function handles the complete process of sending an NVM initialization
 * request to the server and receiving the response. It sends the request and
 * repeatedly attempts to receive a valid response, extracting the client and
 * server NVM IDs from the response once received. This function blocks until
 * the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_clientnvm_id Pointer to store the client NVM ID assigned by
 * the server.
 * @param[out] out_servernvm_id Pointer to store the server NVM ID assigned by
 * the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmInit(whClientContext* c, int32_t* out_rc,
                      uint32_t* out_clientnvm_id, uint32_t* out_servernvm_id);

/**
 * @brief Sends a non-volatile memory (NVM) cleanup request to the server.
 *
 * This function prepares and sends an NVM cleanup request message to the
 * server. This function does not block; it returns immediately after sending
 * the request.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmCleanupRequest(whClientContext* c);

/**
 * @brief Receives a non-volatile memory (NVM) cleanup response from the server.
 *
 * This function attempts to process an NVM cleanup response message from the
 * server. It validates the response. This function does not block; it returns
 * WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmCleanupResponse(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a non-volatile memory (NVM) cleanup request to the server and
 * receives the response.
 *
 * This function handles the complete process of sending an NVM cleanup request
 * to the server and receiving the response. It sends the request and repeatedly
 * attempts to receive a valid response. This function blocks until the entire
 * operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmCleanup(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a request to the server to get available non-volatile memory
 * (NVM) information.
 *
 * This function prepares and sends a request to the server to retrieve
 * information about the available and reclaimable NVM space and objects. This
 * function does not block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmGetAvailableRequest(whClientContext* c);

/**
 * @brief Receives a response from the server with available non-volatile memory
 * (NVM) information.
 *
 * This function attempts to process a response message from the server
 * containing information about the available and reclaimable NVM space and
 * objects. This function does not block; it returns WH_ERROR_NOTREADY if a
 * response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_avail_size Pointer to store the available NVM size.
 * @param[out] out_avail_objects Pointer to store the available NVM objects.
 * @param[out] out_reclaim_size Pointer to store the reclaimable NVM size.
 * @param[out] out_reclaim_objects Pointer to store the reclaimable NVM objects.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmGetAvailableResponse(whClientContext* c, int32_t* out_rc,
                                      uint32_t* out_avail_size,
                                      whNvmId*  out_avail_objects,
                                      uint32_t* out_reclaim_size,
                                      whNvmId*  out_reclaim_objects);

/**
 * @brief Sends a request to the server and receives a response with available
 * non-volatile memory (NVM) information.
 *
 * This function handles the complete process of sending a request to the server
 * to retrieve information about the available and reclaimable NVM space and
 * objects, and receiving the response. It sends the request and repeatedly
 * attempts to receive a valid response. This function blocks until the entire
 * operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_avail_size Pointer to store the available NVM size.
 * @param[out] out_avail_objects Pointer to store the available NVM objects.
 * @param[out] out_reclaim_size Pointer to store the reclaimable NVM size.
 * @param[out] out_reclaim_objects Pointer to store the reclaimable NVM objects.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmGetAvailable(whClientContext* c, int32_t* out_rc,
                              uint32_t* out_avail_size,
                              whNvmId*  out_avail_objects,
                              uint32_t* out_reclaim_size,
                              whNvmId*  out_reclaim_objects);

/**
 * @brief Sends a request to the server to add an object to non-volatile memory
 * (NVM).
 *
 * This function prepares and sends a request to the server to add an object to
 * the NVM. The request includes the object ID, access permissions, flags,
 * label, and data. This function does not block; it returns immediately after
 * sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The ID of the NVM object to add.
 * @param[in] access The access permissions for the NVM object.
 * @param[in] flags Flags associated with the NVM object.
 * @param[in] label_len The length of the label.
 * @param[in] label Pointer to the label data.
 * @param[in] len The length of the data.
 * @param[in] data Pointer to the data to be added.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectRequest(whClientContext* c, whNvmId id,
                                  whNvmAccess access, whNvmFlags flags,
                                  whNvmSize label_len, uint8_t* label,
                                  whNvmSize len, const uint8_t* data);

/**
 * @brief Receives a response from the server after attempting to add an object
 * to non-volatile memory (NVM).
 *
 * This function attempts to process a response message from the server after an
 * add object request. It validates the response and extracts the return code.
 * This function does not block; it returns WH_ERROR_NOTREADY if a response has
 * not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectResponse(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a request to the server and receives a response to add an object
 * to non-volatile memory (NVM).
 *
 * This function handles the complete process of sending a request to the server
 * to add an object to the NVM and receiving the response. It sends the request
 * and repeatedly attempts to receive a valid response. This function blocks
 * until the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The ID of the NVM object to add.
 * @param[in] access The access permissions for the NVM object.
 * @param[in] flags Flags associated with the NVM object.
 * @param[in] label_len The length of the label.
 * @param[in] label Pointer to the label data.
 * @param[in] len The length of the data.
 * @param[in] data Pointer to the data to be added.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmAddObject(whClientContext* c, whNvmId id, whNvmAccess access,
                           whNvmFlags flags, whNvmSize label_len,
                           uint8_t* label, whNvmSize len, const uint8_t* data,
                           int32_t* out_rc);

/**
 * @brief Sends a request to the server to list non-volatile memory (NVM)
 * objects.
 *
 * This function prepares and sends a request to the server to list NVM objects.
 * The request includes the access permissions, flags, and the starting object
 * ID. This function does not block; it returns immediately after sending the
 * request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] access The access permissions for the NVM objects to list.
 * @param[in] flags Flags associated with the NVM objects to list.
 * @param[in] start_id The starting ID of the NVM objects to list.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmListRequest(whClientContext* c, whNvmAccess access,
                             whNvmFlags flags, whNvmId start_id);

/**
 * @brief Receives a response from the server with a list of non-volatile memory
 * (NVM) objects.
 *
 * This function attempts to process a response message from the server
 * containing a list of NVM objects. It validates the response and extracts the
 * return code, count of objects, and the object IDs. The count is the number of
 * objects that match the flags/access pattern starting at start_id. The out_id
 * is the first matching object ID. This function does not block; it returns
 * WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_count Pointer to store the count of NVM objects that match
 * the criteria.
 * @param[out] out_id Pointer to store the ID of the first matching NVM object.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmListResponse(whClientContext* c, int32_t* out_rc,
                              whNvmId* out_count, whNvmId* out_id);

/**
 * @brief Sends a request to the server and receives a response to list
 * non-volatile memory (NVM) objects.
 *
 * This function handles the complete process of sending a request to the server
 * to list NVM objects and receiving the response. It sends the request and
 * repeatedly attempts to receive a valid response. The count is the number of
 * objects that match the flags/access pattern starting at start_id. The out_id
 * is the first matching object ID. This function blocks until the entire
 * operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] access The access permissions for the NVM objects to list.
 * @param[in] flags Flags associated with the NVM objects to list.
 * @param[in] start_id The starting ID of the NVM objects to list.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_count Pointer to store the count of NVM objects that match
 * the criteria.
 * @param[out] out_id Pointer to store the ID of the first matching NVM object.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmList(whClientContext* c, whNvmAccess access, whNvmFlags flags,
                      whNvmId start_id, int32_t* out_rc, whNvmId* out_count,
                      whNvmId* out_id);

/**
 * @brief Sends a request to the server to get metadata of a non-volatile memory
 * (NVM) object.
 *
 * This function prepares and sends a request to the server to retrieve metadata
 * for a specific NVM object. The request includes the object ID. This function
 * does not block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The ID of the NVM object for which metadata is requested.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmGetMetadataRequest(whClientContext* c, whNvmId id);

/**
 * @brief Receives a response from the server with metadata of a non-volatile
 * memory (NVM) object.
 *
 * This function attempts to process a response message from the server
 * containing metadata of an NVM object. It validates the response and extracts
 * the return code, object ID, access permissions, flags, data length, and
 * label. This function does not block; it returns WH_ERROR_NOTREADY if a
 * response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_id Pointer to store the ID of the NVM object.
 * @param[out] out_access Pointer to store the access permissions of the NVM
 * object.
 * @param[out] out_flags Pointer to store the flags of the NVM object.
 * @param[out] out_len Pointer to store the length of the data.
 * @param[in] label_len The length of the label buffer.
 * @param[out] label Pointer to store the label data.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmGetMetadataResponse(whClientContext* c, int32_t* out_rc,
                                     whNvmId* out_id, whNvmAccess* out_access,
                                     whNvmFlags* out_flags, whNvmSize* out_len,
                                     whNvmSize label_len, uint8_t* label);

/**
 * @brief Sends a request to the server and receives a response to get metadata
 * of a non-volatile memory (NVM) object.
 *
 * This function handles the complete process of sending a request to the server
 * to get metadata of an NVM object and receiving the response. It sends the
 * request and repeatedly attempts to receive a valid response. This function
 * blocks until the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The ID of the NVM object for which metadata is requested.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_id Pointer to store the ID of the NVM object.
 * @param[out] out_access Pointer to store the access permissions of the NVM
 * object.
 * @param[out] out_flags Pointer to store the flags of the NVM object.
 * @param[out] out_len Pointer to store the length of the data.
 * @param[in] label_len The length of the label buffer.
 * @param[out] label Pointer to store the label data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmGetMetadata(whClientContext* c, whNvmId id, int32_t* out_rc,
                             whNvmId* out_id, whNvmAccess* out_access,
                             whNvmFlags* out_flags, whNvmSize* out_len,
                             whNvmSize label_len, uint8_t* label);

/**
 * @brief Sends a request to the server to destroy non-volatile memory (NVM)
 * objects.
 *
 * This function prepares and sends a request to the server to destroy a list of
 * NVM objects. The request includes the count of objects and their IDs. This
 * function does not block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] list_count The number of NVM objects to destroy.
 * @param[in] id_list Pointer to an array of IDs of the NVM objects to destroy.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmDestroyObjectsRequest(whClientContext* c, whNvmId list_count,
                                       const whNvmId* id_list);

/**
 * @brief Receives a response from the server after attempting to destroy
 * non-volatile memory (NVM) objects.
 *
 * This function attempts to process a response message from the server after
 * attempting to destroy NVM objects. It validates the response and extracts the
 * return code. This function does not block; it returns WH_ERROR_NOTREADY if a
 * response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmDestroyObjectsResponse(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a request to the server and receives a response to destroy
 * non-volatile memory (NVM) objects.
 *
 * This function handles the complete process of sending a request to the server
 * to destroy NVM objects and receiving the response. It sends the request and
 * repeatedly attempts to receive a valid response. This function blocks until
 * the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] list_count The number of NVM objects to destroy.
 * @param[in] id_list Pointer to an array of IDs of the NVM objects to destroy.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmDestroyObjects(whClientContext* c, whNvmId list_count,
                                const whNvmId* id_list, int32_t* out_rc);

/**
 * @brief Sends a request to the server to read data from a non-volatile memory
 * (NVM) object.
 *
 * This function prepares and sends a request to the server to read data from a
 * specific NVM object. The request includes the object ID, the offset within
 * the NVM object data to start reading from, and the length of data to read.
 * This function does not block; it returns immediately after sending the
 * request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The ID of the NVM object to read from.
 * @param[in] offset The offset within the NVM object data to start reading
 * from.
 * @param[in] data_len The length of data to read.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmReadRequest(whClientContext* c, whNvmId id, whNvmSize offset,
                             whNvmSize data_len);

/**
 * @brief Receives a response from the server with NVM object data.
 *
 * This function attempts to process a response message from the server
 * containing NVM object data. It validates the response and extracts the return
 * code, the length of the data read, and the data itself. This function does
 * not block; it returns WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_len Pointer to store the length of the data read.
 * @param[out] data Pointer to store the NVM object data.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmReadResponse(whClientContext* c, int32_t* out_rc,
                              whNvmSize* out_len, uint8_t* data);

/**
 * @brief Sends a request to the server and receives a response to read data
 * from a non-volatile memory (NVM) object.
 *
 * This function handles the complete process of sending a request to the server
 * to read data from an NVM object and receiving the response. It sends the
 * request and repeatedly attempts to receive a valid response. This function
 * blocks until the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The ID of the NVM object to read from.
 * @param[in] offset The offset within the NVM object data to start reading
 * from.
 * @param[in] data_len The length of data to read.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @param[out] out_len Pointer to store the length of the data read.
 * @param[out] data Pointer to store the NVM object data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmRead(whClientContext* c, whNvmId id, whNvmSize offset,
                      whNvmSize data_len, int32_t* out_rc, whNvmSize* out_len,
                      uint8_t* data);

/**
 * @brief Sends a request to the server to add an object to non-volatile memory
 * (NVM) using DMA with 32-bit client addresses.
 *
 * This function prepares and sends a request to the server to add an object to
 * NVM using DMA. The request includes the metadata client address, the length
 * of the data, and the data client address. This function does not block; it
 * returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] metadata_hostaddr The client address of the metadata.
 * @param[in] data_len The length of the data to be added.
 * @param[in] data_hostaddr The client address of the data to be added.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectDma32Request(whClientContext* c,
                                       uint32_t         metadata_hostaddr,
                                       whNvmSize        data_len,
                                       uint32_t         data_hostaddr);

/**
 * @brief Receives a response from the server after attempting to add an object
 * to non-volatile memory (NVM) using DMA with 32-bit client addresses.
 *
 * This function attempts to process a response message from the server after
 * attempting to add an object to NVM using DMA. It validates the response and
 * extracts the return code. This function does not block; it returns
 * WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectDma32Response(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a request to the server and receives a response to add an object
 * to non-volatile memory (NVM) using DMA with 32-bit client addresses.
 *
 * This function handles the complete process of sending a request to the server
 * to add an object to NVM using DMA and receiving the response. It sends the
 * request and repeatedly attempts to receive a valid response. This function
 * blocks until the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] metadata_hostaddr The client address of the metadata.
 * @param[in] data_len The length of the data to be added.
 * @param[in] data_hostaddr The client address of the data to be added.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectDma32(whClientContext* c, uint32_t metadata_hostaddr,
                                whNvmSize data_len, uint32_t data_hostaddr,
                                int32_t* out_rc);

/**
 * @brief Sends a request to the server to add an object to non-volatile memory
 * (NVM) using DMA with 64-bit client addresses.
 *
 * This function prepares and sends a request to the server to add an object to
 * NVM using DMA. The request includes the metadata client address, the length
 * of the data, and the data client address. This function does not block; it
 * returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] metadata_hostaddr The client address of the metadata.
 * @param[in] data_len The length of the data to be added.
 * @param[in] data_hostaddr The client address of the data to be added.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectDma64Request(whClientContext* c,
                                       uint64_t         metadata_hostaddr,
                                       whNvmSize        data_len,
                                       uint64_t         data_hostaddr);

/**
 * @brief Receives a response from the server after attempting to add an object
 * to non-volatile memory (NVM) using DMA with 64-bit client addresses.
 *
 * This function attempts to process a response message from the server after
 * attempting to add an object to NVM using DMA. It validates the response and
 * extracts the return code. This function does not block; it returns
 * WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectDma64Response(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a request to the server and receives a response to add an object
 * to non-volatile memory (NVM) using DMA with 64-bit client addresses.
 *
 * This function handles the complete process of sending a request to the server
 * to add an object to NVM using DMA and receiving the response. It sends the
 * request and repeatedly attempts to receive a valid response. This function
 * blocks until the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] metadata_hostaddr The client address of the metadata.
 * @param[in] data_len The length of the data to be added.
 * @param[in] data_hostaddr The client address of the data to be added.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectDma64(whClientContext* c, uint64_t metadata_hostaddr,
                                whNvmSize data_len, uint64_t data_hostaddr,
                                int32_t* out_rc);

/**
 * @brief Sends a request to the server to add an object to non-volatile memory
 * (NVM) using DMA, with automatic detection of client address width (32-bit or
 * 64-bit).
 *
 * This function prepares and sends a request to the server to add an object to
 * NVM using DMA. The client address width (32-bit or 64-bit) is automatically
 * detected. The request includes the metadata client address, the length of the
 * data, and the data client address. This function does not block; it returns
 * immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] metadata Pointer to the metadata.
 * @param[in] data_len The length of the data to be added.
 * @param[in] data Pointer to the data to be added.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectDmaRequest(whClientContext* c,
                                     whNvmMetadata*   metadata,
                                     whNvmSize data_len, const uint8_t* data);

/**
 * @brief Receives a response from the server after attempting to add an object
 * to non-volatile memory (NVM) using DMA, with automatic detection of client
 * address width (32-bit or 64-bit).
 *
 * This function attempts to process a response message from the server after
 * attempting to add an object to NVM using DMA. The client address width
 * (32-bit or 64-bit) is automatically detected. It validates the response and
 * extracts the return code. This function does not block; it returns
 * WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectDmaResponse(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a request to the server and receives a response to add an object
 * to non-volatile memory (NVM) using DMA, with automatic detection of client
 * address width (32-bit or 64-bit).
 *
 * This function handles the complete process of sending a request to the server
 * to add an object to NVM using DMA and receiving the response. The client
 * address width (32-bit or 64-bit) is automatically detected. It sends the
 * request and repeatedly attempts to receive a valid response. This function
 * blocks until the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] metadata Pointer to the metadata.
 * @param[in] data_len The length of the data to be added.
 * @param[in] data Pointer to the data to be added.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmAddObjectDma(whClientContext* c, whNvmMetadata* metadata,
                              whNvmSize data_len, const uint8_t* data,
                              int32_t* out_rc);

/**
 * @brief Sends a request to the server to read data from non-volatile memory
 * (NVM) using DMA with a 32-bit client address.
 *
 * This function prepares and sends a request to the server to read data from
 * NVM using DMA with a 32-bit client address. The request includes the NVM ID,
 * offset, length of the data, and the data client address. This function does
 * not block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The NVM ID of the object to read.
 * @param[in] offset The offset within the object to start reading from.
 * @param[in] data_len The length of the data to be read.
 * @param[in] data_hostaddr The 32-bit client address where the data will be
 * read into.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmReadDma32Request(whClientContext* c, whNvmId id,
                                  whNvmSize offset, whNvmSize data_len,
                                  uint32_t data_hostaddr);

/**
 * @brief Receives a response from the server after attempting to read data from
 * non-volatile memory (NVM) using DMA with a 32-bit client address.
 *
 * This function attempts to process a response message from the server after
 * attempting to read data from NVM using DMA with a 32-bit client address. It
 * validates the response and extracts the return code. This function does not
 * block; it returns WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmReadDma32Response(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a request to the server and receives a response to read data
 * from non-volatile memory (NVM) using DMA with a 32-bit client address.
 *
 * This function handles the complete process of sending a request to the server
 * to read data from NVM using DMA with a 32-bit client address and receiving
 * the response. It sends the request and repeatedly attempts to receive a valid
 * response. This function blocks until the entire operation is complete or an
 * error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The NVM ID of the object to read.
 * @param[in] offset The offset within the object to start reading from.
 * @param[in] data_len The length of the data to be read.
 * @param[in] data_hostaddr The 32-bit client address where the data will be
 * read into.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmReadDma32(whClientContext* c, whNvmId id, whNvmSize offset,
                           whNvmSize data_len, uint32_t data_hostaddr,
                           int32_t* out_rc);

/**
 * @brief Sends a request to the server to read data from non-volatile memory
 * (NVM) using DMA with a 64-bit client address.
 *
 * This function prepares and sends a request to the server to read data from
 * NVM using DMA with a 64-bit client address. The request includes the NVM ID,
 * offset, length of the data, and the data client address. This function does
 * not block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The NVM ID of the object to read.
 * @param[in] offset The offset within the object to start reading from.
 * @param[in] data_len The length of the data to be read.
 * @param[in] data_hostaddr The 64-bit client address where the data will be
 * read into.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmReadDma64Request(whClientContext* c, whNvmId id,
                                  whNvmSize offset, whNvmSize data_len,
                                  uint64_t data_hostaddr);

/**
 * @brief Receives a response from the server after attempting to read data from
 * non-volatile memory (NVM) using DMA with a 64-bit client address.
 *
 * This function attempts to process a response message from the server after
 * attempting to read data from NVM using DMA with a 64-bit client address. It
 * validates the response and extracts the return code. This function does not
 * block; it returns WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmReadDma64Response(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a request to the server and receives a response to read data
 * from non-volatile memory (NVM) using DMA with a 64-bit client address.
 *
 * This function handles the complete process of sending a request to the server
 * to read data from NVM using DMA with a 64-bit client address and receiving
 * the response. It sends the request and repeatedly attempts to receive a valid
 * response. This function blocks until the entire operation is complete or an
 * error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The NVM ID of the object to read.
 * @param[in] offset The offset within the object to start reading from.
 * @param[in] data_len The length of the data to be read.
 * @param[in] data_hostaddr The 64-bit client address where the data will be
 * read into.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmReadDma64(whClientContext* c, whNvmId id, whNvmSize offset,
                           whNvmSize data_len, uint64_t data_hostaddr,
                           int32_t* out_rc);

/**
 * @brief Sends a request to the server to read data from non-volatile memory
 * (NVM) using DMA, with automatic detection of client address width (32-bit or
 * 64-bit).
 *
 * This function prepares and sends a request to the server to read data from
 * NVM using DMA. The client address width (32-bit or 64-bit) is automatically
 * detected. The request includes the NVM ID, offset, length of the data, and
 * the data client address. This function does not block; it returns immediately
 * after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The NVM ID of the object to read.
 * @param[in] offset The offset within the object to start reading from.
 * @param[in] data_len The length of the data to be read.
 * @param[in] data Pointer to the data buffer where the data will be read into.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmReadDmaRequest(whClientContext* c, whNvmId id,
                                whNvmSize offset, whNvmSize data_len,
                                uint8_t* data);

/**
 * @brief Receives a response from the server after attempting to read data from
 * non-volatile memory (NVM) using DMA, with automatic detection of client
 * address width (32-bit or 64-bit).
 *
 * This function attempts to process a response message from the server after
 * attempting to read data from NVM using DMA. The client address width (32-bit
 * or 64-bit) is automatically detected. It validates the response and extracts
 * the return code. This function does not block; it returns WH_ERROR_NOTREADY
 * if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_NvmReadDmaResponse(whClientContext* c, int32_t* out_rc);

/**
 * @brief Sends a request to the server and receives a response to read data
 * from non-volatile memory (NVM) using DMA, with automatic detection of client
 * address width (32-bit or 64-bit).
 *
 * This function handles the complete process of sending a request to the server
 * to read data from NVM using DMA and receiving the response. The client
 * address width (32-bit or 64-bit) is automatically detected. It sends the
 * request and repeatedly attempts to receive a valid response. This function
 * blocks until the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The NVM ID of the object to read.
 * @param[in] offset The offset within the object to start reading from.
 * @param[in] data_len The length of the data to be read.
 * @param[in] data Pointer to the data buffer where the data will be read into.
 * @param[out] out_rc Pointer to store the return code from the server.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_NvmReadDma(whClientContext* c, whNvmId id, whNvmSize offset,
                         whNvmSize data_len, uint8_t* data, int32_t* out_rc);

/* Client custom-callback support */

/**
 * @brief Sends a custom callback request to the server.
 *
 * This function prepares and sends a custom callback request to the server.
 * The request includes the custom callback request structure.
 * This function does not block; it returns immediately after sending the
 * request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] req Pointer to the custom callback request structure.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CustomCbRequest(whClientContext*                 c,
                              const whMessageCustomCb_Request* req);

/**
 * @brief Receives a response from the server after sending a custom callback
 * request.
 *
 * This function attempts to process a response message from the server after
 * sending a custom callback request. It validates the response and extracts the
 * return code. This function does not block; it returns WH_ERROR_NOTREADY if a
 * response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] resp Pointer to store the custom callback response from the
 * server.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available, or a negative error code on failure.
 */
int wh_Client_CustomCbResponse(whClientContext*            c,
                               whMessageCustomCb_Response* resp);

/**
 * @brief Sends a request to the server to check if a custom callback is
 * registered.
 *
 * This function prepares and sends a request to the server to check if a custom
 * callback is registered. The request includes the callback ID. This function
 * does not block; it returns immediately after sending the request.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The ID of the custom callback to check.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CustomCheckRegisteredRequest(whClientContext* c, uint32_t id);

/**
 * @brief Receives a response from the server after checking if a custom
 * callback is registered.
 *
 * This function attempts to process a response message from the server after
 * checking if a custom callback is registered. It validates the response and
 * extracts the return code and callback ID. This function does not block; it
 * returns WH_ERROR_NOTREADY if a response has not been received.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] outId Pointer to store the callback ID from the server.
 * @param[out] responseError Pointer to store the response error code from the
 * server.
 * @return int Returns 0 if the callback is registered, WH_ERROR_NOHANDLER if it
 * is not registered, or a negative error code on failure.
 */
int wh_Client_CustomCbCheckRegisteredResponse(whClientContext* c,
                                              uint16_t*        outId,
                                              int*             responseError);

/**
 * @brief Sends a request to the server and receives a response to check if a
 * custom callback is registered.
 *
 * This function handles the complete process of sending a request to the server
 * to check if a custom callback is registered and receiving the response. It
 * sends the request and repeatedly attempts to receive a valid response. This
 * function blocks until the entire operation is complete or an error occurs.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] id The ID of the custom callback to check.
 * @param[out] responseError Pointer to store the response error code from the
 * server.
 * @return int Returns 0 if the callback is registered, WH_ERROR_NOHANDLER if it
 * is not registered, or a negative error code on failure.
 */
int wh_Client_CustomCbCheckRegistered(whClientContext* c, uint16_t id,
                                      int* responseError);


#endif /* WOLFHSM_WH_CLIENT_H_ */
