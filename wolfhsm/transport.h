/*
 * wolfhsm/transport.h
 *
 * Abstract library to provide non-blocking client/server packet-based data
 * transfers.  The transport must support a minimum packet size of
 * WOLFHSM_COMM_MTU, which is about 1300 bytes.
 *
 * This header file provides the declarations for all necessary functions to be
 * implemented by target-specific transports.
 *
 * All functions return an integer value with 0 meaning success and !=0 an error
 * enumerated either within wolfssl/wolfcrypt/error-crypt.h or in the function
 * comments.  Unless otherwise noted, all functions are non-blocking and each
 * may update the context state or perform other bookkeeping actions as
 * necessary.
 */

#ifndef WOLFHSM_TRANSPORT_H_
#define WOLFHSM_TRANSPORT_H_

#include <stdint.h>  /* For sized ints */

typedef struct {
    /* Reset the state of the transport and establish communications.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL context or config, or invalid config
     *          WH_ERROR_ABORTED if fatal error occurred.
     */
    int (*Init)(void* context, const void* config);

    /* Send a new request to the server.  This may also reconnect as necessary.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL data or context, or invalid size
     *          WH_ERROR_NOTREADY if send buffer is not free. Retry.
     *          WH_ERROR_ABORTED if fatal error occurred. Cleanup.
     */
    int (*Send)(void* context, uint16_t size, const void* data);

    /* Receive a new response from the server.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL data or context
     *          WH_ERROR_NOTREADY if recv buffer is not filled. Retry.
     *          WH_ERROR_ABORTED if fatal error occurred. Cleanup.
     */
    int (*Recv)(void* context, uint16_t *out_size, void* data);

    /* Close the connection.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL context
     */
    int (*Cleanup)(void* context);
} wh_TransportClient_Cb;

typedef struct {
    /* Reset the state of the transport and be ready for communications.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL context or config, or invalid config
     *          WH_ERROR_ABORTED if fatal error occurred.
     */
    int (*Init)(void* context, const void* config);

    /* Receive a new request from the client. This may also accept a connection.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL data or context
     *          WH_ERROR_NOTREADY if recv buffer is not filled. Retry.
     *          WH_ERROR_ABORTED if fatal error occurred. Cleanup.
     */
    int (*Recv)(void* context, uint16_t* inout_size, void* data);

    /* Send a new request to the server.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL data or context, or invalid size
     *          WH_ERROR_NOTREADY if send buffer is not free. Retry.
     *          WH_ERROR_ABORTED if fatal error occurred. Cleanup.
     */
    int (*Send)(void* context, uint16_t data_size, const void* data);

    /* Close the connection.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL context
     */
    int (*Cleanup)(void* context);
} wh_TransportServer_Cb;

#endif /* WOLFHSM_TRANSPORT_H_ */
