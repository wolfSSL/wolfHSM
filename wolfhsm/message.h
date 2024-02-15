/*
 * wolfhsm/message.h
 *
 * Basic message structure assuming a reliable comm transport with metadata
 * support of 16-bit type.
 */

#ifndef WOLFHSM_MESSAGE_H_
#define WOLFHSM_MESSAGE_H_

/* Message type and groups */
enum {
    WOLFHSM_MESSAGE_TYPE_MASK           = 0xFF, /* 256 total types */
    WOLFHSM_MESSAGE_TYPE_NONE           = 0x00, /* No message type */

    WOLFHSM_MESSAGE_AUX_REQ_NORMAL      = 0x00, /* Normal request */
    WOLFHSM_MESSAGE_AUX_REQ_NORESP      = 0x01, /* Request without response*/
    WOLFHSM_MESSAGE_AUX_REQ_SESSION     = 0x02, /* Request within session*/

    WOLFHSM_MESSAGE_AUX_RESP_OK         = 0x00, /* Response is valid */
    WOLFHSM_MESSAFE_AUX_RESP_ERROR      = 0x01, /* Request failed with error */
    WOLFHSM_MESSAGE_AUX_RESP_UNSUPP     = 0xFF, /* Request is not supported */
    WOLFHSM_MESSAGE_AUX_RESP_FATAL      = 0xFE, /* Server condition is fatal */

    WOLFHSM_MESSAGE_GROUP_MASK          = 0xE0, /* 32 entries per group */
    WOLFHSM_MESSAGE_GROUP_COMM          = 0x00, /* Messages used for comms */
    WOLFHSM_MESSAGE_GROUP_NVM           = 0x20, /* NVM functions */
    WOLFHSM_MESSAGE_GROUP_KEY           = 0x40, /* Key/counter management */
    WOLFHSM_MESSAGE_GROUP_CRYPTO        = 0x60, /* wolfCrypt CryptoCb */
    WOLFHSM_MESSAGE_GROUP_IMAGE         = 0x80, /* Image/boot management */
    WOLFHSM_MESSAGE_GROUP_PKCS11        = 0xA0, /* PKCS11 protocol */
    WOLFHSM_MESSAGE_GROUP_SHE           = 0xC0, /* SHE protocol */
    WOLFHSM_MESSAGE_GROUP_CUSTOM        = 0xE0, /* User-specified features */
};

typedef struct {
    int return_code;
} whMessage_ErrorResponse;

int whMessage_GetErrorResponse(uint16_t magic,
        const void* data,
        int *out_return_code);

#endif /* WOLFHSM_MESSAGE_H_ */
