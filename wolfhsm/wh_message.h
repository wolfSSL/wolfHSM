/*
 * wolfhsm/wh_message.h
 *
 * Message groups and actions for dispatch and handling based on a 16-bit kind.
 */

#ifndef WOLFHSM_WH_MESSAGE_H_
#define WOLFHSM_WH_MESSAGE_H_

/* Message groups and kind */
enum {
    WH_MESSAGE_KIND_NONE            = 0x0000, /* No message kind. Invalid */

    WH_MESSAGE_GROUP_MASK           = 0xFF00, /* 255 groups */
    WH_MESSAGE_GROUP_NONE           = 0x0000, /* No group.  Invalid. */

    WH_MESSAGE_GROUP_COMM           = 0x0100, /* Messages used for comms */
    WH_MESSAGE_GROUP_NVM            = 0x0200, /* NVM functions */
    WH_MESSAGE_GROUP_KEY            = 0x0300, /* Key/counter management */
    WH_MESSAGE_GROUP_CRYPTO         = 0x0400, /* wolfCrypt CryptoCb */
    WH_MESSAGE_GROUP_IMAGE          = 0x0500, /* Image/boot management */
    WH_MESSAGE_GROUP_PKCS11         = 0x0600, /* PKCS11 protocol */
    WH_MESSAGE_GROUP_SHE            = 0x0700, /* SHE protocol */
    WH_MESSAGE_GROUP_CUSTOM         = 0x1000, /* User-specified features */

    WH_MESSAGE_ACTION_MASK         = 0x00FF, /* 255 subtypes per group*/
    WH_MESSAGE_ACTION_NONE         = 0x0000, /* No action. Invalid. */
};

/* Construct the message kind based on group and action */
#define WH_MESSAGE_KIND(_G, _S) (   ((_G) & WH_MESSAGE_GROUP_MASK) |      \
                                    ((_S) & WH_MESSAGE_ACTION_MASK))

/* Extract the group from the message kind */
#define WH_MESSAGE_GROUP(_K)        ((_K) & WH_MESSAGE_GROUP_MASK)

/* Extract the action from the message kind */
#define WH_MESSAGE_ACTION(_K)      ((_K) & WH_MESSAGE_ACTION_MASK)

#endif /* WOLFHSM_WH_MESSAGE_H_ */
