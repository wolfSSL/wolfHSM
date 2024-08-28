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
 * wolfhsm/wh_message.h
 *
 * Message groups and actions for dispatch and handling based on a 16-bit kind.
 */

#ifndef WOLFHSM_WH_MESSAGE_H_
#define WOLFHSM_WH_MESSAGE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

/* Message groups and kind */
enum WH_MESSAGE_ENUM {
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
    WH_MESSAGE_GROUP_COUNTER        = 0x0800, /* monotonic counters */
    WH_MESSAGE_GROUP_CANCEL         = 0x0900, /* request cancellation */
    WH_MESSAGE_GROUP_CUSTOM         = 0x0A00, /* User-specified features */
    WH_MESSAGE_GROUP_CRYPTO_DMA     = 0x0B00, /* DMA crypto operations */

    WH_MESSAGE_ACTION_MASK          = 0x00FF,  /* 255 subtypes per group*/
    WH_MESSAGE_ACTION_NONE          = 0x0000,  /* No action. Invalid. */
};

/* keystore actions */
enum WH_KEY_ENUM {
    WH_KEY_CACHE,
    WH_KEY_EVICT,
    WH_KEY_EXPORT,
    WH_KEY_COMMIT,
    WH_KEY_ERASE,
};

/* SHE actions */
enum WH_SHE_ENUM {
    WH_SHE_SET_UID,
    WH_SHE_SECURE_BOOT_INIT,
    WH_SHE_SECURE_BOOT_UPDATE,
    WH_SHE_SECURE_BOOT_FINISH,
    WH_SHE_GET_STATUS,
    WH_SHE_LOAD_KEY,
    WH_SHE_LOAD_PLAIN_KEY,
    WH_SHE_EXPORT_RAM_KEY,
    WH_SHE_INIT_RND,
    WH_SHE_RND,
    WH_SHE_EXTEND_SEED,
    WH_SHE_ENC_ECB,
    WH_SHE_ENC_CBC,
    WH_SHE_DEC_ECB,
    WH_SHE_DEC_CBC,
    WH_SHE_GEN_MAC,
    WH_SHE_VERIFY_MAC,
};

/* counter actions */
enum {
    WH_COUNTER_INIT,
    WH_COUNTER_INCREMENT,
    WH_COUNTER_READ,
    WH_COUNTER_DESTROY,
};

/* Construct the message kind based on group and action */
#define WH_MESSAGE_KIND(_G, _S) (   ((_G) & WH_MESSAGE_GROUP_MASK) |      \
                                    ((_S) & WH_MESSAGE_ACTION_MASK))

/* Extract the group from the message kind */
#define WH_MESSAGE_GROUP(_K)        ((_K) & WH_MESSAGE_GROUP_MASK)

/* Extract the action from the message kind */
#define WH_MESSAGE_ACTION(_K)      ((_K) & WH_MESSAGE_ACTION_MASK)

#endif /* !WOLFHSM_WH_MESSAGE_H_ */
