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
 * wolfhsm/error.h
 *
 * WolfHSM-specific error codes
 */

#ifndef WOLFHSM_WH_ERROR_H_
#define WOLFHSM_WH_ERROR_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

enum WH_ERROR_ENUM {
    WH_ERROR_OK = 0, /* Success, no error. */

    /* General errors */
    WH_ERROR_BADARGS     = -2000, /* No side effects. Fix args. */
    WH_ERROR_NOTREADY    = -2001, /* Retry function. */
    WH_ERROR_ABORTED     = -2002, /* Function has fatally failed. Cleanup. */
    WH_ERROR_RESERVED1   = -2003, /* Reserved for future use */
    WH_ERROR_RESERVED2   = -2004, /* Reserved for future use */
    WH_ERROR_CERT_VERIFY = -2005, /* Certificate verification failed */
    WH_ERROR_BUFFER_SIZE = -2006, /* Generic buffer size mismatch. Buffer
                                   * length is not what was expected */
    WH_ERROR_NOHANDLER = -2007,   /* No handler for requested action */
    WH_ERROR_NOTIMPL   = -2008,   /* Functionality not implemented given the
                                      compile-time configuration */
    WH_ERROR_USAGE =
        -2009, /* Operation not permitted based on object/key usage flags */
    WH_ERROR_BADCONFIG = -2010, /* Failed due to runtime configuration */

    /* NVM and keystore specific status returns */
    WH_ERROR_LOCKED      = -2100, /* Unlock and retry if necessary */
    WH_ERROR_ACCESS      = -2101, /* Update access and retry */
    WH_ERROR_NOTVERIFIED = -2102, /* Backing store does not match */
    WH_ERROR_NOTBLANK    = -2103, /* Area is not blank */
    WH_ERROR_NOTFOUND    = -2104, /* Matching object not found */
    WH_ERROR_NOSPACE     = -2105, /* No available space */

    /* SHE-specific error codes */
    WH_SHE_ERC_SEQUENCE_ERROR    = -2200,
    WH_SHE_ERC_KEY_NOT_AVAILABLE = -2201,
    WH_SHE_ERC_KEY_INVALID       = -2202,
    WH_SHE_ERC_KEY_EMPTY         = -2203,
    WH_SHE_ERC_NO_SECURE_BOOT    = -2204,
    WH_SHE_ERC_WRITE_PROTECTED   = -2205,
    WH_SHE_ERC_KEY_UPDATE_ERROR  = -2206,
    WH_SHE_ERC_RNG_SEED          = -2207,
    WH_SHE_ERC_NO_DEBUGGING      = -2208,
    WH_SHE_ERC_BUSY              = -2209,
    WH_SHE_ERC_MEMORY_FAILURE    = -2210,
    WH_SHE_ERC_GENERAL_ERROR     = -2211,
};

#define WH_SHE_ERC_NO_ERROR WH_ERROR_OK

#endif /* !WOLFHSM_WH_ERROR_H_ */
