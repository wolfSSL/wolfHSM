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

/* Consider reusing wolfssl or wolfcrypt errors here */


enum WH_ERROR_ENUM {
    WH_ERROR_OK             = 0,    /* Success, no error. */

    /* General errors */
    WH_ERROR_BADARGS        = -400, /* No side effects. Fix args. */
    WH_ERROR_NOTREADY       = -401, /* Retry function. */
    WH_ERROR_ABORTED        = -402, /* Function has fatally failed. Cleanup. */
    WH_ERROR_CANCEL         = -403, /* Operation was canceled */
    WH_ERROR_CANCEL_LATE    = -404, /* Cancel was processed too late */

    /* NVM-specific status returns */
    WH_ERROR_LOCKED         = -410, /* Unlock and retry if necessary */
    WH_ERROR_ACCESS         = -411, /* Update access and retry */
    WH_ERROR_NOTVERIFIED    = -412, /* Backing store does not match */
    WH_ERROR_NOTBLANK       = -413, /* Area is no blank */
    WH_ERROR_NOTFOUND       = -414, /* Matching object not found */
    WH_ERROR_NOSPACE        = -415, /* No available space */

    /* Custom-callback status returns */
    WH_ERROR_NOHANDLER     = -420, /* No handler registered for action */

    WH_SHE_ERC_SEQUENCE_ERROR = -500,
    WH_SHE_ERC_KEY_NOT_AVAILABLE = -501,
    WH_SHE_ERC_KEY_INVALID = -502,
    WH_SHE_ERC_KEY_EMPTY = -503,
    WH_SHE_ERC_NO_SECURE_BOOT = -504,
    WH_SHE_ERC_WRITE_PROTECTED = -505,
    WH_SHE_ERC_KEY_UPDATE_ERROR = -506,
    WH_SHE_ERC_RNG_SEED = -507,
    WH_SHE_ERC_NO_DEBUGGING = -508,
    WH_SHE_ERC_BUSY = -509,
    WH_SHE_ERC_MEMORY_FAILURE = -510,
    WH_SHE_ERC_GENERAL_ERROR = -511,
};

#define WOLFHSM_SHE_ERC_NO_ERROR WH_ERROR_OK

#endif /* WOLFHSM_WH_ERROR_H_ */
