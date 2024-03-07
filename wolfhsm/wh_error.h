/*
 * wolfhsm/error.h
 *
 * WolfHSM-specific error codes
 */

#ifndef WOLFHSM_WH_ERROR_H_
#define WOLFHSM_WH_ERROR_H_

/* Consider reusing wolfssl or wolfcrypt errors here */

enum {
    WH_ERROR_OK             = 0,    /* Success, no error. */

    /* General errors */
    WH_ERROR_BADARGS        = -400, /* No side effects. Fix args. */
    WH_ERROR_NOTREADY       = -401, /* Retry function. */
    WH_ERROR_ABORTED        = -402, /* Function has fatally failed. Cleanup. */

    /* NVM-specific status returns */
    WH_ERROR_LOCKED         = -410, /* Unlock and retry if necessary */
    WH_ERROR_ACCESS         = -411, /* Update access and retry */
    WH_ERROR_NOTVERIFIED    = -412, /* Backing store does not match */
    WH_ERROR_NOTBLANK       = -413, /* Area is no blank */
    WH_ERROR_NOTFOUND       = -414, /* Matching object not found */
    WH_ERROR_NOSPACE        = -415, /* No available space */
};

#endif /* WOLFHSM_WH_ERROR_H_ */
