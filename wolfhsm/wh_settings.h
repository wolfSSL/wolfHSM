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
 * wolfhsm/wh_settings.h
 *
 * Configuration values:
 *
 *  WOLFHSM_CFG_COMM_DATA_LEN - Maximum length of data payload
 *      Default: 1280 bytes
 *
 *  WOLFHSM_CFG_INFOVERSION Reported version string
 *      Default: "01.01.01"
 *
 *  WOLFHSM_CFG_INFOBUILD Reported build string (SHA hash)
 *      Default: "12345678"
 *
 *  WOLFHSM_CFG_NO_CRYPTO - If defined, include no wolfCrypt dependencies
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_SHE_EXTENSION - If defined, include AutoSAR SHE functionality
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_NVM_OBJECT_COUNT - Number of objects in ram and disk directories
 *      Default: 32
 *
 *  WOLFHSM_CFG_SERVER_KEYCACHE_COUNT - Number of RAM keys
 *      Default: 8
 *
 *  WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE - Size of each key in RAM
 *      Default: 1200
 *
 *  WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT - Number of additional callbacks
 *      Default: 8
 *
 *  WOLFHSM_CFG_SERVER_DMAADDR_COUNT - Number of DMA address regions
 *      Default: 10
 *
 */

#ifndef WOLFHSM_WH_SETTINGS_H_
#define WOLFHSM_WH_SETTINGS_H_

#ifdef WOLFHSM_CFG
#include "wolfhsm_cfg.h"
#endif

#ifndef WOLFHSM_CFG_NO_CRYPTO
#ifdef WOLFSSL_USER_SETTINGS
#include "user_settings.h"
#endif /* WOLFSSL_USER_SETTINGS */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

/** Default shares configurations */
/* Maximum length of the data portion of a request/reply message */
#ifndef WOLFHSM_CFG_COMM_DATA_LEN
#define WOLFHSM_CFG_COMM_DATA_LEN 1280
#endif

/** Default server resource configurations */
/* Reported version string */
#ifndef WOLFHSM_CFG_INFOVERSION
#define WOLFHSM_CFG_INFOVERSION "01.01.01"
#endif

/* Reported build identifier string */
#ifndef WOLFHSM_CFG_INFOBUILD
#define WOLFHSM_CFG_INFOBUILD "12345678"
#endif


/* Number of NVM objects in the directory */
#ifndef WOLFHSM_CFG_NVM_OBJECT_COUNT
#define WOLFHSM_CFG_NVM_OBJECT_COUNT 32
#endif

/* Number of RAM keys */
#ifndef WOLFHSM_CFG_SERVER_KEYCACHE_COUNT
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT  8
#endif

/* Size in bytes of each key cache buffer  */
#ifndef WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE
#define WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE 1200
#endif

/* Custom request shared defs */
#ifndef WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT
#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 8
#endif

/* DMA translation allow entries */
#ifndef WOLFHSM_CFG_SERVER_DMAADDR_COUNT
#define WOLFHSM_CFG_SERVER_DMAADDR_COUNT 10
#endif

/*  WOLFHSM_CFG_CUSTOMCB_LEN - Maximum size of a customcb message.
 *      Default: 256 */
#ifndef WOLFHSM_CFG_CUSTOMCB_LEN
#define WOLFHSM_CFG_CUSTOMCB_LEN 256
#endif

/** Configuration checks */
#ifndef WOLFHSM_CFG_NO_CRYPTO
/* Crypto Cb is mandatory */
#ifndef WOLF_CRYPTO_CB
#error "wolfHSM requires wolfCrypt built with WOLF_CRYPTO_CB"
#endif

/* wolfHSM crypto callback assumes wc_CryptoInfo struct is unionized */
#if !defined(HAVE_ANONYMOUS_INLINE_AGGREGATES) \
    || ( defined(HAVE_ANONYMOUS_INLINE_AGGREGATES) \
         && HAVE_ANONYMOUS_INLINE_AGGREGATES==0  )
#error "wolfHSM needs wolfCrypt built with HAVE_ANONYMOUS_INLINE_AGGREGATES=1"
#endif

#endif /* !WOLFHSM_CFG_NO_CRYPTO */


#endif /* !WOLFHSM_WH_SETTINGS_H_ */
