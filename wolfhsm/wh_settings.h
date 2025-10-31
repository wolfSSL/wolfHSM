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
 *  WOLFHSM_CFG_GLOBAL_KEYS - If defined, enable global key support allowing
 *  keys to be shared across multiple clients
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_KEYWRAP - If defined, include the key wrap functionality
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE - The maximum size (in bytes) of a key that
 *  can be wrapped
 *      Default: 512
 *
 *  WOLFHSM_CFG_HEXDUMP - If defined, include wh_Utils_HexDump functionality
 *                          using stdio.h
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_ENABLE_CLIENT - If defined, include client-specific
 * functionality
 *
 *  WOLFHSM_CFG_ENABLE_SERVER - If defined, include server-specific
 * functionality
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
 *  WOLFHSM_CFG_DMAADDR_COUNT - Number of DMA address regions
 *      Default: 10
 *
 *  WOLFHSM_CFG_SERVER_IMG_MGR_MAX_IMG_COUNT - Maximum number of images that can
 * be managed Default: 4
 *
 *  WOLFHSM_CFG_SERVER_IMG_MGR_MAX_SIG_SIZE - Maximum signature size for image
 * verification Default: 512 bytes (RSA4096)
 *
 *  WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY - if defined, allows to setup a custom
 * callback to handle client to server and/or server to client memory copy
 * operation in DMA requests.
 *     Default: Not defined
 *
 *  WOLFHSM_CFG_IS_TEST_SERVER - If defined, the client-side unit tests assume
 * the server will be running custom server-side test instrumentation meant to
 * test additional edge cases that could otherwise not be triggered when running
 * against a standard server. Not relevant outside of the wolfHSM POSIX port
 * test harness.
 *     Default: Not defined
 *
 *  WOLFHSM_CFG_CANCEL_API - If defined, enables the cancellation API support
 * allowing clients to cancel in-progress operations. This includes the client
 * cancel functions and server-side cancellation handling. When not defined,
 * all cancellation code is compiled out.
 *     Default: Not defined
 *
 *  Overridable porting functions:
 *
 *  XMEMFENCE() - Create a sequential memory consistency sync point.  Note this
 *                is compiler specific and generates hardware specific fence
 *                instructions. Default works for modern gcc and clang
 *      Default: (gcc or clang) __atomic_thread_fence(__ATOMIC_SEQ_CST)
 *               (other) do {} while (0)
 *
 *  XCACHELINE - Size in bytes of a cache line
 *      Default: 32
 *
 *  #ifndef XCACHEFLUSH(ptr) - Flush the cache line including ptr
 *      DefaultL (void)(ptr)
 *
 *  #ifndef XCACHEFLUSHBLK(ptr, n) - Flush the cache lines starting at ptr for
 *                                   at least n bytes
 *      DefaultL wh_Utils_CacheFlush(ptr, n)
 *
 *  #ifndef XCACHEINVLD(ptr) - Invalidate the cache line including ptr
 *      DefaultL (void)(ptr)
 *
 *  #ifndef XCACHEINVLDBLK(ptr, n) - Invalidate the cache lines starting at ptr
 *                                   for at least n bytes
 *      DefaultL wh_Utils_CacheInvalidate(ptr, n)
 *
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

#if defined(DEBUG_CRYPTOCB) || defined(DEBUG_CRYPTOCB_VERBOSE)
#define WOLFHSM_CFG_HEXDUMP
#endif /* DEBUG_CRYPTOCB || DEBUG_CRYPTOCB_VERBOSE */
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

/* Number of big RAM keys */
#ifndef WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT  1
#endif

/* Size in bytes of each key cache buffer  */
#ifndef WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE
#define WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE 256
#endif

/* Size in bytes of each big key cache buffer  */
#ifndef WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE 1200
#endif

/* Custom request shared defs */
#ifndef WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT
#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 8
#endif

/* DMA translation allow entries */
#ifndef WOLFHSM_CFG_DMAADDR_COUNT
#define WOLFHSM_CFG_DMAADDR_COUNT 10
#endif

/* Image manager maximum number of images */
#ifndef WOLFHSM_CFG_SERVER_IMG_MGR_MAX_IMG_COUNT
#define WOLFHSM_CFG_SERVER_IMG_MGR_MAX_IMG_COUNT 4
#endif

/* Image manager maximum signature size (RSA4096 = 512 bytes) */
#ifndef WOLFHSM_CFG_SERVER_IMG_MGR_MAX_SIG_SIZE
#define WOLFHSM_CFG_SERVER_IMG_MGR_MAX_SIG_SIZE 512
#endif

/*  WOLFHSM_CFG_CUSTOMCB_LEN - Maximum size of a customcb message.
 *      Default: 256 */
#ifndef WOLFHSM_CFG_CUSTOMCB_LEN
#define WOLFHSM_CFG_CUSTOMCB_LEN 256
#endif

/* Maximum size of a certificate */
#ifndef WOLFHSM_CFG_MAX_CERT_SIZE
#ifndef WOLFHSM_CFG_DMA
#define WOLFHSM_CFG_MAX_CERT_SIZE WOLFHSM_CFG_COMM_DATA_LEN
#else
#define WOLFHSM_CFG_MAX_CERT_SIZE 4096
#endif
#endif

/** Configuration checks */
#ifndef WOLFHSM_CFG_NO_CRYPTO
/* Crypto Cb is mandatory */
#ifndef WOLF_CRYPTO_CB
#error "wolfHSM requires wolfCrypt built with WOLF_CRYPTO_CB"
#endif

/* wolfHSM crypto callback assumes wc_CryptoInfo struct is unionized */
#if !defined(HAVE_ANONYMOUS_INLINE_AGGREGATES) || \
     (defined(HAVE_ANONYMOUS_INLINE_AGGREGATES) &&\
         HAVE_ANONYMOUS_INLINE_AGGREGATES==0 )
#error "wolfHSM needs wolfCrypt built with HAVE_ANONYMOUS_INLINE_AGGREGATES=1"
#endif

/* Rng is mandatory */
#ifdef NO_RNG
#error "wolfHSM requires wolfCrypt built without NO_RNG"
#endif

#if defined WOLFHSM_CFG_SHE_EXTENSION
#if defined(NO_AES) || \
    !defined(WOLFSSL_CMAC) || \
    !defined(WOLFSSL_AES_DIRECT) || \
    !defined(HAVE_AES_ECB)
#error "WOLFHSM_CFG_SHE_EXTENSION requires AES, WOLFSSL_CMAC, WOLFSSL_AES_DIRECT, and HAVE_AES_ECB"
#endif
#endif

#if defined(WOLFHSM_CFG_KEYWRAP)

#ifndef WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE
#define WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE 2000
#endif

#ifndef WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE
#define WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE 2000
#endif

#if defined(NO_AES) || !defined(HAVE_AESGCM)
#error \
    "WOLFHSM_CFG_KEYWRAP requires NO_AES to be undefined and HAVE_AESGCM to be defined"
#endif

#endif /* WOLFHSM_CFG_KEYWRAP */

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
#if !defined(WOLFSSL_ACERT) || !defined(WOLFSSL_ASN_TEMPLATE)
#error \
    "WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT requires WOLFSSL_ACERT and WOLFSSL_ASN_TEMPLATE configured in wolfSSL"
#endif /* !WOLFSSL_ACERT || !WOLFSSL_ASN_TEMPLATE */
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#if defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_KEYWRAP)
#error "WOLFHSM_CFG_KEYWRAP is incompatible with WOLFHSM_CFG_NO_CRYPTO"
#endif

/** Cache flushing and memory fencing synchronization primitives */
/* Create a full sequential memory fence to ensure compiler memory ordering */
#ifndef XMEMFENCE
 #ifndef WOLFHSM_CFG_NO_CRYPTO
  #include "wolfssl/wolfcrypt/wc_port.h"
  #define XMEMFENCE() XFENCE()
 #else
  #if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)
   #include <stdatomic.h>
   #define XMEMFENCE() atomic_thread_fence(memory_order_seq_cst)
  #elif defined(__GNUC__) || defined(__clang__)
   #define XMEMFENCE() __atomic_thread_fence(__ATOMIC_SEQ_CST)
  #else
   /* PPC32: __asm__ volatile ("sync" : : : "memory") */
   #define XMEMFENCE() do { } while (0)
   #warning "wolfHSM memory transports should have a functional XMEMFENCE"
  #endif
 #endif
#endif

/* Return cacheline size */
#ifndef XCACHELINE
#define XCACHELINE (32)
#endif

/* Flush the cache line at _p. Used after writing to ensure the memory is
 * consistent. */
#ifndef XCACHEFLUSH
#define XCACHEFLUSH(_p) (void)(_p)
/* PPC32: __asm__ volatile ("dcbf 0, %0" : : "r" (_p): "memory") */
#endif

/* Flush the cache lines starting at _p for at least _n bytes. */
#ifndef XCACHEFLUSHBLK
#define XCACHEFLUSHBLK(_p, _n) wh_Utils_CacheFlush((_p), (_n))
#endif

/* Invalidate the cache line at _p. Used prior to reading to ensure
 * freshness. */
#ifndef XCACHEINVLD
#define XCACHEINVLD(_p) (void)(_p)
/* PPC32: __asm__ volatile ("dcbi 0, %0" : : "r" (_p): "memory") */
#endif

/* Invalidate the cache lines starting  at _p for at least _n bytes. */
#ifndef XCACHEINVLDBLK
#define XCACHEINVLDBLK(_p, _n) wh_Utils_CacheInvalidate((_p), (_n))
#endif

/* DMA Configuration */

#ifdef WOLFHSM_CFG_DMA

/* Attempt to discover pointer size from build system/architecture */
#ifndef WH_PTR_SIZE
/* check for __SIZEOF_POINTER__ if available (GCC/clang) */
#if defined(__SIZEOF_POINTER__)
    #define WH_PTR_SIZE __SIZEOF_POINTER__
/* Fallback to compiler/architecture-specific checks */
#elif defined(__IAR_SYSTEMS_ICC__)
/* IAR compiler */
#if __INTPTR_WIDTH__ == 64
        #define WH_PTR_SIZE 8
#elif __INTPTR_WIDTH__ == 32
        #define WH_PTR_SIZE 4
#else
        #error "Unsupported pointer width in IAR toolchain"
#endif
#elif defined(__TASKING__)
/* TASKING compiler */
#if defined(__CPU__) && __CPU__ == 64
        #define WH_PTR_SIZE 8
#elif defined(__CPU__) && __CPU__ == 32
        #define WH_PTR_SIZE 4
#else
        #error "Unsupported pointer width in TASKING toolchain"
#endif
#else
#error \
    "Unable to automatically determine pointer size, please define WH_PTR_SIZE"
#endif
#endif /* WH_PTR_SIZE */


#ifndef WOLFHSM_CFG_DMA_PTR_SIZE
#define WOLFHSM_CFG_DMA_PTR_SIZE (WH_PTR_SIZE)
#endif

#define WH_DMA_IS_32BIT (WOLFHSM_CFG_DMA_PTR_SIZE == 4)
#define WH_DMA_IS_64BIT (WOLFHSM_CFG_DMA_PTR_SIZE == 8)

#if (!WH_DMA_IS_32BIT && !WH_DMA_IS_64BIT)
#error "wolfHSM only supports 32-bit or 64-bit pointer sizes"
#endif

#ifndef WOLFHSM_CFG_DMA_ALT_PTR_SIZE
#if WOLFHSM_CFG_DMA_PTR_SIZE != WH_PTR_SIZE
#error "wolfHSM DMA pointer size must match system pointer size"
#endif
#endif

#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_WH_SETTINGS_H_ */
