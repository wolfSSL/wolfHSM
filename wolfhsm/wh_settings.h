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
 *  WOLFHSM_CFG_CRYPTO_AFFINITY - If defined, enable per-client crypto affinity,
 *  allowing a client to request that crypto operations run on the server's
 *  hardware device (WH_CRYPTO_AFFINITY_HW) or in software
 *  (WH_CRYPTO_AFFINITY_SW). When not defined, the server always uses its
 *  configured devId and the affinity request header field is ignored.
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_KEYWRAP - If defined, include the key wrap functionality
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE - The maximum size (in bytes) of a key that
 *  can be wrapped
 *      Default: 512
 *
 *  WOLFHSM_CFG_HWKEYSTORE - If defined, include the hardware keystore
 *  front-end module and hardware-only key (WH_KEYTYPE_HW) support
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_HWKEYSTORE_MAX_KEY_SIZE - The maximum size (in bytes) of a key
 *  served by a hardware keystore backend
 *      Default: 32
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
 *  WOLFHSM_CFG_ENABLE_TIMEOUT - If defined, include client-side support for
 *  blocking request timeouts
 *
 *  WOLFHSM_CFG_ENABLE_AUTHENTICATION - EXPERIMENTAL. If defined, include the
 *  Auth Manager (wh_auth*), which adds per-client user authentication and
 *  per-user authorization to the server. Clients log in with a credential
 *  (PIN or certificate) to establish a session, and the server checks the
 *  resulting per-user permissions (per message group/action, plus key ID
 *  access) before dispatching a request. Checks are only applied if the
 *  server is configured with an auth context; without one all requests are
 *  processed unchecked. The API and wire format are subject to change and
 *  are not covered by compatibility guarantees.
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
 *  WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS - Maximum number of trusted root NVM IDs
 *  accepted in a single wh_Server_CertVerifyMultiRoot request. Bounded so the
 *  non-DMA wire request fits within WOLFHSM_CFG_COMM_DATA_LEN alongside the
 *  candidate chain, and so the inline DMA request struct stays a fixed-size
 *  POD.
 *      Default: 8
 *
 *  WOLFHSM_CFG_IS_TEST_SERVER - If defined, the client-side unit tests assume
 * the server will be running custom server-side test instrumentation meant to
 * test additional edge cases that could otherwise not be triggered when running
 * against a standard server. Not relevant outside of the wolfHSM POSIX port
 * test harness.
 *     Default: Not defined
 *
 *  WOLFHSM_CFG_DEBUG - If defined, enable basic debug output from wolfHSM
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_DEBUG_VERBOSE - If defined, enable verbose debug output
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_THREADSAFE - If defined, enable thread-safe access to shared
 *      server resources. Requires platform to provide lock callbacks via
 *      whLockConfig. When enabled, protects global key cache, NVM operations,
 *      and hardware crypto (if shared). When not defined, all lock operations
 *      are no-ops with zero overhead.
 *      Default: Not defined
 *
 *  WOLFHSM_CFG_PRINTF - Function or macro for printf redirection. Must have
 *      signature: int func(const char* fmt, ...)
 *      Default: stdlib printf
 *      Example custom definition:
 *          #define WOLFHSM_CFG_PRINTF my_custom_printf
 *
 *  WOLFHSM_CFG_NO_SYS_TIME - If defined, all internal calls to obtain the
 system
 *      time will return 0, removing the need to provide
 WOLFHSM_CFG_PORT_GETTIME
 *      for the active port. Note that this will result in nonsensical benchmark
 *      results and log timestamps.
 *
 *  WOLFHSM_CFG_PORT_GETTIME - Function-like macro returning the current system
 *      time in microseconds as a uint64_t. Must be defined in wolfhsm_cfg.h for
 *      the active port UNLESS WOLFHSM_CFG_NO_SYS_TIME is defined

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
 *  XCACHEFLUSH(ptr) - Flush the cache line including ptr
 *      DefaultL (void)(ptr)
 *
 *  XCACHEFLUSHBLK(ptr, n) - Flush the cache lines starting at ptr for
 *                                   at least n bytes
 *      DefaultL wh_Utils_CacheFlush(ptr, n)
 *
 *  XCACHEINVLD(ptr) - Invalidate the cache line including ptr
 *      DefaultL (void)(ptr)
 *
 *  XCACHEINVLDBLK(ptr, n) - Invalidate the cache lines starting at ptr
 *                                   for at least n bytes
 *      DefaultL wh_Utils_CacheInvalidate(ptr, n)
 *
 *
 *
 *
 */

#ifndef WOLFHSM_WH_SETTINGS_H_
#define WOLFHSM_WH_SETTINGS_H_

#ifdef WOLFHSM_CFG
#include "wolfhsm_cfg.h"
#endif

#include <stdint.h>

/* WH_PADDING_CHECK is an internal sentinel set only by the wire-format
 * struct-padding audit (test/wh_test_check_struct_padding.c). It suppresses
 * external dependencies (wolfSSL headers, etc.) so that audit can compile
 * without dragging in third-party source whose layout could perturb -Wpadded.
 * It is NOT a public configuration flag — do not use it from application
 * code. */
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && !defined(WH_PADDING_CHECK)
#ifdef WOLFSSL_USER_SETTINGS
#include "user_settings.h"
#else
#include <wolfssl/options.h>
#endif /* WOLFSSL_USER_SETTINGS */

#include "wolfssl/wolfcrypt/types.h"

#if defined(WOLFHSM_CFG_DEBUG) || defined(WOLFHSM_CFG_DEBUG_VERBOSE)
#define WOLFHSM_CFG_HEXDUMP
#endif
#endif /* !WOLFHSM_CFG_NO_CRYPTO && !WH_PADDING_CHECK */

/* Platform system time access */
#if !defined WOLFHSM_CFG_NO_SYS_TIME && !defined(WOLFHSM_CFG_PORT_GETTIME)
#error \
    "WOLFHSM_CFG_PORT_GETTIME must be defined to a function returning current time in microseconds"
#endif

#if defined(WOLFHSM_CFG_NO_SYS_TIME)
#define WH_GETTIME_US() ((uint64_t)0)
#else
#define WH_GETTIME_US() ((uint64_t)(WOLFHSM_CFG_PORT_GETTIME)())
#endif

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
#if defined(WOLFHSM_CFG_SHE_EXTENSION)
/* Default to large enough cache to hold all SHE keys */
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT 16
#else
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT  8
#endif
#endif

/* Number of big RAM keys */
#ifndef WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT 3
#endif

/* Size in bytes of each key cache buffer  */
#ifndef WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE
#define WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE 256
#endif

/* Size in bytes of each big key cache buffer  */
#ifndef WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE
#if defined(WOLFSSL_HAVE_MLDSA) || defined(WOLFSSL_HAVE_XMSS) || \
    defined(WOLFSSL_HAVE_LMS)
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE 8192
#else
/* Sane default to hold ASN.1 RSA 4096 public+private key */
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE 1200
#endif
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

/*  WOLFHSM_CFG_LOG_MSG_MAX - Maximum size of a log message including null
 *  terminator.
 *      Default: 256 */
#ifndef WOLFHSM_CFG_LOG_MSG_MAX
#define WOLFHSM_CFG_LOG_MSG_MAX 256
#endif

/* Maximum size of a certificate */
#ifndef WOLFHSM_CFG_MAX_CERT_SIZE
#ifndef WOLFHSM_CFG_DMA
#define WOLFHSM_CFG_MAX_CERT_SIZE WOLFHSM_CFG_COMM_DATA_LEN
#else
#define WOLFHSM_CFG_MAX_CERT_SIZE 4096
#endif
#endif

/* Maximum number of trusted root NVM IDs accepted in one multi-root verify
 * request. Bounded so the request fits within WOLFHSM_CFG_COMM_DATA_LEN
 * alongside the candidate chain, and so the inline DMA request struct stays
 * a fixed-size POD. Default 8; overridable at build time. */
#ifndef WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS
#define WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS 8
#endif

/*-----------------------------------------------------------------------------
 * Debug and Print Configuration
 *---------------------------------------------------------------------------*/

/* User can define WOLFHSM_CFG_PRINTF to override the default printf function.
 * This should be a function-like macro or function pointer that matches:
 * int func(const char* format, ...)
 */
#ifndef WOLFHSM_CFG_PRINTF
    #include <stdio.h>
    #define WOLFHSM_CFG_PRINTF printf
#endif

/* Debug levels can be enabled by defining WOLFHSM_CFG_DEBUG and/or 
 * WOLFHSM_CFG_DEBUG_VERBOSE in wolfhsm_cfg.h or via compiler flags.
 * 
 * WOLFHSM_CFG_DEBUG - Enable basic debug output
 * WOLFHSM_CFG_DEBUG_VERBOSE - Enable verbose debug output (includes basic)
 */

/* Internal print macro - do not use directly 
 * This is the base macro that all other debug macros build on top of */
#ifdef WOLFHSM_CFG_DEBUG
    #if !defined(__CCRH__)
        #define WH_DEBUG_PRINT(fmt, ...) \
            WOLFHSM_CFG_PRINTF(fmt, ##__VA_ARGS__)
    #else
        /* CCRH workaround for ##__VA_ARGS__ */
        #define WH_DEBUG_PRINT(...) WH_DEBUG_PRINT2(__VA_ARGS__, "")
        #define WH_DEBUG_PRINT2(fmt, ...) \
            WOLFHSM_CFG_PRINTF(fmt, ##__VA_ARGS__)
    #endif
#else
    #define WH_DEBUG_PRINT(...) do { } while (0)
#endif

/* Client-side debug print with [client] prefix */
#ifdef WOLFHSM_CFG_DEBUG
    #if !defined(__CCRH__)
        #define WH_DEBUG_CLIENT(fmt, ...) \
            WH_DEBUG_PRINT("[client] " fmt, ##__VA_ARGS__)
    #else
        #define WH_DEBUG_CLIENT(...) WH_DEBUG_CLIENT2(__VA_ARGS__, "")
        #define WH_DEBUG_CLIENT2(fmt, ...) \
            WH_DEBUG_PRINT("[client] " fmt, ##__VA_ARGS__)
    #endif
#else
    #define WH_DEBUG_CLIENT(...) do { } while (0)
#endif

/* Server-side debug print with [server] prefix */
#ifdef WOLFHSM_CFG_DEBUG
    #if !defined(__CCRH__)
        #define WH_DEBUG_SERVER(fmt, ...) \
            WH_DEBUG_PRINT("[server] " fmt, ##__VA_ARGS__)
    #else
        #define WH_DEBUG_SERVER(...) WH_DEBUG_SERVER2(__VA_ARGS__, "")
        #define WH_DEBUG_SERVER2(fmt, ...) \
            WH_DEBUG_PRINT("[server] " fmt, ##__VA_ARGS__)
    #endif
#else
    #define WH_DEBUG_SERVER(...) do { } while (0)
#endif

/* Verbose client-side debug print with function and line context */
#ifdef WOLFHSM_CFG_DEBUG_VERBOSE
    #if !defined(__CCRH__)
        #define WH_DEBUG_CLIENT_VERBOSE(fmt, ...) \
            WH_DEBUG_PRINT("[client:%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__)
    #else
        #define WH_DEBUG_CLIENT_VERBOSE(...) WH_DEBUG_CLIENT_VERBOSE2(__VA_ARGS__, "")
        #define WH_DEBUG_CLIENT_VERBOSE2(fmt, ...) \
            WH_DEBUG_PRINT("[client:%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__)
    #endif
#else
    #define WH_DEBUG_CLIENT_VERBOSE(...) do { } while (0)
#endif

/* Verbose server-side debug print with function and line context */
#ifdef WOLFHSM_CFG_DEBUG_VERBOSE
    #if !defined(__CCRH__)
        #define WH_DEBUG_SERVER_VERBOSE(fmt, ...) \
            WH_DEBUG_PRINT("[server:%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__)
    #else
        #define WH_DEBUG_SERVER_VERBOSE(...) WH_DEBUG_SERVER_VERBOSE2(__VA_ARGS__, "")
        #define WH_DEBUG_SERVER_VERBOSE2(fmt, ...) \
            WH_DEBUG_PRINT("[server:%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__)
    #endif
#else
    #define WH_DEBUG_SERVER_VERBOSE(...) do { } while (0)
#endif

/* Hexdump helper macro - only active in verbose mode */
#if defined(WOLFHSM_CFG_DEBUG_VERBOSE) && defined(WOLFHSM_CFG_HEXDUMP)
    #define WH_DEBUG_VERBOSE_HEXDUMP(msg, data, len) \
        wh_Utils_Hexdump(msg, data, len)
#else
    #define WH_DEBUG_VERBOSE_HEXDUMP(msg, data, len) do { } while (0)
#endif

/** Configuration checks */
/* Skipped under WH_PADDING_CHECK because the wolfSSL feature macros
 * referenced below are only defined when wolfssl/options.h is pulled. */
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && !defined(WH_PADDING_CHECK)
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

/* Client response parsing calls wc_ecc_import_* on devId-bound keys (e.g.
 * wh_Crypto_EccUpdatePrivateOnlyKeyDer from wh_Client_EccVerifyResponse)
 * while the response still sits in the client's comm packet buffer. With
 * WOLFSSL_VALIDATE_ECC_IMPORT those imports re-enter the crypto callback and
 * run a nested HSM transaction that reuses that buffer. The wire protocol
 * tolerates nesting (transactions are strictly sequential), but correctness
 * would rest on every response parser having copied out all data it needs
 * before any import — an invariant that is not enforced or audited. Server
 * builds are unaffected: their import validation dispatches to the server's
 * local crypto provider, not the transport. */
#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFSSL_VALIDATE_ECC_IMPORT)
#error "WOLFSSL_VALIDATE_ECC_IMPORT is not supported in wolfHSM client builds"
#endif

#if defined(WOLFHSM_CFG_SHE_EXTENSION)
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

#endif /* !WOLFHSM_CFG_NO_CRYPTO && !WH_PADDING_CHECK */

#if defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_KEYWRAP)
#error "WOLFHSM_CFG_KEYWRAP is incompatible with WOLFHSM_CFG_NO_CRYPTO"
#endif

/* Crypto affinity selects the devId used for crypto operations, so it has no
 * meaning without wolfCrypt. */
#if defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_CRYPTO_AFFINITY)
#error "WOLFHSM_CFG_CRYPTO_AFFINITY is incompatible with WOLFHSM_CFG_NO_CRYPTO"
#endif

#if defined(WOLFHSM_CFG_HWKEYSTORE)
#ifndef WOLFHSM_CFG_HWKEYSTORE_MAX_KEY_SIZE
#define WOLFHSM_CFG_HWKEYSTORE_MAX_KEY_SIZE 32
#endif
#endif /* WOLFHSM_CFG_HWKEYSTORE */

/* Trusted cert verify cache requires the certificate manager and crypto.
 * Enforce here so downstream code can gate on
 * WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE alone instead of repeating the full
 * dependency chain at every site. */
#if defined(WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE) && \
    !defined(WOLFHSM_CFG_CERTIFICATE_MANAGER)
#error \
    "WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE requires WOLFHSM_CFG_CERTIFICATE_MANAGER"
#endif

#if defined(WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE) && \
    defined(WOLFHSM_CFG_NO_CRYPTO)
#error \
    "WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE is incompatible with WOLFHSM_CFG_NO_CRYPTO"
#endif

/* The global cross-client verify cache is a layered option on top of the
 * per-client cache. Enforce the dependency so downstream code can gate on
 * WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL alone. */
#if defined(WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL) && \
    !defined(WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE)
#error \
    "WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL requires WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE"
#endif

/** Cache flushing and memory fencing synchronization primitives */
/* Create a full sequential memory fence to ensure compiler memory ordering */
#ifndef XMEMFENCE
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && !defined(WH_PADDING_CHECK)
#include "wolfssl/wolfcrypt/wc_port.h"
#define XMEMFENCE() XFENCE()
#else
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && \
    !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#define XMEMFENCE() atomic_thread_fence(memory_order_seq_cst)
#elif defined(__GNUC__) || defined(__clang__)
#define XMEMFENCE() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#else
/* PPC32: __asm__ volatile ("sync" : : : "memory") */
#define XMEMFENCE() \
    do {            \
    } while (0)
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
