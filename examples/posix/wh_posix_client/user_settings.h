#ifndef USER_SETTINGS_H_
#define USER_SETTINGS_H_

/** wolfHSM Client required settings */

/* CryptoCB support */
#define WOLF_CRYPTO_CB
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
/* Optional if debugging cryptocb's */
#if 0
#define DEBUG_CRYPTOCB
#define DEBUG_CRYPTOCB_VERBOSE
#endif

/* Key DER export/import support */
#define WOLFSSL_KEY_GEN
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE

/* C90 compatibility, which doesn't support inline keyword */
#define NO_INLINE
/* Suppresses warning in evp.c */
#define WOLFSSL_IGNORE_FILE_WARN

/* Either NO_HARDEN or set resistance and blinding */
#if 0
#define WC_NO_HARDEN
#else
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#endif


/** Application Settings */

/* Crypto Algo Options */
#define HAVE_CURVE25519
#define HAVE_ECC
#define HAVE_AES_CBC
#define WOLFSSL_AES_COUNTER
#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_CMAC

/* wolfCrypt benchmark settings */
#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED

#ifdef WOLFHSM_CFG_DMA
#undef WOLFSSL_STATIC_MEMORY
#define WOLFSSL_STATIC_MEMORY
#define WOLFSSL_STATIC_MEMORY_TEST_SZ 100000
#endif

/* Include to ensure clock_gettime is declared for benchmark.c */
#include <time.h>
/* Include to support strcasecmp with POSIX build */
#include <strings.h>

#endif /* USER_SETTINGS_H_ */
