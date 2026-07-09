#ifndef USER_SETTINGS_H_
#define USER_SETTINGS_H_

/** wolfHSM Client required settings */

/* CryptoCB support */
#define WOLF_CRYPTO_CB
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
/* Optional if debugging cryptocb's */
#if 0
#define WOLFHSM_CFG_DEBUG
#define WOLFHSM_CFG_DEBUG_VERBOSE
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
#define HAVE_ED25519
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA512_HASHTYPE
#define HAVE_AES_CBC
#define WOLFSSL_AES_COUNTER
#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_CMAC
#define HAVE_HKDF
/* RSA is on by default (NO_RSA undefined); WOLFSSL_KEY_GEN above
 * enables wc_MakeRsaKey for csm_smoke's RSA-2048 keygen + sign +
 * verify KAT in port/autosar/classic/examples/csm_smoke/test_kat.c.
 * ap_smoke (Adaptive) currently only exercises RSA verify, not
 * keygen, but shares this user_settings.h. */

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
