#ifndef USER_SETTINGS_H_
#define USER_SETTINGS_H_

/* Client wolfSSL settings */

/* wolfHSM Required */
#define WOLF_CRYPTO_CB
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
#define WOLFCRYPT_ONLY

/* Optional if debugging cryptocb's */
/*#define DEBUG_CRYPTOCB */
/*#define DEBUG_CRYPTOCB_VERBOSE */

/* Temporarily set this to key export function  */
#define WOLFSSL_KEY_GEN

/* Crypto Options */
#define HAVE_CURVE25519
#define HAVE_ECC
#define HAVE_AES_CBC
#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_CMAC

/* wolfCrypt benchmark settings */
#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED

/* Include to ensure clock_gettime is declared for benchmark.c */
#include <time.h>
/* Include to support strcasecmp with POSIX build */
#include <strings.h>



#endif /* USER_SETTINGS_H_ */
