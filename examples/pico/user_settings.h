#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* WolfHSM Configuration */
#ifndef WOLFHSM_CFG_ENABLE_CLIENT
#define WOLFHSM_CFG_ENABLE_CLIENT
#endif

#ifndef WOLFHSM_CFG_ENABLE_SERVER
#define WOLFHSM_CFG_ENABLE_SERVER
#endif

/* Transport Configuration */
#define WOLFHSM_CFG_TRANS_SHM

/* Environment */
#ifndef WOLFSSL_USER_SETTINGS
    #define WOLFSSL_USER_SETTINGS
#endif
#define WOLFSSL_WOLFHSM

#ifdef PICO_PLATFORM
    #include <pico/stdlib.h>
#endif

#define NO_FILESYSTEM
#ifndef NO_MAIN_DRIVER
    #define NO_MAIN_DRIVER
#endif
#define WOLFSSL_NO_SOCK

/* Time function */
#define WOLFHSM_CFG_PORT_GETTIME time_us_64

/* WolfCrypt Configuration */
#define WOLF_CRYPTO_CB
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
#define WOLFSSL_WOLFHSM
#define WOLFSSL_KEY_GEN
#define WOLFSSL_CERT_GEN


/* Suppress hardened build warning */
#define WC_NO_HARDEN

#define NO_WRITEV
#define SINGLE_THREADED

/* Use custom IO for wolfSSL */
#define WOLFSSL_USER_IO

#define WOLFSSL_RPIPICO
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define WC_NO_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK wc_pico_rng_gen_block
#define WC_RESEED_INTERVAL (1000000)

/* Ensure the prototype is visible for the implementation check, but avoid conflicts if it's already in the header */
#ifdef __cplusplus
extern "C" {
#endif
int wc_pico_rng_gen_block(unsigned char *output, unsigned int sz);
#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */
