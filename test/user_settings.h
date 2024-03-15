/* user_settings.h
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Common configuration */
#define WOLFCRYPT_ONLY
//#define BIG_ENDIAN_ORDER
#define WOLF_CRYPTO_CB
//#define WOLFSSL_KEY_GEN
#define SINGLE_THREADED
#define WC_NO_ASYNC_THREADING
#define WOLFSSL_USE_ALIGN
#define HAVE_WC_INTROSPECTION
#define WOLFSSL_IGNORE_FILE_WARN

#define WOLFSSL_NO_MALLOC

/* Hardening options */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Remove unneeded features*/
#define NO_MAIN_DRIVER
#define NO_ERROR_STRINGS
#define NO_ERROR_QUEUE
#define NO_FILESYSTEM
#define NO_INLINE
#define NO_OLD_TLS
#define WOLFSSL_NO_TLS12
#define NO_DO178

/* Remove unneded namespace */
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME

/* RSA Options */
//#define NO_RSA
#define HAVE_RSA
#define WC_RSA_PSS
#define WOLFSSL_PSS_LONG_SALT
#define FP_MAX_BITS 4096

/* ECC Options */
//#define HAVE_ECC
#define NO_ECC
#define TFM_ECC256
#define ECC_SHAMIR
#define HAVE_SUPPORTED_CURVES

/* Curve25519 Options */
#define HAVE_CURVE25519

/* DH and DHE Options */
#define HAVE_DH_DEFAULT_PARAMS
#define HAVE_FFDHE_2048

/* AES Options */
#define HAVE_AES
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define WOLFSSL_CMAC

/* SHA Options */
#define NO_SHA
#define HAVE_SHA256

/* Composite features */
#define HAVE_HKDF
#define HAVE_HASHDRBG

/* Remove unneeded crypto */
#define NO_DSA
#define NO_RC4
#define NO_PSK
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256
#define NO_PWDBASED

/* Disable DH for now */
#define NO_DH

/* Cert processing options */
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE

/* TLS features that are not used */
/* TODO: Check to see if these can be removed */
#define HAVE_TLS_EXTENSIONS
#define HAVE_ENCRYPT_THEN_MAC

/* Math library selection. Move to target */

#define USE_FAST_MATH

//#define WOLFSSL_SP_MATH_ALL

/* Allows custom "custom_time()" function to be used for benchmark */
#define WOLFSSL_USER_CURRTIME
#define USER_TICKS

/* Standard Lib - C89 */
#define XSTRCASECMP(s1,s2) strcmp((s1),(s2))

/* ------------------------------------------------------------------------- */
/* Memory */
/* ------------------------------------------------------------------------- */
#if 0
    /* Static memory requires fast math or SP math with no malloc */
    #define WOLFSSL_STATIC_MEMORY

    /* Disable fallback malloc/free */
    #define WOLFSSL_NO_MALLOC
    #if 1
        #define WOLFSSL_MALLOC_CHECK /* trap malloc failure */
    #endif
#endif


#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */
