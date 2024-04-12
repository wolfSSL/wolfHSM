/*
 * wolfhsm/wh_common.h
 *
 */

#ifndef WOLFHSM_WH_COMMON_H_
#define WOLFHSM_WH_COMMON_H_

/* TODO: consider using the version without _t */
#include <stdint.h>

/* Device Id to be registered and passed to wolfCrypt functions */
#define WOLFHSM_DEV_ID 0x5748534D  /* "WHSM" */

#define WOLFHSM_DIGEST_STUB 8

/** Resource allocations */
enum {
    WOLFHSM_NUM_COUNTERS = 8,       /* Number of non-volatile 32-bit counters */
    WOLFHSM_NUM_RAMKEYS = 2,        /* Number of RAM keys */
    WOLFHSM_NUM_NVMOBJECTS = 32,    /* Number of NVM objects in the directory */
    WOLFHSM_NUM_MANIFESTS = 8,      /* Number of compiletime manifests */
    WOLFHSM_KEYCACHE_BUFSIZE = 1200, /* Size in bytes of key cache buffer  */
};


/** Non-volatile counters */

/* HSM Counter identifier type. */
typedef uint16_t whCounterId;


/** Key Management */

/* HSM key identifier type.  Top nibble identifies key type/location */
typedef uint16_t whKeyId;

/* Id Constants */
#define WOLFHSM_KEYID_ERASED 0x0000

/* Key Masks */
#define WOLFHSM_KEYID_MASK   0x00FF
#define WOLFHSM_KEYUSER_MASK 0x0F00
#define WOLFHSM_KEYTYPE_MASK 0xF000

/* Key Flags */
#define WOLFHSM_KEYFLAG_RSA         0x1000
#define WOLFHSM_KEYFLAG_ECC         0x2000
#define WOLFHSM_KEYFLAG_CURVE25519  0x3000
#define WOLFHSM_KEYFLAG_ED25519     0x4000
#define WOLFHSM_KEYFLAG_AES         0x5000
#define WOLFHSM_KEYFLAG_HMAC        0x6000
#define WOLFHSM_KEYFLAG_CMAC        0x7000

/* Key Types */
#define WOLFHSM_KEYTYPE_CRYPTO  0x1000
/* She keys are technically raw keys but a SHE keyId needs */
#define WOLFHSM_KEYTYPE_SHE     0x2000

#define MAKE_WOLFHSM_KEYID(_type, _user, _id) \
    (whKeyId)(((_type) & WOLFHSM_KEYID_MASK) | (((_user) & 0xF) << 8) | ((_id) & WOLFHSM_KEYID_MASK))


/** NVM Management */

/* HSM NVM object identifier type. */
typedef uint16_t whNvmId;

/* HSM NVM Size type */
typedef uint16_t whNvmSize;

/* HSM NVM Access type */
typedef uint16_t whNvmAccess;

/* HSM NVM Flags type */
typedef uint16_t whNvmFlags;

/* HSM NVM metadata structure */
enum {
    WOLFHSM_NVM_LABEL_LEN = 24,
    WOLFHSM_NVM_METADATA_LEN = 32,
    WOLFHSM_NVM_MAX_OBJECT_SIZE = 65535,
};

/* List flags */
#define WOLFHSM_NVM_ACCESS_ANY (0xFFFF)
#define WOLFHSM_NVM_FLAGS_ANY (0xFFFF)

/* User-specified metadata for an NVM object */
typedef struct {
    whNvmId id;             /* Unique identifier */
    whNvmAccess access;     /* Growth */
    whNvmFlags flags;       /* Growth */
    whNvmSize len;          /* Length of data in bytes */
    uint8_t label[WOLFHSM_NVM_LABEL_LEN];
} whNvmMetadata;
/* static_assert(sizeof(whNvmMetadata) == WOLFHSM_NVM_METADATA_LEN) */


/* Custom request shared defs */
#define WH_CUSTOM_CB_NUM_CALLBACKS 8

#endif /* WOLFHSM_WH_COMMON_H_ */
