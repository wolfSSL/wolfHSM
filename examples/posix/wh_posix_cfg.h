/* This holds all constants used in the POSIX examples */

#ifndef WH_POSIX_CFG_H
#define WH_POSIX_CFG_H

/* ===========================================
 * TRANSPORT AND COMMUNICATION CONSTANTS
 * =========================================== */

/* Client and Server IDs */
#define WH_POSIX_CLIENT_ID 12
#define WH_POSIX_SERVER_ID 57
#define WH_POSIX_MAX_CLIENT_ID 255

/* TCP Communication */
#define WH_POSIX_SERVER_TCP_PORT 23456
#define WH_POSIX_SERVER_TCP_IPSTRING "127.0.0.1"

/* Shared Memory Configuration */
#define WH_POSIX_SHARED_MEMORY_NAME "wh_example_shm"

/* ===========================================
 * DMA AND BUFFER SIZES
 * =========================================== */

/* Request and Response Buffer Sizes */
#define WH_POSIX_REQ_SIZE 1024
#define WH_POSIX_RESP_SIZE 1024
#define WH_POSIX_DMA_SIZE 8000

/* Data Buffer Sizes */
#define WH_POSIX_DATA_BUFFER_SIZE 0x400 /* 1024 bytes */
#define WH_POSIX_KEY_BUFFER_SIZE 4096
#define WH_POSIX_MAX_LINE_LENGTH 4608 /* 512 + PATH_MAX */

/* ===========================================
 * FILE SYSTEM CONSTANTS
 * =========================================== */

/* File Path Limits */
#define WH_POSIX_PATH_MAX 4096
#define WH_POSIX_LABEL_SIZE 256

/* ===========================================
 * CRYPTO CONSTANTS
 * =========================================== */

/* RSA Key Sizes */
#define WH_POSIX_RSA_MIN_SIZE 1024
#define WH_POSIX_RSA_2048_SIZE 2048
#define WH_POSIX_RSA_4096_SIZE 4096

/* ECC Key Sizes */
#define WH_POSIX_ECC_KEYSIZE 32
#define WH_POSIX_FP_MAX_BITS 8192

/* AES Constants */
#define WH_POSIX_AES_KEYSIZE 16
#define WH_POSIX_AES_TEXTSIZE 16
#define WH_POSIX_AES_AUTHSIZE 16
#define WH_POSIX_AES_TAGSIZE 16

/* CMAC Constants */
#define WH_POSIX_CMAC_TEXTSIZE 1000

/* Key Cache Constants */
#define WH_POSIX_KEYCACHE_KEYSIZE 16

/* ===========================================
 * MEMORY AND STORAGE CONSTANTS
 * =========================================== */

/* Flash and RAM Sizes */
#define WH_POSIX_FLASH_RAM_SIZE (1024 * 1024) /* 1MB */
#define WH_POSIX_STATIC_MEMORY_TEST_SZ 120000

/* NVM Object Count */
#define WH_POSIX_NVM_OBJECT_COUNT 30


/* Macros for maximum client ID and key ID */
#define MAX_CLIENT_ID 255
#define MAX_KEY_ID UINT16_MAX

/* Macros for maximum file path length (Linux PATH_MAX is a good reference) */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Parameterize MAX_LINE_LENGTH by 512 bytes + MAX_FILE_PATH_LENGTH */
#define MAX_LINE_LENGTH (512 + PATH_MAX)


/* ===========================================
 * STATIC MEMORY ALLOCATION SIZES
 * =========================================== */

/* Static Memory Size List */
#define WH_POSIX_STATIC_MEM_LIST_SIZE 9
#define WH_POSIX_STATIC_MEM_SIZE_1 176
#define WH_POSIX_STATIC_MEM_SIZE_2 256
#define WH_POSIX_STATIC_MEM_SIZE_3 288
#define WH_POSIX_STATIC_MEM_SIZE_4 704
#define WH_POSIX_STATIC_MEM_SIZE_5 1056
#define WH_POSIX_STATIC_MEM_SIZE_6 1712
#define WH_POSIX_STATIC_MEM_SIZE_7 2112
#define WH_POSIX_STATIC_MEM_SIZE_8 2368
#define WH_POSIX_STATIC_MEM_SIZE_9 4096

/* Static Memory Distribution List */
#define WH_POSIX_STATIC_MEM_DIST_1 3
#define WH_POSIX_STATIC_MEM_DIST_2 1
#define WH_POSIX_STATIC_MEM_DIST_3 1
#define WH_POSIX_STATIC_MEM_DIST_4 1
#define WH_POSIX_STATIC_MEM_DIST_5 1
#define WH_POSIX_STATIC_MEM_DIST_6 1
#define WH_POSIX_STATIC_MEM_DIST_7 1
#define WH_POSIX_STATIC_MEM_DIST_8 3
#define WH_POSIX_STATIC_MEM_DIST_9 1

#endif
