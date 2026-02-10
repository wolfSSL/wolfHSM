/*
 * Example server app using POSIX transport
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <stdlib.h> /* For atoi */
#include <string.h> /* For memset, memcpy, strcmp */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> /* for read/close */
#include <time.h>   /* For nanosleep */
#include <errno.h>
#include <ctype.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
/* included to print out the version of wolfSSL linked with */
#include "wolfssl/version.h"
#endif

#include "wh_posix_cfg.h"
#include "wh_posix_server_cfg.h"

/** Local declarations */
static int wh_ServerTask(void* cf, const char* keyFilePath, int keyId,
                         int clientId, whNvmFlags flags);

static void _sleepMs(long milliseconds);
#if !defined(WOLFHSM_CFG_NO_CRYPTO)
static int  _hardwareCryptoCb(int devId, struct wc_CryptoInfo* info, void* ctx);
#endif
static void _sleepMs(long milliseconds)
{
    struct timespec req;
    req.tv_sec  = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&req, NULL);
}

enum {
    ONE_MS = 1,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_SERVER_ID 57
const char* type = "tcp"; /* default to tcp type */

static int loadAndStoreKeys(whServerContext* server, whKeyId* outKeyId,
                            const char* keyFilePath, int keyId, int clientId,
                            whNvmFlags flags)
{
#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    int           ret;
    int           keyFd;
    int           keySz;
    char          keyLabel[] = "baby's first key";
    uint8_t       keyBuf[4096];
    whNvmMetadata meta = {0};

    /* open the key file */
    ret = keyFd = open(keyFilePath, O_RDONLY, 0);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to open %s %d\n", keyFilePath, ret);
        return ret;
    }

    /* read the key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to read %s %d\n", keyFilePath, ret);
        close(keyFd);
        return ret;
    }
    ret = 0;
    close(keyFd);

    WOLFHSM_CFG_PRINTF("Loading key from %s (size=%d) with keyId=0x%02X and "
                       "clientId=0x%01X and flags=0x%04X\n",
                       keyFilePath, keySz, keyId, clientId, flags);

    /* cache the key in the HSM, get HSM assigned keyId */
    /* set the metadata fields */
    meta.id    = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, clientId, keyId);
    meta.flags = (whNvmFlags)flags;
    meta.len   = keySz;
    memcpy(meta.label, keyLabel, strlen(keyLabel));

    /* Get HSM assigned keyId if not set */
    if (keyId == WH_KEYID_ERASED) {
        ret = wh_Server_KeystoreGetUniqueId(server, &meta.id);
        WOLFHSM_CFG_PRINTF("got unique ID = 0x%02X\n", meta.id & WH_KEYID_MASK);
    }
    WOLFHSM_CFG_PRINTF("key NVM ID = "
                       "0x%04X\n\ttype=0x%01X\n\tuser=0x%01X\n\tkeyId=0x%"
                       "02X\n\tflags=0x%04X\n",
                       meta.id, WH_KEYID_TYPE(meta.id), WH_KEYID_USER(meta.id),
                       WH_KEYID_ID(meta.id), meta.flags);

    if (ret == 0) {
        ret = wh_Server_KeystoreCacheKey(server, &meta, keyBuf);
        if (ret != 0) {
            WOLFHSM_CFG_PRINTF("Failed to wh_Server_KeystoreCacheKey, ret=%d\n", ret);
            return ret;
        }
    }
    else {
        WOLFHSM_CFG_PRINTF("Failed to wh_Server_KeystoreGetUniqueId, ret=%d\n", ret);
        return ret;
    }

    *outKeyId = meta.id;
    return ret;
#else
    (void)server;
    (void)outKeyId;
    (void)keyFilePath;
    (void)keyId;
    (void)clientId;
    (void)flags;
    return WH_ERROR_NOTIMPL;
#endif /* !WOLFHSM_CFG_NO_CRYPTO */
}

static int wh_ServerTask(void* cf, const char* keyFilePath, int keyId,
                         int clientId, whNvmFlags flags)
{
    whServerContext server[1];
    whServerConfig* config     = (whServerConfig*)cf;
    int             ret        = 0;
    whCommConnected last_state = WH_COMM_DISCONNECTED;
    whKeyId         loadedKeyId;

    if (config == NULL) {
        return -1;
    }

    ret = wh_Server_Init(server, config);

    /* Load keys into cache if file path is provided */
    if (keyFilePath != NULL) {
        ret = loadAndStoreKeys(server, &loadedKeyId, keyFilePath, keyId,
                               clientId, flags);
        if (ret != 0) {
            WOLFHSM_CFG_PRINTF("server failed to load key, ret=%d\n", ret);
            (void)wh_Server_Cleanup(server);
            return ret;
        }
    }

    if (ret == 0) {
        WOLFHSM_CFG_PRINTF("Waiting for connection...\n");
        if (strcmp(type, "shm") == 0 || strcmp(type, "dma") == 0) {
            /* Shared memory assumes connected once memory is setup */
            wh_Server_SetConnected(server, WH_COMM_CONNECTED);
        }

        while (1) {
            ret = wh_Server_HandleRequestMessage(server);
            if (ret == WH_ERROR_NOTREADY) {
                _sleepMs(ONE_MS);
            }
            else if (ret != WH_ERROR_OK) {
                WOLFHSM_CFG_PRINTF("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
                break;
            }
            else {
                whCommConnected current_state;
                int             get_conn_result =
                    wh_Server_GetConnected(server, &current_state);
                if (get_conn_result == WH_ERROR_OK) {
                    if (current_state == WH_COMM_CONNECTED &&
                        last_state == WH_COMM_DISCONNECTED) {
                        WOLFHSM_CFG_PRINTF("Server connected\n");
                        last_state = WH_COMM_CONNECTED;
                    }
                    else if (current_state == WH_COMM_DISCONNECTED &&
                             last_state == WH_COMM_CONNECTED) {
                        WOLFHSM_CFG_PRINTF("Server disconnected\n");
                        last_state = WH_COMM_DISCONNECTED;

                        /* POSIX TCP transport requires server to be
                         * re-initialized in order to reconnect */

                        (void)wh_Server_Cleanup(server);

                        /* Reinitialize the server */
                        ret = wh_Server_Init(server, config);
                        if (ret != 0) {
                            WOLFHSM_CFG_PRINTF("Failed to reinitialize server: %d\n", ret);
                            break;
                        }

                        if (ret == WH_ERROR_OK && (strcmp(type, "shm") == 0 ||
                                                   strcmp(type, "dma") == 0)) {
                            /* Shared memory assumes connected once memory is
                             * setup */
                            wh_Server_SetConnected(server, WH_COMM_CONNECTED);
                        }

                        /* Reload keys into cache if file path was provided */
                        if (keyFilePath != NULL) {
                            ret = loadAndStoreKeys(server, &loadedKeyId,
                                                   keyFilePath, keyId, clientId,
                                                   flags);
                            if (ret != 0) {
                                WOLFHSM_CFG_PRINTF("server failed to load key, ret=%d\n",
                                       ret);
                                break;
                            }
                        }
                    }
                }
                else {
                    WOLFHSM_CFG_PRINTF("Failed to get connection state: %d\n",
                           get_conn_result);
                }
            }
        }
    }
    return ret;
}
#if !defined(WOLFHSM_CFG_NO_CRYPTO)
static int _hardwareCryptoCb(int devId, struct wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    /* Default response */
    int ret = CRYPTOCB_UNAVAILABLE;
    switch (info->algo_type) {
        case WC_ALGO_TYPE_RNG: {
            /*WOLFHSM_CFG_PRINTF("Hardware Crypto Callback: RNG operation requested\n");*/
            /* Extract info parameters */
            uint8_t* out  = info->rng.out;
            uint32_t size = info->rng.sz;

            /* III Not random, just simple counter */
            static uint16_t my_counter = 1;
            if (my_counter > 4096) {
                /* Only allow 4096 bytes to be generated */
                ret = CRYPTOCB_UNAVAILABLE;
            }
            else {
                uint32_t i = 0;
                for (i = 0; i < size; i++) {
                    out[i] = (uint8_t)my_counter++;
                }
                ret = 0;
            }
            break;
        }
        default:
            /*WOLFHSM_CFG_PRINTF("Hardware Crypto Callback: Unsupported algorithm type\n");
             */
            ret = CRYPTOCB_UNAVAILABLE;
    }
    return ret;
}
#endif
static void Usage(const char* exeName)
{
    WOLFHSM_CFG_PRINTF(
        "Usage: %s --key <key_file_path> --id <key_id> --client <client_id> "
        "--nvminit <nvm_init_file_path> --type <type> --flags <flags>\n",
        exeName);
    WOLFHSM_CFG_PRINTF("Example: %s --key key.bin --id 123 --client 456 "
                       "--nvminit nvm_init.txt --type tcp --flags 0\n",
                       exeName);
    WOLFHSM_CFG_PRINTF("type: tcp (default), shm");
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_TLS)
    WOLFHSM_CFG_PRINTF(", tls");
#if !defined(NO_PSK)
    WOLFHSM_CFG_PRINTF(", psk");
#endif
#endif /* !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_TLS) */
#ifdef WOLFHSM_CFG_DMA
    WOLFHSM_CFG_PRINTF(", dma");
#endif
    WOLFHSM_CFG_PRINTF("\n");
}


int main(int argc, char** argv)
{
    int         rc              = 0;
    const char* keyFilePath     = NULL;
    const char* nvmInitFilePath = NULL;
    int         keyId = WH_KEYID_ERASED; /* Default key ID if none provided */
    int         clientId = 12; /* Default client ID if none provided */
    whNvmFlags  flags =
        WH_NVM_FLAGS_USAGE_ANY; /* Default flags if none provided */
    uint8_t     memory[WH_POSIX_FLASH_RAM_SIZE] = {0};
    whServerConfig s_conf[1];

    WOLFHSM_CFG_PRINTF("Example wolfHSM POSIX server ");
#ifndef WOLFHSM_CFG_NO_CRYPTO
    WOLFHSM_CFG_PRINTF("built with wolfSSL version %s\n", LIBWOLFSSL_VERSION_STRING);
#else
    WOLFHSM_CFG_PRINTF("built with WOLFHSM_CFG_NO_CRYPTO\n");
#endif

    /* Parse command-line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            keyFilePath = argv[++i];
        }
        else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            keyId = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--client") == 0 && i + 1 < argc) {
            clientId = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--nvminit") == 0 && i + 1 < argc) {
            nvmInitFilePath = argv[++i];
        }
        else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            type = argv[++i];
        }
        else if (strcmp(argv[i], "--flags") == 0 && i + 1 < argc) {
            char* end;
            errno             = 0;
            unsigned long val = strtoul(argv[i + 1], &end, 0);

            if (errno || *end || val > 0xFFFF) {
                WOLFHSM_CFG_PRINTF("Invalid --flags value: %s\n", argv[i + 1]);
                return -1;
            }

            flags = (whNvmFlags)val;
            i++;
        }
        else {
            WOLFHSM_CFG_PRINTF("Invalid argument: %s\n", argv[i]);
            Usage(argv[0]);
            return -1;
        }
    }

    /* Server configuration/context */
    memset(s_conf, 0, sizeof(whServerConfig));
    if (strcmp(type, "tcp") == 0) {
        WOLFHSM_CFG_PRINTF("Using TCP transport\n");
        rc = wh_PosixServer_ExampleTcpConfig(s_conf);
        if (rc != WH_ERROR_OK) {
            WOLFHSM_CFG_PRINTF("Failed to initialize TCP transport\n");
            return -1;
        }
    }
    else if (strcmp(type, "shm") == 0) {
        WOLFHSM_CFG_PRINTF("Using shared memory transport\n");
        rc = wh_PosixServer_ExampleShmConfig(s_conf);
        if (rc != WH_ERROR_OK) {
            WOLFHSM_CFG_PRINTF(
                "Failed to initialize shared memory transport\n");
            return -1;
        }
    }
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_TLS)
    else if (strcmp(type, "tls") == 0) {
        WOLFHSM_CFG_PRINTF("Using TLS transport\n");
        rc = wh_PosixServer_ExampleTlsConfig(s_conf);
        if (rc != WH_ERROR_OK) {
            WOLFHSM_CFG_PRINTF("Failed to initialize TLS transport\n");
            return -1;
        }
    }
#if !defined(NO_PSK)
    else if (strcmp(type, "psk") == 0) {
        WOLFHSM_CFG_PRINTF("Using TLS PSK transport\n");
        rc = wh_PosixServer_ExamplePskConfig(s_conf);
        if (rc != WH_ERROR_OK) {
            WOLFHSM_CFG_PRINTF("Failed to initialize TLS PSK transport\n");
            return -1;
        }
    }
#endif /* !defined(NO_PSK) */
#endif /* !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_TLS) */
#ifdef WOLFHSM_CFG_DMA
    else if (strcmp(type, "dma") == 0) {
        WOLFHSM_CFG_PRINTF("Using DMA with shared memory transport\n");
        rc = wh_PosixServer_ExampleShmDmaConfig(s_conf);
        if (rc != WH_ERROR_OK) {
            WOLFHSM_CFG_PRINTF(
                "Failed to initialize DMA with shared memory transport\n");
            return -1;
        }
    }
#endif /* WOLFHSM_CFG_DMA */
    else {
        WOLFHSM_CFG_PRINTF("Invalid server type: %s\n", type);
        return -1;
    }

    /* RamSim Flash state and configuration */
    rc = wh_PosixServer_ExampleRamSimConfig(s_conf, memory);
    if (rc != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to initialize RAMSim: %d\n", rc);
        return rc;
    }

    /* NVM Flash Configuration using RamSim HAL Flash */
    rc = wh_PosixServer_ExampleNvmConfig(s_conf, nvmInitFilePath);
    if (rc != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to initialize NVM: %d\n", rc);
        return rc;
    }
#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    /* Crypto context */
    whServerCryptoContext crypto[1] = {0};

#if defined(WOLFHSM_CFG_SHE_EXTENSION)
    whServerSheContext she[1] = {{0}};
#endif


    s_conf->crypto = crypto;
    s_conf->devId  = INVALID_DEVID;
#if defined(WOLFHSM_CFG_SHE_EXTENSION)
    s_conf->she = she;
#endif

    /* Initialize crypto library and hardware */
    wolfCrypt_Init();

    /* Context 3: Server Software Crypto */
    WC_RNG  rng[1];
    uint8_t buffer[128] = {0};
    wc_InitRng_ex(rng, NULL, INVALID_DEVID);
    wc_RNG_GenerateBlock(rng, buffer, sizeof(buffer));
    wc_FreeRng(rng);
    wh_Utils_Hexdump("Context 3: Server SW RNG:\n", buffer, sizeof(buffer));

/* Context 4: Server Hardware Crypto */
#define HW_DEV_ID 100
    memset(buffer, 0, sizeof(buffer));
    wc_CryptoCb_RegisterDevice(HW_DEV_ID, _hardwareCryptoCb, NULL);
    wc_InitRng_ex(rng, NULL, HW_DEV_ID);
    wc_RNG_GenerateBlock(rng, buffer, sizeof(buffer));
    wc_FreeRng(rng);
    wh_Utils_Hexdump("Context 4: Server HW RNG:\n", buffer, sizeof(buffer));

    /* Context 5: Set default server crypto to use cryptocb */
    s_conf->devId = HW_DEV_ID;
    WOLFHSM_CFG_PRINTF("Context 5: Setting up default server crypto with devId=%d\n",
           s_conf->devId);

    rc = wc_InitRng_ex(crypto->rng, NULL, s_conf->devId);
    if (rc != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitRng_ex: %d\n", rc);
        return rc;
    }

    rc = wh_ServerTask(s_conf, keyFilePath, keyId, clientId, flags);
    if (rc != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Server task failed: %d\n", rc);
        return rc;
    }
    rc = wc_FreeRng(crypto->rng);
    if (rc != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_FreeRng: %d\n", rc);
        return rc;
    }
    rc = wolfCrypt_Cleanup();
    if (rc != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wolfCrypt_Cleanup: %d\n", rc);
        return rc;
    }
#else
    (void)keyFilePath;
    (void)keyId;
    (void)clientId;
    rc = wh_ServerTask(s_conf, keyFilePath, keyId, clientId, flags);
    if (rc != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Server task failed: %d\n", rc);
        return rc;
    }
#endif
    return rc;
}
