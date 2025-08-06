/*
 * Example server app using POSIX TCP transport
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
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "port/posix/posix_transport_tcp.h"

/** Local declarations */
static int wh_ServerTask(void* cf, const char* keyFilePath, int keyId,
                         int clientId);

static void _sleepMs(long milliseconds);
static int _hardwareCryptoCb(int devId, struct wc_CryptoInfo* info, void* ctx);

/* Macros for maximum client ID and key ID */
#define MAX_CLIENT_ID 255
#define MAX_KEY_ID UINT16_MAX

/* Macros for maximum file path length (Linux PATH_MAX is a good reference) */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Parameterize MAX_LINE_LENGTH by 512 bytes + MAX_FILE_PATH_LENGTH */
#define MAX_LINE_LENGTH (512 + PATH_MAX)

/* Structure representing an entry in the linked list */
typedef struct Entry {
    uint8_t       clientId; /* Used only for keys */
    uint16_t      id;       /* Object ID for NVM, keyId for keys */
    uint16_t      access;   /* Access permissions */
    uint16_t      flags;    /* Flags for the object */
    char*         label;    /* Label for the object */
    char*         filePath; /* File path for the object */
    struct Entry* next;     /* Pointer to the next entry */
} Entry;

/* Head of the linked list for entries */
static Entry* entryHead = NULL;

/* Function prototypes for NVM init */
static Entry* createEntry(uint8_t clientId, uint16_t id, uint16_t access,
                          uint16_t flags, const char* label,
                          const char* filePath);
static void   appendEntry(Entry** head, uint8_t clientId, uint16_t id,
                          uint16_t access, uint16_t flags, const char* label,
                          const char* filePath);
static void   processEntry(Entry* entry, int isKey, whNvmContext* nvmContext);
static void   processEntries(whNvmContext* nvmContext);
static void   freeEntries(void);
static void   stripComment(char* line);
static void   trimWhitespace(char* str);
static int  parseInteger(const char* str, uint32_t maxValue, uint32_t* result);
static void parseNvmInitFile(const char* filePath);
static int initializeNvm(whNvmContext* nvmContext, const char* nvmInitFilePath);

static void _sleepMs(long milliseconds)
{
    struct timespec req;
    req.tv_sec  = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&req, NULL);
}

enum {
    ONE_MS         = 1,
    FLASH_RAM_SIZE = 1024 * 1024,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_SERVER_ID 57

/* Creates a new entry in the linked list based on the provided parameters */
static Entry* createEntry(uint8_t clientId, uint16_t id, uint16_t access,
                          uint16_t flags, const char* label,
                          const char* filePath)
{
    Entry* newEntry = (Entry*)malloc(sizeof(Entry));
    if (!newEntry) {
        fprintf(stderr, "Memory allocation error\n");
        exit(EXIT_FAILURE);
    }
    newEntry->clientId = clientId;
    newEntry->id       = id;
    newEntry->access   = access;
    newEntry->flags    = flags;
    newEntry->label    = strdup(label);
    newEntry->filePath = strdup(filePath);
    newEntry->next     = NULL;
    return newEntry;
}

/* Appends a new entry to the linked list */
static void appendEntry(Entry** head, uint8_t clientId, uint16_t id,
                        uint16_t access, uint16_t flags, const char* label,
                        const char* filePath)
{
    Entry* newEntry = createEntry(clientId, id, access, flags, label, filePath);
    if (*head == NULL) {
        *head = newEntry;
    }
    else {
        Entry* current = *head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = newEntry;
    }
}

/* Function to remove comments from a line */
static void stripComment(char* line)
{
    char* commentStart = strchr(line, '#');
    if (commentStart) {
        /* Null-terminate the line at the start of the comment */
        *commentStart = '\0';
    }
}

/* Function to trim leading and trailing whitespace */
static void trimWhitespace(char* str)
{
    /* Trim leading whitespace */
    char* start = str;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }

    /* Trim trailing whitespace */
    char* end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    /* Copy the trimmed string back into the original buffer */
    memmove(str, start, strlen(start) + 1);
}

/* Function to parse a uint16_t or uint8_t from a string (handles hex or
 * decimal) */
static int parseInteger(const char* str, uint32_t maxValue, uint32_t* result)
{
    char*         endPtr;
    unsigned long value;

    value = strtoul(str, &endPtr, 0);

    if (*endPtr != '\0' || value > maxValue) {
        return 0; /* Error: invalid number */
    }

    *result = (uint32_t)value;
    return 1; /* Success */
}

/* Function to parse the NVM init file and build the linked list */
static void parseNvmInitFile(const char* filePath)
{
    FILE* file = fopen(filePath, "r");
    if (!file) {
        perror("Error opening NVM init file");
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];
    int  lineNumber = 0;

    while (fgets(line, sizeof(line), file)) {
        lineNumber++;
        stripComment(line);
        trimWhitespace(line);

        /* Skip empty lines after removing comments and whitespace */
        if (strlen(line) == 0) {
            continue;
        }

        char*    token;
        char     label[256], filePath[PATH_MAX];
        uint32_t clientId = 0, id, access, flags;

        /* Check if the line defines a key or an object */
        if (strncmp(line, "key", 3) == 0) {
            /* Parse client ID for key entries */
            token = strtok(line + 3, " ");
            if (!token || !parseInteger(token, MAX_CLIENT_ID, &clientId)) {
                fprintf(stderr,
                        "Error on line %d: Malformed key entry - invalid "
                        "clientId\n",
                        lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }

            /* Parse key ID for key entries */
            token = strtok(NULL, " ");
            if (!token || !parseInteger(token, MAX_KEY_ID, &id)) {
                fprintf(
                    stderr,
                    "Error on line %d: Malformed key entry - invalid keyId\n",
                    lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
        else if (strncmp(line, "obj", 3) == 0) {
            /* Parse object ID for object entries */
            token = strtok(line + 3, " ");
            if (!token || !parseInteger(token, MAX_KEY_ID, &id)) {
                fprintf(
                    stderr,
                    "Error on line %d: Malformed object entry - invalid id\n",
                    lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
        else {
            /* Report error for unknown entry types */
            fprintf(stderr,
                    "Error on line %d: Malformed line or unknown entry type\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* Parse access field */
        token = strtok(NULL, " ");
        if (!token || !parseInteger(token, UINT16_MAX, &access)) {
            fprintf(stderr,
                    "Error on line %d: Malformed entry - invalid access\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* Parse flags */
        token = strtok(NULL, " ");
        if (!token || !parseInteger(token, UINT16_MAX, &flags)) {
            fprintf(stderr,
                    "Error on line %d: Malformed entry - invalid flags\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* Parse the label (enclosed in quotes) */
        token = strtok(NULL, "\"");
        if (!token) {
            fprintf(stderr,
                    "Error on line %d: Malformed entry - missing or incorrect "
                    "label format\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }
        snprintf(label, sizeof(label), "%s", token);

        /* Parse the file path */
        token = strtok(NULL, " ");
        if (!token || sscanf(token, "%s", filePath) != 1) {
            fprintf(stderr,
                    "Error on line %d: Malformed entry - missing file path\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* Add the parsed entry to the linked list */
        appendEntry(&entryHead, (uint8_t)clientId, (uint16_t)id,
                    (uint16_t)access, (uint16_t)flags, label, filePath);
    }

    fclose(file);
}

/* Process an entry by reading the file and adding it to NVM */
static void processEntry(Entry* entry, int isKey, whNvmContext* nvmContext)
{
    FILE* file = fopen(entry->filePath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error processing entry: Unable to open file %s\n",
                entry->filePath);
        return;
    }

    /* Get the file size */
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* Allocate memory for the file data */
    uint8_t* buffer = (uint8_t*)malloc(fileSize);
    if (buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for file %s\n",
                entry->filePath);
        fclose(file);
        return;
    }

    /* Read the file data into the buffer */
    size_t bytesRead = fread(buffer, 1, fileSize, file);
    fclose(file);

    if (bytesRead != (size_t)fileSize) {
        fprintf(stderr, "Error: Failed to read entire file %s\n",
                entry->filePath);
        free(buffer);
        return;
    }

    /* Create metadata for the new entry */
    whNvmMetadata meta = {0};
    if (isKey) {
        /* Keys have special ID format */
        meta.id = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, entry->clientId, entry->id);
        printf("Processing Key Entry - ClientID: 0x%X, KeyID: 0x%X, Meta ID: "
               "0x%X, "
               "Access: 0x%X, Flags: 0x%X, Label: %s, File: %s, Size: %ld\n",
               entry->clientId, entry->id, meta.id, entry->access, entry->flags,
               entry->label, entry->filePath, fileSize);
    }
    else {
        meta.id = entry->id;
        printf("Processing Object Entry - ID: 0x%X, Access: 0x%X, Flags: 0x%X, "
               "Label: %s, File: %s, Size: %ld\n",
               entry->id, entry->access, entry->flags, entry->label,
               entry->filePath, fileSize);
    }
    meta.access = entry->access;
    meta.flags  = entry->flags;
    meta.len    = fileSize;
    snprintf((char*)meta.label, WH_NVM_LABEL_LEN, "%s", entry->label);

    int rc = wh_Nvm_AddObject(nvmContext, &meta, fileSize, buffer);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to add entry ID %u to NVM, ret = %d\n",
                meta.id, rc);
    }

    free(buffer);
}

/* Process all entries in the linked list */
static void processEntries(whNvmContext* nvmContext)
{
    Entry* current = entryHead;
    while (current != NULL) {
        /* Determine if it's a key based on clientId */
        int isKey = (current->clientId != 0);
        processEntry(current, isKey, nvmContext);
        current = current->next;
    }
}

/* Free the memory allocated for the linked list */
static void freeEntries(void)
{
    Entry* current = entryHead;
    while (current != NULL) {
        Entry* next = current->next;
        free(current->label);
        free(current->filePath);
        free(current);
        current = next;
    }
    entryHead = NULL;
}

/* Initialize NVM with contents from the NVM init file */
static int initializeNvm(whNvmContext* nvmContext, const char* nvmInitFilePath)
{
    if (nvmContext == NULL || nvmInitFilePath == NULL) {
        return -1;
    }

    /* Parse the NVM init file */
    parseNvmInitFile(nvmInitFilePath);

    /* Process the entries */
    processEntries(nvmContext);

    /* Free the allocated memory */
    freeEntries();

    return 0;
}

static int loadAndStoreKeys(whServerContext* server, whKeyId* outKeyId,
                            const char* keyFilePath, int keyId, int clientId)
{
    int           ret;
    int           keyFd;
    int           keySz;
    char          keyLabel[] = "baby's first key";
    uint8_t       keyBuf[4096];
    whNvmMetadata meta = {0};

    /* open the key file */
    ret = keyFd = open(keyFilePath, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", keyFilePath, ret);
        return ret;
    }

    /* read the key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", keyFilePath, ret);
        close(keyFd);
        return ret;
    }
    ret = 0;
    close(keyFd);

    printf(
        "Loading key from %s (size=%d) with keyId=0x%02X and clientId=0x%01X\n",
        keyFilePath, keySz, keyId, clientId);

    /* cache the key in the HSM, get HSM assigned keyId */
    /* set the metadata fields */
    meta.id    = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, clientId, keyId);
    meta.flags = 0;
    meta.len   = keySz;
    memcpy(meta.label, keyLabel, strlen(keyLabel));

    /* Get HSM assigned keyId if not set */
    if (keyId == WH_KEYID_ERASED) {
        ret = wh_Server_KeystoreGetUniqueId(server, &meta.id);
        printf("got unique ID = 0x%02X\n", meta.id & WH_KEYID_MASK);
    }
    printf(
        "key NVM ID = 0x%04X\n\ttype=0x%01X\n\tuser=0x%01X\n\tkeyId=0x%02X\n",
        meta.id, WH_KEYID_TYPE(meta.id), WH_KEYID_USER(meta.id),
        WH_KEYID_ID(meta.id));

    if (ret == 0) {
        ret = wh_Server_KeystoreCacheKey(server, &meta, keyBuf);
        if (ret != 0) {
            printf("Failed to wh_Server_KeystoreCacheKey, ret=%d\n", ret);
            return ret;
        }
    }
    else {
        printf("Failed to wh_Server_KeystoreGetUniqueId, ret=%d\n", ret);
        return ret;
    }

    *outKeyId = meta.id;
    return ret;
}


static int wh_ServerTask(void* cf, const char* keyFilePath, int keyId,
                         int clientId)
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
                               clientId);
        if (ret != 0) {
            printf("server failed to load key, ret=%d\n", ret);
            (void)wh_Server_Cleanup(server);
            return ret;
        }
    }


    if (ret == 0) {
        printf("Waiting for connection...\n");
        while (1) {
            ret = wh_Server_HandleRequestMessage(server);
            if (ret == WH_ERROR_NOTREADY) {
                _sleepMs(ONE_MS);
            }
            else if (ret != WH_ERROR_OK) {
                printf("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
                break;
            }
            else {
                whCommConnected current_state;
                int             get_conn_result =
                    wh_Server_GetConnected(server, &current_state);
                if (get_conn_result == WH_ERROR_OK) {
                    if (current_state == WH_COMM_CONNECTED &&
                        last_state == WH_COMM_DISCONNECTED) {
                        printf("Server connected\n");
                        last_state = WH_COMM_CONNECTED;
                    }
                    else if (current_state == WH_COMM_DISCONNECTED &&
                             last_state == WH_COMM_CONNECTED) {
                        printf("Server disconnected\n");
                        last_state = WH_COMM_DISCONNECTED;

                        /* POSIX TCP transport requires server to be
                         * re-initialized in order to reconnect */

                        (void)wh_Server_Cleanup(server);

                        /* Reinitialize the server */
                        ret = wh_Server_Init(server, config);
                        if (ret != 0) {
                            printf("Failed to reinitialize server: %d\n", ret);
                            break;
                        }

                        /* Reload keys into cache if file path was provided */
                        if (keyFilePath != NULL) {
                            ret =
                                loadAndStoreKeys(server, &loadedKeyId,
                                                 keyFilePath, keyId, clientId);
                            if (ret != 0) {
                                printf("server failed to load key, ret=%d\n",
                                       ret);
                                break;
                            }
                        }
                    }
                }
                else {
                    printf("Failed to get connection state: %d\n",
                           get_conn_result);
                }
            }
        }
    }
    return ret;
}

static int _hardwareCryptoCb(int devId, struct wc_CryptoInfo* info,
                                   void* ctx)
{
    (void)devId;
    (void)ctx;

    /* Default response */
    int ret = CRYPTOCB_UNAVAILABLE;
    switch(info->algo_type) {
        case WC_ALGO_TYPE_RNG: {
            /*printf("Hardware Crypto Callback: RNG operation requested\n");*/
            /* Extract info parameters */
            uint8_t* out = info->rng.out;
            uint32_t size = info->rng.sz;

            /* III Not random, just simple counter */
            static uint16_t my_counter = 1;
            if(my_counter > 4096) {
                /* Only allow 4096 bytes to be generated */
                ret= CRYPTOCB_UNAVAILABLE;
            } else {
                uint32_t i = 0;
                for (i = 0; i < size; i++) {
                    out[i] = (uint8_t)my_counter++;
                }
                ret = 0;
            }
            break;
        }
        default:
            /*printf("Hardware Crypto Callback: Unsupported algorithm type\n"); */
            ret = CRYPTOCB_UNAVAILABLE;
    }
    return ret;
}

int main(int argc, char** argv)
{
    int         rc              = 0;
    const char* keyFilePath     = NULL;
    const char* nvmInitFilePath = NULL;
    int         keyId = WH_KEYID_ERASED; /* Default key ID if none provided */
    int         clientId = 12; /* Default client ID if none provided */

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
    }

    /* Server configuration/context */
    whTransportServerCb            ptttcb[1]      = {PTT_SERVER_CB};
    posixTransportTcpServerContext tsc[1]         = {};
    posixTransportTcpConfig        mytcpconfig[1] = {{
               .server_ip_string = WH_SERVER_TCP_IPSTRING,
               .server_port      = WH_SERVER_TCP_PORT,
    }};
    whCommServerConfig             cs_conf[1]     = {{
                        .transport_cb      = ptttcb,
                        .transport_context = (void*)tsc,
                        .transport_config  = (void*)mytcpconfig,
                        .server_id         = WH_SERVER_ID,
    }};

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_RAM_SIZE / 2,
        .pageSize   = 8,
        .erasedByte = (uint8_t)0,
    }};
    const whFlashCb  fcb[1]     = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};

    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {{0}};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {{
        .devId = INVALID_DEVID,
    }};

#if defined(WOLFHSM_CFG_SHE_EXTENSION)
    whServerSheContext she[1] = {{0}};
#endif

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .devId       = INVALID_DEVID,
#if defined(WOLFHSM_CFG_SHE_EXTENSION)
        .she         = she,
#endif
    }};

    rc = wh_Nvm_Init(nvm, n_conf);
    if (rc != 0) {
        printf("Failed to initialize NVM: %d\n", rc);
        return rc;
    }

    /* Initialize NVM with contents from the NVM init file if provided */
    if (nvmInitFilePath != NULL) {
        printf("Initializing NVM with contents from %s\n", nvmInitFilePath);
        rc = initializeNvm(nvm, nvmInitFilePath);
        if (rc != 0) {
            printf("Failed to initialize NVM from file: %d\n", rc);
            return rc;
        }
        printf("NVM initialization completed successfully\n");
    }

    /* Initialize crypto library and hardware */
    wolfCrypt_Init();

    /* Context 3: Server Software Crypto */
    WC_RNG rng[1];
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
    crypto->devId = HW_DEV_ID;
    printf("Context 5: Setting up default server crypto with devId=%d\n",
                crypto->devId);

    rc = wc_InitRng_ex(crypto->rng, NULL, crypto->devId);
    if (rc != 0) {
        printf("Failed to wc_InitRng_ex: %d\n", rc);
        return rc;
    }

    rc = wh_ServerTask(s_conf, keyFilePath, keyId, clientId);

    rc = wc_FreeRng(crypto->rng);
    if (rc != 0) {
        printf("Failed to wc_FreeRng: %d\n", rc);
        return rc;
    }
    rc = wolfCrypt_Cleanup();
    if (rc != 0) {
        printf("Failed to wolfCrypt_Cleanup: %d\n", rc);
        return rc;
    }

    return rc;
}
