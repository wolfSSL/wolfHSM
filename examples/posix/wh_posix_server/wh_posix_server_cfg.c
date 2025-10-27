/*
 * Example server app using POSIX transport
 */
#include <stdio.h>  /* For printf */
#include <stdlib.h> /* For atoi */
#include <string.h> /* For memset, memcpy, strcmp */
#include <ctype.h>  /* For isspace */

#include "wh_posix_cfg.h"
#include "wh_posix_server_cfg.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "port/posix/posix_transport_shm.h"
#include "port/posix/posix_transport_tcp.h"
#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "port/posix/posix_transport_tls.h"
#endif

posixTransportShmConfig shmConfig;
posixTransportTcpConfig tcpConfig;
#ifndef WOLFHSM_CFG_NO_CRYPTO
posixTransportTlsConfig tlsConfig;
#endif

whCommServerConfig s_comm;

whTransportServerCb            tcpCb = PTT_SERVER_CB;
whTransportServerCb            shmCb = POSIX_TRANSPORT_SHM_SERVER_CB;
#ifndef WOLFHSM_CFG_NO_CRYPTO
whTransportServerCb tlsCb = PTTLS_SERVER_CB;
#endif
posixTransportShmServerContext tscShm;
posixTransportTcpServerContext tscTcp;
#ifndef WOLFHSM_CFG_NO_CRYPTO
posixTransportTlsServerContext tscTls;
#endif

#ifdef WOLFSSL_STATIC_MEMORY
whTransportServerCb            dmaCb = POSIX_TRANSPORT_SHM_SERVER_CB;
posixTransportShmServerContext tscDma;
whServerDmaConfig              dmaConfig;

/* Server configuration setup example for transport
 * Does not setup flash, nvm, crypto, she, etc. */
int wh_PosixServer_ExampleShmDmaConfig(void* conf)
{
    whServerConfig* s_conf = (whServerConfig*)conf;

    memset(&tscDma, 0, sizeof(posixTransportShmServerContext));
    memset(&s_comm, 0, sizeof(whCommServerConfig));

    shmConfig.name      = WH_POSIX_SHARED_MEMORY_NAME;
    shmConfig.req_size  = WH_POSIX_REQ_SIZE;
    shmConfig.resp_size = WH_POSIX_RESP_SIZE;
    shmConfig.dma_size  = WH_POSIX_DMA_SIZE;

    dmaConfig.cb               = posixTransportShm_ServerStaticMemDmaCallback;
    dmaConfig.dmaAddrAllowList = NULL;

    s_comm.transport_cb      = &dmaCb;
    s_comm.transport_context = (void*)&tscDma;
    s_comm.transport_config  = (void*)&shmConfig;
    s_comm.server_id         = WH_POSIX_SERVER_ID;

    s_conf->dmaConfig   = &dmaConfig;
    s_conf->comm_config = &s_comm;

    return WH_ERROR_OK;
}
#endif


/* Server configuration setup example for transport
 * Does not setup flash, nvm, crypto, she, etc. */
int wh_PosixServer_ExampleShmConfig(void* conf)
{
    whServerConfig* s_conf = (whServerConfig*)conf;

    memset(&tscShm, 0, sizeof(posixTransportShmServerContext));
    memset(&s_comm, 0, sizeof(whCommServerConfig));

    shmConfig.name      = WH_POSIX_SHARED_MEMORY_NAME;
    shmConfig.req_size  = WH_POSIX_REQ_SIZE;
    shmConfig.resp_size = WH_POSIX_RESP_SIZE;
    shmConfig.dma_size  = WH_POSIX_DMA_SIZE;

    s_comm.transport_cb      = &shmCb;
    s_comm.transport_context = (void*)&tscShm;
    s_comm.transport_config  = (void*)&shmConfig;
    s_comm.server_id         = WH_POSIX_SERVER_ID;

    s_conf->comm_config = &s_comm;

    return WH_ERROR_OK;
}


/* Server configuration setup example for transport
 * Does not setup flash, nvm, crypto, she, etc. */
int wh_PosixServer_ExampleTcpConfig(void* conf)
{
    whServerConfig* s_conf = (whServerConfig*)conf;

    /* Server configuration/context */
    memset(&tscTcp, 0, sizeof(posixTransportTcpServerContext));

    tcpConfig.server_ip_string = WH_POSIX_SERVER_TCP_IPSTRING;
    tcpConfig.server_port      = WH_POSIX_SERVER_TCP_PORT;

    s_comm.transport_cb      = &tcpCb;
    s_comm.transport_context = (void*)&tscTcp;
    s_comm.transport_config  = (void*)&tcpConfig;
    s_comm.server_id         = WH_POSIX_SERVER_ID;

    s_conf->comm_config = &s_comm;

    return WH_ERROR_OK;
}

#ifndef WOLFHSM_CFG_NO_CRYPTO
/* Server configuration setup example for TLS transport
 * Does not setup flash, nvm, crypto, she, etc. */

#undef USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048
#include "wolfssl/certs_test.h"

#ifdef WOLFSSL_STATIC_MEMORY
#define EXAMPLE_STATIC_MEMORY_SIZE 70000
static unsigned char memoryBuffer[EXAMPLE_STATIC_MEMORY_SIZE];
WOLFSSL_HEAP_HINT*   heap               = NULL;
unsigned int         staticMemoryList[] = {176,  304,  384,  480, 1008,
                                           3328, 4560, 5152, 8928};
unsigned int         staticMemoryDist[] = {14, 4, 3, 3, 4, 10, 2, 1, 1};
#endif

#ifndef NO_PSK
static unsigned int psk_tls12_server_cb(WOLFSSL* ssl, const char* identity,
                                        unsigned char* key,
                                        unsigned int   key_max_len)
{
    size_t len;

    memset(key, 0, key_max_len);
    printf("PSK TLS12 server callback\n");
    printf("PSK client identity: %s\n", identity);
    printf("Enter PSK password to accept: ");
    if (fgets((char*)key, key_max_len - 1, stdin) == NULL) {
        memset(key, 0, key_max_len);
        return 0U;
    }
    len = strcspn((char*)key, "\n");
    ((char*)key)[len] = '\0';
    (void)ssl;
    return (unsigned int)len;
}

#ifdef WOLFSSL_TLS13
static unsigned int psk_tls13_server_cb(WOLFSSL* ssl, const char* identity,
                                        unsigned char* key,
                                        unsigned int   key_max_len,
                                        const char**   ciphersuite)
{
    size_t len;

    memset(key, 0, key_max_len);
    printf("PSK TLS13 server callback\n");
    printf("PSK client identity: %s\n", identity);
    *ciphersuite = "TLS13-AES128-GCM-SHA256";

    printf("Enter PSK password: ");
    if (fgets((char*)key, key_max_len - 1, stdin) == NULL) {
        memset(key, 0, key_max_len);
        return 0U;
    }
    len = strcspn((char*)key, "\n");
    ((char*)key)[len] = '\0';

    (void)ssl;
    return (unsigned int)len;
}
#endif /* WOLFSSL_TLS13 */

static int
wh_PosixServer_ExamplePskContextSetup(posixTransportTlsServerContext* ctx)
{
    /* uncomment and compile with DEBUG_WOLFSSL for debugging  */
    /* wolfSSL_Debugging_ON(); */

#ifdef WOLFSSL_STATIC_MEMORY
    /* Initialize static memory buffer */
    if (wc_LoadStaticMemory_ex(&heap, WH_POSIX_STATIC_MEM_LIST_SIZE,
                               staticMemoryList, staticMemoryDist, memoryBuffer,
                               EXAMPLE_STATIC_MEMORY_SIZE, 0, 0) != 0) {
        return WH_ERROR_ABORTED;
    }

    ctx->ssl_ctx = wolfSSL_CTX_new_ex(wolfSSLv23_server_method_ex(heap), heap);
#else
    ctx->ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
#endif
    if (ctx->ssl_ctx == NULL) {
#ifdef WOLFSSL_STATIC_MEMORY
        if (heap) {
            wc_UnloadStaticMemory(heap);
            heap = NULL;
        }
#endif
        return WH_ERROR_ABORTED;
    }

    wolfSSL_CTX_set_psk_server_callback(ctx->ssl_ctx, psk_tls12_server_cb);
#ifdef WOLFSSL_TLS13
    wolfSSL_CTX_set_psk_server_tls13_callback(ctx->ssl_ctx,
                                              psk_tls13_server_cb);
#endif /* WOLFSSL_TLS13 */
    wolfSSL_CTX_use_psk_identity_hint(ctx->ssl_ctx, "wolfHSM Example Server");
    return WH_ERROR_OK;
}
#endif /* NO_PSK */

static int
wh_PosixServer_ExampleTlsContextSetup(posixTransportTlsServerContext* ctx)
{
    int rc;

    /* uncomment and compile with DEBUG_WOLFSSL for debugging  */
    /* wolfSSL_Debugging_ON(); */

#ifdef WOLFSSL_STATIC_MEMORY
    if (wc_LoadStaticMemory_ex(&heap, WH_POSIX_STATIC_MEM_LIST_SIZE,
                               staticMemoryList, staticMemoryDist, memoryBuffer,
                               EXAMPLE_STATIC_MEMORY_SIZE, 0, 0) != 0) {
        return WH_ERROR_ABORTED;
    }

    ctx->ssl_ctx = wolfSSL_CTX_new_ex(wolfSSLv23_server_method_ex(heap), heap);
#else
    ctx->ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
#endif

    if (ctx->ssl_ctx == NULL) {
#ifdef WOLFSSL_STATIC_MEMORY
        if (heap) {
            wc_UnloadStaticMemory(heap);
            heap = NULL;
        }
#endif
        return WH_ERROR_ABORTED;
    }
    /* don't use wolfHSM for local TLS crypto */
    wolfSSL_CTX_SetDevId(ctx->ssl_ctx, INVALID_DEVID);

    /* Load server certificate */
    rc = wolfSSL_CTX_use_certificate_buffer(ctx->ssl_ctx, server_cert_der_2048,
                                            sizeof(server_cert_der_2048),
                                            CTC_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
#ifdef WOLFSSL_STATIC_MEMORY
        if (heap) {
            wc_UnloadStaticMemory(heap);
            heap = NULL;
        }
#endif
        return WH_ERROR_ABORTED;
    }

    /* Load CA certificate for client verification if enabled */
    rc = wolfSSL_CTX_load_verify_buffer(ctx->ssl_ctx, client_cert_der_2048,
                                        sizeof(client_cert_der_2048),
                                        WOLFSSL_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
#ifdef WOLFSSL_STATIC_MEMORY
        if (heap) {
            wc_UnloadStaticMemory(heap);
            heap = NULL;
        }
#endif
        return WH_ERROR_ABORTED;
    }

    /* load private key for TLS connection */
    rc = wolfSSL_CTX_use_PrivateKey_buffer(ctx->ssl_ctx, server_key_der_2048,
                                           sizeof(server_key_der_2048),
                                           CTC_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
#ifdef WOLFSSL_STATIC_MEMORY
        if (heap) {
            wc_UnloadStaticMemory(heap);
            heap = NULL;
        }
#endif
        return WH_ERROR_ABORTED;
    }

    /* Setup server for mutual authentication. It will try to verify the clients
     * certificate so both the client and server authenticate the peer
     * connecting with. */
    wolfSSL_CTX_set_verify(ctx->ssl_ctx, WOLFSSL_VERIFY_PEER, NULL);

    return WH_ERROR_OK;
}


static int wh_PosixServer_ExampleTlsCommonContextSetup(void* ctx)
{
    whServerConfig* s_conf = (whServerConfig*)ctx;

    /* Server configuration/context */
    memset(&tscTls, 0, sizeof(posixTransportTlsServerContext));

    /* Initialize TCP context fields that need specific values */
    tscTls.listen_fd_p1  = 0; /* Invalid fd */
    tscTls.accept_fd_p1  = 0; /* Invalid fd */
    tscTls.request_recv  = 0;
    tscTls.buffer_offset = 0;

    tlsConfig.server_ip_string = WH_POSIX_SERVER_TCP_IPSTRING;
    tlsConfig.server_port      = WH_POSIX_SERVER_TCP_PORT;
    tlsConfig.verify_peer      = true;

    s_comm.transport_cb      = &tlsCb;
    s_comm.transport_context = (void*)&tscTls;
    s_comm.transport_config  = (void*)&tlsConfig;
    s_comm.server_id         = WH_POSIX_SERVER_ID;

    s_conf->comm_config = &s_comm;

    return WH_ERROR_OK;
}

int wh_PosixServer_ExampleTlsConfig(void* conf)
{
    if (wh_PosixServer_ExampleTlsCommonContextSetup(conf) != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }

    if (wh_PosixServer_ExampleTlsContextSetup(&tscTls) != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

#ifndef NO_PSK
int wh_PosixServer_ExamplePskConfig(void* conf)
{
    if (wh_PosixServer_ExampleTlsCommonContextSetup(conf) != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }

    if (wh_PosixServer_ExamplePskContextSetup(&tscTls) != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}
#endif /* NO_PSK */
#endif

static const whFlashCb  fcb = WH_FLASH_RAMSIM_CB;
static whFlashRamsimCfg fc_conf;

int wh_PosixServer_ExampleRamSimConfig(void* conf, uint8_t* memory)
{
    whServerConfig* s_conf = (whServerConfig*)conf;

    fc_conf.size       = WH_POSIX_FLASH_RAM_SIZE,
    fc_conf.sectorSize = WH_POSIX_FLASH_RAM_SIZE / 2, fc_conf.pageSize = 8;
    fc_conf.erasedByte = (uint8_t)0;
    fc_conf.memory     = memory;

    (void)s_conf;
    return WH_ERROR_OK;
}


/*******************************************************/
/* NVM related functions */
/*******************************************************/

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


/* Creates a new entry in the linked list based on the provided parameters */
static Entry* createEntry(uint8_t clientId, uint16_t id, uint16_t access,
                          uint16_t flags, const char* label,
                          const char* filePath)
{
    Entry* newEntry = (Entry*)malloc(sizeof(Entry));
    if (!newEntry) {
        WOLFHSM_CFG_PRINTF("Memory allocation error\n");
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
                WOLFHSM_CFG_PRINTF("Error on line %d: Malformed key entry - invalid "
                        "clientId\n",
                        lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }

            /* Parse key ID for key entries */
            token = strtok(NULL, " ");
            if (!token || !parseInteger(token, MAX_KEY_ID, &id)) {
                WOLFHSM_CFG_PRINTF("Error on line %d: Malformed key entry - invalid keyId\n",
                    lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
        else if (strncmp(line, "obj", 3) == 0) {
            /* Parse object ID for object entries */
            token = strtok(line + 3, " ");
            if (!token || !parseInteger(token, MAX_KEY_ID, &id)) {
                WOLFHSM_CFG_PRINTF("Error on line %d: Malformed object entry - invalid id\n",
                    lineNumber);
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
        else {
            /* Report error for unknown entry types */
            WOLFHSM_CFG_PRINTF("Error on line %d: Malformed line or unknown entry type\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* Parse access field */
        token = strtok(NULL, " ");
        if (!token || !parseInteger(token, UINT16_MAX, &access)) {
            WOLFHSM_CFG_PRINTF("Error on line %d: Malformed entry - invalid access\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* Parse flags */
        token = strtok(NULL, " ");
        if (!token || !parseInteger(token, UINT16_MAX, &flags)) {
            WOLFHSM_CFG_PRINTF("Error on line %d: Malformed entry - invalid flags\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        /* Parse the label (enclosed in quotes) */
        token = strtok(NULL, "\"");
        if (!token) {
            WOLFHSM_CFG_PRINTF("Error on line %d: Malformed entry - missing or incorrect "
                    "label format\n",
                    lineNumber);
            fclose(file);
            exit(EXIT_FAILURE);
        }
        snprintf(label, sizeof(label), "%s", token);

        /* Parse the file path */
        token = strtok(NULL, " ");
        if (!token || sscanf(token, "%s", filePath) != 1) {
            WOLFHSM_CFG_PRINTF("Error on line %d: Malformed entry - missing file path\n",
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
        WOLFHSM_CFG_PRINTF("Error processing entry: Unable to open file %s\n",
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
        WOLFHSM_CFG_PRINTF("Error: Memory allocation failed for file %s\n",
                entry->filePath);
        fclose(file);
        return;
    }

    /* Read the file data into the buffer */
    size_t bytesRead = fread(buffer, 1, fileSize, file);
    fclose(file);

    if (bytesRead != (size_t)fileSize) {
        WOLFHSM_CFG_PRINTF("Error: Failed to read entire file %s\n",
                entry->filePath);
        free(buffer);
        return;
    }

    /* Create metadata for the new entry */
    whNvmMetadata meta = {0};
    if (isKey) {
        /* Keys have special ID format */
        meta.id = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, entry->clientId, entry->id);
        WOLFHSM_CFG_PRINTF("Processing Key Entry - ClientID: 0x%X, KeyID: 0x%X, Meta ID: "
               "0x%X, "
               "Access: 0x%X, Flags: 0x%X, Label: %s, File: %s, Size: %ld\n",
               entry->clientId, entry->id, meta.id, entry->access, entry->flags,
               entry->label, entry->filePath, fileSize);
    }
    else {
        meta.id = entry->id;
        WOLFHSM_CFG_PRINTF("Processing Object Entry - ID: 0x%X, Access: 0x%X, Flags: 0x%X, "
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
        WOLFHSM_CFG_PRINTF("Error: Failed to add entry ID %u to NVM, ret = %d\n",
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


int wh_PosixServer_ExampleNvmConfig(void* conf, const char* nvmInitFilePath)
{
    int                      rc;
    whServerConfig*          s_conf = (whServerConfig*)conf;
    static whNvmConfig       n_conf = {0};
    static whNvmFlashConfig  nf_conf;
    static whNvmFlashContext nfc[1]  = {0};
    static whNvmCb           nfcb[1] = {WH_NVM_FLASH_CB};
    static whNvmContext      nvm[1]  = {{0}};
    static whFlashRamsimCtx  fc      = {0};


    nf_conf.cb      = &fcb;
    nf_conf.context = &fc;
    nf_conf.config  = &fc_conf;

    n_conf.cb      = nfcb;
    n_conf.context = nfc;
    n_conf.config  = &nf_conf;

    s_conf->nvm = nvm;
    rc          = wh_Nvm_Init(nvm, &n_conf);
    if (rc != 0) {
        WOLFHSM_CFG_PRINTF("Failed to initialize NVM: %d\n", rc);
        return rc;
    }

    /* Initialize NVM with contents from the NVM init file if provided */
    if (nvmInitFilePath != NULL) {
        WOLFHSM_CFG_PRINTF("Initializing NVM with contents from %s\n", nvmInitFilePath);
        rc = initializeNvm(nvm, nvmInitFilePath);
        if (rc != 0) {
            WOLFHSM_CFG_PRINTF("Failed to initialize NVM from file: %d\n", rc);
            return rc;
        }
        WOLFHSM_CFG_PRINTF("NVM initialization completed successfully\n");
    }

    return WH_ERROR_OK;
}
