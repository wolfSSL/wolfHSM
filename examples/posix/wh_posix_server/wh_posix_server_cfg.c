/*
 * Example server app using POSIX transport
 */

#include "wh_posix_cfg.h"
#include "wh_posix_server_cfg.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "port/posix/posix_transport_shm.h"
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_transport_dma.h"

posixTransportShmConfig shmConfig;
posixTransportTcpConfig tcpConfig;

whCommServerConfig s_comm;

whTransportServerCb tcpCb = PTT_SERVER_CB;
whTransportServerCb shmCb = POSIX_TRANSPORT_SHM_SERVER_CB;
posixTransportShmServerContext tscShm;
posixTransportTcpServerContext tscTcp;

#ifdef WOLFSSL_STATIC_MEMORY
whTransportServerCb dmaCb = POSIX_TRANSPORT_SHM_SERVER_CB;
posixTransportShmServerContext tscDma;
whServerDmaConfig dmaConfig;

/* Server configuration setup example for transport
 * Does not setup flash, nvm, crypto, she, etc. */
int Server_ExampleDMAConfig(void* conf)
{
    whServerConfig* s_conf = (whServerConfig*)conf;

    memset(&tscDma, 0, sizeof(posixTransportShmServerContext));
    memset(&s_comm, 0, sizeof(whCommServerConfig));

    shmConfig.name      = WH_POSIX_SHARED_MEMORY_NAME;
    shmConfig.req_size  = WH_POSIX_REQ_SIZE;
    shmConfig.resp_size = WH_POSIX_RESP_SIZE;
    shmConfig.dma_size  = WH_POSIX_DMA_SIZE;

    dmaConfig.cb = wh_Server_PosixStaticMemoryDMA;
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
int Server_ExampleSHMConfig(void* conf)
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
int Server_ExampleTCPConfig(void* conf)
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

static const whFlashCb  fcb = WH_FLASH_RAMSIM_CB;
static whFlashRamsimCfg fc_conf;

int Server_ExampleRAMSimConfig(void* conf, uint8_t* memory)
{
    whServerConfig* s_conf = (whServerConfig*)conf;
    
    fc_conf.size       = WH_POSIX_FLASH_RAM_SIZE,
    fc_conf.sectorSize = WH_POSIX_FLASH_RAM_SIZE / 2,
    fc_conf.pageSize   = 8;
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


int Server_ExampleNVMConfig(void* conf, const char* nvmInitFilePath)
{
    int rc;
    whServerConfig* s_conf = (whServerConfig*)conf;
    static whNvmConfig n_conf = {0};
    static whNvmFlashConfig  nf_conf;
    static whNvmFlashContext nfc[1]     = {0};
    static whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};
    static whNvmContext nvm[1] = {{0}};
    static whFlashRamsimCtx fc = {0};


    nf_conf.cb      = &fcb;
    nf_conf.context = &fc;
    nf_conf.config  = &fc_conf;

    n_conf.cb      = nfcb;
    n_conf.context = nfc;
    n_conf.config  = &nf_conf;

    s_conf->nvm = nvm;
    rc = wh_Nvm_Init(nvm, &n_conf);
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

    return WH_ERROR_OK;
}
