#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <getopt.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "port/posix/posix_flash_file.h"
#include "port/posix/posix_transport_tcp.h"

/* Macros for maximum client ID and key ID */
#define MAX_CLIENT_ID 255
#define MAX_KEY_ID UINT16_MAX

/* Macros for maximum file path length (Linux PATH_MAX is a good reference) */
#define MAX_FILE_PATH_LENGTH PATH_MAX

/* Parameterize MAX_LINE_LENGTH by 512 bytes + MAX_FILE_PATH_LENGTH */
#define MAX_LINE_LENGTH (512 + MAX_FILE_PATH_LENGTH)

#define INTERMEDIATE_FILE "nvm_metadata.txt"
#define DEFAULT_IMAGE_FILE "whNvmImage.bin"
#define DEFAULT_PARTITION_SIZE 0x10000
#define DEFAULT_ERASED_BYTE 0xFF

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
Entry* entryHead = NULL;

/* Flag to indicate if we're in test mode, set by --test command line argument.
 * If set, write the metadata ID/filepath pair to an intermediate file so the
 * test code can parse this file and associate object IDs with their input data
 * to verify the results against known good data */
static int gTestMode = 0;


/* Function prototypes */
static void   writeMetadataToFile(uint32_t metadataId, const char* filePath);
static int    initializeServer(whServerContext*      serverContext,
                               whNvmContext*         nvmContext,
                               const whServerConfig* serverConfig,
                               const whNvmConfig*    nvmConfig);
static void   cleanupServer(whServerContext* serverContext);
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
static void parseConfigFile(const char* filePath);


/* Creates a new entry in the linked list based on the provided parameters */
Entry* createEntry(uint8_t clientId, uint16_t id, uint16_t access,
                   uint16_t flags, const char* label, const char* filePath)
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
void appendEntry(Entry** head, uint8_t clientId, uint16_t id, uint16_t access,
                 uint16_t flags, const char* label, const char* filePath)
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

/* Writes a list entry to NVM and optionally to an intermediate file for
 * test mode */
static void processEntry(Entry* entry, int isKey, whNvmContext* nvmContext)
{
    FILE* file = fopen(entry->filePath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file %s\n", entry->filePath);
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

    if (bytesRead != fileSize) {
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

    if (gTestMode) {
        writeMetadataToFile(meta.id, entry->filePath);
    }

    free(buffer);
}

/* Iterates through the linked list and processes each entry */
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

/* Frees the memory allocated for the linked list */
void freeEntries()
{
    Entry* current = entryHead;
    while (current != NULL) {
        Entry* next = current->next;
        free(current->label);
        free(current->filePath);
        free(current);
        current = next;
    }
}

/* Function to remove comments from a line */
void stripComment(char* line)
{
    char* commentStart = strchr(line, '#');
    if (commentStart) {
        /* Null-terminate the line at the start of the comment */
        *commentStart = '\0';
    }
}

/* Function to trim leading and trailing whitespace */
void trimWhitespace(char* str)
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
int parseInteger(const char* str, uint32_t maxValue, uint32_t* result)
{
    char* endPtr;
    long  value;

    if (strstr(str, "0x") == str) {
        /* Parse as hexadecimal */
        value = strtol(str, &endPtr, 16);
    }
    else {
        /* Parse as decimal */
        value = strtol(str, &endPtr, 10);
    }

    if (*endPtr != '\0' || value < 0 || value > maxValue) {
        return 0; /* Error: invalid number */
    }

    *result = (uint32_t)value;
    return 1; /* Success */
}

/* Function to parse the configuration file and build the linked list */
void parseConfigFile(const char* filePath)
{
    FILE* file = fopen(filePath, "r");
    if (!file) {
        perror("Error opening file");
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
        char     label[256], filePath[MAX_FILE_PATH_LENGTH];
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

/* Writes the metadata ID and filepath to an intermediate file for test mode.
 *  The format of the file should be comma separated <metadata ID>,<file path>
 * pairs, with one entry per line */
static void writeMetadataToFile(uint32_t metadataId, const char* filePath)
{
    FILE* file = fopen(INTERMEDIATE_FILE, "a");
    if (file == NULL) {
        fprintf(stderr,
                "Error: Unable to open intermediate file for writing\n");
        return;
    }

    char fullPath[PATH_MAX];
    if (realpath(filePath, fullPath) == NULL) {
        fprintf(stderr, "Error: Unable to get full path for %s\n", filePath);
        fclose(file);
        return;
    }

    fprintf(file, "%u,%s\n", metadataId, fullPath);
    fclose(file);
}

/* Initialize the NVM and server */
static int initializeServer(whServerContext*      serverContext,
                            whNvmContext*         nvmContext,
                            const whServerConfig* serverConfig,
                            const whNvmConfig*    nvmConfig)
{
    /* Initialize the NVM context */
    int rc = wh_Nvm_Init(nvmContext, nvmConfig);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to initialize NVM, ret = %d\n", rc);
        return EXIT_FAILURE;
    }

    rc = wh_Server_Init(serverContext, (whServerConfig*)serverConfig);
    if (rc != 0) {
        fprintf(stderr, "Failed to initialize wolfHSM server: ret = %d\n", rc);
        return rc;
    }
    return 0;
}

static void cleanupServer(whServerContext* serverContext)
{
    wh_Server_Cleanup(serverContext);
}

int main(int argc, char* argv[])
{
    int                  rc = 0;
    int                  opt;
    char*                config_file        = NULL;
    char*                image_file         = DEFAULT_IMAGE_FILE;
    uint32_t             partition_size     = DEFAULT_PARTITION_SIZE;
    uint8_t              erased_byte        = DEFAULT_ERASED_BYTE;
    int                  invert_erased_byte = 0;
    static struct option long_options[]     = {
            {"test", no_argument, 0, 't'},
            {"image", optional_argument, 0, 'i'},
            {"size", required_argument, 0, 's'},
            {"invert-erased-byte", no_argument, 0, 'e'},
            {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "ti::s:e", long_options, NULL)) !=
           -1) {
        switch (opt) {
            case 't':
                gTestMode = 1;
                break;
            case 'i':
                if (optarg) {
                    image_file = optarg;
                }
                break;
            case 's':
                if (strncmp(optarg, "0x", 2) == 0) {
                    partition_size = (uint32_t)strtoul(optarg + 2, NULL, 16);
                }
                else {
                    partition_size = (uint32_t)strtoul(optarg, NULL, 10);
                }
                if (partition_size == 0) {
                    fprintf(stderr, "Error: Invalid partition size\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'e':
                invert_erased_byte = 1;
                break;
            default:
                fprintf(stderr,
                        "Usage: %s [--test] [--image[=<file>]] [--size <size>] "
                        "[--invert-erased-byte] <config-file>\n",
                        argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: Config file is mandatory\n");
        fprintf(stderr,
                "Usage: %s [--test] [--image[=<file>]] [--size <size>] "
                "[--invert-erased-byte] <config-file>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    config_file = argv[optind];

    if (invert_erased_byte) {
        erased_byte = 0x00;
    }

    /* Server configuration/context */
    whTransportServerCb            gTransportServerCb[1]      = {PTT_SERVER_CB};
    posixTransportTcpServerContext gTransportServerContext[1] = {};
    posixTransportTcpConfig        gTransportTcpConfig[1]     = {{
                   .server_ip_string = "127.0.0.1",
                   .server_port      = 8080,
    }};

    whCommServerConfig gCommServerConfig[1] = {{
        .transport_cb      = gTransportServerCb,
        .transport_context = (void*)gTransportServerContext,
        .transport_config  = (void*)gTransportTcpConfig,
        .server_id         = 34,
    }};

    /* POSIX flash file NVM configuration */
    posixFlashFileConfig gPosixFlashConfig = {
        .filename       = image_file,
        .partition_size = partition_size,
        .erased_byte    = erased_byte,
    };

    /* POSIX flash file context */
    posixFlashFileContext gPosixFlashContext = {0};

    /* NVM Flash configuration using POSIX flash file */
    const whFlashCb  gFlashCb[1]     = {POSIX_FLASH_FILE_CB};
    whNvmFlashConfig gNvmFlashConfig = {.cb      = gFlashCb,
                                        .context = &gPosixFlashContext,
                                        .config  = &gPosixFlashConfig};

    whNvmFlashContext gNvmFlashContext = {0};
    const whNvmCb     gNvmCb[1]        = {WH_NVM_FLASH_CB};

    whNvmConfig gNvmConfig = {.cb      = (whNvmCb*)gNvmCb,
                              .context = &gNvmFlashContext,
                              .config  = &gNvmFlashConfig};

    whNvmContext gNvmContext = {0};

    /* Server configuration */
    whServerConfig gServerConfig = {
        .comm_config = gCommServerConfig,
        .nvm         = &gNvmContext,
#ifndef WOLFHSM_CFG_NO_CRYPTO
        .crypto = NULL,
#ifdef WOLFHSM_CFG_SHE_EXTENSION
        .she = NULL,
#endif /* WOLFHSM_CFG_SHE_EXTENSION */
#endif /* WOLFHSM_CFG_NO_CRYPTO */
        .dmaConfig = NULL,
    };

    whServerContext gServerContext = {0};

    /* Initialize the server */
    rc = initializeServer(&gServerContext, &gNvmContext, &gServerConfig,
                          &gNvmConfig);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to initialize server, ret = %d\n", rc);
        return EXIT_FAILURE;
    }

    if (gTestMode) {
        /* Clear the intermediate file before processing */
        FILE* file = fopen(INTERMEDIATE_FILE, "w");
        if (file != NULL) {
            fclose(file);
        }
        else {
            fprintf(stderr, "Warning: Unable to clear intermediate file\n");
        }
    }

    /* Parse the configuration file */
    parseConfigFile(config_file);

    /* Process the entries */
    processEntries(&gNvmContext);

    /* Free the allocated memory */
    freeEntries();

    /* Cleanup the server */
    cleanupServer(&gServerContext);

    return EXIT_SUCCESS;
}
