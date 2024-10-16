#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_nvm.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"

/* Dummy transport */
#include "port/posix/posix_transport_tcp.h"

/* Flash implementations to test */
#include "wolfhsm/wh_flash_ramsim.h"
#include "port/posix/posix_flash_file.h"


/* Dummy Server comms config (unused) */
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


/* Default parameters for the NVM Flash configurations to test */
/* The file containing the NVM image to use for the tests */
#ifndef FLASH_IMAGE_FILENAME
#define FLASH_IMAGE_FILENAME "../whNvmImage.bin"
#endif
/* The size of the NVM partition to use for the tests */
#ifndef FLASH_PARTITION_SIZE
#define FLASH_PARTITION_SIZE 0x10000
#endif
/* The byte value that represents an erased NVM flash byte */
#ifndef FLASH_ERASED_BYTE
#define FLASH_ERASED_BYTE 0xFF
#endif
/* The file containing the object ID and file path pairs, holding golden truth
 * data */
#ifndef TEST_DATA_OBJID_FILE_MAPPING
#define TEST_DATA_OBJID_FILE_MAPPING "../nvm_metadata.txt"
#endif


/* Global NVM Configurations that should be checked */

/* RamSim Flash state and configuration */
whFlashRamsimCtx gFlashRamsimContext[1] = {0};
whFlashRamsimCfg gFlashRamsimConfig[1]  = {{
     .size       = FLASH_PARTITION_SIZE * 2,
     .sectorSize = FLASH_PARTITION_SIZE,
     .pageSize   = 8,
     .erasedByte = FLASH_ERASED_BYTE,
     .initData   = NULL, /* Init data will be set dynamically */
}};
const whFlashCb  gFlashRamsimCb[1]      = {WH_FLASH_RAMSIM_CB};
#define INIT_RAMSIM_NVM_FLASH_CONFIG                          \
    {                                                         \
        .cb = gFlashRamsimCb, .context = gFlashRamsimContext, \
        .config = gFlashRamsimConfig                          \
    }

/* POSIX flash file state and configuration */
static posixFlashFileContext      gPosixFlashContext = {0};
static const posixFlashFileConfig gPosixFlashConfig  = {
     .filename       = FLASH_IMAGE_FILENAME,
     .partition_size = FLASH_PARTITION_SIZE,
     .erased_byte    = FLASH_ERASED_BYTE,
};
const whFlashCb gPosixFlashCb[1] = {POSIX_FLASH_FILE_CB};
#define INIT_POSIX_NVM_FLASH_CONFIG                          \
    {                                                        \
        .cb = gPosixFlashCb, .context = &gPosixFlashContext, \
        .config = &gPosixFlashConfig                         \
    }

/* Global array holding all the NVM Flash configurations to test */
const whNvmFlashConfig gNvmFlashConfigsToTest[] = {
    INIT_POSIX_NVM_FLASH_CONFIG,
    INIT_RAMSIM_NVM_FLASH_CONFIG,
};
/* Number of NVM Flash configurations to test */
#define NVM_FLASH_CONFIGS_TO_TEST_COUNT \
    (sizeof(gNvmFlashConfigsToTest) / sizeof(gNvmFlashConfigsToTest[0]))

/* Object ID/file path pair for golden truth data linked list */
typedef struct MetadataEntry {
    whNvmId               id;
    char                  filePath[PATH_MAX];
    struct MetadataEntry* next;
} MetadataEntry;

/* Linked list of the object ID and file path pairs for golden truth data */
static MetadataEntry* gMetadataHead = NULL;

static void freeMetadataEntries()
{
    MetadataEntry* current = gMetadataHead;
    while (current != NULL) {
        MetadataEntry* next = current->next;
        free(current);
        current = next;
    }
    gMetadataHead = NULL;
}

/* Load objectId/file path pairs into the linked list from the test output
 * file*/
static int loadMetadataEntries()
{
    FILE* file = fopen(TEST_DATA_OBJID_FILE_MAPPING, "r");
    if (file == NULL) {
        fprintf(stderr,
                "Error: Unable to open intermediate file for reading\n");
        return -1;
    }

    char line[PATH_MAX + 20]; /* Extra space for the ID and comma */
    while (fgets(line, sizeof(line), file)) {
        MetadataEntry* newEntry = (MetadataEntry*)malloc(sizeof(MetadataEntry));
        if (newEntry == NULL) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            fclose(file);
            freeMetadataEntries();
            return -1;
        }

        if (sscanf(line, "%hu,%s", &newEntry->id, newEntry->filePath) != 2) {
            fprintf(stderr,
                    "Error: Invalid line format in intermediate file\n");
            free(newEntry);
            fclose(file);
            freeMetadataEntries();
            return -1;
        }

        newEntry->next = gMetadataHead;
        gMetadataHead  = newEntry;
    }

    fclose(file);
    return 0;
}

/* Lookup the file path for a given object ID in the linked list */
static const char* getFilePathForId(whNvmId id)
{
    MetadataEntry* current = gMetadataHead;
    while (current != NULL) {
        if (current->id == id) {
            return current->filePath;
        }
        current = current->next;
    }
    return NULL;
}

/* Compare the NVM data against the known good input file data for a given
 * object ID */
static int checkNvmDataValid(whNvmId id, const uint8_t* nvmData,
                             whNvmSize nvmDataLen)
{
    const char* filePath = getFilePathForId(id);
    if (filePath == NULL) {
        fprintf(stderr, "Error: No file path found for ID %u\n", id);
        return -1;
    }

    FILE* file = fopen(filePath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file %s for comparison\n",
                filePath);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fileSize != nvmDataLen) {
        fprintf(stderr,
                "Error: File size (%ld) doesn't match NVM data length (%u) for "
                "ID %u\n",
                fileSize, nvmDataLen, id);
        fclose(file);
        return -1;
    }

    uint8_t* fileData = malloc(fileSize);
    if (fileData == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for ID %u\n", id);
        fclose(file);
        return -1;
    }

    size_t bytesRead = fread(fileData, 1, fileSize, file);
    fclose(file);

    if (bytesRead != fileSize) {
        fprintf(stderr, "Error: Failed to read entire file for ID %u\n", id);
        free(fileData);
        return -1;
    }

    int result = memcmp(fileData, nvmData, nvmDataLen);
    if (result != 0) {
        fprintf(stderr, "Error: Data mismatch for ID %u\n", id);
        fprintf(stderr, "Expected (File) Data:\n");
        for (size_t i = 0; i < nvmDataLen; i++) {
            fprintf(stderr, "%02X ", fileData[i]);
            if ((i + 1) % 16 == 0)
                fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");

        fprintf(stderr, "Actual (NVM) Data:\n");
        for (size_t i = 0; i < nvmDataLen; i++) {
            fprintf(stderr, "%02X ", nvmData[i]);
            if ((i + 1) % 16 == 0)
                fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
    }
    else {
        printf("Data verification successful for ID %u\n", id);
    }

    free(fileData);
    return result;
}

/* Enumerate the NVM objects and check their data against the known good input
 * file data */
int _checkNvm(whServerContext* server)
{
    int         rc;
    whNvmId     startId   = 0;
    whNvmId     currentId = 0;
    whNvmId     count     = 0;
    whNvmAccess access    = WH_NVM_ACCESS_ANY;
    whNvmFlags  flags     = WH_NVM_FLAGS_ANY;

    do {
        rc = wh_Nvm_List(server->nvm, access, flags, startId, &count,
                         &currentId);
        if (rc != WH_ERROR_OK) {
            fprintf(stderr, "Error listing NVM objects: %d\n", rc);
            return rc;
        }

        printf("NVM List: Count=%u\n", count);

        if (count > 0) {
            whNvmMetadata meta;

            rc = wh_Nvm_GetMetadata(server->nvm, currentId, &meta);
            if (rc != WH_ERROR_OK) {
                fprintf(stderr, "Error getting metadata for object %u: %d\n",
                        currentId, rc);
                return rc;
            }

            printf("Object ID: %u\n", meta.id);
            printf("Access: 0x%04x\n", meta.access);
            printf("Flags: 0x%04x\n", meta.flags);
            printf("Length: %u\n", meta.len);
            printf("Label: %s\n", meta.label);

            uint8_t* data = malloc(meta.len);
            if (data == NULL) {
                fprintf(stderr, "Memory allocation failed\n");
                return WH_ERROR_ABORTED;
            }

            rc = wh_Nvm_Read(server->nvm, currentId, 0, meta.len, data);
            if (rc != WH_ERROR_OK) {
                fprintf(stderr, "Error reading object %u: %d\n", currentId, rc);
                free(data);
                return rc;
            }

            rc = checkNvmDataValid(currentId, data, meta.len);
            if (rc != 0) {
                free(data);
                return WH_ERROR_ABORTED;
            }

            free(data);
        }

        /* Move to the next object */
        startId = currentId;

    } while (count > 0);

    return WH_ERROR_OK;
}

/* Initializes a local server and NVM context with the provided NVM config and
 * enumerates the NVM objects. */
int _initAndCheckNvmFlashCfg(whNvmFlashConfig* nvmFlashCfg)
{
    int               rc;
    whNvmFlashContext nvmFlashCtx[1];
    whNvmCb           nvmCb[1] = {WH_NVM_FLASH_CB};
    whNvmContext      nvmCtx[1];
    whServerContext   serverCtx[1];
    uint8_t*          initData = NULL;

    /* If this is the RamSim configuration, set the initData config field to the
     * contents of the NVM image */
    if (nvmFlashCfg->cb == gFlashRamsimCb) {
        printf("Initializing RamSim NVM Flash\n");

        FILE* file = fopen(FLASH_IMAGE_FILENAME, "rb");
        if (file == NULL) {
            fprintf(stderr, "Error: Unable to open %s for reading\n",
                    FLASH_IMAGE_FILENAME);
            return WH_ERROR_BADARGS;
        }

        fseek(file, 0, SEEK_END);
        long fileSize = ftell(file);
        fseek(file, 0, SEEK_SET);

        initData = (uint8_t*)malloc(fileSize);
        if (initData == NULL) {
            fprintf(stderr, "Error: Memory allocation failed for initData\n");
            fclose(file);
            return WH_ERROR_ABORTED;
        }

        size_t bytesRead = fread(initData, 1, fileSize, file);
        fclose(file);

        if (bytesRead != fileSize) {
            fprintf(stderr, "Error: Failed to read entire file %s\n",
                    FLASH_IMAGE_FILENAME);
            free(initData);
            return WH_ERROR_ABORTED;
        }

        ((whFlashRamsimCfg*)nvmFlashCfg->config)->initData = initData;
    }

    /* Build temporary NVM config for the input NVM Flash config */
    whNvmConfig nvmCfg[1] = {{
        .cb      = nvmCb,
        .context = nvmFlashCtx,
        .config  = nvmFlashCfg,
    }};

    /* Initialize the NVM context */
    rc = wh_Nvm_Init(nvmCtx, nvmCfg);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "Error: Failed to initialize NVM, ret = %d\n", rc);
        return rc;
    }

    /* Build server configuration to use the input NVM context */
    whServerConfig serverCfg[1] = {{
        .comm_config = gCommServerConfig,
        .nvm         = nvmCtx,
    }};

    /* Initialize the server */
    rc = wh_Server_Init(serverCtx, serverCfg);
    if (rc != WH_ERROR_OK) {
        fprintf(stderr, "Failed to initialize wolfHSM server: ret = %d\n", rc);
        return rc;
    }

    /* Check the NVM against expected values */
    if (rc == WH_ERROR_OK) {
        rc = _checkNvm(serverCtx);
        if (rc != WH_ERROR_OK) {
            fprintf(stderr, "NVM check failed: ret = %d\n", rc);
        }

        (void)wh_Server_Cleanup(serverCtx);
    }

    /* Clean up the RAMsim initData if it was dynamically allocated */
    if (initData != NULL) {
        free(initData);
        ((whFlashRamsimCfg*)nvmFlashCfg->config)->initData = NULL;
    }

    return rc;
}


int main(void)
{
    int rc = 0;

    /* Load metadata entries from the intermediate file */
    rc = loadMetadataEntries();
    if (rc != 0) {
        fprintf(stderr, "Failed to load metadata entries\n");
        return rc;
    }

    for (size_t i = 0; i < NVM_FLASH_CONFIGS_TO_TEST_COUNT; i++) {
        printf("Testing NVM Flash config %zu\n", i);
        rc = _initAndCheckNvmFlashCfg(
            (whNvmFlashConfig*)&gNvmFlashConfigsToTest[i]);
        if (rc != WH_ERROR_OK) {
            fprintf(stderr, "NVM check failed for config %zu: ret = %d\n", i,
                    rc);
            break;
        }
    }

    /* Clean up metadata entries at the end */
    freeMetadataEntries();

    return rc;
}
