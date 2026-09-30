/*
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * tools/whnvmtool/test/test_whnvmtool.c
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "wolfhsm/wh_common.h"
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

/* Hex output files and their generation parameters. All image/hex pairs are
 * produced by the Makefile test-gen target and must match its invocations.
 * The main test image uses erased byte 0x00 and a base address 8 bytes below
 * a 64KB boundary, so a record must be split at the boundary and an extended
 * linear address record emitted mid-file. The FF image uses the default
 * erased byte 0xFF and a high base address with an alignment, covering the
 * initial extended linear address record and range expansion to alignment
 * boundaries. The merge image uses an alignment large enough that the
 * expanded directory and data ranges overlap, so they must be merged into
 * one range, which also ends exactly on a 64KB boundary */
#ifndef HEX_IMAGE_FILENAME
#define HEX_IMAGE_FILENAME "../whNvmImage.hex"
#endif
#ifndef FLASH_IMAGE_FF_FILENAME
#define FLASH_IMAGE_FF_FILENAME "../whNvmImageFF.bin"
#endif
#ifndef HEX_IMAGE_FF_FILENAME
#define HEX_IMAGE_FF_FILENAME "../whNvmImageFF.hex"
#endif
#ifndef FLASH_IMAGE_MERGE_FILENAME
#define FLASH_IMAGE_MERGE_FILENAME "../whNvmImageMerge.bin"
#endif
#ifndef HEX_IMAGE_MERGE_FILENAME
#define HEX_IMAGE_MERGE_FILENAME "../whNvmImageMerge.hex"
#endif
#define HEX_BASE_ADDR 0xFFF8UL
#define HEX_FF_BASE_ADDR 0x0800FFF0UL
#define HEX_FF_ALIGN 16
#define HEX_FF_ERASED_BYTE 0xFF
#define HEX_MERGE_BASE_ADDR 0x0800F800UL
#define HEX_MERGE_ALIGN 0x800
#define HEX_MERGE_ERASED_BYTE 0xFF

/* Longest valid hex line: ':' + 8 header chars + 255 data bytes + checksum,
 * plus line ending */
#define HEX_MAX_LINE (1 + 8 + 255 * 2 + 2 + 3)


/* Global NVM Configurations that should be checked */

/* RamSim Flash state and configuration */
uint8_t memory[FLASH_PARTITION_SIZE * 2] = {0};
whFlashRamsimCtx gFlashRamsimContext[1] = {0};
whFlashRamsimCfg gFlashRamsimConfig[1]  = {{
     .size       = FLASH_PARTITION_SIZE * 2,
     .sectorSize = FLASH_PARTITION_SIZE,
     .pageSize   = 8,
     .erasedByte = FLASH_ERASED_BYTE,
     .initData   = NULL, /* Init data will be set dynamically */
     .memory     = memory,
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

/* SHE entries pack the update counter and protection flags into the first 8
 * label bytes as big-endian words. whnvmtool inlines this encoding (it builds
 * without SHE support, so it cannot call wh_She_Meta2Label()); pin the exact
 * bytes for the SHE entries in test.nvminit so the encodings cannot drift. */
typedef struct {
    whNvmId id;
    uint8_t label[WH_NVM_LABEL_LEN];
    int     seen;
} SheLabelEntry;

static SheLabelEntry gSheLabelEntries[] = {
    /* she 0xC 4 0 0x00: counter 0, flags 0 */
    {WH_MAKE_KEYID(WH_KEYTYPE_SHE, 0xC, 4), {0}, 0},
    /* she 0 1 5 0x01: counter 5 in label[0..3], flags 1 in label[4..7] */
    {WH_MAKE_KEYID(WH_KEYTYPE_SHE, 0, 1),
     {0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01},
     0},
};
#define SHE_LABEL_ENTRY_COUNT \
    (sizeof(gSheLabelEntries) / sizeof(gSheLabelEntries[0]))

static void resetSheLabelChecks(void)
{
    for (size_t i = 0; i < SHE_LABEL_ENTRY_COUNT; i++) {
        gSheLabelEntries[i].seen = 0;
    }
}

/* Compare the label of a known SHE object against its expected bytes;
 * non-SHE ids pass through */
static int checkSheLabelValid(const whNvmMetadata* meta)
{
    for (size_t i = 0; i < SHE_LABEL_ENTRY_COUNT; i++) {
        SheLabelEntry* entry = &gSheLabelEntries[i];
        if (entry->id != meta->id) {
            continue;
        }
        if (memcmp(meta->label, entry->label, WH_NVM_LABEL_LEN) != 0) {
            fprintf(stderr, "Error: SHE label mismatch for ID 0x%X\n",
                    meta->id);
            fprintf(stderr, "Expected label:\n");
            for (size_t j = 0; j < WH_NVM_LABEL_LEN; j++) {
                fprintf(stderr, "%02X ", entry->label[j]);
            }
            fprintf(stderr, "\nActual label:\n");
            for (size_t j = 0; j < WH_NVM_LABEL_LEN; j++) {
                fprintf(stderr, "%02X ", meta->label[j]);
            }
            fprintf(stderr, "\n");
            return -1;
        }
        entry->seen = 1;
    }
    return 0;
}

/* Require every expected SHE object to have been enumerated, so the label
 * checks cannot silently become vacuous if the fixture ids change */
static int checkAllSheLabelsSeen(void)
{
    for (size_t i = 0; i < SHE_LABEL_ENTRY_COUNT; i++) {
        if (!gSheLabelEntries[i].seen) {
            fprintf(stderr, "Error: SHE object 0x%X not found in NVM\n",
                    gSheLabelEntries[i].id);
            return -1;
        }
    }
    return 0;
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
        WOLFHSM_CFG_PRINTF("Data verification successful for ID %u\n", id);
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

    resetSheLabelChecks();

    do {
        rc = wh_Nvm_List(server->nvm, access, flags, startId, &count,
                         &currentId);
        if (rc != WH_ERROR_OK) {
            fprintf(stderr, "Error listing NVM objects: %d\n", rc);
            return rc;
        }

        WOLFHSM_CFG_PRINTF("NVM List: Count=%u\n", count);

        if (count > 0) {
            whNvmMetadata meta;

            rc = wh_Nvm_GetMetadata(server->nvm, currentId, &meta);
            if (rc != WH_ERROR_OK) {
                fprintf(stderr, "Error getting metadata for object %u: %d\n",
                        currentId, rc);
                return rc;
            }

            WOLFHSM_CFG_PRINTF("Object ID: %u\n", meta.id);
            WOLFHSM_CFG_PRINTF("Access: 0x%04x\n", meta.access);
            WOLFHSM_CFG_PRINTF("Flags: 0x%04x\n", meta.flags);
            WOLFHSM_CFG_PRINTF("Length: %u\n", meta.len);
            WOLFHSM_CFG_PRINTF("Label: %s\n", meta.label);

            if (checkSheLabelValid(&meta) != 0) {
                return WH_ERROR_ABORTED;
            }

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

    if (checkAllSheLabelsSeen() != 0) {
        return WH_ERROR_ABORTED;
    }

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
#if WH_BIG_ENDIAN
    const uint8_t expectedEpoch[8] = {0x12, 0x34, 0x56, 0x78,
                                      0, 0, 0, 0};
    const uint8_t swappedMagic[4] = {0x78, 0x56, 0x34, 0x12};
    const size_t magicOffset = 0;
#else
    const uint8_t expectedEpoch[8] = {0, 0, 0, 0,
                                      0x78, 0x56, 0x34, 0x12};
    const uint8_t swappedMagic[4] = {0x12, 0x34, 0x56, 0x78};
    const size_t magicOffset = 4;
#endif

    /* If this is the RamSim configuration, set the initData config field to the
     * contents of the NVM image */
    if (nvmFlashCfg->cb == gFlashRamsimCb) {
        WOLFHSM_CFG_PRINTF("Initializing RamSim NVM Flash\n");

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

        if ((bytesRead < 4 * WHFU_BYTES_PER_UNIT) ||
            (memcmp(initData, expectedEpoch, sizeof(expectedEpoch)) != 0)) {
            fprintf(stderr, "Error: NVM image state byte order mismatch\n");
            free(initData);
            return WH_ERROR_ABORTED;
        }

        /* A marker byte swap must not affect partition or object loading. */
        memcpy(initData + magicOffset, swappedMagic, sizeof(swappedMagic));
        memcpy(initData + 3 * WHFU_BYTES_PER_UNIT + magicOffset,
               swappedMagic, sizeof(swappedMagic));
        WOLFHSM_CFG_PRINTF("Checking byte-swapped partition and object "
                           "epoch magic\n");

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

static int hexNibble(char ch)
{
    if ((ch >= '0') && (ch <= '9')) {
        return ch - '0';
    }
    if ((ch >= 'A') && (ch <= 'F')) {
        return ch - 'A' + 10;
    }
    if ((ch >= 'a') && (ch <= 'f')) {
        return ch - 'a' + 10;
    }
    return -1;
}

static int parseHexPair(const char* s, uint8_t* out)
{
    int hi = hexNibble(s[0]);
    int lo = hexNibble(s[1]);
    if ((hi < 0) || (lo < 0)) {
        return -1;
    }
    *out = (uint8_t)((hi << 4) | lo);
    return 0;
}

/* Read a whole file into a malloc'd buffer, requiring an exact size */
static uint8_t* loadFile(const char* path, long expectedSize)
{
    uint8_t* data = NULL;
    long     size = 0;
    FILE*    file = fopen(path, "rb");

    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open %s\n", path);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (size != expectedSize) {
        fprintf(stderr, "Error: %s is %ld bytes, expected %ld\n", path, size,
                expectedSize);
        fclose(file);
        return NULL;
    }
    data = malloc(size);
    if ((data == NULL) || (fread(data, 1, size, file) != (size_t)size)) {
        fprintf(stderr, "Error: Failed to read %s\n", path);
        free(data);
        data = NULL;
    }
    fclose(file);
    return data;
}

/* Verify an intel hex file against the binary image it was generated from.
 * The hex records overlaid on an erased-filled canvas must reproduce the
 * binary image exactly, proving the hex contains every programmed byte and
 * nothing that differs from the erased state. Additional checks require that
 * the hex does not cover the never-programmed regions: the inactive
 * partition must be absent and total coverage must stay far below the
 * partition size, since a fresh image only programs the partition state, the
 * used directory entries, and the object data. If align > 1, every covered
 * run must start and end on an align-byte boundary */
static int checkHexImage(const char* hexPath, const char* binPath,
                         uint8_t erasedByte, uint32_t baseAddr, uint32_t align)
{
    const uint32_t imageSize = FLASH_PARTITION_SIZE * 2;
    uint8_t*       binData   = NULL;
    uint8_t*       canvas    = NULL;
    uint8_t*       covered   = NULL;
    FILE*          hexFile   = NULL;
    char           line[HEX_MAX_LINE];
    uint32_t       upperAddr     = 0;
    uint32_t       coveredCount  = 0;
    uint32_t       coveredErased = 0;
    uint32_t       i;
    int            seenEof = 0;
    int            lineNum = 0;
    int            rc      = -1;

    binData = loadFile(binPath, (long)imageSize);
    if (binData == NULL) {
        goto cleanup; /* loadFile reports the error */
    }
    canvas  = malloc(imageSize);
    covered = calloc(imageSize, 1);
    if ((canvas == NULL) || (covered == NULL)) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }
    hexFile = fopen(hexPath, "r");
    if (hexFile == NULL) {
        fprintf(stderr, "Error: Unable to open %s\n", hexPath);
        goto cleanup;
    }
    memset(canvas, erasedByte, imageSize);

    while (fgets(line, sizeof(line), hexFile) != NULL) {
        size_t   lineLen;
        uint8_t  recLen  = 0;
        uint8_t  addrHi  = 0;
        uint8_t  addrLo  = 0;
        uint8_t  recType = 0;
        uint8_t  sum     = 0;
        uint8_t  byte    = 0;
        uint8_t  data[255];
        uint32_t recAddr;

        lineNum++;
        lineLen = strlen(line);
        while ((lineLen > 0) &&
               ((line[lineLen - 1] == '\n') || (line[lineLen - 1] == '\r'))) {
            line[--lineLen] = '\0';
        }

        if (seenEof) {
            fprintf(stderr, "%s:%d: record after EOF record\n", hexPath,
                    lineNum);
            goto cleanup;
        }
        if ((lineLen < 11) || (line[0] != ':') ||
            (parseHexPair(&line[1], &recLen) != 0) ||
            (parseHexPair(&line[3], &addrHi) != 0) ||
            (parseHexPair(&line[5], &addrLo) != 0) ||
            (parseHexPair(&line[7], &recType) != 0) ||
            (lineLen != (size_t)(11 + 2 * recLen))) {
            fprintf(stderr, "%s:%d: malformed record\n", hexPath, lineNum);
            goto cleanup;
        }

        /* Checksum: all record bytes including the checksum sum to 0 */
        sum = (uint8_t)(recLen + addrHi + addrLo + recType);
        for (i = 0; i < recLen; i++) {
            if (parseHexPair(&line[9 + 2 * i], &data[i]) != 0) {
                fprintf(stderr, "%s:%d: malformed record\n", hexPath, lineNum);
                goto cleanup;
            }
            sum = (uint8_t)(sum + data[i]);
        }
        if ((parseHexPair(&line[9 + 2 * recLen], &byte) != 0) ||
            ((uint8_t)(sum + byte) != 0)) {
            fprintf(stderr, "%s:%d: bad checksum\n", hexPath, lineNum);
            goto cleanup;
        }

        recAddr = (upperAddr << 16) | ((uint32_t)addrHi << 8) | addrLo;
        switch (recType) {
            case 0: /* data */
                /* Records must not cross a 64KB boundary. The end offset
                 * is computed in 64 bits so a record at the top of the
                 * address space cannot wrap past the image size check */
                if ((((recAddr & 0xFFFF) + recLen) > 0x10000) ||
                    (recAddr < baseAddr) ||
                    (((uint64_t)(recAddr - baseAddr) + recLen) > imageSize)) {
                    fprintf(stderr, "%s:%d: record out of range\n", hexPath,
                            lineNum);
                    goto cleanup;
                }
                for (i = 0; i < recLen; i++) {
                    uint32_t off = recAddr - baseAddr + i;
                    if (covered[off]) {
                        fprintf(stderr, "%s:%d: overlapping records\n", hexPath,
                                lineNum);
                        goto cleanup;
                    }
                    canvas[off]  = data[i];
                    covered[off] = 1;
                    coveredCount++;
                    if (data[i] == erasedByte) {
                        coveredErased++;
                    }
                }
                break;
            case 1: /* EOF */
                if ((recLen != 0) || (addrHi != 0) || (addrLo != 0)) {
                    fprintf(stderr, "%s:%d: malformed EOF record\n", hexPath,
                            lineNum);
                    goto cleanup;
                }
                seenEof = 1;
                break;
            case 4: /* extended linear address */
                if ((recLen != 2) || ((recAddr & 0xFFFF) != 0)) {
                    fprintf(stderr, "%s:%d: malformed type 04 record\n",
                            hexPath, lineNum);
                    goto cleanup;
                }
                upperAddr = ((uint32_t)data[0] << 8) | data[1];
                break;
            default:
                fprintf(stderr, "%s:%d: unexpected record type %u\n", hexPath,
                        lineNum, recType);
                goto cleanup;
        }
    }
    if (!seenEof) {
        fprintf(stderr, "%s: missing EOF record\n", hexPath);
        goto cleanup;
    }

    /* Overlaying the hex on an erased canvas must reproduce the image */
    for (i = 0; i < imageSize; i++) {
        if (canvas[i] != binData[i]) {
            fprintf(stderr,
                    "%s: mismatch with %s at offset 0x%X: hex canvas 0x%02X, "
                    "image 0x%02X\n",
                    hexPath, binPath, i, canvas[i], binData[i]);
            goto cleanup;
        }
    }

    /* A fresh image never programs the inactive partition */
    for (i = FLASH_PARTITION_SIZE; i < imageSize; i++) {
        if (covered[i]) {
            fprintf(stderr, "%s: record covers inactive partition\n", hexPath);
            goto cleanup;
        }
    }

    /* The small test image must cover far less than the partition; anything
     * close means erased filler is being emitted */
    if ((coveredCount == 0) || (coveredCount >= (FLASH_PARTITION_SIZE / 4))) {
        fprintf(stderr, "%s: implausible coverage %u bytes\n", hexPath,
                coveredCount);
        goto cleanup;
    }

    /* Programmed bytes whose value equals the erased byte must still be
     * emitted. None at all means the hex was derived from the image contents
     * instead of from tracking which bytes were programmed */
    if (coveredErased == 0) {
        fprintf(stderr, "%s: no covered bytes equal the erased byte\n",
                hexPath);
        goto cleanup;
    }

    /* Covered runs must honor the requested alignment */
    if (align > 1) {
        i = 0;
        while (i < imageSize) {
            uint32_t runStart;
            while ((i < imageSize) && !covered[i]) {
                i++;
            }
            if (i == imageSize) {
                break;
            }
            runStart = i;
            while ((i < imageSize) && covered[i]) {
                i++;
            }
            if (((runStart % align) != 0) ||
                (((i % align) != 0) && (i != imageSize))) {
                fprintf(stderr, "%s: run [0x%X, 0x%X) not %u-byte aligned\n",
                        hexPath, runStart, i, align);
                goto cleanup;
            }
        }
    }

    WOLFHSM_CFG_PRINTF("Hex image check successful for %s (%u bytes)\n",
                       hexPath, coveredCount);
    rc = 0;

cleanup:
    if (hexFile != NULL) {
        fclose(hexFile);
    }
    free(binData);
    free(canvas);
    free(covered);
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
        WOLFHSM_CFG_PRINTF("Testing NVM Flash config %zu\n", i);
        rc = _initAndCheckNvmFlashCfg(
            (whNvmFlashConfig*)&gNvmFlashConfigsToTest[i]);
        if (rc != WH_ERROR_OK) {
            fprintf(stderr, "NVM check failed for config %zu: ret = %d\n", i,
                    rc);
            break;
        }
    }

    /* Verify the hex outputs contain exactly the programmed bytes of their
     * binary images */
    if (rc == WH_ERROR_OK) {
        rc = checkHexImage(HEX_IMAGE_FILENAME, FLASH_IMAGE_FILENAME,
                           FLASH_ERASED_BYTE, HEX_BASE_ADDR, 1);
        if (rc == 0) {
            rc = checkHexImage(HEX_IMAGE_FF_FILENAME, FLASH_IMAGE_FF_FILENAME,
                               HEX_FF_ERASED_BYTE, HEX_FF_BASE_ADDR,
                               HEX_FF_ALIGN);
        }
        if (rc == 0) {
            rc = checkHexImage(HEX_IMAGE_MERGE_FILENAME,
                               FLASH_IMAGE_MERGE_FILENAME,
                               HEX_MERGE_ERASED_BYTE, HEX_MERGE_BASE_ADDR,
                               HEX_MERGE_ALIGN);
        }
        if (rc != 0) {
            fprintf(stderr, "Hex image check failed\n");
        }
    }

    /* Clean up metadata entries at the end */
    freeMetadataEntries();

    return rc;
}
