#include <stdint.h>

/* Configuration and context structures */
typedef struct {
    uint32_t size;
    uint32_t sectorSize;
    uint32_t pageSize;
    uint8_t  erasedByte;
} WhNvmFlashRamSimCfg;

typedef struct {
    uint8_t* memory;
    uint32_t size;
    uint32_t sectorSize;
    uint32_t pageSize;
    int      writeLocked;
    uint8_t  erasedByte;
} WhNvmFlashRamSimCtx;

/* Error codes */
#define WH_NVM_FLASH_RAMSIM_OK 0
#define WH_NVM_FLASH_RAMSIM_ERR_INVALID_PARAM -1
#define WH_NVM_FLASH_RAMSIM_ERR_WRITE_LOCKED -2
#define WH_NVM_FLASH_RAMSIM_ERR_NOT_BLANK -3

/* Enable (1) or disable (0) debug printouts */
#define WH_NVM_FLASH_RAMSIM_DEBUG 0

/* Simulator function prototypes */
int WhNvmFlashRamSim_Init(void* context, const void* config);
int WhNvmFlashRamSim_Cleanup(void* context);
int WhNvmFlashRamSim_Program(void* context, uint32_t offset, uint32_t size,
                             const uint8_t* data);
int WhNvmFlashRamSim_Read(void* context, uint32_t offset, uint32_t size,
                          uint8_t* data);
int WhNvmFlashRamSim_Erase(void* context, uint32_t offset, uint32_t size);
int WhNvmFlashRamSim_Verify(void* context, uint32_t offset, uint32_t size,
                            const uint8_t* data);
int WhNvmFlashRamSim_BlankCheck(void* context, uint32_t offset, uint32_t size);
uint32_t WhNvmFlashRamSim_PartitionSize(void* context);
int WhNvmFlashRamSim_WriteLock(void* context, uint32_t offset, uint32_t size);
int WhNvmFlashRamSim_WriteUnlock(void* context, uint32_t offset, uint32_t size);

/* clang-format off */
#define WH_NVM_FLASH_RAMSIM_CB                           \
    {                                                    \
        .Init          = WhNvmFlashRamSim_Init,          \
        .Cleanup       = WhNvmFlashRamSim_Cleanup,       \
        .PartitionSize = WhNvmFlashRamSim_PartitionSize, \
        .WriteLock     = WhNvmFlashRamSim_WriteLock,     \
        .WriteUnlock   = WhNvmFlashRamSim_WriteUnlock,   \
        .Read          = WhNvmFlashRamSim_Read,          \
        .Program       = WhNvmFlashRamSim_Program,       \
        .Erase         = WhNvmFlashRamSim_Erase,         \
        .Verify        = WhNvmFlashRamSim_Verify,        \
        .BlankCheck    = WhNvmFlashRamSim_BlankCheck,    \
    }
/* clang-format on */
