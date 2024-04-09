#ifndef WH_SERVER_DMA_H_
#define WH_SERVER_DMA_H_

#include <stdint.h>
#include "wolfhsm/wh_server.h"

struct whServerContext_t;

/* Indicates to the callback the type of operation the callback should handle */
typedef enum {
    WH_DMA_OPER_CLIENT_READ_PRE = 0, /* Descriptive comment: address validation/Map/unmap/prefetch/cache/etc*/
    WH_DMA_OPER_CLIENT_READ_POST = 1,
    WH_DMA_OPER_CLIENT_WRITE_PRE  = 2,
    WH_DMA_OPER_CLIENT_WRITE_POST = 3,
} whDmaOper;

/* Flags embedded in request/response structs provided by client */
typedef struct {
    uint8_t cacheForceInvalidate : 1;
} whDmaFlags;

typedef int (*whDmaClientMem32Cb)(struct whServerContext_t* server,
                                  uint32_t clientAddr, void** serverPtr,
                                  uint32_t len, whDmaOper oper,
                                  whDmaFlags flags);
typedef int (*whDmaClientMem64Cb)(struct whServerContext_t* server,
                                  uint64_t clientAddr, void** serverPtr,
                                  uint64_t len, whDmaOper oper,
                                  whDmaFlags flags);

typedef struct {
    whDmaClientMem32Cb cb32;
    whDmaClientMem64Cb cb64;
} whDmaCb;


#endif /* WH_SERVER_DMA_H_ */