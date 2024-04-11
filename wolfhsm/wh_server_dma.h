#ifndef WH_SERVER_DMA_H_
#define WH_SERVER_DMA_H_

#include <stdint.h>
#include <stddef.h>

#include "wolfhsm/wh_server.h"

#define WH_DMA_ADDR_ALLOWLIST_SIZE (10)

struct whServerContext_t;

/* Indicates to a DMA callback the type of memory operation the callback must
 * act on. Common use cases are remapping client addresses into server address
 * space (map in READ_PRE/WRITE_PRE, unmap in READ_POST/WRITE_POST), or
 * invalidating a cache block before reading from or after writing to client
 * memory */
typedef enum {
    /* Indicates server is about to read from client memory */
    WH_DMA_OPER_CLIENT_READ_PRE = 0,
    /* Indicates server has just read from client memory */
    WH_DMA_OPER_CLIENT_READ_POST = 1,
    /* Indicates server is about to write to client memory */
    WH_DMA_OPER_CLIENT_WRITE_PRE  = 2,
    /* Indicates server has just written from client memory */
    WH_DMA_OPER_CLIENT_WRITE_POST = 3,
} whServerDmaOper;

/* Flags embedded in request/response structs provided by client */
typedef struct {
    uint8_t cacheForceInvalidate : 1;
} whServerDmaFlags;

/* DMA callbacks invoked internally by wolfHSM before and after every client
 * memory operation. There are separate callbacks for processing 32-bit and
 * 64-bit client addresses */
typedef int (*whServerDmaClientMem32Cb)(struct whServerContext_t* server,
                                        uint32_t clientAddr, void** serverPtr,
                                        uint32_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);
typedef int (*whServerDmaClientMem64Cb)(struct whServerContext_t* server,
                                        uint64_t clientAddr, void** serverPtr,
                                        uint64_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);

typedef struct {
    void*  addr;
    size_t size;
} whServerDmaAddr;

typedef whServerDmaAddr whServerDmaAddrList[WH_DMA_ADDR_ALLOWLIST_SIZE];

/* Holds allowable client read/write addresses */
typedef struct {
    whServerDmaAddrList readList;  /* Allowed client read addresses */
    whServerDmaAddrList writeList; /* Allowed client write addresses */
} whServerDmaAddrAllowList;

/* Configuration struct for initializing a server */
typedef struct {
    whServerDmaClientMem32Cb        cb32; /* DMA callback for 32-bit system */
    whServerDmaClientMem64Cb        cb64; /* DMA callback for 64-bit system */
    const whServerDmaAddrAllowList* dmaAddrAllowList; /* allowed addresses */
} whServerDmaConfig;

typedef struct {
    whServerDmaClientMem32Cb        cb32; /* DMA callback for 32-bit system */
    whServerDmaClientMem64Cb        cb64; /* DMA callback for 64-bit system */
    const whServerDmaAddrAllowList* dmaAddrAllowList; /* allowed addresses */
} whServerDmaContext;

/* Registers custom client DMA callbacks to handle platform specific
 * restrictions on accessing the client address space such as caching and
 * address translation */
int wh_Server_DmaRegisterCb32(struct whServerContext_t* server,
                              whServerDmaClientMem32Cb  cb);
int wh_Server_DmaRegisterCb64(struct whServerContext_t* server,
                              whServerDmaClientMem64Cb  cb);
int wh_Server_DmaRegisterAllowList(struct whServerContext_t*       server,
                                   const whServerDmaAddrAllowList* allowlist);

/* Helper functions to invoke user supplied client address DMA callbacks */
int wh_Server_DmaProcessClientAddress32(struct whServerContext_t* server,
                                        uint32_t clientAddr, void** serverPtr,
                                        uint32_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);
int wh_Server_DmaProcessClientAddress64(struct whServerContext_t* server,
                                        uint64_t clientAddr, void** serverPtr,
                                        uint64_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);

int whServerDma_CopyFromClient32(struct whServerContext_t* server,
                                 void* serverPtr, uint32_t clientAddr,
                                 size_t len, whServerDmaFlags flags);
int whServerDma_CopyFromClient64(struct whServerContext_t* server,
                                 void* serverPtr, uint64_t clientAddr,
                                 size_t len, whServerDmaFlags flags);

int whServerDma_CopyToClient32(struct whServerContext_t* server,
                               uint32_t clientAddr, void* serverPtr, size_t len,
                               whServerDmaFlags flags);
int whServerDma_CopyToClient64(struct whServerContext_t* server,
                               uint64_t clientAddr, void* serverPtr, size_t len,
                               whServerDmaFlags flags);


#endif /* WH_SERVER_DMA_H_ */