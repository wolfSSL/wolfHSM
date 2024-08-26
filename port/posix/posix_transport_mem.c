#include "port/posix/posix_transport_mem.h"

#include <fcntl.h>     /* For O_* constants */
#include <sys/mman.h>  /* For shm_open, mmap */
#include <sys/stat.h>  /* For mode constants */
#include <unistd.h>    /* For ftruncate */
#include <errno.h>     /* For errno */
#include <stdio.h>     /* For perror */
#include <stdlib.h>    /* For exit */
#include <stdatomic.h> /* For atomic_int */
#include <string.h>    /* For strncpy, strlen */
#include <limits.h>    /* For NAME_MAX */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

typedef struct {
    atomic_int refCount;
} ShmHeader;

/** Callback function declarations */
int posixTransportMem_Init(void* c, const void* cf,
                           whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    int                       rc;
    int                       shmFd;
    struct stat               shmStat;
    size_t                    shmSize;
    size_t                    shmNameLen;
    ShmHeader*                header;
    whTransportMemConfig      tMemCfg;
    posixTransportMemContext* ctx    = (posixTransportMemContext*)c;
    posixTransportMemConfig*  config = (posixTransportMemConfig*)cf;

    if (ctx == NULL || config == NULL || config->shmFileName == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* check shmFileName for max length */
    shmNameLen = strnlen(config->shmFileName, NAME_MAX + 1);
    if (shmNameLen > NAME_MAX) {
        return WH_ERROR_BADARGS;
    }

    ctx->shmFileName = calloc(shmNameLen + 1, sizeof(char));
    strncpy(ctx->shmFileName, config->shmFileName, shmNameLen);

    shmSize = sizeof(ShmHeader) + config->req_size + config->resp_size;

    /* Attempt to open the shared memory object serving as the backing store */
    shmFd = shm_open(ctx->shmFileName, O_RDWR, 0666);
    if (shmFd == -1) {
        if (errno == ENOENT) {
            /* Shared memory object doesn't exist, create it */
            shmFd = shm_open(ctx->shmFileName, O_CREAT | O_RDWR, 0666);
            if (shmFd == -1) {
                perror("shm_open");
                exit(EXIT_FAILURE);
            }

            /* Set the size of the shared memory object */
            if (ftruncate(shmFd, shmSize) == -1) {
                perror("ftruncate");
                exit(EXIT_FAILURE);
            }
        }
        else {
            perror("shm_open");
            exit(EXIT_FAILURE);
        }
    }
    else {
        /* Shared memory object already exists, check its size */
        if (fstat(shmFd, &shmStat) == -1) {
            perror("fstat");
            close(shmFd);
            exit(EXIT_FAILURE);
        }

        if (shmStat.st_size != shmSize) {
            fprintf(
                stderr,
                "Error: Shared memory size does not match expected size.\n");
            close(shmFd);
            exit(EXIT_FAILURE);
        }
    }

    /* Map the shared memory object */
    ctx->shmBuf =
        mmap(NULL, shmSize, PROT_READ | PROT_WRITE, MAP_SHARED, shmFd, 0);
    if (ctx->shmBuf == MAP_FAILED) {
        perror("mmap");
        close(shmFd);
        exit(EXIT_FAILURE);
    }
    header = (ShmHeader*)ctx->shmBuf;

    /* Initialize or increment the reference count */
    atomic_fetch_add(&header->refCount, 1);

    /* allocate a shared memory transport context */
    ctx->transport_ctx = malloc(sizeof(whTransportMemContext));
    if (ctx->transport_ctx == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Configure the underlying transport context */
    tMemCfg.req_size  = config->req_size;
    tMemCfg.resp_size = config->resp_size;
    tMemCfg.req       = ctx->shmBuf + sizeof(ShmHeader);
    tMemCfg.resp      = ctx->shmBuf + sizeof(ShmHeader) + config->req_size;

    /* Initialize the shared memory transport using our newly mmapped buffer */
    rc = wh_TransportMem_Init(ctx->transport_ctx, &tMemCfg, connectcb,
                              connectcb_arg);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Close the file descriptor after mmap */
    close(shmFd);
    return 0;
}


int posixTransportMem_InitClear(void* c, const void* cf,
                                whCommSetConnectedCb connectcb,
                                void*                connectcb_arg)
{
    posixTransportMemContext* ctx = (posixTransportMemContext*)c;

    int rc = posixTransportMem_Init(ctx, cf, connectcb, connectcb_arg);
    if (rc == 0) {
        /* Zero the buffers */
        wh_Utils_memset_flush((void*)ctx->transport_ctx->req, 0,
                              ctx->transport_ctx->req_size);
        wh_Utils_memset_flush((void*)ctx->transport_ctx->resp, 0,
                              ctx->transport_ctx->resp_size);
    }
    return rc;
}


int posixTransportMem_Cleanup(void* c)
{
    posixTransportMemContext* ctx = (posixTransportMemContext*)c;
    ShmHeader*                header;

    if (ctx == NULL || ctx->transport_ctx == NULL || ctx->shmBuf == NULL) {
        return WH_ERROR_BADARGS;
    }

    header = (ShmHeader*)ctx->shmBuf;

    /* Decrement the reference count */
    if (atomic_fetch_sub(&header->refCount, 1) == 1) {
        /* If the reference count is now zero, unlink the shared memory */
        if (shm_unlink(ctx->shmFileName) == -1) {
            perror("shm_unlink");
            exit(EXIT_FAILURE);
        }
    }

    /* Unmap the shared memory */
    if (munmap(ctx->shmBuf, sizeof(header) + ctx->transport_ctx->req_size +
                                ctx->transport_ctx->resp_size) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }

    /* Free the allocated memory */
    free(ctx->shmFileName);
    free(ctx->transport_ctx);

    return 0;
}


int posixTransportMem_SendRequest(void* c, uint16_t len, const void* data)
{
    posixTransportMemContext* ctx = (posixTransportMemContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_SendRequest(ctx->transport_ctx, len, data);
}


int posixTransportMem_RecvRequest(void* c, uint16_t* out_len, void* data)
{
    posixTransportMemContext* ctx = (posixTransportMemContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_RecvRequest(ctx->transport_ctx, out_len, data);
}


int posixTransportMem_SendResponse(void* c, uint16_t len, const void* data)
{
    posixTransportMemContext* ctx = (posixTransportMemContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_SendResponse(ctx->transport_ctx, len, data);
}


int posixTransportMem_RecvResponse(void* c, uint16_t* out_len, void* data)
{
    posixTransportMemContext* ctx = (posixTransportMemContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_RecvResponse(ctx->transport_ctx, out_len, data);
}