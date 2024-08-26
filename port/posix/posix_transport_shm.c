#include "port/posix/posix_transport_shm.h"

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
int posixTransportShm_ServerInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg)
{
    int                       rc;
    int                       shmFd;
    size_t                    shmSize;
    size_t                    shmNameLen;
    ShmHeader*                header;
    whTransportMemConfig      tMemCfg;
    posixTransportShmContext* ctx    = (posixTransportShmContext*)c;
    posixTransportShmConfig*  config = (posixTransportShmConfig*)cf;

    if (ctx == NULL || config == NULL || config->shmObjName == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* check shmObjName for max length */
    shmNameLen = strnlen(config->shmObjName, NAME_MAX + 1);
    if (shmNameLen > NAME_MAX) {
        return WH_ERROR_BADARGS;
    }

    ctx->shmObjName = calloc(shmNameLen + 1, sizeof(char));
    strncpy(ctx->shmObjName, config->shmObjName, shmNameLen);

    shmSize = sizeof(ShmHeader) + config->req_size + config->resp_size;

    /* Attempt to open the shared memory object serving as the backing store
     * without attempting to create it. If it already exists, attempt to delete
     * it, and verify that it is gone. */
    shmFd = shm_open(ctx->shmObjName, O_RDWR, 0666);
    if (shmFd > 0) {
        close(shmFd);
        shm_unlink(ctx->shmObjName);
        shmFd = shm_open(ctx->shmObjName, O_RDWR, 0666);
    }

    /* If shared memory object doesn't exist, create it and set the size */
    if (shmFd == -1) {
        if (errno == ENOENT) {
            /* Shared memory object doesn't exist, create it */
            shmFd = shm_open(ctx->shmObjName, O_CREAT | O_RDWR, 0666);
            if (shmFd == -1) {
                perror("server shm_open");
                exit(EXIT_FAILURE);
            }

            /* Set the size of the shared memory object */
            if (ftruncate(shmFd, shmSize) == -1) {
                perror("ftruncate");
                exit(EXIT_FAILURE);
            }
        }
        else {
            /* Other unspecified error, bail */
            perror("server shm_open");
            exit(EXIT_FAILURE);
        }
    }
    else {
        /* Something went wrong with unlink, we are unable to remove the
         * existing shared memory object, bail */
        fprintf(
            stderr,
            "Error: Shared memory object already exists, unable to delete.\n");
        exit(EXIT_FAILURE);
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
    ctx->transportMemCtx = malloc(sizeof(whTransportMemContext));
    if (ctx->transportMemCtx == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Configure the underlying transport context */
    tMemCfg.req_size  = config->req_size;
    tMemCfg.resp_size = config->resp_size;
    tMemCfg.req       = ctx->shmBuf + sizeof(ShmHeader);
    tMemCfg.resp      = ctx->shmBuf + sizeof(ShmHeader) + config->req_size;

    /* Initialize the shared memory transport using our newly mmapped buffer */
    rc = wh_TransportMem_Init(ctx->transportMemCtx, &tMemCfg, connectcb,
                              connectcb_arg);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Close the file descriptor after mmap */
    close(shmFd);
    return 0;
}


/** Callback function declarations */
int posixTransportShm_ClientInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg)
{
    int                       rc;
    int                       shmFd;
    struct stat               shmStat;
    size_t                    shmSize;
    size_t                    shmNameLen;
    ShmHeader*                header;
    whTransportMemConfig      tMemCfg;
    posixTransportShmContext* ctx    = (posixTransportShmContext*)c;
    posixTransportShmConfig*  config = (posixTransportShmConfig*)cf;

    if (ctx == NULL || config == NULL || config->shmObjName == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* check shmObjName for max length */
    shmNameLen = strnlen(config->shmObjName, NAME_MAX + 1);
    if (shmNameLen > NAME_MAX) {
        return WH_ERROR_BADARGS;
    }

    ctx->shmObjName = calloc(shmNameLen + 1, sizeof(char));
    strncpy(ctx->shmObjName, config->shmObjName, shmNameLen);

    shmSize = sizeof(ShmHeader) + config->req_size + config->resp_size;

    /* Attempt to open the shared memory backing store. If it doesn't exist yet,
     * sleep */
    while (1) {
        shmFd = shm_open(ctx->shmObjName, O_RDWR, 0666);
        if (shmFd == -1) {
            if (errno != ENOENT) {
                perror("client shm_open");
                exit(EXIT_FAILURE);
            }
            else {
                sleep(1);
            }
        }
        else {
            break;
        }
    }

    /* Shared memory object already exists, check its size */
    if (fstat(shmFd, &shmStat) == -1) {
        perror("fstat");
        close(shmFd);
        exit(EXIT_FAILURE);
    }

    if (shmStat.st_size != shmSize) {
        fprintf(stderr,
                "Error: Shared memory size does not match expected size.\n");
        close(shmFd);
        exit(EXIT_FAILURE);
    }

    /* Ensure the ref count is 1, meaning the server has successfully
     * initialized */

    /* Map the shared memory object */
    ctx->shmBuf =
        mmap(NULL, shmSize, PROT_READ | PROT_WRITE, MAP_SHARED, shmFd, 0);
    if (ctx->shmBuf == MAP_FAILED) {
        perror("mmap");
        close(shmFd);
        exit(EXIT_FAILURE);
    }
    header = (ShmHeader*)ctx->shmBuf;

    /* Spin and wait until the server bumps the ref count. We can now use the
     * buffer */
    while (atomic_load(&header->refCount) < 1) {
        sleep(1);
    }

    /* allocate a shared memory transport context */
    ctx->transportMemCtx = malloc(sizeof(whTransportMemContext));
    if (ctx->transportMemCtx == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Configure the underlying transport context */
    tMemCfg.req_size  = config->req_size;
    tMemCfg.resp_size = config->resp_size;
    tMemCfg.req       = ctx->shmBuf + sizeof(ShmHeader);
    tMemCfg.resp      = ctx->shmBuf + sizeof(ShmHeader) + config->req_size;

    /* Initialize the shared memory transport using our newly mmapped buffer */
    rc = wh_TransportMem_Init(ctx->transportMemCtx, &tMemCfg, connectcb,
                              connectcb_arg);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Clear the comms buffers */
    wh_Utils_memset_flush((void*)ctx->transportMemCtx->req, 0,
                          ctx->transportMemCtx->req_size);
    wh_Utils_memset_flush((void*)ctx->transportMemCtx->resp, 0,
                          ctx->transportMemCtx->resp_size);

    /* Close the file descriptor after mmap */
    close(shmFd);
    return 0;
}


int posixTransportShm_Cleanup(void* c)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;
    ShmHeader*                header;

    if (ctx == NULL || ctx->transportMemCtx == NULL || ctx->shmBuf == NULL) {
        return WH_ERROR_BADARGS;
    }

    header = (ShmHeader*)ctx->shmBuf;

    /* Decrement the reference count */
    if (atomic_fetch_sub(&header->refCount, 1) == 1) {
        /* If the reference count is now zero, unlink the shared memory */
        if (shm_unlink(ctx->shmObjName) == -1) {
            perror("shm_unlink");
            exit(EXIT_FAILURE);
        }
    }

    /* Unmap the shared memory */
    if (munmap(ctx->shmBuf, sizeof(header) + ctx->transportMemCtx->req_size +
                                ctx->transportMemCtx->resp_size) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }

    /* Free the allocated memory */
    free(ctx->shmObjName);
    free(ctx->transportMemCtx);

    return 0;
}


int posixTransportShm_SendRequest(void* c, uint16_t len, const void* data)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_SendRequest(ctx->transportMemCtx, len, data);
}


int posixTransportShm_RecvRequest(void* c, uint16_t* out_len, void* data)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_RecvRequest(ctx->transportMemCtx, out_len, data);
}


int posixTransportShm_SendResponse(void* c, uint16_t len, const void* data)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_SendResponse(ctx->transportMemCtx, len, data);
}


int posixTransportShm_RecvResponse(void* c, uint16_t* out_len, void* data)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_RecvResponse(ctx->transportMemCtx, out_len, data);
}
