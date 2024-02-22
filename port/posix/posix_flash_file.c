/*
 * port/posix/posix_flash_file.c
 *
 * Interfaces and defines to support Flash on a POSIX-based simulator
 */

#include <stddef.h>     /* For NULL */
#include <fcntl.h>      /* For O_xxxx */
#include <sys/types.h>  /* For off_t, stat */
#include <sys/stat.h>   /* For fstat */
#include <unistd.h>     /* For open, close, pread, pwrite */
#include <errno.h>      /* For errno */
#include <string.h>     /* For memset, memcpy */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"

#include "posix_flash_file.h"

enum {
    PFF_VERIFY_BUFFER_LEN = 64,
    PFF_BLANKCHECK_BUFFER_LEN = 64,
};

/** Local declarations */
#define MAX_OFFSET(_context) (_context->partition_size * 2)

/* Helper for pwrite like memset.  Write the byte in c to filedes for size
 * bytes starting at offset */
static ssize_t pfill(int filedes, int c, size_t size, off_t offset);

/** Local implementations */
static ssize_t pfill(int filedes, int c, size_t size, off_t offset)
{
    int rc = 0;
    uint8_t data = (uint8_t)c;
    size_t count = 0;
    while (count < size) {
        rc = pwrite(filedes, &data, sizeof(data), offset + count);
        if (rc != sizeof(data)) return rc;
        count += sizeof(data);
    }
    return size;
}


int posixFlashFile_Init(   void* c,
                        const void* cf)
{
    posixFlashFileContext* context = c;
    const posixFlashFileConfig* config = cf;
    struct stat st = {0};
    off_t file_size = 0;

    int ret = 0;
    int rc = 0;

    if ((context == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Open the storage backend */
    rc = open(config->filename, O_RDWR|O_CREAT|O_SYNC, S_IRUSR | S_IWUSR);
    if (rc >= 0) {
        /* File is open, setup context */
        memset(context, 0, sizeof(*context));
        context->fd_p1 = rc + 1;
        context->partition_size = config->partition_size;
        context->erased_byte = config->erased_byte;

        rc = fstat(context->fd_p1 - 1, &st);
        if (rc == 0) {
            file_size = st.st_size;

            if (file_size < MAX_OFFSET(context)) {
                /* Write ERASE_BYTE to fill up to the storage size */
                rc = pfill( context->fd_p1 - 1,
                            context->erased_byte,
                            MAX_OFFSET(context) - file_size,
                            file_size);
                if (rc < 0) {
                    /* Error while writing */
                    ret = WH_ERROR_ABORTED;
                }
            } else if (file_size > MAX_OFFSET(context)) {
                rc = ftruncate( context->fd_p1 - 1,
                                MAX_OFFSET(context));
                if (rc < 0) {
                    /* Error while truncating */
                    ret = WH_ERROR_ABORTED;
                }
            }
        }

        if (ret != 0) {
            /* Error at some point. Clean up */
            posixFlashFile_Cleanup(context);
        }
    } else {
        /* Failed to open initially */
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}

int posixFlashFile_Cleanup(void* c)
{
    posixFlashFileContext* context = c;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if(context->fd_p1 > 0) {
        /* Ignore errors here */
        (void)close(context->fd_p1 - 1);
        context->fd_p1 = 0;
    }
    return 0;
}

uint32_t posixFlashFile_PartitionSize(void* c)
{
    posixFlashFileContext* context = c;
    if (context == NULL) {
        return 0;
    }
    return context->partition_size;
}

int posixFlashFile_WriteLock(  void* c,
                            uint32_t offset,
                            uint32_t size)
{
    (void)offset; (void)size;
    posixFlashFileContext* context = c;
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    context->unlocked = 0;
    return 0;
}
int posixFlashFile_WriteUnlock(void* c,
                            uint32_t offset,
                            uint32_t size)
{
    (void)offset; (void)size;
    posixFlashFileContext* context = c;
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    context->unlocked = 1;
    return 0;

}
int posixFlashFile_Read(   void* c,
                        uint32_t offset,
                        uint32_t size,
                        uint8_t* data)
{
    posixFlashFileContext* context = c;
    if (    (context == NULL) ||
            (offset + size > MAX_OFFSET(context))){
        return WH_ERROR_BADARGS;
    }

    if (    (data == NULL) ||
            (size == 0)) {
        /* No need to read */
        return 0;
    }

    ssize_t rc = pread( context->fd_p1 - 1,
                        (void*) data,
                        (size_t) size,
                        (off_t) offset);
    if (rc != size) {
        /* Error while reading */
        return WH_ERROR_ABORTED;
    }
    return 0;
}

int posixFlashFile_Program(void* c,
        uint32_t offset, uint32_t size, const uint8_t* data)
{
    posixFlashFileContext* context = c;
    if (    (context == NULL) ||
            (offset + size > MAX_OFFSET(context))){
        return WH_ERROR_BADARGS;
    }

    if (    (data == NULL) ||
            (size == 0)) {
        /* No need to write */
        return 0;
    }

    if (    !context->unlocked) {
        /* Programming is locked */
        return WH_ERROR_LOCKED;
    }

    ssize_t rc = pwrite(    context->fd_p1 - 1,
                            (void*) data,
                            (size_t) size,
                            (off_t) offset);
    if (rc != size) {
        /* Error while writing */
        return WH_ERROR_ABORTED;
    }
    return 0;
}

int posixFlashFile_Verify( void* c,
                        uint32_t offset,
                        uint32_t size,
                        const uint8_t* data)
{
    posixFlashFileContext* context = c;
    uint8_t buffer[PFF_VERIFY_BUFFER_LEN];
    uint32_t end_offset = offset + size;
    uint32_t data_offset = 0;

    if (    (context == NULL) ||
            (offset + size > MAX_OFFSET(context))){
        return WH_ERROR_BADARGS;
    }

    if (    (data == NULL) ||
            (size == 0)) {
        /* No need to verify */
        return 0;
    }

    while (offset < end_offset) {
        uint32_t this_size = sizeof(buffer);
        int ret = 0;

        if (this_size > end_offset - offset) {
            this_size = end_offset - offset;
        }

        ret = posixFlashFile_Read(context, offset, this_size, buffer);
        if (ret != 0) {
            return ret;
        }
        if (memcmp(data + data_offset, buffer, this_size) != 0) {
            return WH_ERROR_NOTVERIFIED;
        }
        offset += this_size;
        data_offset += this_size;
    }
    return 0;
}

int posixFlashFile_Erase(void* c,
        uint32_t offset, uint32_t size)
{
    posixFlashFileContext* context = c;
    if (    (context == NULL) ||
            (offset + size > MAX_OFFSET(context))){
        return WH_ERROR_BADARGS;
    }

    if (size == 0) {
        /* No need to erase */
        return 0;
    }

    if (!context->unlocked) {
        /* Erasing is locked */
        return WH_ERROR_LOCKED;
    }

    ssize_t rc = pfill( context->fd_p1 - 1,
                        context->erased_byte,
                        (size_t) size,
                        (off_t) offset);
    if (rc != size) {
        /* Error while writing */
        return WH_ERROR_ABORTED;
    }
    return 0;
}

int posixFlashFile_BlankCheck(void* c,
        uint32_t offset, uint32_t size)
{
    int ret = 0;
    posixFlashFileContext* context = c;
    uint8_t buffer[PFF_BLANKCHECK_BUFFER_LEN];
    uint8_t erased[PFF_BLANKCHECK_BUFFER_LEN];
    uint32_t end_offset = offset + size;
    uint32_t this_size = 0;

    if (    (context == NULL) ||
            (offset + size > MAX_OFFSET(context))){
        return WH_ERROR_BADARGS;
    }

    if (size == 0) {
        /* No need to blankcheck */
        return 0;
    }

    memset(erased, context->erased_byte, sizeof(erased));

    while (offset < end_offset) {
        this_size = sizeof(buffer);

        if (this_size > end_offset - offset) {
            this_size = end_offset - offset;
        }

        ret = posixFlashFile_Read(context, offset, this_size, buffer);
        if (ret != 0) {
            /* Error reading. Return error */
            break;
        }
        if (memcmp(erased, buffer, this_size) != 0) {
            /* Didn't match.  Early return */
            ret = WH_ERROR_NOTBLANK;
            break;
        }
        offset += this_size;
    }
    return ret;
}
