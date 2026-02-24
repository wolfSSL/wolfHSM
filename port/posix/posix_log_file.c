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
 * port/posix/posix_log_file.c
 *
 * POSIX file-based logging backend with thread-safe access
 */

#include <stddef.h>    /* For NULL */
#include <stdio.h>     /* For snprintf, FILE operations */
#include <fcntl.h>     /* For O_xxxx */
#include <sys/types.h> /* For off_t */
#include <sys/stat.h>  /* For fstat */
#include <unistd.h>    /* For open, close, write, ftruncate, lseek */
#include <errno.h>     /* For errno */
#include <string.h>    /* For memset, strncpy, strlen */
#include <time.h>      /* For clock_gettime */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_log.h"

#include "posix_log_file.h"

#ifdef WOLFHSM_CFG_LOGGING

/* Helper function to convert string to log level */
static whLogLevel posixLogFile_StringToLevel(const char* str)
{
    if (strcmp(str, "INFO") == 0) {
        return WH_LOG_LEVEL_INFO;
    }
    else if (strcmp(str, "ERROR") == 0) {
        return WH_LOG_LEVEL_ERROR;
    }
    else if (strcmp(str, "SECEVENT") == 0) {
        return WH_LOG_LEVEL_SECEVENT;
    }
    return WH_LOG_LEVEL_INFO; /* Default */
}

int posixLogFile_Init(void* context, const void* config)
{
    posixLogFileContext*      ctx = context;
    const posixLogFileConfig* cfg = config;
    int                       rc  = 0;

    if ((ctx == NULL) || (cfg == NULL) || (cfg->filename == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize context */
    memset(ctx, 0, sizeof(*ctx));
    ctx->fd = -1;

    /* Initialize mutex */
    rc = pthread_mutex_init(&ctx->mutex, NULL);
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }

    /* Copy filename */
    strncpy(ctx->filename, cfg->filename, sizeof(ctx->filename) - 1);
    ctx->filename[sizeof(ctx->filename) - 1] = '\0';

    /* Open log file for append/create */
    ctx->fd =
        open(ctx->filename, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (ctx->fd < 0) {
        (void)pthread_mutex_destroy(&ctx->mutex);
        return WH_ERROR_ABORTED;
    }

    ctx->initialized = 1;
    return WH_ERROR_OK;
}

int posixLogFile_Cleanup(void* context)
{
    posixLogFileContext* ctx = context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->initialized) {
        if (ctx->fd >= 0) {
            close(ctx->fd);
            ctx->fd = -1;
        }
        (void)pthread_mutex_destroy(&ctx->mutex);
        ctx->initialized = 0;
    }

    return WH_ERROR_OK;
}

int posixLogFile_AddEntry(void* context, const whLogEntry* entry)
{
    posixLogFileContext* ctx = context;
    char                 buffer[1024];
    int                  len;
    ssize_t              bytes_written;

    if ((ctx == NULL) || (entry == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized || ctx->fd < 0) {
        return WH_ERROR_ABORTED;
    }

    /* Lock mutex */
    if (pthread_mutex_lock(&ctx->mutex) != 0) {
        return WH_ERROR_ABORTED;
    }

    /* Format log entry: TIMESTAMP|LEVEL|FILE:LINE|FUNCTION|MESSAGE\n */
    len = snprintf(buffer, sizeof(buffer), "%llu|%s|%s:%u|%s|%.*s\n",
                   (unsigned long long)entry->timestamp,
                   wh_Log_LevelToString(entry->level),
                   entry->file ? entry->file : "", entry->line,
                   entry->function ? entry->function : "", (int)entry->msg_len,
                   entry->msg);

    if (len < 0 || (size_t)len >= sizeof(buffer)) {
        (void)pthread_mutex_unlock(&ctx->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Write to file */
    bytes_written = write(ctx->fd, buffer, len);

    /* Unlock mutex */
    (void)pthread_mutex_unlock(&ctx->mutex);

    if (bytes_written != len) {
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

int posixLogFile_Export(void* context, void* export_arg)
{
    posixLogFileContext* ctx = context;
    FILE*                out_fp  = (FILE*)export_arg;
    FILE*                in_fp   = NULL;
    char                 line[2048];
    int                  ret = 0;
    int                  fd_dup = -1;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized || ctx->fd < 0) {
        return WH_ERROR_ABORTED;
    }

    /* Default to stdout if no FILE* provided */
    if (out_fp == NULL) {
        out_fp = stdout;
    }

    /* Lock mutex */
    if (pthread_mutex_lock(&ctx->mutex) != 0) {
        return WH_ERROR_ABORTED;
    }

    /* Flush any pending writes */
    if (fsync(ctx->fd) != 0) {
        (void)pthread_mutex_unlock(&ctx->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Open file for reading (using fdopen with dup'd fd) */
    fd_dup = dup(ctx->fd);
    if (fd_dup < 0) {
        (void)pthread_mutex_unlock(&ctx->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Seek to beginning */
    lseek(fd_dup, 0, SEEK_SET);

    in_fp = fdopen(fd_dup, "r");
    if (in_fp == NULL) {
        close(fd_dup);
        (void)pthread_mutex_unlock(&ctx->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Read and write each line to output */
    while (fgets(line, sizeof(line), in_fp) != NULL) {
        if (fputs(line, out_fp) == EOF) {
            ret = WH_ERROR_ABORTED;
            break;
        }
    }

    fclose(in_fp); /* Also closes fd_dup */

    /* Unlock mutex */
    (void)pthread_mutex_unlock(&ctx->mutex);

    return ret;
}

int posixLogFile_Iterate(void* context, whLogIterateCb iterate_cb,
                         void* iterate_arg)
{
    posixLogFileContext* ctx = context;
    FILE*                fp      = NULL;
    char                 line[2048];
    int                  ret = 0;
    int                  fd_dup = -1;

    if ((ctx == NULL) || (iterate_cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized || ctx->fd < 0) {
        return WH_ERROR_ABORTED;
    }

    /* Lock mutex */
    if (pthread_mutex_lock(&ctx->mutex) != 0) {
        return WH_ERROR_ABORTED;
    }

    /* Flush any pending writes */
    if (fsync(ctx->fd) != 0) {
        (void)pthread_mutex_unlock(&ctx->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Open file for reading (using fdopen with dup'd fd) */
    fd_dup = dup(ctx->fd);
    if (fd_dup < 0) {
        (void)pthread_mutex_unlock(&ctx->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Seek to beginning */
    lseek(fd_dup, 0, SEEK_SET);

    fp = fdopen(fd_dup, "r");
    if (fp == NULL) {
        close(fd_dup);
        (void)pthread_mutex_unlock(&ctx->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Read and parse each line */
    while (fgets(line, sizeof(line), fp) != NULL) {
        whLogEntry         entry;
        char               level_str[32];
        char               file_buf[256];
        char               func_buf[256];
        char               msg_buf[WOLFHSM_CFG_LOG_MSG_MAX];
        unsigned long long timestamp;
        unsigned int       line_num;
        int                parsed = 0;

        memset(&entry, 0, sizeof(entry));

        /* Parse: TIMESTAMP|LEVEL|FILE:LINE|FUNCTION|MESSAGE\n */
        parsed = sscanf(line, "%llu|%31[^|]|%255[^:]:%u|%255[^|]|%255[^\n]",
                        &timestamp, level_str, file_buf, &line_num,
                        func_buf, msg_buf);

        /* Minimum number of fields to parse is 5, msg is optional */
        if (parsed >= 5) {
            entry.timestamp = timestamp;
            entry.level     = posixLogFile_StringToLevel(level_str);
            entry.file      = file_buf;
            entry.function  = func_buf;
            entry.line      = line_num;
            entry.msg_len   = strlen(msg_buf);
            if (entry.msg_len >= WOLFHSM_CFG_LOG_MSG_MAX) {
                entry.msg_len = WOLFHSM_CFG_LOG_MSG_MAX - 1;
            }
            memcpy(entry.msg, msg_buf, entry.msg_len);
            entry.msg[entry.msg_len] = '\0';

            /* Invoke callback */
            ret = iterate_cb(iterate_arg, &entry);
            if (ret != 0) {
                break;
            }
        }
    }

    fclose(fp); /* Also closes fd_dup */

    /* Unlock mutex */
    (void)pthread_mutex_unlock(&ctx->mutex);

    return ret;
}

int posixLogFile_Clear(void* context)
{
    posixLogFileContext* ctx = context;
    int                  ret     = 0;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized || ctx->fd < 0) {
        return WH_ERROR_ABORTED;
    }

    /* Lock mutex */
    if (pthread_mutex_lock(&ctx->mutex) != 0) {
        return WH_ERROR_ABORTED;
    }

    /* Truncate file to zero length */
    if (ftruncate(ctx->fd, 0) != 0) {
        ret = WH_ERROR_ABORTED;
    }

    /* Seek to beginning */
    if (ret == 0) {
        if (lseek(ctx->fd, 0, SEEK_SET) < 0) {
            ret = WH_ERROR_ABORTED;
        }
    }

    /* Unlock mutex */
    (void)pthread_mutex_unlock(&ctx->mutex);

    return ret;
}

#endif /* WOLFHSM_CFG_LOGGING */
