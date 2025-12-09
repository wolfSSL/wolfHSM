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

/* Helper function to convert log level to string */
static const char* posixLogFile_LevelToString(whLogLevel level)
{
    switch (level) {
        case WH_LOG_LEVEL_INFO:
            return "INFO";
        case WH_LOG_LEVEL_ERROR:
            return "ERROR";
        case WH_LOG_LEVEL_SECEVENT:
            return "SECEVENT";
        default:
            return "UNKNOWN";
    }
}

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

int posixLogFile_Init(void* c, const void* cf)
{
    posixLogFileContext*      context = c;
    const posixLogFileConfig* config  = cf;
    int                       rc      = 0;

    if ((context == NULL) || (config == NULL) || (config->filename == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize context */
    memset(context, 0, sizeof(*context));
    context->fd = -1;

    /* Initialize mutex */
    rc = pthread_mutex_init(&context->mutex, NULL);
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }

    /* Copy filename */
    strncpy(context->filename, config->filename, sizeof(context->filename) - 1);
    context->filename[sizeof(context->filename) - 1] = '\0';

    /* Open log file for append/create */
    context->fd =
        open(context->filename, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (context->fd < 0) {
        pthread_mutex_destroy(&context->mutex);
        return WH_ERROR_ABORTED;
    }

    context->initialized = 1;
    return WH_ERROR_OK;
}

int posixLogFile_Cleanup(void* c)
{
    posixLogFileContext* context = c;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (context->initialized) {
        if (context->fd >= 0) {
            close(context->fd);
            context->fd = -1;
        }
        pthread_mutex_destroy(&context->mutex);
        context->initialized = 0;
    }

    return WH_ERROR_OK;
}

int posixLogFile_AddEntry(void* c, const whLogEntry* entry)
{
    posixLogFileContext* context = c;
    char                 buffer[1024];
    int                  len;
    ssize_t              bytes_written;

    if ((context == NULL) || (entry == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!context->initialized || context->fd < 0) {
        return WH_ERROR_ABORTED;
    }

    /* Lock mutex */
    pthread_mutex_lock(&context->mutex);

    /* Format log entry: TIMESTAMP|LEVEL|FILE:LINE|FUNCTION|MESSAGE\n */
    len = snprintf(buffer, sizeof(buffer), "%llu|%s|%s:%u|%s|%.*s\n",
                   (unsigned long long)entry->timestamp,
                   posixLogFile_LevelToString(entry->level),
                   entry->file ? entry->file : "", entry->line,
                   entry->function ? entry->function : "", (int)entry->msg_len,
                   entry->msg);

    if (len < 0 || (size_t)len >= sizeof(buffer)) {
        pthread_mutex_unlock(&context->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Write to file */
    bytes_written = write(context->fd, buffer, len);

    /* Unlock mutex */
    pthread_mutex_unlock(&context->mutex);

    if (bytes_written != len) {
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

int posixLogFile_Export(void* c, void* export_arg)
{
    posixLogFileContext* context = c;
    FILE*                out_fp  = (FILE*)export_arg;
    FILE*                in_fp   = NULL;
    char                 line[2048];
    int                  ret = 0;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (!context->initialized || context->fd < 0) {
        return WH_ERROR_ABORTED;
    }

    /* Default to stdout if no FILE* provided */
    if (out_fp == NULL) {
        out_fp = stdout;
    }

    /* Lock mutex */
    pthread_mutex_lock(&context->mutex);

    /* Flush any pending writes */
    if (fsync(context->fd) != 0) {
        pthread_mutex_unlock(&context->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Open file for reading (using fdopen with dup'd fd) */
    int fd_dup = dup(context->fd);
    if (fd_dup < 0) {
        pthread_mutex_unlock(&context->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Seek to beginning */
    lseek(fd_dup, 0, SEEK_SET);

    in_fp = fdopen(fd_dup, "r");
    if (in_fp == NULL) {
        close(fd_dup);
        pthread_mutex_unlock(&context->mutex);
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
    pthread_mutex_unlock(&context->mutex);

    return ret;
}

int posixLogFile_Iterate(void* c, whLogIterateCb iterate_cb, void* iterate_arg)
{
    posixLogFileContext* context = c;
    FILE*                fp      = NULL;
    char                 line[2048];
    int                  ret = 0;

    if ((context == NULL) || (iterate_cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!context->initialized || context->fd < 0) {
        return WH_ERROR_ABORTED;
    }

    /* Lock mutex */
    pthread_mutex_lock(&context->mutex);

    /* Flush any pending writes */
    if (fsync(context->fd) != 0) {
        pthread_mutex_unlock(&context->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Open file for reading (using fdopen with dup'd fd) */
    int fd_dup = dup(context->fd);
    if (fd_dup < 0) {
        pthread_mutex_unlock(&context->mutex);
        return WH_ERROR_ABORTED;
    }

    /* Seek to beginning */
    lseek(fd_dup, 0, SEEK_SET);

    fp = fdopen(fd_dup, "r");
    if (fp == NULL) {
        close(fd_dup);
        pthread_mutex_unlock(&context->mutex);
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

        memset(&entry, 0, sizeof(entry));

        /* Parse: TIMESTAMP|LEVEL|FILE:LINE|FUNCTION|MESSAGE\n */
        int parsed = sscanf(line, "%llu|%31[^|]|%255[^:]:%u|%255[^|]|%255[^\n]",
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
    pthread_mutex_unlock(&context->mutex);

    return ret;
}

int posixLogFile_Clear(void* c)
{
    posixLogFileContext* context = c;
    int                  ret     = 0;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (!context->initialized || context->fd < 0) {
        return WH_ERROR_ABORTED;
    }

    /* Lock mutex */
    pthread_mutex_lock(&context->mutex);

    /* Truncate file to zero length */
    if (ftruncate(context->fd, 0) != 0) {
        ret = WH_ERROR_ABORTED;
    }

    /* Seek to beginning */
    if (ret == 0) {
        if (lseek(context->fd, 0, SEEK_SET) < 0) {
            ret = WH_ERROR_ABORTED;
        }
    }

    /* Unlock mutex */
    pthread_mutex_unlock(&context->mutex);

    return ret;
}

#endif /* WOLFHSM_CFG_LOGGING */
