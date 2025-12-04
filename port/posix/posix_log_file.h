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
 * port/posix/posix_log_file.h
 * POSIX file-based logging backend with thread-safe access using mutex
 * protection. Logs are written as flat text files with one entry per line.
 */

#ifndef PORT_POSIX_POSIX_LOG_FILE_H_
#define PORT_POSIX_POSIX_LOG_FILE_H_

#include <pthread.h>

#include "wolfhsm/wh_log.h"

/* In memory context structure for POSIX file-based logging */
typedef struct posixLogFileContext_t {
    pthread_mutex_t mutex;         /* Global file access mutex */
    int             fd;            /* File descriptor (-1 if not initialized) */
    char            filename[256]; /* Fixed-size filename buffer */
    int             initialized;   /* Initialization flag */
} posixLogFileContext;

/* In memory configuration structure for POSIX file-based logging */
typedef struct posixLogFileConfig_t {
    const char* filename; /* Log file path (null terminated) */
} posixLogFileConfig;

/* Callback functions */
int posixLogFile_Init(void* context, const void* config);
int posixLogFile_Cleanup(void* context);
int posixLogFile_AddEntry(void* context, const whLogEntry* entry);
/* Export log entries to FILE* specified by export_arg.
 * @param context posixLogFileContext
 * @param export_arg FILE* to write to, or NULL to write to stdout
 * @return 0 on success, error code on failure */
int posixLogFile_Export(void* context, void* export_arg);
/* Iterate log entries by parsing file and invoking callback for each entry.
 * @param context posixLogFileContext
 * @param iterate_cb User callback invoked for each parsed entry
 * @param iterate_arg User argument passed to callback
 * @return 0 on success, non-zero if callback stops iteration early */
int      posixLogFile_Iterate(void* context, whLogIterateCb iterate_cb,
                              void* iterate_arg);
int      posixLogFile_Clear(void* context);

/* Convenience macro for callback table initialization */
/* clang-format off */
#define POSIX_LOG_FILE_CB                                                     \
    {                                                                         \
        .Init = posixLogFile_Init,                                            \
        .Cleanup = posixLogFile_Cleanup,                                      \
        .AddEntry = posixLogFile_AddEntry,                                    \
        .Export = posixLogFile_Export,                                        \
        .Iterate = posixLogFile_Iterate,                                      \
        .Clear = posixLogFile_Clear,                                          \
    }
/* clang-format on */

#endif /* !PORT_POSIX_POSIX_LOG_FILE_H_ */
