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
 * wolfhsm/wh_log.h
 *
 * Generic logging frontend API with callback backend interface
 */

#ifndef WOLFHSM_WH_LOG_H_
#define WOLFHSM_WH_LOG_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

/** Log levels */
typedef enum {
    WH_LOG_LEVEL_INFO     = 0, /* Informational message */
    WH_LOG_LEVEL_ERROR    = 1, /* Error message */
    WH_LOG_LEVEL_SECEVENT = 2  /* Security event */
} whLogLevel;

/** Log entry structure with fixed-size message buffer */
typedef struct {
    uint64_t    timestamp;             /* Unix timestamp (microseconds) */
    whLogLevel  level;                 /* Log level */
    const char* file;                  /* Source file (__FILE__) */
    const char* function;              /* Function name (__func__) */
    uint32_t    line;                  /* Line number (__LINE__) */
    uint32_t    msg_len;               /* Actual message length (excluding
                                        * null terminator) */
    char msg[WOLFHSM_CFG_LOG_MSG_MAX]; /* Fixed buffer with null
                                        * terminator */
} whLogEntry;

/** User-provided callback for iterating log entries.
 * Return 0 to continue iteration, non-zero to stop early. */
typedef int (*whLogIterateCb)(void* arg, const whLogEntry* entry);

/** Backend callback interface */
typedef struct {
    int (*Init)(void* context, const void* config);
    int (*Cleanup)(void* context);
    int (*AddEntry)(void* context, const whLogEntry* entry);
    int (*Export)(void* context, void* export_arg);
    int (*Iterate)(void* context, whLogIterateCb iterate_cb, void* iterate_arg);
    int (*Clear)(void* context);
} whLogCb;

/** Frontend context */
typedef struct {
    whLogCb* cb;      /* Callback table */
    void*    context; /* Opaque backend context */
} whLogContext;

/** Frontend configuration */
typedef struct {
    whLogCb* cb;      /* Callback table */
    void*    context; /* Pre-allocated backend context */
    void*    config;  /* Backend-specific config */
} whLogConfig;

/** Frontend API */
int wh_Log_Init(whLogContext* ctx, const whLogConfig* config);
int wh_Log_Cleanup(whLogContext* ctx);
int wh_Log_AddEntry(whLogContext* ctx, const whLogEntry* entry);
int wh_Log_Export(whLogContext* ctx, void* export_arg);
int wh_Log_Iterate(whLogContext* ctx, whLogIterateCb iterate_cb,
                   void* iterate_arg);
int wh_Log_Clear(whLogContext* ctx);

/*
 * Internal logging helpers. Both silently truncate to WOLFHSM_CFG_LOG_MSG_MAX -
 * 1 and always null-terminate the stored message.
 */

void wh_Log_InternalSubmit(whLogContext* ctx, whLogLevel level,
                           const char* file, const char* function,
                           uint32_t line, const char* src, size_t src_len);
void wh_Log_InternalFormat(whLogContext* ctx, whLogLevel level,
                           const char* file, const char* function,
                           uint32_t line, const char* fmt, ...);

/* Logging helper macros. These should be used as the primary API to the logging
 * interface */
#ifdef WOLFHSM_CFG_LOGGING

/* String literal logging macro */
#define WH_LOG(ctx, lvl, message)                                         \
    do {                                                                  \
        wh_Log_InternalSubmit((ctx), (lvl), __FILE__, __func__, __LINE__, \
                              (message), sizeof(message) - 1);            \
    } while (0)

/* Formatted logging macro (printf-style variadic arguments) */
#if !defined(__CCRH__)
#define WH_LOG_F(ctx, lvl, fmt, ...)                                      \
    do {                                                                  \
        wh_Log_InternalFormat((ctx), (lvl), __FILE__, __func__, __LINE__, \
                              (fmt), ##__VA_ARGS__);                      \
    } while (0)
#else
/* CCRH workaround for empty __VA_ARGS__ */
#define WH_LOG_F(ctx, lvl, ...) WH_LOG_F2((ctx), (lvl), __VA_ARGS__, "")
#define WH_LOG_F2(ctx, lvl, fmt, ...)                                     \
    do {                                                                  \
        wh_Log_InternalFormat((ctx), (lvl), __FILE__, __func__, __LINE__, \
                              (fmt), ##__VA_ARGS__);                      \
    } while (0)
#endif

/* Assertion logging helpers:
 * - Log only when (cond) is false, then return (retcode)
 * - Variants for literal message, C string, and formatted message
 */
#define WH_LOG_ASSERT(ctx, lvl, cond, message)                                \
    do {                                                                      \
        if (!(cond)) {                                                        \
            wh_Log_InternalSubmit((ctx), (lvl), __FILE__, __func__, __LINE__, \
                                  (message), sizeof(message) - 1);            \
        }                                                                     \
    } while (0)


#define WH_LOG_ASSERT_F(ctx, lvl, cond, fmt, ...)         \
    do {                                                  \
        if (!(cond)) {                                    \
            WH_LOG_F((ctx), (lvl), (fmt), ##__VA_ARGS__); \
        }                                                 \
    } while (0)

/* Log on error helpers:
 * - Log only when (rc) is not equal to WH_ERROR_OK
 * - Variants for literal message, C string, and formatted message
 */
#define WH_LOG_ON_ERROR(ctx, lvl, rc, message)                                \
    do {                                                                      \
        if ((rc) != WH_ERROR_OK) {                                            \
            wh_Log_InternalSubmit((ctx), (lvl), __FILE__, __func__, __LINE__, \
                                  (message), sizeof(message) - 1);            \
        }                                                                     \
    } while (0)

#define WH_LOG_ON_ERROR_F(ctx, lvl, rc, fmt, ...)         \
    do {                                                  \
        if ((rc) != WH_ERROR_OK) {                        \
            WH_LOG_F((ctx), (lvl), (fmt), ##__VA_ARGS__); \
        }                                                 \
    } while (0)


#else /* !WOLFHSM_CFG_LOGGING */

/* Stub macros that compile to nothing when logging is disabled */
#define WH_LOG(ctx, lvl, message) \
    do {                          \
    } while (0)
#define WH_LOG_F(ctx, lvl, fmt, ...) \
    do {                             \
    } while (0)

#define WH_LOG_ASSERT(ctx, lvl, cond, message) \
    do {                                       \
    } while (0)
#define WH_LOG_ASSERT_F(ctx, lvl, cond, fmt, ...) \
    do {                                          \
    } while (0)

#define WH_LOG_ON_ERROR(ctx, lvl, rc, message) \
    do {                                       \
    } while (0)
#define WH_LOG_ON_ERROR_F(ctx, lvl, rc, fmt, ...) \
    do {                                          \
    } while (0)

#endif /* WOLFHSM_CFG_LOGGING */

#endif /* WOLFHSM_WH_LOG_H_ */
