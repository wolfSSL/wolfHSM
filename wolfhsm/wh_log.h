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

/* Log levels */
typedef enum {
    WH_LOG_LEVEL_INFO     = 0, /* Informational message */
    WH_LOG_LEVEL_ERROR    = 1, /* Error message */
    WH_LOG_LEVEL_SECEVENT = 2  /* Security event */
} whLogLevel;

/* Log entry structure with fixed-size message buffer */
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

/* User-provided callback for iterating log entries.
 * Return 0 to continue iteration, non-zero to stop early. */
typedef int (*whLogIterateCb)(void* arg, const whLogEntry* entry);

/* Backend callback interface */
typedef struct {
    int (*Init)(void* context, const void* config);
    int (*Cleanup)(void* context);
    int (*AddEntry)(void* context, const whLogEntry* entry);
    int (*Export)(void* context, void* export_arg);
    int (*Iterate)(void* context, whLogIterateCb iterate_cb, void* iterate_arg);
    int (*Clear)(void* context);
} whLogCb;

/* Frontend context */
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

/* Frontend API */

/** 
 * @brief Initialize the logging context with a backend configuration.
 *
 * This function initializes a logging context by setting up the callback
 * interface and initializing the backend logging system. The context must
 * be properly initialized before any other logging operations can be performed.
 *
 * @param ctx Pointer to the logging context to initialize. Must not be NULL.
 * @param config Pointer to the logging configuration containing the callback
 *               table, backend context, and backend-specific configuration.
 *
 * @return WH_ERROR_OK on success.
 * @return WH_ERROR_BADARGS if ctx or config is NULL, or if config->cb is NULL.
 * @return WH_ERROR_NOTIMPL if the backend does not support initialization.
 * @return Other error codes may be returned by the backend Init callback.
 */
int wh_Log_Init(whLogContext* ctx, const whLogConfig* config);

/** Cleanup and deinitialize the logging context.
 *
 * This function performs cleanup operations on the logging context, including
 * calling the backend cleanup callback. After cleanup, the context should not
 * be used until reinitialized with wh_Log_Init().
 *
 * @param ctx Pointer to the logging context to cleanup. Must not be NULL.
 *
 * @return WH_ERROR_OK on success.
 * @return WH_ERROR_BADARGS if ctx is NULL.
 * @return WH_ERROR_ABORTED if the context has not been initialized.
 * @return WH_ERROR_NOTIMPL if the backend does not support cleanup.
 * @return Other error codes may be returned by the backend Cleanup callback.
 */
int wh_Log_Cleanup(whLogContext* ctx);

/** 
 * @brief Add a complete log entry to the logging system.
 *
 * This function adds a fully-formed log entry to the logging backend. The
 * entry must contain all required fields including timestamp, level, source
 * location, and message. This is a low-level function typically used by
 * higher-level logging functions like wh_Log_AddMsg().
 *
 * @param ctx Pointer to the initialized logging context. Must not be NULL.
 * @param entry Pointer to the log entry structure containing all log
 *              information. Must not be NULL. The entry->msg buffer must be
 *              properly formatted with a null terminator, and entry->msg_len
 *              must reflect the actual message length.
 *
 * @return WH_ERROR_OK on success.
 * @return WH_ERROR_BADARGS if ctx or entry is NULL.
 * @return WH_ERROR_ABORTED if the context has not been initialized.
 * @return WH_ERROR_NOTIMPL if the backend does not support adding entries.
 * @return Other error codes may be returned by the backend AddEntry callback.
 *
 * @note Message truncation will occur if the message length exceeds
 *       WOLFHSM_CFG_LOG_MSG_MAX.
 */
int wh_Log_AddEntry(whLogContext* ctx, const whLogEntry* entry);

/** 
 * @brief Add a log message with source location information.
 *
 * This function creates a log entry from a string message and automatically
 * captures the current timestamp. The message is copied into the log entry
 * buffer, with truncation if necessary. The remainder of the message buffer
 * is zero-padded to prevent information leakage.
 *
 * @param ctx Pointer to the initialized logging context. Must not be NULL.
 * @param level Log level for the message (WH_LOG_LEVEL_INFO, WH_LOG_LEVEL_ERROR,
 *              or WH_LOG_LEVEL_SECEVENT).
 * @param file Source file name (typically __FILE__). May be NULL.
 * @param function Function name (typically __func__). May be NULL.
 * @param line Line number (typically __LINE__).
 * @param msg Pointer to the message string to log. May be NULL, in which case
 *            an empty message is logged.
 * @param msg_len Length of the message string in bytes, excluding the null
 *                terminator. If msg_len is 0, an empty message is logged.
 *
 * @note The message is truncated to WOLFHSM_CFG_LOG_MSG_MAX - 1 bytes if
 *       msg_len exceeds the maximum.
 * @note The WH_LOG() macro provides a more convenient interface that
 *       automatically captures __FILE__, __func__, and __LINE__.
 */
void wh_Log_AddMsg(whLogContext* ctx, whLogLevel level, const char* file,
                   const char* function, uint32_t line, const char* msg,
                   size_t msg_len);

/** Add a formatted log message with source location information.
 *
 * This function creates a log entry from a printf-style format string and
 * variadic arguments. The formatted message is generated using vsnprintf()
 * and then passed to wh_Log_AddMsg(). This allows for dynamic message
 * construction with variable arguments.
 *
 * @param ctx Pointer to the initialized logging context. Must not be NULL.
 * @param level Log level for the message (WH_LOG_LEVEL_INFO, WH_LOG_LEVEL_ERROR,
 *              or WH_LOG_LEVEL_SECEVENT).
 * @param file Source file name (typically __FILE__). May be NULL.
 * @param function Function name (typically __func__). May be NULL.
 * @param line Line number (typically __LINE__).
 * @param fmt printf-style format string. Must not be NULL.
 * @param ... Variadic arguments matching the format specifiers in fmt.
 *
 * @note The formatted message is truncated to WOLFHSM_CFG_LOG_MSG_MAX - 1 bytes
 *       if the formatted output exceeds the maximum.
 * @note The WH_LOG_F() macro provides a more convenient interface that
 *       automatically captures __FILE__, __func__, and __LINE__.
 */
void wh_Log_AddMsgF(whLogContext* ctx, whLogLevel level, const char* file,
                    const char* function, uint32_t line, const char* fmt, ...);

/** Export log entries from the logging backend.
 *
 * This function triggers an export operation in the logging backend, allowing
 * log entries to be exported to an external format or location. The exact
 * behavior and format of the export is backend-specific
 *
 * @param ctx Pointer to the initialized logging context. Must not be NULL.
 * @param export_arg Backend-specific argument for the export operation.
 *                   The interpretation of this parameter depends on the
 *                   backend implementation. May be NULL if the backend
 *                   does not require additional arguments.
 *
 * @return WH_ERROR_OK on success.
 * @return WH_ERROR_BADARGS if ctx is NULL.
 * @return WH_ERROR_ABORTED if the context has not been initialized.
 * @return WH_ERROR_NOTIMPL if the backend does not support export.
 * @return Other error codes may be returned by the backend Export callback.
 *
 * @note The export operation is backend-specific. Consult the backend
 *       documentation for details on the export_arg parameter and export format.
 */
int wh_Log_Export(whLogContext* ctx, void* export_arg);

/** 
 * @brief Iterate over log entries using a callback function.
 *
 * This function iterates through all log entries in the logging backend,
 * calling the provided callback function for each entry. The iteration
 * continues until all entries have been processed or the callback returns
 * a non-zero value to stop early.
 *
 * @param ctx Pointer to the initialized logging context. Must not be NULL.
 * @param iterate_cb Callback function to call for each log entry. Must not be
 *                   NULL. The callback receives iterate_arg and a pointer to
 *                   the current log entry. Returns 0 to continue iteration,
 *                   non-zero to stop early.
 * @param iterate_arg User-provided argument passed to the callback function
 *                    on each invocation. May be NULL.
 *
 * @return WH_ERROR_OK on success (all entries processed or iteration stopped
 *         by callback).
 * @return WH_ERROR_BADARGS if ctx or iterate_cb is NULL.
 * @return WH_ERROR_ABORTED if the context has not been initialized.
 * @return WH_ERROR_NOTIMPL if the backend does not support iteration.
 * @return Other error codes may be returned by the backend Iterate callback.
 *
 * @note The order of iteration is backend-specific and may not be guaranteed
 *       to be chronological or any particular order
 */
int wh_Log_Iterate(whLogContext* ctx, whLogIterateCb iterate_cb,
                   void* iterate_arg);

/** Clear all log entries from the logging backend.
 *
 * This function removes all log entries from the logging backend, effectively
 * resetting the log to an empty state. After clearing, no log entries will
 * be available until new entries are added.
 *
 * @param ctx Pointer to the initialized logging context. Must not be NULL.
 *
 * @return WH_ERROR_OK on success.
 * @return WH_ERROR_BADARGS if ctx is NULL.
 * @return WH_ERROR_ABORTED if the context has not been initialized.
 * @return WH_ERROR_NOTIMPL if the backend does not support clearing.
 * @return Other error codes may be returned by the backend Clear callback.
 *
 * @note The behavior of this function is backend-specific. Some backends may
 *       immediately free storage, while others may mark entries for deletion.
 */
int wh_Log_Clear(whLogContext* ctx);

/* Logging helper macros. These should be used as the primary API to the logging
 * interface */
#ifdef WOLFHSM_CFG_LOGGING

/* String literal logging macro */
#define WH_LOG(ctx, lvl, message)                                    \
    do {                                                             \
        wh_Log_AddMsg((ctx), (lvl), __FILE__, __func__, __LINE__,    \
                      (message), sizeof(message) - 1);               \
    } while (0)

/* Formatted logging macro (printf-style variadic arguments) */
#if !defined(__CCRH__)
#define WH_LOG_F(ctx, lvl, fmt, ...)                                 \
    do {                                                             \
        wh_Log_AddMsgF((ctx), (lvl), __FILE__, __func__, __LINE__,   \
                       (fmt), ##__VA_ARGS__);                        \
    } while (0)
#else
/* CCRH workaround for empty __VA_ARGS__ */
#define WH_LOG_F(ctx, lvl, ...) WH_LOG_F2((ctx), (lvl), __VA_ARGS__, "")
#define WH_LOG_F2(ctx, lvl, fmt, ...)                                \
    do {                                                             \
        wh_Log_AddMsgF((ctx), (lvl), __FILE__, __func__, __LINE__,   \
                       (fmt), ##__VA_ARGS__);                        \
    } while (0)
#endif

/* Assertion logging helpers:
 * - Log only when (cond) is false, then return (retcode)
 * - Variants for literal message, C string, and formatted message
 */
#define WH_LOG_ASSERT(ctx, lvl, cond, message)                            \
    do {                                                                  \
        if (!(cond)) {                                                    \
            wh_Log_AddMsg((ctx), (lvl), __FILE__, __func__, __LINE__,     \
                          (message), sizeof(message) - 1);                \
        }                                                                 \
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
#define WH_LOG_ON_ERROR(ctx, lvl, rc, message)                            \
    do {                                                                  \
        if ((rc) != WH_ERROR_OK) {                                        \
            wh_Log_AddMsg((ctx), (lvl), __FILE__, __func__, __LINE__,     \
                          (message), sizeof(message) - 1);                \
        }                                                                 \
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
