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
 * wolfhsm/wh_log_printf.h
 *
 * Printf logging backend that simply prints out log entries as they are added,
 * with no backing store.
 */

#ifndef WOLFHSM_WH_LOG_PRINTF_H_
#define WOLFHSM_WH_LOG_PRINTF_H_

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_log.h"

#include <stddef.h>

/* Printf configuration structure */
typedef struct whLogPrintfConfig_t {
    int logIfNotDebug; /* When non-zero, log entries are printed even if
                        * WOLFHSM_CFG_DEBUG is not defined. When zero, entries
                        * are only printed if WOLFHSM_CFG_DEBUG is defined. This
                        * flag applies to all log levels */
} whLogPrintfConfig;

/* Printf context structure */
typedef struct whLogPrintfContext_t {
    int initialized;   /* Initialization flag */
    int logIfNotDebug; /* Copied from config */
} whLogPrintfContext;

/* Callback functions */
int whLogPrintf_Init(void* context, const void* config);
int whLogPrintf_AddEntry(void* context, const whLogEntry* entry);

/* Convenience macro for callback table initialization.
 */
/* clang-format off */
#define WH_LOG_PRINTF_CB                   \
    {                                      \
        .Init     = whLogPrintf_Init,      \
        .Cleanup  = NULL,                  \
        .AddEntry = whLogPrintf_AddEntry,  \
        .Export   = NULL,                  \
        .Iterate  = NULL,                  \
        .Clear    = NULL,                  \
    }
/* clang-format on */

#endif /* !WOLFHSM_WH_LOG_PRINTF_H_ */
