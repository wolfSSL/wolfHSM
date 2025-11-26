/*
 * Copyright (C) 2025 wolfSSL Inc.
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
 * tools/whnvmtool/whnvmtool.h
 *
 * Tool print macros for whnvmtool following wolfHSM debug pattern
 */
#ifndef WHNVMTOOL_H
#define WHNVMTOOL_H

#include "wolfhsm/wh_settings.h"

/* Safe bounded string copy with guaranteed NUL-termination */
#define wh_strncpyz(dst, src, n) do { \
    if ((n) > 0) { \
        size_t i; \
        for (i = 0; i < (n) - 1 && (src)[i] != '\0'; i++) { \
            (dst)[i] = (src)[i]; \
        } \
        (dst)[i] = '\0'; \
    } \
} while (0)

/* Tool print macros following wolfHSM debug pattern */

/* Always-on stdout printing (like WH_TEST_PRINT) */
#define WH_TOOL_PRINT(fmt, ...) \
    WOLFHSM_CFG_PRINTF(fmt, ##__VA_ARGS__)

/* Always-on error printing to stderr (like WH_ERROR_PRINT) */
#if !defined(__CCRH__)
#define WH_TOOL_ERROR(fmt, ...) \
    WOLFHSM_CFG_FPRINTF(stderr, "Error: " fmt, ##__VA_ARGS__)
#else
#define WH_TOOL_ERROR(...) WH_TOOL_ERROR2(__VA_ARGS__, "")
#define WH_TOOL_ERROR2(fmt, ...) \
    WOLFHSM_CFG_FPRINTF(stderr, "Error: " fmt, ##__VA_ARGS__)
#endif

/* Always-on warning printing to stderr */
#if !defined(__CCRH__)
#define WH_TOOL_WARN(fmt, ...) \
    WOLFHSM_CFG_FPRINTF(stderr, "Warning: " fmt, ##__VA_ARGS__)
#else
#define WH_TOOL_WARN(...) WH_TOOL_WARN2(__VA_ARGS__, "")
#define WH_TOOL_WARN2(fmt, ...) \
    WOLFHSM_CFG_FPRINTF(stderr, "Warning: " fmt, ##__VA_ARGS__)
#endif

/* Always-on info printing to stderr (no prefix) */
#if !defined(__CCRH__)
#define WH_TOOL_INFO(fmt, ...) \
    WOLFHSM_CFG_FPRINTF(stderr, fmt, ##__VA_ARGS__)
#else
#define WH_TOOL_INFO(...) WH_TOOL_INFO2(__VA_ARGS__, "")
#define WH_TOOL_INFO2(fmt, ...) \
    WOLFHSM_CFG_FPRINTF(stderr, fmt, ##__VA_ARGS__)
#endif

/* Debug printing (gated like WH_TEST_DEBUG_PRINT) */
#ifdef WOLFHSM_CFG_DEBUG_VERBOSE
#if !defined(__CCRH__)
#define WH_TOOL_DEBUG(fmt, ...) \
    WOLFHSM_CFG_FPRINTF(stderr, "[DEBUG]: " fmt, ##__VA_ARGS__)
#else
#define WH_TOOL_DEBUG(...) WH_TOOL_DEBUG2(__VA_ARGS__, "")
#define WH_TOOL_DEBUG2(fmt, ...) \
    WOLFHSM_CFG_FPRINTF(stderr, "[DEBUG]: " fmt, ##__VA_ARGS__)
#endif
#else
#define WH_TOOL_DEBUG(...) do { } while (0)
#endif

/* File stream printing (for CSV writes and other file output) */
#if !defined(__CCRH__)
#define WH_TOOL_FPRINT(stream, fmt, ...) \
    WOLFHSM_CFG_FPRINTF((stream), (fmt), ##__VA_ARGS__)
#else
#define WH_TOOL_FPRINT(...) WH_TOOL_FPRINT2(__VA_ARGS__, "")
#define WH_TOOL_FPRINT2(stream, fmt, ...) \
    WOLFHSM_CFG_FPRINTF((stream), (fmt), ##__VA_ARGS__)
#endif

#endif /* WHNVMTOOL_H */

