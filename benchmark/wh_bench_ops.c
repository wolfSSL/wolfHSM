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
#include <stdint.h>
#include <string.h> /* For memset, memcpy */

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <sys/time.h> /* For gettimeofday and struct timeval */
#endif

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wh_bench_ops.h"
#include "wh_bench_utils.h"

#if defined(WOLFHSM_CFG_BENCH_ENABLE)

static uint64_t _benchGetTimeUs(void);
#if !defined(WOLFHSM_CFG_BENCH_CUSTOM_TIME_FUNC)
static uint64_t _benchGetTimeUsDefault(void);
#endif

#if defined(WOLFHSM_CFG_BENCH_CUSTOM_TIME_FUNC)
/* Use the user-provided time function */
#define WH_BENCH_USE_TIME_FUNC WOLFHSM_CFG_BENCH_CUSTOM_TIME_FUNC
#else
/* Default is to use the internal time function */
#define WH_BENCH_USE_TIME_FUNC _benchGetTimeUsDefault
#endif

#if !defined(WOLFHSM_CFG_BENCH_CUSTOM_TIME_FUNC)
/* Default implementation for getting current time in microseconds */
static uint64_t _benchGetTimeUsDefault(void)
{
    uint64_t timeUs = 0;

#if defined(WOLFHSM_CFG_TEST_POSIX)
    struct timeval tv;
    gettimeofday(&tv, NULL);
    timeUs = (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
#else
    /* Default implementation - should be overridden for actual platform */
    /* This is just a placeholder that returns a monotonically increasing value
     */
    static uint64_t fakeTime = 0;
    fakeTime += 1000; /* Increment by a fake 1ms each call */
    timeUs = fakeTime;
#endif

    return timeUs;
}
#endif /* !(WOLFHSM_CFG_BENCH_CUSTOM_TIME_FUNC) */

/* Get time in microseconds using the compile-time configured time function */
static uint64_t _benchGetTimeUs(void)
{
    return WH_BENCH_USE_TIME_FUNC();
}

/* Initialize benchmark context */
int wh_Bench_Init(whBenchOpContext* ctx)
{
    int i;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Clear all benchmark operations */
    memset(ctx, 0, sizeof(whBenchOpContext));

    /* Initialize each operation entry */
    for (i = 0; i < MAX_BENCH_OPS; i++) {
        ctx->ops[i].valid      = 0;
        ctx->ops[i].inProgress = 0;
        ctx->ops[i].minTimeUs =
            (uint64_t)-1; /* Set to maximum possible value */
    }

    ctx->opCount = 0;

    return WH_ERROR_OK;
}

/* Register a new benchmark operation */
int wh_Bench_RegisterOp(whBenchOpContext* ctx, const char* name,
                        whBenchOpThroughputType tpType, int* id)
{
    int i;

    if (ctx == NULL || name == NULL || id == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check if operation with this name already exists */
    for (i = 0; i < ctx->opCount; i++) {
        if (ctx->ops[i].valid &&
            strncmp(ctx->ops[i].name, name, sizeof((ctx->ops[i].name))) == 0) {
            *id = i;
            return WH_ERROR_OK; /* Operation already registered */
        }
    }

    /* Check if we have room for a new operation */
    if (ctx->opCount >= MAX_BENCH_OPS) {
        return WH_ERROR_BADARGS;
    }

    /* Register the new operation */
    *id = ctx->opCount;
    strncpy(ctx->ops[*id].name, name, MAX_OP_NAME - 1);
    ctx->ops[*id].name[MAX_OP_NAME - 1] = '\0'; /* Ensure null termination */
    ctx->ops[*id].valid                 = 1;
    ctx->ops[*id].inProgress            = 0;
    ctx->ops[*id].totalTimeUs           = 0;
    ctx->ops[*id].minTimeUs = (uint64_t)-1; /* Set to maximum possible value */
    ctx->ops[*id].maxTimeUs = 0;
    ctx->ops[*id].count     = 0;
    ctx->ops[*id].throughputType = tpType;
    ctx->ops[*id].dataSize       = 0;
    ctx->ops[*id].throughput     = 0.0;

    ctx->opCount++;

    return WH_ERROR_OK;
}

/* Set data size for throughput calculation */
int wh_Bench_SetDataSize(whBenchOpContext* ctx, int id, uint64_t bytes)
{
    if (ctx == NULL || id < 0 || id >= ctx->opCount || !ctx->ops[id].valid) {
        return WH_ERROR_BADARGS;
    }

    ctx->ops[id].dataSize = bytes;

    return WH_ERROR_OK;
}

/* Start timing an operation */
int wh_Bench_StartOp(whBenchOpContext* ctx, int id)
{
    if (ctx == NULL || id < 0 || id >= ctx->opCount || !ctx->ops[id].valid) {
        return WH_ERROR_BADARGS;
    }

    /* Check if operation is already in progress */
    if (ctx->ops[id].inProgress) {
        return WH_ERROR_BADARGS;
    }

    /* Set in progress flag before starting timer */
    ctx->ops[id].inProgress = 1;

    /* Record start time */
    ctx->ops[id].startTimeUs = _benchGetTimeUs();

    return WH_ERROR_OK;
}

/* Stop timing an operation and update statistics */
int wh_Bench_StopOp(whBenchOpContext* ctx, int id)
{
    uint64_t endTime;
    uint64_t elapsedTime;

    /* Get end time and calculate elapsed time (time-critical section) */
    endTime = _benchGetTimeUs();

    /* check args after timing for max perf */
    if (ctx == NULL || id < 0 || id >= ctx->opCount || !ctx->ops[id].valid ||
        !ctx->ops[id].inProgress) {
        return WH_ERROR_BADARGS;
    }

    /* Clear in progress flag after stopping timer */
    ctx->ops[id].inProgress = 0;

    elapsedTime = endTime - ctx->ops[id].startTimeUs;

    /* Update statistics */
    ctx->ops[id].totalTimeUs += elapsedTime;
    ctx->ops[id].count++;

    /* Update min time if this operation was faster */
    if (elapsedTime < ctx->ops[id].minTimeUs) {
        ctx->ops[id].minTimeUs = elapsedTime;
    }

    /* Update max time if this operation was slower */
    if (elapsedTime > ctx->ops[id].maxTimeUs) {
        ctx->ops[id].maxTimeUs = elapsedTime;
    }

    /* Calculate throughput if applicable. Throughput is calculated based on the
     * total number of bytes processed divided by the total elapsed time (in
     * seconds). */
    if (ctx->ops[id].throughputType != BENCH_THROUGHPUT_NONE) {
        double seconds = (double)ctx->ops[id].totalTimeUs / 1000000.0;

        switch (ctx->ops[id].throughputType) {
            case BENCH_THROUGHPUT_XBPS:
                /* Calculate bytes per second */
                if (seconds > 0 && ctx->ops[id].dataSize > 0) {
                    ctx->ops[id].throughput = ((double)ctx->ops[id].dataSize *
                                               (double)ctx->ops[id].count) /
                                              seconds;
                }
                break;

            case BENCH_THROUGHPUT_OPS:
                /* Calculate operations per second */
                if (seconds > 0) {
                    ctx->ops[id].throughput =
                        (double)ctx->ops[id].count / seconds;
                }
                break;

            default:
                /* No throughput calculation */
                break;
        }
    }

    return WH_ERROR_OK;
}

/* Print intermediate benchmark results for a single operation */
int wh_Bench_PrintIntermediateResult(whBenchOpContext* ctx, int id)
{

    if (ctx == NULL || id < 0 || id >= ctx->opCount || !ctx->ops[id].valid) {
        return WH_ERROR_BADARGS;
    }

    /* Only print if we have data */
    if (ctx->ops[id].count == 0) {
        return WH_ERROR_OK;
    }

    WH_BENCH_PRINTF("%s: count=%llu, ", ctx->ops[id].name,
                    (unsigned long long)ctx->ops[id].count);

    /* Print size appropriately */
    if (ctx->ops[id].throughputType == BENCH_THROUGHPUT_XBPS ||
        ctx->ops[id].dataSize > 0) {
        WH_BENCH_PRINTF("size=%llu, ",
                        (unsigned long long)ctx->ops[id].dataSize);
    }
    else {
        WH_BENCH_PRINTF("size=N/A, ");
    }

    /* Print throughput - directly using printf with formatting */
    if (ctx->ops[id].throughputType == BENCH_THROUGHPUT_XBPS) {
        double throughput = ctx->ops[id].throughput;

        if (throughput < 1024.0) {
            /* Bytes per second */
            WH_BENCH_PRINTF("%.2f B/s", throughput);
        }
        else if (throughput < 1024.0 * 1024.0) {
            /* Kilobytes per second */
            WH_BENCH_PRINTF("%.2f kB/s", throughput / 1024.0);
        }
        else {
            /* Megabytes per second */
            WH_BENCH_PRINTF("%.2f MB/s", throughput / (1024.0 * 1024.0));
        }
    }
    else if (ctx->ops[id].throughputType == BENCH_THROUGHPUT_OPS) {
        WH_BENCH_PRINTF("%.2f ops/s", ctx->ops[id].throughput);
    }
    else {
        /* No throughput */
        WH_BENCH_PRINTF("N/A");
    }

    WH_BENCH_PRINTF("\n");

    return WH_ERROR_OK;
}

/* Print benchmark results */
int wh_Bench_PrintResults(whBenchOpContext* ctx)
{
    int      i;
    uint64_t avgTime;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_BENCH_PRINTF("\nBenchmark Results ");
    switch (ctx->transportType) {
        case WH_BENCH_TRANSPORT_MEM:
            WH_BENCH_PRINTF("(Memory):\n");
            break;
        case WH_BENCH_TRANSPORT_SHM:
            WH_BENCH_PRINTF("(Shared Memory):\n");
            break;
        case WH_BENCH_TRANSPORT_TCP:
            WH_BENCH_PRINTF("(TCP):\n");
            break;
        case WH_BENCH_TRANSPORT_DMA:
            WH_BENCH_PRINTF("(DMA):\n");
            break;
    }
    WH_BENCH_PRINTF(
        "|--------------------------------|------------|------------|----------"
        "--|------------|------------|--------------------|\n");
    /* Fixed-width table header */
    WH_BENCH_PRINTF(
        "| %-30s | %-10s | %-10s | %-10s | %-10s | %-10s | %-18s |\n",
        "Operation", "Count", "Size", "Min (us)", "Avg (us)", "Max (us)",
        "Throughput");
    WH_BENCH_PRINTF(
        "|--------------------------------|------------|------------|----------"
        "--|------------|------------|--------------------|\n");

    for (i = 0; i < ctx->opCount; i++) {
        if (ctx->ops[i].valid && ctx->ops[i].count > 0) {
            /* Calculate average time */
            avgTime = ctx->ops[i].totalTimeUs / ctx->ops[i].count;

            /* Print operation name and count */
            WH_BENCH_PRINTF("| %-30s | %-10llu | ", ctx->ops[i].name,
                            (unsigned long long)ctx->ops[i].count);

            /* Print size field */
            if (ctx->ops[i].throughputType == BENCH_THROUGHPUT_XBPS ||
                ctx->ops[i].dataSize > 0) {
                WH_BENCH_PRINTF("%-10llu | ",
                                (unsigned long long)ctx->ops[i].dataSize);
            }
            else {
                WH_BENCH_PRINTF("%-10s | ", "N/A");
            }

            /* Print timing measurements */
            WH_BENCH_PRINTF("%-10llu | %-10llu | %-10llu | ",
                            (unsigned long long)ctx->ops[i].minTimeUs,
                            (unsigned long long)avgTime,
                            (unsigned long long)ctx->ops[i].maxTimeUs);

            /* Print throughput - directly using printf with formatting */
            char buffer[20] = {0};
            if (ctx->ops[i].throughputType == BENCH_THROUGHPUT_XBPS) {
                double throughput = ctx->ops[i].throughput;

                if (throughput < 1024.0) {
                    /* Bytes per second */
                    WH_BENCH_SNPRINTF(buffer, sizeof(buffer), 
                                "%.2f B/s", throughput);
                }
                else if (throughput < 1024.0 * 1024.0) {
                    /* Kilobytes per second */
                    WH_BENCH_SNPRINTF(buffer, sizeof(buffer), 
                                "%.2f KB/s", throughput / 1024.0);
                }
                else {
                    /* Megabytes per second */
                    WH_BENCH_SNPRINTF(buffer, sizeof(buffer), 
                                "%.2f MB/s", throughput / (1024.0 * 1024.0));
                }
            }
            else if (ctx->ops[i].throughputType == BENCH_THROUGHPUT_OPS) {
                WH_BENCH_SNPRINTF(buffer, sizeof(buffer), 
                                "%.2f ops/s", ctx->ops[i].throughput);
            }
            else {
                /* No throughput */
                WH_BENCH_SNPRINTF(buffer, sizeof(buffer), "N/A");
            }
            WH_BENCH_PRINTF("%-18s |\n", buffer);
        }
    }

    WH_BENCH_PRINTF(
        "|--------------------------------|------------|------------|----------"
        "--|------------|------------|--------------------|\n");

    return WH_ERROR_OK;
}

/* Reset benchmark statistics but keep registered operations */
int wh_Bench_Reset(whBenchOpContext* ctx)
{
    int i;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    for (i = 0; i < ctx->opCount; i++) {
        if (ctx->ops[i].valid) {
            ctx->ops[i].totalTimeUs = 0;
            ctx->ops[i].inProgress  = 0;
            ctx->ops[i].minTimeUs =
                (uint64_t)-1; /* Set to maximum possible value */
            ctx->ops[i].maxTimeUs  = 0;
            ctx->ops[i].count      = 0;
            ctx->ops[i].throughput = 0.0;
            /* Keep dataSize and throughputType */
        }
    }

    return WH_ERROR_OK;
}

/* Clean up benchmark context */
int wh_Bench_Cleanup(whBenchOpContext* ctx)
{
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Clear benchmark context */
    memset(ctx, 0, sizeof(whBenchOpContext));

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_BENCH_ENABLE */
