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
 * benchmark/wh_bench_ops.h
 *
 */
#ifndef WH_BENCH_OPS_H_
#define WH_BENCH_OPS_H_

#include <stdint.h>

/* Maximum number of operations that can be registered */
#define MAX_BENCH_OPS 83
/* Maximum length of operation name */
#define MAX_OP_NAME 64

/* Throughput metric types */
typedef enum {
    BENCH_THROUGHPUT_NONE, /* No throughput calculation */
    BENCH_THROUGHPUT_XBPS, /* Auto-scaled bytes per second */
    BENCH_THROUGHPUT_OPS   /* Operations per second */
} whBenchOpThroughputType;

/* Transport type enumeration for benchmark testing */
typedef enum {
    WH_BENCH_TRANSPORT_MEM =
        0, /* Memory transport (WH_TRANSPORT_MEM_CLIENT_CB) */
    WH_BENCH_TRANSPORT_POSIX_SHM, /* Shared memory transport
                               (POSIX_TRANSPORT_SHM_CLIENT_CB) */
    WH_BENCH_TRANSPORT_POSIX_TCP, /* TCP transport (PTT_CLIENT_CB) */
    WH_BENCH_TRANSPORT_POSIX_DMA, /* DMA transport
                                     (POSIX_TRANSPORT_REF_CLIENT_CB) */
} whBenchTransportType;

typedef struct whBenchOp {
    /* Name of the operation being timed */
    char name[MAX_OP_NAME];
    /* Is this a valid benchmark entry */
    int valid;
    /* Is this operation currently in progress? */
    int inProgress;
    /* Total time spent on this operation (in microseconds) */
    uint64_t totalTimeUs;
    /* Minimum time for a single operation (in microseconds) */
    uint64_t minTimeUs;
    /* Maximum time for a single operation (in microseconds) */
    uint64_t maxTimeUs;
    /* Start time for current operation (in microseconds) */
    uint64_t startTimeUs;
    /* Number of times this operation has been performed */
    uint64_t count;
    /* Type of throughput measurement */
    whBenchOpThroughputType throughputType;
    /* Size of data processed in bytes */
    uint64_t dataSize;
    /* Calculated throughput value */
    double throughput;
} whBenchOp;

typedef struct whBenchOpContext {
    whBenchOp ops[MAX_BENCH_OPS]; /* Array of operations */
    int       opCount;            /* Number of registered operations */
    whBenchTransportType transportType;      /* Type of transport */
} whBenchOpContext;

/*
 * Benchmark Timing API
 */

/* Initialize benchmark context */
int wh_Bench_Init(whBenchOpContext* ctx);

/* Register a new benchmark operation with a name, returns ID via pointer */
int wh_Bench_RegisterOp(whBenchOpContext* ctx, const char* name,
                        whBenchOpThroughputType tpType, int* id);

/* Set the data size for throughput calculation (needed for MBps/KBps metrics)
 */
int wh_Bench_SetDataSize(whBenchOpContext* ctx, int id, uint64_t bytes);

/* Start timing an operation with given ID */
int wh_Bench_StartOp(whBenchOpContext* ctx, int id);

/* Stop timing an operation with given ID and update statistics */
int wh_Bench_StopOp(whBenchOpContext* ctx, int id);

/* Print benchmark results as formatted table */
int wh_Bench_PrintResults(whBenchOpContext* ctx);

/* Print intermediate benchmark results for a single operation */
int wh_Bench_PrintIntermediateResult(whBenchOpContext* ctx, int id);

/* Reset benchmark statistics but keep registered operations */
int wh_Bench_Reset(whBenchOpContext* ctx);

/* Clean up benchmark context */
int wh_Bench_Cleanup(whBenchOpContext* ctx);

#endif /* WH_BENCH_OPS_H_ */
