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

#ifndef WH_BENCH_MODULE_H_
#define WH_BENCH_MODULE_H_

#include "wolfhsm/wh_settings.h"

#include "wolfhsm/wh_client.h"

#include "wh_bench_ops.h"
#include "wh_bench_utils.h"
#include "wh_bench_data.h"

#ifndef WOLFHSM_CFG_BENCH_CRYPT_ITERS
#define WOLFHSM_CFG_BENCH_CRYPT_ITERS 100
#endif

#ifndef WOLFHSM_CFG_BENCH_KG_ITERS
#define WOLFHSM_CFG_BENCH_KG_ITERS 10
#endif

#ifndef WOLFHSM_CFG_BENCH_PK_ITERS
#define WOLFHSM_CFG_BENCH_PK_ITERS 10
#endif


/**
 * @brief Function prototype for a generic benchmark module function.
 *
 * A benchmark module function implements a specific benchmark test using the
 * benchmark context and operation id for timing on the supplied client context.
 *
 * @param client  Pointer to the client context to use for the benchmark
 * @param benchCtx Pointer to the benchmark context to use for timing
 * @param opId    The id of the operation to benchmark
 * @param params  Optional parameters for the benchmark
 *
 * @return 0 on success, or a negative error code on failure
 */
typedef int (*wh_BenchModuleFunc)(whClientContext* client,
                                  BenchOpContext* benchCtx, int opId,
                                  void* params);


#endif /* WH_BENCH_MODULE_H_ */