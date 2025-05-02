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
 * benchmark/wh_benchmark.h
 *
 */
#ifndef BENCHMARK_WH_BENCHMARK_H_
#define BENCHMARK_WH_BENCHMARK_H_

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

/*
 * Runs the client benchmarks against a server using POSIX threads
 * Returns 0 on success and a non-zero error code on failure
 */
int wh_Bench_ClientServer_Posix(void);

/*
 * Client-side benchmarking function. Takes in a client configuration,
 * initializes the client, runs benchmarks against the server, then cleans up
 * and closes the client.
 */
int wh_Bench_ClientCfg(whClientConfig* clientCfg);

/*
 * Client-side benchmarking function. Runs the benchmarks on an already
 * initialized client context with no initialization or cleanup.
 */
int wh_Bench_ClientCtx(whClientContext* client);

/* Server-side processing loop for benchmarking */
int wh_Bench_ServerCfgLoop(whServerConfig* serverCfg);

#endif /* BENCHMARK_WH_BENCHMARK_H_ */
