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
#include "wolfhsm/wh_settings.h"
#include "wh_bench.h"
#include "wh_bench_utils.h"

int main(void)
{
    WH_BENCH_PRINTF("Running wolfHSM benchmarks\n");

#if defined(WOLFHSM_CFG_TEST_POSIX)
    WH_BENCH_PRINTF(
        "Running benchmarks with memory transport in POSIX threads\n");
    int ret = wh_Bench_ClientServer_Posix();
    if (ret != 0) {
        WH_BENCH_PRINTF("Memory transport benchmark failed: %d\n", ret);
        return ret;
    }
#else
    WH_BENCH_PRINTF(
        "POSIX thread benchmarks not enabled. Define WOLFHSM_CFG_TEST_POSIX "
        "to enable.\n");
#endif

    return 0;
}