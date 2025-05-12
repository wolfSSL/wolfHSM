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

#include "wh_bench_data.h"

#if defined(WOLFHSM_CFG_BENCH_ENABLE)

#if !defined(WOLFHSM_CFG_BENCH_CUSTOM_DATA_BUFFERS)
uint8_t wh_bench_data_in_buffer[WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE]  = {0};
uint8_t wh_bench_data_out_buffer[WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE] = {0};
#endif

#if defined(WOLFHSM_CFG_DMA) && !defined(WOLFHSM_CFG_BENCH_CUSTOM_DMA_BUFFER)
/* Define the DMA buffer if using built-in buffer */
uint8_t wh_bench_data_dma_buffer[WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE] = {0};
#endif

#endif /* WOLFHSM_CFG_BENCH_ENABLE */