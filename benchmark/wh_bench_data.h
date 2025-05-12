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

#ifndef WH_BENCH_DATA_H_
#define WH_BENCH_DATA_H_
#include <stdint.h>
#include "wolfhsm/wh_settings.h"

/* default size of the data buffer */
#ifndef WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE
#define WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE 0x400 /* 1024 bytes */
#endif

#if defined(WOLFHSM_CFG_BENCH_CUSTOM_DATA_BUFFERS)
#define WH_BENCH_DATA_IN_BUFFER ((void*)WOLFHSM_CFG_BENCH_CUSTOM_DATA_IN_BUFFER)
#define WH_BENCH_DATA_OUT_BUFFER \
    ((void*)WOLFHSM_CFG_BENCH_CUSTOM_DATA_OUT_BUFFER)
#else
extern uint8_t wh_bench_data_in_buffer[WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE];
extern uint8_t wh_bench_data_out_buffer[WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE];
#define WH_BENCH_DATA_IN_BUFFER (void*)wh_bench_data_in_buffer
#define WH_BENCH_DATA_OUT_BUFFER (void*)wh_bench_data_out_buffer
#endif

#if defined(WOLFHSM_CFG_DMA)

/* default size of the DMA buffer */
#ifndef WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE
#define WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE 0x8000
#endif

/* Allow the user to define a custom DMA buffer of size
 * WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE */
#if defined(WOLFHSM_CFG_BENCH_CUSTOM_DMA_BUFFER)
#define WH_BENCH_DMA_BUFFER ((void*)WOLFHSM_CFG_BENCH_CUSTOM_DMA_BUFFER)
#else
/* built-in buffer for DMA operations */
extern uint8_t wh_bench_data_dma_buffer[WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE];
#define WH_BENCH_DMA_BUFFER wh_bench_data_dma_buffer
#endif

#endif /* WOLFHSM_CFG_DMA */

#endif /* WH_BENCH_DATA_H_ */
