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

#ifndef WH_BENCH_UTILS_H
#define WH_BENCH_UTILS_H

#include "wolfhsm/wh_settings.h"

/* Define the WH_BENCH_PRINTF macro */
#if defined(WOLFHSM_CFG_BENCH_CUSTOM_PRINTF)
#define WH_BENCH_PRINTF WOLFHSM_CFG_BENCH_CUSTOM_PRINTF
#else
#include <stdio.h> /* use default printf */
#define WH_BENCH_PRINTF printf
#define WH_BENCH_SNPRINTF snprintf
#endif

#endif /* WH_BENCH_UTILS_H_ */