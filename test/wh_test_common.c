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

#include <string.h>

#include <wolfhsm/wh_nvm.h>
#include <wolfhsm/wh_nvm_flash.h>
#include <wolfhsm/wh_nvm_flash_log.h>
#include <wolfhsm/wh_flash_ramsim.h>
#include <wolfhsm/wh_error.h>

#include "wh_test_common.h"
#if defined(WOLFHSM_CFG_TEST_CLIENT_TIMEOUT)
#include <sys/time.h> /* For gettimeofday */
#endif

/**
 * Helper function to configure and select an NVM backend for testing.
 *
 * @param type      The type of NVM backend to configure (see
 * NvmTestBackendType).
 * @param nvmSetup  Pointer to a union of NVM backend setup structures (output).
 * @param nvmCfg    Pointer to the NVM configuration structure to populate
 * (output).
 * @param fCfg      Pointer to the RamSim flash configuration structure.
 * @param fCtx      Pointer to the RamSim flash context structure.
 * @param fCb       Pointer to the RamSim flash callback structure.
 *
 * @return WH_ERROR_OK on success, or WH_ERROR_BADARGS on failure.
 */
int whTest_NvmCfgBackend(whTestNvmBackendType   type,
                         whTestNvmBackendUnion* nvmSetup, whNvmConfig* nvmCfg,
                         whFlashRamsimCfg* fCfg, whFlashRamsimCtx* fCtx,
                         const whFlashCb* fCb)
{

    WH_TEST_ASSERT(nvmSetup != NULL);
    WH_TEST_ASSERT(nvmCfg != NULL);
    WH_TEST_ASSERT(fCfg != NULL);

    switch (type) {
#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
        case WH_NVM_TEST_BACKEND_FLASH_LOG:
            nvmSetup->nvmFlashLogCfg.flash_cb = fCb;
            /* restrict simulated flash partition to nvm_flash_log_partition */
            WH_TEST_ASSERT(fCfg->size >= WH_NVM_FLASH_LOG_PARTITION_SIZE * 2);
            fCfg->sectorSize = WH_NVM_FLASH_LOG_PARTITION_SIZE;
            nvmSetup->nvmFlashLogCfg.flash_cfg = fCfg;
            nvmSetup->nvmFlashLogCfg.flash_ctx = fCtx;
            memset(&nvmSetup->nvmFlashLogCtx, 0,
                   sizeof(nvmSetup->nvmFlashLogCtx));
            static whNvmCb nflcb[1] = {WH_NVM_FLASH_LOG_CB};

            nvmCfg->cb      = nflcb;
            nvmCfg->context = &nvmSetup->nvmFlashLogCtx;
            nvmCfg->config  = &nvmSetup->nvmFlashLogCfg;
            break;
#endif
        case WH_NVM_TEST_BACKEND_FLASH:
            /* NVM Flash Configuration using RamSim HAL Flash */
            nvmSetup->nvmFlashCfg.cb      = fCb;
            nvmSetup->nvmFlashCfg.context = fCtx;
            nvmSetup->nvmFlashCfg.config  = fCfg;

            memset(&nvmSetup->nvmFlashCtx, 0, sizeof(nvmSetup->nvmFlashCtx));
            static whNvmCb nfcb[1] = {WH_NVM_FLASH_CB};

            nvmCfg->cb      = nfcb;
            nvmCfg->context = &nvmSetup->nvmFlashCtx;
            nvmCfg->config  = &nvmSetup->nvmFlashCfg;
            break;

        default:
            return WH_ERROR_BADARGS;
    }

    return 0;
}

#if defined(WOLFHSM_CFG_TEST_CLIENT_TIMEOUT)
#include <time.h>
#include <sys/time.h> /* For gettimeofday */

uint64_t whTest_GetCurrentTime(int reset)
{
    (void)reset;
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;

    /* Convert to milliseconds number. */
    return (uint64_t)ts.tv_sec * 1000ULL +
           (uint64_t)ts.tv_nsec / 1000000ULL;
#else
    struct timeval tv;
    if (gettimeofday(&tv, 0) < 0)
        return 0;
    /* Convert to milliseconds number. */
    return (uint64_t)(tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL);
#endif
}
/* start_time stores the time (in milliseconds) returned by the GetCurrentTime()
 * callback when the operation started.
 * The actual unit depends on the GetCurrentTime() implementation.
 * timeout_val represents the timeout in milliseconds(default),
 * which is derived from the timeout value in whCommClientConfig.
 */
int whTest_CheckTimeout(uint64_t* start_time, uint64_t timeout_val)
{
    uint64_t current_time;
    uint64_t elapsed_time;

    if (start_time == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (timeout_val == 0) {
        return WH_ERROR_OK;
    }

    current_time = whTest_GetCurrentTime(0);
    elapsed_time = current_time - *start_time;

    if (elapsed_time > timeout_val) {
        return WH_ERROR_TIMEOUT;
    }

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_CLIENT_TIMEOUT */
