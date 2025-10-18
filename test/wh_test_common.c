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
#if defined(WOLFHSM_CFG_TEST_CLIENT_CRYPTIMEOUT)
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

#if defined(WOLFHSM_CFG_TEST_CLIENT_CRYPTIMEOUT)
uint32_t whTest_GetCurrentTime(int reset)
{
    struct timeval tv;
    (void)reset;
    if (gettimeofday(&tv, 0) < 0)
        return 0;
    /* Convert to milliseconds number. */
    return (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}
/* start_time stores the time (in milliseconds) returned by the GetCurrentTime()
 * callback when the operation started.
 * The actual unit depends on the GetCurrentTime() implementation.
 * timeout_ms represents the timeout in milliseconds, which is derived from
 * the crypt_timeout value in whCommClientConfig.
 */
int whTest_CheckCryptoTimeout(uint32_t* start_time, uint32_t timeout_ms)
{
    uint32_t current_time = whTest_GetCurrentTime(0);
    uint32_t elapsed_time = current_time - *start_time;

    if (timeout_ms == 0) {
        return WH_ERROR_OK;
    }
    if (elapsed_time > timeout_ms) {
        return WH_ERROR_CRYPTIMEOUT;
    }
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_CLIENT_CRYPTIMEOUT */
