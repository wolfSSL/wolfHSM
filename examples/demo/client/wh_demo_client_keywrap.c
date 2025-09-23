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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_nvm_flash.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/random.h"

#include "port/posix/posix_flash_file.h"

#include "wh_demo_client_keywrap.h"
#include "test/wh_test_keywrap.h"

#ifdef WOLFHSM_CFG_KEYWRAP

int wh_DemoClient_KeyWrap(whClientContext* client)
{
    int ret;

    /* file-based flash state and configuration */
    posixFlashFileContext flashFileCtx;
    posixFlashFileConfig  flashFileCfg   = {.filename       = "flashFile",
                                            .partition_size = 1024 * 1024,
                                            .erased_byte    = 0xff};
    whFlashCb             flashFileCb[1] = {POSIX_FLASH_FILE_CB};

    ret = flashFileCb->Init(&flashFileCtx, &flashFileCfg);
    if (ret != WH_ERROR_OK) {
        printf("Failed to flashCb->Init %d\n", ret);
        return ret;
    }

    ret =
        flashFileCb->WriteUnlock(&flashFileCtx, 0, flashFileCfg.partition_size);
    if (ret != WH_ERROR_OK) {
        printf("Failed to flashCb->WriteUnlock %d\n", ret);
        return ret;
    }
    ret = whTest_Client_KeyWrap(client);
    if (ret != WH_ERROR_OK) {
        printf("Failed to whTest_Client_KeyWrap %d\n", ret);
        return ret;
    }

    ret =
        whTest_Client_WriteWrappedKeysToNvm(client, &flashFileCtx, flashFileCb);
    if (ret != WH_ERROR_OK) {
        printf("Failed to whTest_Client_WriteWrappedKeysToNvm %d\n", ret);
        return ret;
    }

    ret =
        whTest_Client_UseWrappedKeysFromNvm(client, &flashFileCtx, flashFileCb);
    if (ret != WH_ERROR_OK) {
        printf("Failed to whTest_Client_UseWrappedKeysFromNvm %d\n", ret);
        return ret;
    }

    flashFileCb->Cleanup(&flashFileCtx);

    return ret;
}
#endif /* WOLFHSM_CFG_KEYWRAP */
