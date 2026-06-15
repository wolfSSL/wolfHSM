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
#ifndef WH_TEST_KEYWRAP_H_
#define WH_TEST_KEYWRAP_H_

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

int whTest_Client_KeyWrap(whClientContext* ctx);
int whTest_Client_DataWrap(whClientContext* ctx);
int whTest_KeyWrapClientConfig(whClientConfig* cf);

#if defined(WOLFHSM_CFG_HWKEYSTORE) && defined(WOLFHSM_CFG_KEYWRAP)
#include "wolfhsm/wh_hwkeystore.h"

/* Test getKey callback emulating a hardware keystore backend; bind this to
 * the server's whHwKeystoreContext when running whTest_Client_HwKeystore.
 * Defined in wh_test_keywrap.c, so only available when keywrap is enabled */
int whTest_HwKeystoreGetKeyCb(void* context, whKeyId keyId, uint8_t* out,
                              uint16_t* inout_len);
int whTest_Client_HwKeystore(whClientContext* ctx);

/* Convenience callback-table initializer for the emulated test backend. The
 * backend needs no setup/teardown, so Init and Cleanup are NULL */
/* clang-format off */
#define WH_TEST_HWKEYSTORE_CB                 \
    {                                         \
        .Init    = NULL,                      \
        .Cleanup = NULL,                      \
        .GetKey  = whTest_HwKeystoreGetKeyCb, \
    }
/* clang-format on */
#endif /* WOLFHSM_CFG_HWKEYSTORE && WOLFHSM_CFG_KEYWRAP */

#endif /* WH_TEST_KEYWRAP_H_ */
