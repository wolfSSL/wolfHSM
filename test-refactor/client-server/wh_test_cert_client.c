/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * test-refactor/wh_test_cert_client.c
 *
 * Client-side certificate test suite. Exercises the cert
 * manager through the client request/response API.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) \
    && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

extern const unsigned char ROOT_A_CERT[];
extern const size_t        ROOT_A_CERT_len;


/*
 * Verify that wh_Client_CertReadTrusted reports WH_ERROR_BUFFER_SIZE
 * and updates the cert_len out-param when the caller buffer is too
 * small to hold the returned certificate.
 */
int whTest_CertReadTrustedSmallBuffer(whClientContext* ctx)
{
    int32_t       out_rc          = 0;
    const whNvmId cert_id         = 103;
    uint8_t       small_buf[16]   = {0};
    uint8_t       full_buf[2048]  = {0};
    uint32_t      cert_len        = 0;

    /* Sanity: the test cert must actually exceed the small buffer. */
    WH_TEST_ASSERT_RETURN(ROOT_A_CERT_len > sizeof(small_buf));
    WH_TEST_ASSERT_RETURN(ROOT_A_CERT_len <= sizeof(full_buf));

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrusted(
        ctx, cert_id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_A_CERT, ROOT_A_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Undersized buffer. */
    cert_len = sizeof(small_buf);
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertReadTrusted(
        ctx, cert_id, small_buf, &cert_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_BUFFER_SIZE);
    WH_TEST_ASSERT_RETURN(cert_len == ROOT_A_CERT_len);

    /* Retry with a properly sized buffer using the reported length. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertReadTrusted(
        ctx, cert_id, full_buf, &cert_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(cert_len == ROOT_A_CERT_len);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(ctx, cert_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    return 0;
}

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
