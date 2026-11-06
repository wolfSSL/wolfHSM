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
 * test-refactor/wh_test_cert_data_extern.h
 *
 * Declarations for the test certificate data defined once in
 * wh_test_cert_data.c.
 */

#ifndef WH_TEST_CERT_DATA_EXTERN_H_
#define WH_TEST_CERT_DATA_EXTERN_H_

#include <stddef.h>

#include "wolfhsm/wh_settings.h"

extern const unsigned char ROOT_A_CERT[];
extern const size_t        ROOT_A_CERT_len;
extern const unsigned char INTERMEDIATE_A_CERT[];
extern const size_t        INTERMEDIATE_A_CERT_len;
extern const unsigned char LEAF_A_CERT[];
extern const size_t        LEAF_A_CERT_len;
extern const unsigned char RAW_CERT_CHAIN_A[];
extern const size_t        RAW_CERT_CHAIN_A_len;
extern const unsigned char CERT_CHAIN_A_P7B[];
extern const size_t        CERT_CHAIN_A_P7B_len;
extern const unsigned char LEAF_A_PUBKEY[];
extern const size_t        LEAF_A_PUBKEY_len;

extern const unsigned char ROOT_B_CERT[];
extern const size_t        ROOT_B_CERT_len;
extern const unsigned char INTERMEDIATE_B_CERT[];
extern const size_t        INTERMEDIATE_B_CERT_len;
extern const unsigned char LEAF_B_CERT[];
extern const size_t        LEAF_B_CERT_len;
extern const unsigned char RAW_CERT_CHAIN_B[];
extern const size_t        RAW_CERT_CHAIN_B_len;
extern const unsigned char CERT_CHAIN_B_P7B[];
extern const size_t        CERT_CHAIN_B_P7B_len;

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
extern unsigned char caCert_der[];
extern unsigned int  caCert_der_len;
extern unsigned char caPub_der[];
extern unsigned int  caPub_der_len;
extern unsigned char dummyCert_der[];
extern unsigned int  dummyCert_der_len;
extern unsigned char dummyPub_der[];
extern unsigned int  dummyPub_der_len;
extern unsigned char attrCert_der[];
extern unsigned int  attrCert_der_len;
#endif

#endif /* WH_TEST_CERT_DATA_EXTERN_H_ */
