/*
 * Copyright (C) 2024 wolfSSL Inc.
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
 * test/wh_test_cert.h
 */

#ifndef WOLFHSM_WH_TEST_CERT_H_
#define WOLFHSM_WH_TEST_CERT_H_

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

/* Run certificate configuration tests */
int whTest_CertRamSim(void);
int whTest_CertServerCfg(whServerConfig* serverCfg);
int whTest_CertClient(whClientContext* client);
#if defined(WOLFHSM_CFG_DMA)
int whTest_CertClientDma_ClientServerTestInternal(whClientContext* client);
#endif

#endif /* !WOLFHSM_WH_TEST_CERT_H_ */ 