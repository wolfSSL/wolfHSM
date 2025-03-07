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
 * wolfhsm/wh_server_cert.h
 */

#ifndef WOLFHSM_WH_SERVER_CERT_H_
#define WOLFHSM_WH_SERVER_CERT_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm.h"

/* Initialize the certificate manager */
int wh_Server_CertInit(whServerContext* server);

/* Add a trusted certificate to NVM storage */
int wh_Server_CertAddTrusted(whServerContext* server, whNvmId id,
                             const uint8_t* cert, uint32_t cert_len);

/* Delete a trusted certificate from NVM storage */
int wh_Server_CertDeleteTrusted(whServerContext* server, whNvmId id);

/* Get a trusted certificate from NVM storage */
int wh_Server_CertGetTrusted(whServerContext* server, whNvmId id, uint8_t* cert,
                             uint32_t* cert_len);

/* Verify a certificate against trusted certificates */
int wh_Server_CertVerify(whServerContext* server, const uint8_t* cert,
                         uint32_t cert_len, whNvmId trustedRootNvmId);

/* Handle a certificate request and generate a response */
int wh_Server_HandleCertRequest(whServerContext* server, uint16_t magic,
                                uint16_t action, uint16_t seq,
                                uint16_t req_size, const void* req_packet,
                                uint16_t* out_resp_size, void* resp_packet);

#endif /* !WOLFHSM_WH_SERVER_CERT_H_ */