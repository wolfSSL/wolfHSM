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

/**
 * @brief Initialize the certificate manager
 * @param server The server context
 * @return WH_ERROR_OK on success, error code on failure
 */
int wh_Server_CertInit(whServerContext* server);

/**
 * @brief Add a trusted certificate to NVM storage
 * @param server The server context
 * @param id The NVM ID to store the certificate under
 * @param cert The certificate data buffer
 * @param cert_len Length of the certificate data
 * @return WH_ERROR_OK on success, error code on failure
 */
int wh_Server_CertAddTrusted(whServerContext* server, whNvmId id,
                             const uint8_t* cert, uint32_t cert_len);

/**
 * @brief Delete a trusted certificate from NVM storage
 * @param server The server context
 * @param id The NVM ID of the certificate to delete
 * @return WH_ERROR_OK on success, error code on failure
 */
int wh_Server_CertEraseTrusted(whServerContext* server, whNvmId id);

/**
 * @brief Get a trusted certificate from NVM storage
 * @param server The server context
 * @param id The NVM ID of the certificate to read
 * @param cert Buffer to store the certificate data
 * @param inout_cert_len On input, size of cert buffer. On output, actual cert
 * size
 * @return WH_ERROR_OK on success, error code on failure. If certificate is too
 * large for the buffer, WH_ERROR_BUFFER_SIZE will be returned and
 * inout_cert_len will be updated to the actual certificate size.
 */
int wh_Server_CertReadTrusted(whServerContext* server, whNvmId id,
                              uint8_t* cert, uint32_t* inout_cert_len);

/**
 * @brief Verify a certificate against trusted certificates
 * @param server The server context
 * @param cert The certificate data to verify
 * @param cert_len Length of the certificate data
 * @param trustedRootNvmId NVM ID of the trusted root certificate
 * @return WH_ERROR_OK on success, error code on failure
 */
int wh_Server_CertVerify(whServerContext* server, const uint8_t* cert,
                         uint32_t cert_len, whNvmId trustedRootNvmId);

/**
 * @brief Handle a certificate request and generate a response
 * @param server The server context
 * @param magic Magic number for message validation
 * @param action The certificate action to perform
 * @param seq Sequence number for the request
 * @param req_size Size of the request packet
 * @param req_packet The request packet data
 * @param out_resp_size Size of the response packet
 * @param resp_packet Buffer to store the response packet
 * @return WH_ERROR_OK on success, error code on failure
 */
int wh_Server_HandleCertRequest(whServerContext* server, uint16_t magic,
                                uint16_t action, uint16_t seq,
                                uint16_t req_size, const void* req_packet,
                                uint16_t* out_resp_size, void* resp_packet);

#endif /* !WOLFHSM_WH_SERVER_CERT_H_ */