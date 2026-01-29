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
 * src/wh_message_auth.c
 *
 * Message translation functions for Auth Manager messages
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"

#include "wolfhsm/wh_message_auth.h"


int wh_MessageAuth_TranslateSimpleResponse(
    uint16_t magic, const whMessageAuth_SimpleResponse* src,
    whMessageAuth_SimpleResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}

int wh_MessageAuth_TranslateLoginRequest(
    uint16_t magic, const void* src_packet, uint16_t src_size,
    whMessageAuth_LoginRequest* dest_header, uint8_t* dest_auth_data)
{
    const whMessageAuth_LoginRequest* src_header;
    const uint8_t*                    src_data;
    uint16_t header_size = sizeof(whMessageAuth_LoginRequest);
    uint16_t expected_size;

    if ((src_packet == NULL) || (dest_header == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (src_size < header_size) {
        return WH_ERROR_BADARGS;
    }

    src_header = (const whMessageAuth_LoginRequest*)src_packet;
    src_data   = (const uint8_t*)src_packet + header_size;

    WH_T16(magic, dest_header, src_header, method);
    if (src_header != dest_header) {
        memcpy(dest_header->username, src_header->username,
               sizeof(dest_header->username));
        /* make sure the destination username is null terminated */
        dest_header->username[sizeof(dest_header->username) - 1] = '\0';
    }
    WH_T16(magic, dest_header, src_header, auth_data_len);

    expected_size = (uint16_t)(header_size + dest_header->auth_data_len);
    if (dest_header->auth_data_len > WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN ||
        src_size < expected_size) {
        return WH_ERROR_BADARGS;
    }

    if (dest_auth_data != NULL && dest_header->auth_data_len > 0) {
        memcpy(dest_auth_data, src_data, dest_header->auth_data_len);
    }
    return 0;
}

int wh_MessageAuth_TranslateLoginResponse(
    uint16_t magic, const whMessageAuth_LoginResponse* src,
    whMessageAuth_LoginResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, user_id);

    return 0;
}

int wh_MessageAuth_TranslateLogoutRequest(
    uint16_t magic, const whMessageAuth_LogoutRequest* src,
    whMessageAuth_LogoutRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    WH_T16(magic, dest, src, user_id);
    return 0;
}


int wh_MessageAuth_FlattenPermissions(whAuthPermissions* permissions,
                                      uint8_t* buffer, uint16_t buffer_len)
{
    int      idx = 0, i;
    uint16_t keyIdCount;
    uint32_t keyId;

    if (permissions == NULL || buffer == NULL ||
        buffer_len < WH_FLAT_PERMISSIONS_LEN) {
        return WH_ERROR_BADARGS;
    }

    /* Serialize groupPermissions (2 bytes) */
    buffer[idx++] = (uint8_t)(permissions->groupPermissions & 0xFF);
    buffer[idx++] = (uint8_t)((permissions->groupPermissions >> 8) & 0xFF);

    /* Serialize actionPermissions array (4*WH_NUMBER_OF_GROUPS*WH_AUTH_ACTION_WORDS bytes) */
    for (i = 0; i < WH_NUMBER_OF_GROUPS; i++) {
        int j;
        for (j = 0; j < WH_AUTH_ACTION_WORDS; j++) {
            uint32_t actionPerm = permissions->actionPermissions[i][j];
            buffer[idx++] = (uint8_t)(actionPerm & 0xFF);
            buffer[idx++] = (uint8_t)((actionPerm >> 8) & 0xFF);
            buffer[idx++] = (uint8_t)((actionPerm >> 16) & 0xFF);
            buffer[idx++] = (uint8_t)((actionPerm >> 24) & 0xFF);
        }
    }

    /* Serialize keyIdCount (2 bytes) */
    keyIdCount    = (permissions->keyIdCount > WH_AUTH_MAX_KEY_IDS)
                        ? WH_AUTH_MAX_KEY_IDS
                        : permissions->keyIdCount;
    buffer[idx++] = (uint8_t)(keyIdCount & 0xFF);
    buffer[idx++] = (uint8_t)((keyIdCount >> 8) & 0xFF);

    /* Serialize keyIds array (4*WH_AUTH_MAX_KEY_IDS bytes) */
    for (i = 0; i < WH_AUTH_MAX_KEY_IDS; i++) {
        if (i < keyIdCount) {
            keyId = permissions->keyIds[i];
        }
        else {
            keyId = 0; /* Pad with zeros */
        }
        buffer[idx++] = (uint8_t)(keyId & 0xFF);
        buffer[idx++] = (uint8_t)((keyId >> 8) & 0xFF);
        buffer[idx++] = (uint8_t)((keyId >> 16) & 0xFF);
        buffer[idx++] = (uint8_t)((keyId >> 24) & 0xFF);
    }

    return 0;
}


int wh_MessageAuth_UnflattenPermissions(uint8_t* buffer, uint16_t buffer_len,
                                        whAuthPermissions* permissions)
{
    int      idx = 0, i;
    uint16_t keyIdCount;
    uint32_t keyId;

    if (buffer == NULL || permissions == NULL ||
        buffer_len < WH_FLAT_PERMISSIONS_LEN) {
        return WH_ERROR_BADARGS;
    }

    /* Deserialize groupPermissions (2 bytes) */
    permissions->groupPermissions = buffer[idx] | (buffer[idx + 1] << 8);
    idx += 2;

    /* Deserialize actionPermissions array (4*WH_NUMBER_OF_GROUPS*WH_AUTH_ACTION_WORDS bytes) */
    for (i = 0; i < WH_NUMBER_OF_GROUPS; i++) {
        int j;
        for (j = 0; j < WH_AUTH_ACTION_WORDS; j++) {
            permissions->actionPermissions[i][j] =
                buffer[idx] |
                (buffer[idx + 1] << 8) |
                (buffer[idx + 2] << 16) |
                (buffer[idx + 3] << 24);
            idx += 4;
        }
    }

    /* Deserialize keyIdCount (2 bytes) */
    keyIdCount = buffer[idx] | (buffer[idx + 1] << 8);
    idx += 2;
    if (keyIdCount > WH_AUTH_MAX_KEY_IDS) {
        keyIdCount = WH_AUTH_MAX_KEY_IDS;
    }
    permissions->keyIdCount = keyIdCount;

    /* Deserialize keyIds array (4*WH_AUTH_MAX_KEY_IDS bytes) */
    for (i = 0; i < WH_AUTH_MAX_KEY_IDS; i++) {
        keyId = buffer[idx] |
                (buffer[idx + 1] << 8) |
                (buffer[idx + 2] << 16) |
                (buffer[idx + 3] << 24);
        permissions->keyIds[i] = keyId;
        idx += 4;
    }

    return 0;
}


int wh_MessageAuth_TranslateUserAddRequest(
    uint16_t magic, const void* src_packet, uint16_t src_size,
    whMessageAuth_UserAddRequest* dest_header, uint8_t* dest_credentials)
{
    const whMessageAuth_UserAddRequest* src_header;
    const uint8_t*                      src_data;
    uint16_t header_size = sizeof(whMessageAuth_UserAddRequest);
    uint16_t expected_size;

    if ((src_packet == NULL) || (dest_header == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (src_size < header_size) {
        return WH_ERROR_BADARGS;
    }

    src_header = (const whMessageAuth_UserAddRequest*)src_packet;
    src_data   = (const uint8_t*)src_packet + header_size;

    if (src_header != dest_header) {
        memcpy(dest_header->username, src_header->username,
               sizeof(dest_header->username));
        memcpy(dest_header->permissions, src_header->permissions,
               sizeof(dest_header->permissions));
    }

    WH_T16(magic, dest_header, src_header, method);
    WH_T16(magic, dest_header, src_header, credentials_len);

    expected_size = (uint16_t)(header_size + dest_header->credentials_len);
    if (dest_header->credentials_len > WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN ||
        src_size < expected_size) {
        return WH_ERROR_BUFFER_SIZE;
    }

    if (dest_credentials != NULL && dest_header->credentials_len > 0) {
        memcpy(dest_credentials, src_data, dest_header->credentials_len);
    }
    return 0;
}

int wh_MessageAuth_TranslateUserAddResponse(
    uint16_t magic, const whMessageAuth_UserAddResponse* src,
    whMessageAuth_UserAddResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, user_id);
    return 0;
}

int wh_MessageAuth_TranslateUserDeleteRequest(
    uint16_t magic, const whMessageAuth_UserDeleteRequest* src,
    whMessageAuth_UserDeleteRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    WH_T16(magic, dest, src, user_id);
    return 0;
}

int wh_MessageAuth_TranslateUserGetRequest(
    uint16_t magic, const whMessageAuth_UserGetRequest* src,
    whMessageAuth_UserGetRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (src != dest) {
        memcpy(dest->username, src->username, sizeof(dest->username));
    }
    (void)magic;
    return 0;
}

int wh_MessageAuth_TranslateUserGetResponse(
    uint16_t magic, const whMessageAuth_UserGetResponse* src,
    whMessageAuth_UserGetResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, user_id);
    if (src != dest) {
        memcpy(dest->permissions, src->permissions, sizeof(dest->permissions));
    }
    return 0;
}

int wh_MessageAuth_TranslateUserSetPermissionsRequest(
    uint16_t magic, const whMessageAuth_UserSetPermissionsRequest* src,
    whMessageAuth_UserSetPermissionsRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, user_id);
    if (src != dest) {
        memcpy(dest->permissions, src->permissions, sizeof(dest->permissions));
    }
    return 0;
}

int wh_MessageAuth_TranslateUserSetCredentialsRequest(
    uint16_t magic, const void* src_packet, uint16_t src_size,
    whMessageAuth_UserSetCredentialsRequest* dest_header,
    uint8_t* dest_current_creds, uint8_t* dest_new_creds)
{
    const whMessageAuth_UserSetCredentialsRequest* src_header;
    const uint8_t*                                 src_data;
    uint16_t header_size = sizeof(whMessageAuth_UserSetCredentialsRequest);
    uint16_t expected_size;

    if ((src_packet == NULL) || (dest_header == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (src_size < header_size) {
        return WH_ERROR_BADARGS;
    }

    src_header = (const whMessageAuth_UserSetCredentialsRequest*)src_packet;
    src_data   = (const uint8_t*)src_packet + header_size;

    /* Translate header fields */
    WH_T16(magic, dest_header, src_header, user_id);
    WH_T16(magic, dest_header, src_header, method);
    WH_T16(magic, dest_header, src_header, current_credentials_len);
    WH_T16(magic, dest_header, src_header, new_credentials_len);

    if (src_header->current_credentials_len >
        WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN) {
        return WH_ERROR_BUFFER_SIZE;
    }
    if (src_header->new_credentials_len > WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Validate lengths */
    expected_size = header_size + src_header->current_credentials_len +
                    src_header->new_credentials_len;
    if (src_size < expected_size) {
        return WH_ERROR_BADARGS;
    }

    /* Copy variable-length credential data */
    if (dest_current_creds != NULL && src_header->current_credentials_len > 0) {
        memcpy(dest_current_creds, src_data,
               src_header->current_credentials_len);
    }
    if (dest_new_creds != NULL && src_header->new_credentials_len > 0) {
        memcpy(dest_new_creds, src_data + src_header->current_credentials_len,
               src_header->new_credentials_len);
    }

    return 0;
}
