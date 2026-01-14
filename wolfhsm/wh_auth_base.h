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
 * wolfhsm/wh_auth_base.h
 *
 * Basic authentication and authorization implementation.
 */

 #ifndef WOLFHSM_WH_AUTH_BASE_H_
 #define WOLFHSM_WH_AUTH_BASE_H_
 
 /* Pick up compile-time configuration */
 #include "wolfhsm/wh_settings.h"
 
 #include <stdint.h>
 
 #include "wolfhsm/wh_common.h"
 #include "wolfhsm/wh_auth.h"


int wh_AuthBase_Init(void* context, const void *config);

int wh_AuthBase_Cleanup(void* context);

int wh_AuthBase_Login(void* context, uint8_t client_id,
                          whAuthMethod method, const char* username,
                          const void* auth_data,
                          uint16_t auth_data_len,
                          uint16_t* out_user_id,
                          whAuthPermissions* out_permissions,
                          int* loggedIn);

int wh_AuthBase_Logout(void* context, uint16_t current_user_id, uint16_t user_id);


int wh_AuthBase_CheckRequestAuthorization(void* context,
    uint16_t user_id, uint16_t group, uint16_t action);

/* authorization check on key usage after the request has been parsed and before
 * the action is done */
int wh_AuthBase_CheckKeyAuthorization(void* context, uint16_t user_id,
    uint32_t key_id, uint16_t action);

int wh_AuthBase_UserAdd(void* context, const char* username,
    uint16_t* out_user_id, whAuthPermissions permissions,
    whAuthMethod method, const void* credentials, uint16_t credentials_len);

int wh_AuthBase_UserDelete(void* context, uint16_t current_user_id, uint16_t user_id);

int wh_AuthBase_UserSetPermissions(void* context, uint16_t current_user_id,
    uint16_t user_id, whAuthPermissions permissions);

int wh_AuthBase_UserGet(void* context, const char* username, uint16_t* out_user_id,
    whAuthPermissions* out_permissions);

int wh_AuthBase_UserSetCredentials(void* context, uint16_t user_id,
    whAuthMethod method,
    const void* current_credentials, uint16_t current_credentials_len,
    const void* new_credentials, uint16_t new_credentials_len);

#endif /* WOLFHSM_WH_AUTH_BASE_H_ */