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
 * wolfhsm_cfg.h
 *
 * wolfHSM compile-time options.  Override here for your application
 */

#ifndef WOLFHSM_CFG_H_
#define WOLFHSM_CFG_H_


/** wolfHSM settings.  Simple overrides to show they work */
/* #define WOLFHSM_CFG_NO_CRYPTO */
/* #define WOLFHSM_CFG_SHE_EXTENSION */

#define WOLFHSM_CFG_COMM_DATA_LEN 1280


#define WOLFHSM_CFG_NVM_OBJECT_COUNT 30
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT 10
#define WOLFHSM_CFG_SERVER_KEYCACHE_SIZE 1280
#define WOLFHSM_CFG_SERVER_DMAADDR_COUNT 8
#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 6

/* Test specific configuration */


#endif /* WOLFHSM_CFG_H_ */
