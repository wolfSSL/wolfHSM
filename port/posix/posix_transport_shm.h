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
 * port/posix_transport_shm.h
 *
 * wolfHSM Transport Mem binding using POSIX shared memory functionality
 */

#ifndef PORT_POSIX_POSIX_TRANSPORT_SHM_H_
#define PORT_POSIX_POSIX_TRANSPORT_SHM_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_comm.h"

/** Common configuration structure */
typedef struct {
    char*    shmObjName; /* Null terminated, up to NAME_MAX */
    uint16_t req_size;
    uint16_t resp_size;
    uint8_t  WH_PAD[4];
} posixTransportShmConfig;


/** Common context */

typedef struct {
    char*                  shmObjName;
    void*                  shmBuf;
    whTransportMemContext* transportMemCtx;
} posixTransportShmContext;

/* Naming conveniences. Reuses the same types. */
typedef posixTransportShmContext posixTransportShmClientContext;
typedef posixTransportShmContext posixTransportShmServerContext;

/** Callback function declarations */
int posixTransportShm_ClientInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);
int posixTransportShm_ServerInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);

int posixTransportShm_Cleanup(void* c);
int posixTransportShm_SendRequest(void* c, uint16_t len, const void* data);
int posixTransportShm_RecvRequest(void* c, uint16_t* out_len, void* data);
int posixTransportShm_SendResponse(void* c, uint16_t len, const void* data);
int posixTransportShm_RecvResponse(void* c, uint16_t* out_len, void* data);

#define POSIX_TRANSPORT_SHM_CLIENT_CB              \
    {                                              \
        .Init    = posixTransportShm_ClientInit,   \
        .Send    = posixTransportShm_SendRequest,  \
        .Recv    = posixTransportShm_RecvResponse, \
        .Cleanup = posixTransportShm_Cleanup,      \
    }

#define POSIX_TRANSPORT_SHM_SERVER_CB              \
    {                                              \
        .Init    = posixTransportShm_ServerInit,   \
        .Recv    = posixTransportShm_RecvRequest,  \
        .Send    = posixTransportShm_SendResponse, \
        .Cleanup = posixTransportShm_Cleanup,      \
    }


#endif /* !PORT_POSIX_POSIX_TRANSPORT_SHM_H_ */
