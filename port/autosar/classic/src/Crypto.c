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
 * port/autosar/classic/src/Crypto.c
 *
 * Module initialization, version, and the main dispatcher entry points
 * (Crypto_Init, Crypto_GetVersionInfo, Crypto_ProcessJob, Crypto_CancelJob,
 * Crypto_MainFunction). Primitive implementations live in the sibling
 * Crypto_*.c files.
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"
#include "wh_autosar_alg_map.h"

#include "wolfhsm/wh_error.h"

#include <string.h>

#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
#include "Det.h"
#define CRYPTO_DET_REPORT(sid, errid) \
    (void)Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, (sid), (errid))
#else
#define CRYPTO_DET_REPORT(sid, errid) ((void)0)
#endif

static wh_AutosarDriverObject s_driverObjects[CRYPTO_DRIVER_OBJECT_COUNT];
static boolean                s_initialised = FALSE;

/* Default slot lock is a no-op. Integrators with concurrent ProcessJob /
 * MainFunction callers provide a strong definition that hooks into their
 * SchM critical section. WH_AUTOSAR_WEAK abstracts the per-toolchain
 * weak-symbol syntax (see wh_autosar_classic_internal.h). */
WH_AUTOSAR_WEAK void wh_Autosar_LockSlots(wh_AutosarDriverObject* obj)
{
    (void)obj;
}
WH_AUTOSAR_WEAK void wh_Autosar_UnlockSlots(wh_AutosarDriverObject* obj)
{
    (void)obj;
}

wh_AutosarDriverObject* wh_Autosar_GetDriverObject(uint32 objectId)
{
    if (objectId >= CRYPTO_DRIVER_OBJECT_COUNT) {
        return NULL;
    }
    return &s_driverObjects[objectId];
}

int wh_Autosar_DriverObjectInit(wh_AutosarDriverObject* obj)
{
    int rc;
    if (obj == NULL) {
        return WH_ERROR_BADARGS;
    }
    rc = wh_Autosar_PlatformClientConfig(&obj->client);
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    return wh_Client_CommInit(&obj->client, NULL, NULL);
}

int wh_Autosar_DriverObjectCleanup(wh_AutosarDriverObject* obj)
{
    if (obj == NULL) {
        return WH_ERROR_BADARGS;
    }
    (void)wh_Client_CommClose(&obj->client);
    return wh_Client_Cleanup(&obj->client);
}

void Crypto_Init(void)
{
    uint32 i;

    for (i = 0u; i < CRYPTO_DRIVER_OBJECT_COUNT; ++i) {
        wh_AutosarDriverObject* obj = &s_driverObjects[i];
        (void)memset(obj, 0, sizeof(*obj));
        if (wh_Autosar_DriverObjectInit(obj) != WH_ERROR_OK) {
            CRYPTO_DET_REPORT(CRYPTO_INIT_SID, CRYPTO_E_INIT_FAILED);
            continue;
        }
        obj->initialised = TRUE;
    }
    if (wh_Autosar_KeystoreInit() != WH_ERROR_OK) {
        CRYPTO_DET_REPORT(CRYPTO_INIT_SID, CRYPTO_E_INIT_FAILED);
    }
    s_initialised = TRUE;
}

void Crypto_GetVersionInfo(Std_VersionInfoType* versionInfo)
{
    if (versionInfo == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_GETVERSIONINFO_SID, CRYPTO_E_PARAM_POINTER);
        return;
    }
    versionInfo->vendorID         = CRYPTO_VENDOR_ID;
    versionInfo->moduleID         = CRYPTO_MODULE_ID;
    versionInfo->sw_major_version = CRYPTO_SW_MAJOR_VERSION;
    versionInfo->sw_minor_version = CRYPTO_SW_MINOR_VERSION;
    versionInfo->sw_patch_version = CRYPTO_SW_PATCH_VERSION;
}

Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType* job)
{
    wh_AutosarDriverObject* obj;

    if (!s_initialised) {
        CRYPTO_DET_REPORT(CRYPTO_PROCESSJOB_SID, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    if (job == NULL || job->jobPrimitiveInfo == NULL ||
        job->jobPrimitiveInfo->primitiveInfo == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }

    obj = wh_Autosar_GetDriverObject(objectId);
    if (obj == NULL || !obj->initialised) {
        CRYPTO_DET_REPORT(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    if (job->jobPrimitiveInfo->processingType == 0u) {
        return wh_Autosar_ProcessJobSync(obj, job);
    }
    return wh_Autosar_ProcessJobAsync(obj, job);
}

Std_ReturnType Crypto_CancelJob(uint32 objectId, Crypto_JobType* job)
{
    wh_AutosarDriverObject* obj;
    uint32                  i;
    Std_ReturnType          ret = E_NOT_OK;

    obj = wh_Autosar_GetDriverObject(objectId);
    if (obj == NULL || !obj->initialised || job == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_CANCELJOB_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }

    wh_Autosar_LockSlots(obj);
    for (i = 0u; i < CRYPTO_MAX_ASYNC_JOBS; ++i) {
        wh_AutosarJobSlot* slot = &obj->asyncSlots[i];
        if (slot->job != job) {
            continue;
        }
        switch (slot->state) {
            case WH_AUTOSAR_ASYNC_PENDING:
                /* wolfHSM has no in-flight cancel primitive — flip the
                 * state so MainFunction drains and discards the Response
                 * without notifying CryIf. */
                slot->state = WH_AUTOSAR_ASYNC_CANCELLING;
                ret         = E_OK;
                break;
            case WH_AUTOSAR_ASYNC_QUEUED:
            case WH_AUTOSAR_ASYNC_COMPLETE:
            case WH_AUTOSAR_ASYNC_IDLE:
                /* Not on the wire or already done — drop directly. */
                slot->state = WH_AUTOSAR_ASYNC_IDLE;
                slot->job   = NULL;
                ret         = E_OK;
                break;
            case WH_AUTOSAR_ASYNC_CANCELLING:
                ret = E_OK; /* idempotent */
                break;
            default:
                break;
        }
        if (ret == E_OK) {
            job->jobState = CRYPTO_JOBSTATE_IDLE;
            break;
        }
    }
    wh_Autosar_UnlockSlots(obj);
    return ret;
}

void Crypto_MainFunction(void)
{
    uint32 i;
    if (!s_initialised) {
        return;
    }
    for (i = 0u; i < CRYPTO_DRIVER_OBJECT_COUNT; ++i) {
        if (s_driverObjects[i].initialised) {
            wh_Autosar_MainFunctionObject(&s_driverObjects[i]);
        }
    }
}
