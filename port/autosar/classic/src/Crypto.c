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
 * Crypto_Init, ProcessJob, CancelJob and MainFunction entry points.
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"
#include "wh_autosar_alg_map.h"

#include "wolfhsm/wh_error.h"

#include <string.h>

/* The dispatcher compares job fields against these, so the BSW's values must
 * match R22-11. */
#define WH_AUTOSAR_ASSERT_EQ(a, b) \
    typedef char wh_autosar_assert_##a[((uint32)(a) == (uint32)(b)) ? 1 : -1]
WH_AUTOSAR_ASSERT_EQ(CRYPTO_HASH, WH_AUTOSAR_SERVICE_HASH);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_MACGENERATE, WH_AUTOSAR_SERVICE_MAC_GENERATE);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_MACVERIFY, WH_AUTOSAR_SERVICE_MAC_VERIFY);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ENCRYPT, WH_AUTOSAR_SERVICE_ENCRYPT);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_DECRYPT, WH_AUTOSAR_SERVICE_DECRYPT);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_AEADENCRYPT, WH_AUTOSAR_SERVICE_AEAD_ENCRYPT);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_AEADDECRYPT, WH_AUTOSAR_SERVICE_AEAD_DECRYPT);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_SIGNATUREGENERATE,
                     WH_AUTOSAR_SERVICE_SIGNATURE_GENERATE);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_SIGNATUREVERIFY,
                     WH_AUTOSAR_SERVICE_SIGNATURE_VERIFY);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_RANDOMGENERATE, WH_AUTOSAR_SERVICE_RANDOM);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_RANDOMSEED, WH_AUTOSAR_SERVICE_RANDOM_SEED);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_KEYGENERATE, WH_AUTOSAR_SERVICE_KEY_GENERATE);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_KEYDERIVE, WH_AUTOSAR_SERVICE_KEY_DERIVE);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_KEYEXCHANGECALCPUBVAL,
                     WH_AUTOSAR_SERVICE_KEY_EXCHANGE_PUB);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_KEYEXCHANGECALCSECRET,
                     WH_AUTOSAR_SERVICE_KEY_EXCHANGE_SEC);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_KEYSETVALID, WH_AUTOSAR_SERVICE_KEY_SET_VALID);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_KEYSETINVALID, WH_AUTOSAR_SERVICE_KEY_SET_INVALID);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_SHA2_224, WH_AUTOSAR_ALGOFAM_SHA2_224);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_SHA2_256, WH_AUTOSAR_ALGOFAM_SHA2_256);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_SHA2_384, WH_AUTOSAR_ALGOFAM_SHA2_384);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_SHA2_512, WH_AUTOSAR_ALGOFAM_SHA2_512);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_AES, WH_AUTOSAR_ALGOFAM_AES);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_RSA, WH_AUTOSAR_ALGOFAM_RSA);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_ED25519, WH_AUTOSAR_ALGOFAM_ED25519);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_ECCNIST, WH_AUTOSAR_ALGOFAM_ECCNIST);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_HKDF, WH_AUTOSAR_ALGOFAM_HKDF);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_ECDSA, WH_AUTOSAR_ALGOFAM_ECDSA);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_X25519, WH_AUTOSAR_ALGOFAM_X25519);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOFAM_ECDH, WH_AUTOSAR_ALGOFAM_ECDH);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOMODE_ECB, WH_AUTOSAR_ALGOMODE_ECB);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOMODE_CBC, WH_AUTOSAR_ALGOMODE_CBC);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOMODE_CTR, WH_AUTOSAR_ALGOMODE_CTR);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOMODE_GCM, WH_AUTOSAR_ALGOMODE_GCM);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOMODE_RSASSA_PSS, WH_AUTOSAR_ALGOMODE_PSS);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOMODE_RSASSA_PKCS1_V1_5,
                     WH_AUTOSAR_ALGOMODE_PKCS1_V1_5);
WH_AUTOSAR_ASSERT_EQ(CRYPTO_ALGOMODE_CMAC, WH_AUTOSAR_ALGOMODE_CMAC);

#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
#include "Det.h"
#define CRYPTO_DET_REPORT(sid, errid) \
    (void)Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, (sid), (errid))
#else
#define CRYPTO_DET_REPORT(sid, errid) ((void)0)
#endif

static wh_AutosarDriverObject s_driverObjects[CRYPTO_DRIVER_OBJECT_COUNT];
static boolean                s_initialised = FALSE;

/* No-op defaults; integrators map these to SchM critical sections. */
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

void Crypto_Init(const Crypto_ConfigType* configPtr)
{
    uint32 i;

    (void)configPtr;

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

    if (job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_SYNC) {
        return wh_Autosar_ProcessJobSync(obj, job);
    }
    return wh_Autosar_ProcessJobAsync(obj, job);
}

Std_ReturnType Crypto_CancelJob(uint32 objectId, Crypto_JobType* job)
{
    wh_AutosarDriverObject* obj;
    uint32                  i;
    Std_ReturnType          ret = E_NOT_OK;

    if (!s_initialised) {
        CRYPTO_DET_REPORT(CRYPTO_CANCELJOB_SID, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
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
                slot->state = WH_AUTOSAR_ASYNC_IDLE;
                slot->job   = NULL;
                ret         = E_OK;
                break;
            case WH_AUTOSAR_ASYNC_CANCELLING:
                ret = E_OK;
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
