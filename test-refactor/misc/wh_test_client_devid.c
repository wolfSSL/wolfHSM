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
 * test-refactor/misc/wh_test_client_devid.c
 *
 * Client devId registration lifecycle. Equivalent coverage to
 * test/wh_test_multiclient.c::whTest_MultiClientDevIdLifecycle.
 *
 * wh_Client_Init registers the client's devIds in wolfCrypt's process-global,
 * fixed-size cryptoCb table and wh_Client_Cleanup must unregister them: the
 * table is only reset when the last wolfCrypt user in the process cleans up,
 * so a leaked entry both consumes a table slot and keeps dispatching into the
 * dead client context. Every Init rebinds the global WH_DEV_ID (and
 * WH_DEV_ID_DMA with DMA) to its own context and additionally registers the
 * configured devId when it differs from WH_DEV_ID; any client's Cleanup
 * unregisters the globals. These tests observe table occupancy through the
 * only public accessors (Register/UnRegister) by counting how many throwaway
 * registrations fit before the table is full.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLF_CRYPTO_CB)

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define BUFFER_SIZE 4096

/* Throwaway devId base for probing free cryptoCb table slots ("WHT\0"+i).
 * Outside the global devIds (WH_DEV_ID / WH_DEV_ID_DMA), the custom test
 * devIds, and the fill range below. */
#define PROBE_DEV_ID_BASE 0x57485400
/* Upper bound on probed slots. Must be >= wolfCrypt's
 * MAX_CRYPTO_DEVID_CALLBACKS (internal to cryptocb.c; default 8). */
#define PROBE_MAX_SLOTS 128

/* Separate devId base ("WHU\0"+i) for table-fill entries that stay
 * registered while _countFreeCryptoCbSlots() runs: wolfCrypt re-registration
 * of an existing devId reuses its entry, so fill ids must never collide with
 * the probe ids or the count comes back wrong (and the counter's
 * unregistration pass would tear the fill entries down). */
#define FILL_DEV_ID_BASE 0x57485500

/* Global devIds rebound by every wh_Client_Init: WH_DEV_ID, plus
 * WH_DEV_ID_DMA when DMA support is compiled in. Their table slots are
 * shared by all clients in the process (each Init rebinds the same
 * entries). */
#ifdef WOLFHSM_CFG_DMA
#define GLOBAL_DEVID_COUNT 2
#else
#define GLOBAL_DEVID_COUNT 1
#endif

/* Slots consumed by one wh_Client_Init with a custom (non-default) devId on
 * an otherwise unoccupied table: the globals plus the configured devId */
#define DEVIDS_PER_INIT (GLOBAL_DEVID_COUNT + 1)

/* Custom per-client devIds for the two-client cases ("WH"+n). Distinct from
 * WH_DEV_ID, WH_DEV_ID_DMA, and the probe range. */
#define TEST_DEVID_1 0x57480001
#define TEST_DEVID_2 0x57480002

static int _probeCryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)info;
    (void)ctx;
    return CRYPTOCB_UNAVAILABLE;
}

/* Count free slots in the cryptoCb table by registering throwaway devIds
 * until registration fails, then unregistering them all. */
static int _countFreeCryptoCbSlots(void)
{
    int count = 0;
    int i;

    for (i = 0; i < PROBE_MAX_SLOTS; i++) {
        if (wc_CryptoCb_RegisterDevice(PROBE_DEV_ID_BASE + i, _probeCryptoCb,
                                       NULL) != 0) {
            break;
        }
        count++;
    }
    for (i = 0; i < count; i++) {
        wc_CryptoCb_UnRegisterDevice(PROBE_DEV_ID_BASE + i);
    }
    return count;
}

static int _whTest_ClientDevIdLifecycle(void)
{
    int slotsBase = 0;
    int slots     = 0;
    int rc        = 0;
    int i         = 0;

    /* Client transports: no servers needed, registration lifecycle only */
    static uint8_t       req1[BUFFER_SIZE];
    static uint8_t       resp1[BUFFER_SIZE];
    whTransportMemConfig tmcf1[1] = {{
        .req       = (whTransportMemCsr*)req1,
        .req_size  = sizeof(req1),
        .resp      = (whTransportMemCsr*)resp1,
        .resp_size = sizeof(resp1),
    }};

    whTransportClientCb         tccb1[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc1[1]    = {0};
    whCommClientConfig          cc_conf1[1] = {{
                 .transport_cb      = tccb1,
                 .transport_context = (void*)tmcc1,
                 .transport_config  = (void*)tmcf1,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientContext             client1[1]  = {0};
    whClientConfig              c_conf1[1]  = {{
                      .comm = cc_conf1,
    }};

    static uint8_t       req2[BUFFER_SIZE];
    static uint8_t       resp2[BUFFER_SIZE];
    whTransportMemConfig tmcf2[1] = {{
        .req       = (whTransportMemCsr*)req2,
        .req_size  = sizeof(req2),
        .resp      = (whTransportMemCsr*)resp2,
        .resp_size = sizeof(resp2),
    }};

    whTransportClientCb         tccb2[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc2[1]    = {0};
    whCommClientConfig          cc_conf2[1] = {{
                 .transport_cb      = tccb2,
                 .transport_context = (void*)tmcc2,
                 .transport_config  = (void*)tmcf2,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID + 1,
    }};
    whClientContext             client2[1]  = {0};
    whClientConfig              c_conf2[1]  = {{
                      .comm = cc_conf2,
    }};

    /* Client ids outside 1..WH_CLIENT_ID_MAX are rejected before any
     * initialization */
    cc_conf1[0].client_id = 0;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Client_Init(client1, c_conf1));
    cc_conf1[0].client_id = WH_CLIENT_ID_MAX + 1;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Client_Init(client1, c_conf1));
    cc_conf1[0].client_id = WH_TEST_DEFAULT_CLIENT_ID;

    /* Negative devIds and (with DMA) the reserved WH_DEV_ID_DMA are
     * rejected before any initialization */
    c_conf1[0].devId = -1;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Client_Init(client1, c_conf1));
#ifdef WOLFHSM_CFG_DMA
    c_conf1[0].devId = WH_DEV_ID_DMA;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Client_Init(client1, c_conf1));
#endif /* WOLFHSM_CFG_DMA */
    c_conf1[0].devId = 0;

    /* Hold an app-level wolfCrypt reference for the whole test so the
     * cryptoCb table is never reset by a final wolfCrypt_Cleanup: any entry
     * a client leaks stays visible, as it would in a process with other
     * active wolfCrypt users. */
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());

    slotsBase = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slotsBase >= GLOBAL_DEVID_COUNT + 2);

    /* A config that leaves devId 0 binds the default WH_DEV_ID; only the
     * global devIds occupy table slots */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client1, c_conf1));
    WH_TEST_ASSERT_RETURN(WH_CLIENT_DEVID(client1) == WH_DEV_ID);
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - GLOBAL_DEVID_COUNT);

    /* Cleanup must release every slot Init consumed even though wolfCrypt
     * stays initialized (the app still holds a reference) */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);

    /* Re-init with the same config must succeed and register again */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client1, c_conf1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - GLOBAL_DEVID_COUNT);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);

    /* A custom configured devId is registered alongside the globals */
    c_conf1[0].devId = TEST_DEVID_1;
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client1, c_conf1));
    WH_TEST_ASSERT_RETURN(WH_CLIENT_DEVID(client1) == TEST_DEVID_1);
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - DEVIDS_PER_INIT);

    /* Two simultaneously active clients with distinct devIds: the second
     * Init rebinds the shared global entries (net zero new slots) and adds
     * only its own devId */
    c_conf2[0].devId = TEST_DEVID_2;
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client2, c_conf2));
    WH_TEST_ASSERT_RETURN(WH_CLIENT_DEVID(client2) == TEST_DEVID_2);
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - DEVIDS_PER_INIT - 1);

    /* Cleaning up one client releases its own devId and the shared global
     * devIds -- the globals are yanked from the still-active sibling, which
     * is the documented single-client contract for WH_DEV_ID/WH_DEV_ID_DMA.
     * The sibling's own configured devId stays registered. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - 1);

    /* Re-init the first client while the second stays active: the globals
     * are rebound and both custom devIds are live again */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client1, c_conf1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - DEVIDS_PER_INIT - 1);

    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client2));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - 1);

    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);
    c_conf1[0].devId = 0;
    c_conf2[0].devId = 0;

    /* Init with a full cryptoCb table must fail cleanly (WH_ERROR_ABORTED)
     * and the failure-path cleanup must not disturb existing entries */
    for (i = 0; i < slotsBase; i++) {
        WH_TEST_RETURN_ON_FAIL(wc_CryptoCb_RegisterDevice(
            FILL_DEV_ID_BASE + i, _probeCryptoCb, NULL));
    }
    rc = wh_Client_Init(client1, c_conf1);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(WH_CLIENT_DEVID(client1) == 0);
    for (i = 0; i < slotsBase; i++) {
        wc_CryptoCb_UnRegisterDevice(FILL_DEV_ID_BASE + i);
    }
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);

    /* Init that fails partway through its registrations (the custom devId
     * fits, but a later global rebind hits the full table) must unwind
     * exactly the entries it registered and leave the fill entries intact */
    for (i = 0; i < slotsBase - (DEVIDS_PER_INIT - 1); i++) {
        WH_TEST_RETURN_ON_FAIL(wc_CryptoCb_RegisterDevice(
            FILL_DEV_ID_BASE + i, _probeCryptoCb, NULL));
    }
    c_conf1[0].devId = TEST_DEVID_1;
    rc               = wh_Client_Init(client1, c_conf1);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == DEVIDS_PER_INIT - 1);
    for (i = 0; i < slotsBase - (DEVIDS_PER_INIT - 1); i++) {
        wc_CryptoCb_UnRegisterDevice(FILL_DEV_ID_BASE + i);
    }
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);
    c_conf1[0].devId = 0;

    (void)wolfCrypt_Cleanup();

    return 0;
}

int whTest_ClientDevId(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing client devId registration lifecycle...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientDevIdLifecycle());

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && !WOLFHSM_CFG_NO_CRYPTO && \
        * WOLF_CRYPTO_CB */
