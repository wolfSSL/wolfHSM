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
 * test/wh_test_she_no_nvm.c
 *
 * NVM-less SHE test. A server is started with a NULL NVM context
 * (whServerConfig.nvm == NULL) and a client provisions every SHE key it needs
 * purely from client-held AES-GCM wrapped blobs: it wraps the plaintext SHE
 * keys into blobs under the boot-provisioned server KEK, then primes them into
 * the server's volatile key cache via unwrap-and-cache. The client then
 * drives the client-facing SHE surface (secure boot, LoadKey, LoadPlainKey,
 * ECB/CBC, CMAC, ExportRamKey, and the PRNG) to prove it all works without
 * any NVM backing.
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy, strlen */

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

#if defined(WOLFHSM_CFG_SHE_EXTENSION) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_KEYWRAP)

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"

/* The threaded harness with a NULL-NVM server needs POSIX threads plus both a
 * client and an in-process server, and AES-GCM for the wrapped-key blobs. */
#if defined(HAVE_AESGCM) && defined(WOLFHSM_CFG_TEST_POSIX) && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <pthread.h>

#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_she.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_she.h"
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_she_crypto.h"

#include "wh_test_common.h"
#include "wh_test_keywrap_util.h"
#include "wh_test_she_no_nvm.h"

enum {
    BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                  WOLFHSM_CFG_COMM_DATA_LEN,
};

#ifndef TEST_ADMIN_USERNAME
#define TEST_ADMIN_USERNAME "admin"
#endif
#ifndef TEST_ADMIN_PIN
#define TEST_ADMIN_PIN "1234"
#endif

/* Test KEK cache id (intrinsic in production; the server task provisions the
 * key, whTest_KeywrapKek, in its cache the way boot code would). */
#define SHE_NONVM_KEK_ID 0x20
/* SHE slot provisioned via unwrap-and-cache and used directly. */
#define SHE_NONVM_WORKING_SLOT 4
/* SHE slot loaded through the SheLoadKey protocol (cache path). */
#define SHE_NONVM_USER_SLOT 5
/* Wrapped-blob size for one 16-byte SHE key (matches the server's KEK). */
#define SHE_NONVM_BLOB_SZ \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(whNvmMetadata) + WH_SHE_KEY_SZ)

/* ---- Hardcoded plaintext test material ---------------------------------- */

static const uint8_t s_uid[WH_SHE_UID_SZ] = {0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x01};

/* Reused from the SHE test vectors. */
static const uint8_t s_secretKey[WH_SHE_KEY_SZ] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t s_masterEcuKey[WH_SHE_KEY_SZ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t s_bootMacKey[WH_SHE_KEY_SZ] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90};
static const uint8_t s_workingKey[WH_SHE_KEY_SZ] = {
    0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98};
static const uint8_t s_userKey[WH_SHE_KEY_SZ] = {
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
static const uint8_t s_prngSeed[WH_SHE_KEY_SZ] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
static const uint8_t s_entropy[WH_SHE_KEY_SZ] = {
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};

/* A SHE key the test holds as a client-side wrapped blob, plus its plaintext
 * and SHE label fields. */
typedef struct {
    whKeyId  slot;    /* SHE slot id (WH_SHE_*_ID) */
    uint32_t counter; /* SHE label counter */
    uint32_t flags;   /* SHE label flags */
    uint8_t  plain[WH_SHE_KEY_SZ];
    uint8_t  blob[SHE_NONVM_BLOB_SZ];
    uint16_t blobSz;
} SheNoNvmKey;

/* boot MAC digest = CMAC_bootMacKey(zeros || size || bootloader) */
static int _ComputeBootMac(const uint8_t* bootloader, uint32_t bootloaderSz,
                           const uint8_t* bootMacKey, uint8_t* digestOut)
{
    int     ret;
    Cmac    cmac[1];
    uint8_t zeros[WH_SHE_BOOT_MAC_PREFIX_LEN] = {0};
    word32  digestSz                          = WH_SHE_KEY_SZ;

    if ((ret = wc_InitCmac(cmac, bootMacKey, WH_SHE_KEY_SZ, WC_CMAC_AES,
                           NULL)) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, zeros, sizeof(zeros))) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, (const uint8_t*)&bootloaderSz,
                             sizeof(bootloaderSz))) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, bootloader, bootloaderSz)) != 0) {
        return ret;
    }
    digestSz = AES_BLOCK_SIZE;
    return wc_CmacFinal(cmac, digestOut, &digestSz);
}

/* Wrap every SHE key the test uses into a client-held blob, under the
 * trusted KEK that boot code provisioned in the server cache
 * (_ProvisionServerKek). Unwrap-and-cache requires a trusted KEK
 * (WH_NVM_FLAGS_TRUSTED), which a client can never set, so the client cannot
 * upload the KEK; it only names it by id and wraps under the same known
 * bytes. */
static int _WrapSheKeyBlobs(whClientContext* client, SheNoNvmKey* keys, int n)
{
    int ret;
    int i;

    for (i = 0; i < n; i++) {
        keys[i].blobSz = (uint16_t)sizeof(keys[i].blob);
        ret            = whTest_BuildSheKeyBlob(
            whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
            WH_MAKE_KEYID(WH_KEYTYPE_SHE, client->comm->client_id,
                                     keys[i].slot),
            keys[i].counter, keys[i].flags, keys[i].plain, keys[i].blob,
            &keys[i].blobSz);
        if (ret != 0) {
            WH_ERROR_PRINT("no-nvm: wrap SHE slot %u failed %d\n",
                           (unsigned)keys[i].slot, ret);
            return ret;
        }
    }

    return 0;
}

/* Unwrap and cache every SHE key blob so the keys are resident in the
 * server's volatile cache, ready for the SHE API to use. */
static int _UnwrapAndCacheSHEKeys(whClientContext* client, SheNoNvmKey* keys,
                                  int n, whKeyId kekId)
{
    int      ret;
    int      i;
    uint16_t outId;

    for (i = 0; i < n; i++) {
        outId = 0;
        ret   = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                                            keys[i].blob, keys[i].blobSz, &outId);
        if (ret != 0) {
            WH_ERROR_PRINT("no-nvm: unwrap-and-cache SHE slot %u failed %d\n",
                           (unsigned)keys[i].slot, ret);
            return ret;
        }
    }

    return 0;
}

static int _SheNoNvmClientConfig(whClientConfig* config)
{
    int             ret         = 0;
    whClientContext client[1]   = {0};
    uint32_t        outClientId = 0;
    uint32_t        outServerId = 0;
    whKeyId         kekId       = SHE_NONVM_KEK_ID;

    uint8_t  bootloader[64];
    uint32_t bootloaderSz = sizeof(bootloader);
    uint8_t  sreg         = 0;

    uint8_t m1[WH_SHE_M1_SZ];
    uint8_t m2[WH_SHE_M2_SZ];
    uint8_t m3[WH_SHE_M3_SZ];
    uint8_t m4[WH_SHE_M4_SZ];
    uint8_t m5[WH_SHE_M5_SZ];
    uint8_t o4[WH_SHE_M4_SZ];
    uint8_t o5[WH_SHE_M5_SZ];

    uint8_t plain[WH_SHE_KEY_SZ];
    uint8_t cipher[WH_SHE_KEY_SZ];
    uint8_t back[WH_SHE_KEY_SZ];
    uint8_t mac[WH_SHE_KEY_SZ];
    uint8_t iv[WH_SHE_KEY_SZ] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                 0x0c, 0x0d, 0x0e, 0x0f};

    /* SHE keys provisioned purely from client-held wrapped blobs:
     *   SECRET_KEY     - auth for ExportRamKey and PRNG derivation
     *   MASTER_ECU_KEY - auth for the user-slot LoadKey below
     *   BOOT_MAC_KEY   - secure-boot CMAC key
     *   BOOT_MAC       - expected bootloader CMAC (computed below)
     *   working slot   - used directly via the SHE cipher API
     *   PRNG_SEED      - seed state for InitRnd/ExtendSeed
     * SECRET_KEY is SHE slot 0; priming it via unwrap-and-cache relies on the
     * keystore exempting SHE keys from the "id 0 == unassigned" check. */
    SheNoNvmKey keys[6];

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInit(client, &outClientId, &outServerId));
#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthLogin(
        client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME, TEST_ADMIN_PIN,
        strlen(TEST_ADMIN_PIN), &ret, NULL));
#endif

    /* Build the key table. Plaintext is hardcoded; BOOT_MAC is the CMAC of the
     * (fixed) bootloader so secure boot will accept it. */
    memset(bootloader, 0xB7, sizeof(bootloader));
    memset(keys, 0, sizeof(keys));

    keys[0].slot    = WH_SHE_SECRET_KEY_ID;
    keys[0].counter = 1;
    memcpy(keys[0].plain, s_secretKey, WH_SHE_KEY_SZ);

    keys[1].slot    = WH_SHE_MASTER_ECU_KEY_ID;
    keys[1].counter = 1;
    memcpy(keys[1].plain, s_masterEcuKey, WH_SHE_KEY_SZ);

    keys[2].slot    = WH_SHE_BOOT_MAC_KEY_ID;
    keys[2].counter = 1;
    memcpy(keys[2].plain, s_bootMacKey, WH_SHE_KEY_SZ);

    keys[3].slot    = WH_SHE_BOOT_MAC;
    keys[3].counter = 1;
    ret =
        _ComputeBootMac(bootloader, bootloaderSz, s_bootMacKey, keys[3].plain);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: compute BOOT_MAC failed %d\n", ret);
        goto exit;
    }

    keys[4].slot    = SHE_NONVM_WORKING_SLOT;
    keys[4].counter = 1;
    memcpy(keys[4].plain, s_workingKey, WH_SHE_KEY_SZ);

    keys[5].slot    = WH_SHE_PRNG_SEED_ID;
    keys[5].counter = 1;
    memcpy(keys[5].plain, s_prngSeed, WH_SHE_KEY_SZ);

    /* wrap every SHE key into a client-held blob under the server's KEK */
    ret = _WrapSheKeyBlobs(client, keys, 6);
    if (ret != 0) {
        goto exit;
    }

    /* prime them into the NULL-NVM server's volatile cache */
    ret = _UnwrapAndCacheSHEKeys(client, keys, 6, kekId);
    if (ret != 0) {
        goto exit;
    }
    WH_TEST_PRINT("SHE no-nvm: unwrap-and-cache provisioning SUCCESS\n");

    /* Secure boot using the cached BOOT_MAC_KEY + BOOT_MAC. */
    ret = wh_Client_SheSetUid(client, (uint8_t*)s_uid, sizeof(s_uid));
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheSetUid failed %d\n", ret);
        goto exit;
    }
    ret = wh_Client_SheSecureBoot(client, bootloader, bootloaderSz);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheSecureBoot failed %d\n", ret);
        goto exit;
    }
    ret = wh_Client_SheGetStatus(client, &sreg);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheGetStatus failed %d\n", ret);
        goto exit;
    }
    if ((sreg & WH_SHE_SREG_BOOT_OK) == 0 ||
        (sreg & WH_SHE_SREG_BOOT_FINISHED) == 0 ||
        (sreg & WH_SHE_SREG_SECURE_BOOT) == 0) {
        WH_ERROR_PRINT("no-nvm: secure boot status 0x%02x\n", sreg);
        ret = WH_ERROR_ABORTED;
        goto exit;
    }
    WH_TEST_PRINT("SHE no-nvm: secure boot SUCCESS\n");

    /* LoadKey cache path: load a user key (auth = master ECU key, primed via
     * unwrap-and-cache above). The loaded key lands in the cache because the
     * server has no NVM (src/wh_server_she.c LOAD_KEY nvm==NULL guard). */
    ret = wh_She_GenerateLoadableKey(
        SHE_NONVM_USER_SLOT, WH_SHE_MASTER_ECU_KEY_ID, 1, 0, (uint8_t*)s_uid,
        (uint8_t*)s_userKey, (uint8_t*)s_masterEcuKey, m1, m2, m3, m4, m5);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: generate user-slot M1/M2/M3 failed %d\n", ret);
        goto exit;
    }
    ret = wh_Client_SheLoadKey(client, m1, m2, m3, o4, o5);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: LoadKey user slot failed %d\n", ret);
        goto exit;
    }
    WH_TEST_PRINT("SHE no-nvm: LoadKey (cache path) SUCCESS\n");

    /* ECB round trip on the LoadKey-provisioned user slot. */
    memset(plain, 0x11, sizeof(plain));
    ret = wh_Client_SheEncEcb(client, SHE_NONVM_USER_SLOT, plain, cipher,
                              sizeof(plain));
    if (ret == 0) {
        ret = wh_Client_SheDecEcb(client, SHE_NONVM_USER_SLOT, cipher, back,
                                  sizeof(cipher));
    }
    if (ret != 0 || memcmp(plain, back, sizeof(plain)) != 0) {
        WH_ERROR_PRINT("no-nvm: user-slot ECB round trip failed %d\n", ret);
        ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
        goto exit;
    }

    /* ECB round trip on the unwrap-and-cache-provisioned working slot. */
    memset(plain, 0x22, sizeof(plain));
    ret = wh_Client_SheEncEcb(client, SHE_NONVM_WORKING_SLOT, plain, cipher,
                              sizeof(plain));
    if (ret == 0) {
        ret = wh_Client_SheDecEcb(client, SHE_NONVM_WORKING_SLOT, cipher, back,
                                  sizeof(cipher));
    }
    if (ret != 0 || memcmp(plain, back, sizeof(plain)) != 0) {
        WH_ERROR_PRINT("no-nvm: working-slot ECB round trip failed %d\n", ret);
        ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
        goto exit;
    }
    WH_TEST_PRINT("SHE no-nvm: ECB round trips SUCCESS\n");

    /* RAM key: plain load, ECB, then export + re-import round trip. The
     * exported M1..M5 authenticate with SECRET_KEY (slot 0); re-importing
     * reproduces the same RAM key, so decrypting the earlier ciphertext must
     * round-trip back to the plaintext. */
    ret = wh_Client_SheLoadPlainKey(client, (uint8_t*)s_workingKey,
                                    WH_SHE_KEY_SZ);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheLoadPlainKey failed %d\n", ret);
        goto exit;
    }
    memset(plain, 0x33, sizeof(plain));
    ret = wh_Client_SheEncEcb(client, WH_SHE_RAM_KEY_ID, plain, cipher,
                              sizeof(plain));
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: RAM EncEcb failed %d\n", ret);
        goto exit;
    }
    ret = wh_Client_SheExportRamKey(client, m1, m2, m3, m4, m5);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: SheExportRamKey failed %d\n", ret);
        goto exit;
    }
    ret = wh_Client_SheLoadKey(client, m1, m2, m3, o4, o5);
    if (ret != 0) {
        WH_ERROR_PRINT("no-nvm: re-import exported RAM key failed %d\n", ret);
        goto exit;
    }
    ret = wh_Client_SheDecEcb(client, WH_SHE_RAM_KEY_ID, cipher, back,
                              sizeof(cipher));
    if (ret != 0 || memcmp(plain, back, sizeof(plain)) != 0) {
        WH_ERROR_PRINT("no-nvm: RAM ECB export round trip failed %d\n", ret);
        ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
        goto exit;
    }
    WH_TEST_PRINT("SHE no-nvm: ExportRamKey round trip SUCCESS\n");

    memset(plain, 0x44, sizeof(plain));
    ret = wh_Client_SheEncCbc(client, WH_SHE_RAM_KEY_ID, iv, sizeof(iv), plain,
                              cipher, sizeof(plain));
    if (ret == 0) {
        ret = wh_Client_SheDecCbc(client, WH_SHE_RAM_KEY_ID, iv, sizeof(iv),
                                  cipher, back, sizeof(cipher));
    }
    if (ret != 0 || memcmp(plain, back, sizeof(plain)) != 0) {
        WH_ERROR_PRINT("no-nvm: RAM CBC round trip failed %d\n", ret);
        ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
        goto exit;
    }

    ret = wh_Client_SheGenerateMac(client, WH_SHE_RAM_KEY_ID, plain,
                                   sizeof(plain), mac, sizeof(mac));
    if (ret == 0) {
        ret = wh_Client_SheVerifyMac(client, WH_SHE_RAM_KEY_ID, plain,
                                     sizeof(plain), mac, sizeof(mac), &sreg);
    }
    if (ret != 0 || sreg != 0) {
        WH_ERROR_PRINT("no-nvm: RAM CMAC failed ret=%d status=%d\n", ret, sreg);
        ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
        goto exit;
    }
    WH_TEST_PRINT("SHE no-nvm: RAM key ECB/CBC/CMAC SUCCESS\n");

    /* PRNG: init from SECRET_KEY + PRNG_SEED, draw a block, then extend the
     * seed. InitRnd/ExtendSeed cache the updated PRNG seed since there is no
     * NVM to persist it to. */
    {
        uint8_t  rnd[WH_SHE_KEY_SZ];
        uint32_t rndSz = sizeof(rnd);

        ret = wh_Client_SheInitRnd(client);
        if (ret == 0) {
            ret = wh_Client_SheRnd(client, rnd, &rndSz);
        }
        if (ret == 0) {
            ret = wh_Client_SheExtendSeed(client, (uint8_t*)s_entropy,
                                          sizeof(s_entropy));
        }
        if (ret != 0) {
            WH_ERROR_PRINT("no-nvm: PRNG init/rnd/extend failed %d\n", ret);
            goto exit;
        }
    }
    WH_TEST_PRINT("SHE no-nvm: PRNG (init/rnd/extend) SUCCESS\n");

    /* The boot-provisioned KEK is a WH_NVM_FLAGS_TRUSTED key: the client
     * must be able neither to read it nor to evict it. */
    {
        uint8_t  kbuf[sizeof(whTest_KeywrapKek)];
        uint16_t kbufSz = (uint16_t)sizeof(kbuf);
        uint8_t  klabel[WH_NVM_LABEL_LEN];

        ret = wh_Client_KeyExport(client, kekId, klabel, sizeof(klabel), kbuf,
                                  &kbufSz);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("no-nvm: KEK export expected ACCESS, got %d\n", ret);
            ret = (ret == 0) ? WH_ERROR_ABORTED : ret;
            goto exit;
        }
        ret = wh_Client_KeyEvict(client, kekId);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("no-nvm: KEK evict expected ACCESS, got %d\n", ret);
            ret = (ret == 0) ? WH_ERROR_ABORTED : ret;
            goto exit;
        }
        ret = 0;
    }
    WH_TEST_PRINT("SHE no-nvm: KEK unreadable and immutable SUCCESS\n");
    WH_TEST_PRINT("SHE no-nvm flow SUCCESS\n");

exit:
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommClose(client));
    if (ret == 0) {
        WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));
    }
    else {
        wh_Client_Cleanup(client);
    }

    return ret;
}

/* Provision the trusted KEK directly in the server cache, the way boot code
 * would on an NVM-less device. It carries WH_NVM_FLAGS_TRUSTED -- a flag the
 * request handlers strip from every client path, so only server-internal
 * provisioning like this can set it. That makes it the trusted KEK that
 * unwrap-and-cache requires. committed=0 keeps it pinned for the life of
 * the (NVM-less) server. The id matches what the client names: plain
 * SHE_NONVM_KEK_ID translated against WH_TEST_DEFAULT_CLIENT_ID. */
static int _ProvisionServerKek(whServerContext* server)
{
    whNvmMetadata meta = {0};

    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID,
                                SHE_NONVM_KEK_ID);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP |
                 WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_NONMODIFIABLE;
    meta.len = (whNvmSize)sizeof(whTest_KeywrapKek);
    memcpy(meta.label, "SHE no-nvm KEK", sizeof("SHE no-nvm KEK"));

    return wh_Server_KeystoreCacheKey(server, &meta,
                                      (uint8_t*)whTest_KeywrapKek);
}

/* Server event loop, started on its own thread with a NULL NVM context. */
static int _SheNoNvmServerConfig(whServerConfig* config)
{
    whServerContext server[1]    = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int             ret          = 0;

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, config));
    /* Boot-time KEK provisioning happens before the server accepts requests. */
    WH_TEST_RETURN_ON_FAIL(_ProvisionServerKek(server));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));

    while (am_connected == WH_COMM_CONNECTED) {
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) && (ret != WH_ERROR_OK)) {
            WH_ERROR_PRINT("no-nvm: HandleRequestMessage failed %d\n", ret);
            break;
        }
        wh_Server_GetConnected(server, &am_connected);
    }
    if ((ret == 0) || (ret == WH_ERROR_NOTREADY)) {
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    }
    else {
        ret = wh_Server_Cleanup(server);
    }

    return ret;
}

static void* _SheNoNvmServerTask(void* cf)
{
    WH_TEST_ASSERT(0 == _SheNoNvmServerConfig((whServerConfig*)cf));
    return NULL;
}

static void* _SheNoNvmClientTask(void* cf)
{
    WH_TEST_ASSERT(0 == _SheNoNvmClientConfig((whClientConfig*)cf));
    return NULL;
}

static void _SheNoNvmThreadTest(whClientConfig* c_conf, whServerConfig* s_conf)
{
    pthread_t cthread = {0};
    pthread_t sthread = {0};
    void*     retval;
    int       rc = 0;

    rc = pthread_create(&sthread, NULL, _SheNoNvmServerTask, s_conf);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _SheNoNvmClientTask, c_conf);
        if (rc == 0) {
            /* All good. Block on joining */
            pthread_join(cthread, &retval);
            pthread_join(sthread, &retval);
        }
        else {
            /* Cancel the server thread */
            pthread_cancel(sthread);
            pthread_join(sthread, &retval);
        }
    }
}

int whTest_SheNoNvm(void)
{
    /* Memory transport shared between client and server threads. */
    uint8_t              req[BUFFER_SIZE]  = {0};
    uint8_t              resp[BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]           = {{
                  .req       = (whTransportMemCsr*)req,
                  .req_size  = sizeof(req),
                  .resp      = (whTransportMemCsr*)resp,
                  .resp_size = sizeof(resp),
    }};

    /* Client configuration/contexts */
    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientConfig              c_conf[1]  = {{
                      .comm = cc_conf,
    }};

    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    whServerCryptoContext crypto[1] = {0};
    whServerSheContext    she[1];

    /* The whole point of this test: a server with NO NVM backing. */
    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = NULL,
        .crypto      = crypto,
        .she         = she,
        .devId       = INVALID_DEVID,
    }};

    memset(she, 0, sizeof(she));

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));

    _SheNoNvmThreadTest(c_conf, s_conf);

    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}

#endif /* HAVE_AESGCM && WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT \
          && WOLFHSM_CFG_ENABLE_SERVER */

#endif /* WOLFHSM_CFG_SHE_EXTENSION && !WOLFHSM_CFG_NO_CRYPTO && \
          WOLFHSM_CFG_KEYWRAP */
