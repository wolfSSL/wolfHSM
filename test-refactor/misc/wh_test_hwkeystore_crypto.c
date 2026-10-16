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
 * test-refactor/misc/wh_test_hwkeystore_crypto.c
 *
 * End-to-end test of hardware keys in AES and CMAC requests and as key wrap
 * KEKs, with clients loading keys (WOLFHSM_CFG_HWKEYSTORE_LOAD). Two clients
 * talk to two servers that share
 * one NVM and one hardware keystore, like one HSM serving two cores.
 *
 * The servers' crypto callback is a mock AES engine with eight write-only
 * AES-128 key slots with some arbitrary restrictions:
 *   K0, K1  device keys that no client can name
 *   K2      a key the port loads at boot. Clients can use it but not set or
 *           clear it
 *   K3, K4  loadable by clients for generic use
 *   K5-K7   used as scratch keys for port-internal functionality
 * The mock runs each operation with wolfCrypt in software, using the key in
 * the slot, and implements the wolfCrypt keystore callback that loads, clears
 * and describes slots.
 *
 * Each client talks to its server over the autopoll mem transport
 * (wh_test_transport_mem_autopoll.h), so the blocking client APIs work without
 * threads.
 *
 *   _whTest_HwKeyMap          - GetInfo for every hardware key ID
 *   _whTest_HwKeyPortKey      - both clients use K2 but can't set or clear it
 *   _whTest_HwKeyLoadAndUse   - load a keystore key into a hardware key and use
 *                               it in every AES mode and CMAC, standard and DMA
 *   _whTest_HwKeyAllocation   - picking a free key, explicit IDs, running out,
 *                               reloading, and another client's keys
 *   _whTest_HwKeyUsage        - the copy keeps the source key's usage flags,
 *                               and every AES and CMAC request checks them
 *   _whTest_HwKeySource       - evict keeps the copy, erase and revoke clear it
 *   _whTest_HwKeyRefused      - sources and targets the server or port refuses
 *   _whTest_HwKeyClear        - Clear and ClearAll
 *   _whTest_HwKeyShared       - keys loaded with the global flag
 *   _whTest_HwKeyNoFallback   - a key the hardware lost fails instead of
 *                               running in software
 *   _whTest_HwKeyKek          - the port key and client-loaded keys as key wrap
 *                               KEKs: only port keys are trusted
 *   _whTest_HwKeyPortKeyOwner - a port key registered for one client
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) &&                            \
    defined(WOLFHSM_CFG_ENABLE_SERVER) &&                            \
    defined(WOLFHSM_CFG_HWKEYSTORE_LOAD) && defined(HAVE_AES_ECB) && \
    defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_COUNTER) &&         \
    defined(HAVE_AESGCM) && defined(WOLFSSL_CMAC) &&                 \
    defined(WOLFSSL_AES_DIRECT)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_hwkeystore.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"

#include "wh_test_common.h"
#include "wh_test_list.h"
#include "wh_test_transport_mem_autopoll.h"

#define BUFFER_SIZE 4096
#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (128 * 1024)
#define FLASH_PAGE_SIZE 8

/* wolfCrypt devIds: the mock engine, and one per client */
#define MOCK_DEVID 0x4D4B4553
#define CLIENT1_DEVID 0x484B4331
#define CLIENT2_DEVID 0x484B4332

#define CLIENT1_ID WH_TEST_DEFAULT_CLIENT_ID
#define CLIENT2_ID (WH_TEST_DEFAULT_CLIENT_ID + 1)

/* Mock engine slots */
#define MOCK_SLOTS 8
#define MOCK_PORT_SLOT 2
#define MOCK_LOAD_FIRST 3
#define MOCK_LOAD_LAST 4

/* Client keyIds of the hardware keys */
#define HW(id) ((whKeyId)WH_CLIENT_KEYID_MAKE_HW(id))

#define USAGE_AES_CMAC                                         \
    (WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT | \
     WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY)

/* Test data sizes */
#define TEST_MSG_SZ 80
#define TEST_BLOCKS_SZ (3 * AES_BLOCK_SIZE) /* ECB and CBC */
#define TEST_CTR_SZ 37
#define TEST_GCM_SZ 37
#define TEST_CMAC_SZ 70
#define TEST_GCM_IV_SZ 12

/* Keystore IDs used by the tests */
#define SRC_SHARED_ID 0x20
#define SRC_TRUSTED_ID 0x21
#define SRC_MISSING_ID 0x22

/* ------------------------------------------------------------------------
 * Mock AES engine
 * ------------------------------------------------------------------------ */

/* What each slot may hold */
enum {
    MOCK_NONE = 0, /* Not a hardware key */
    MOCK_LOAD,     /* Loaded and cleared by clients */
    MOCK_PORT,     /* Loaded by the port at boot */
};

static const uint8_t _mockRole[MOCK_SLOTS] = {
    MOCK_NONE, /* K0 */
    MOCK_NONE, /* K1 */
    MOCK_PORT, /* K2 */
    MOCK_LOAD, /* K3 */
    MOCK_LOAD, /* K4 */
    MOCK_NONE, /* K5 */
    MOCK_NONE, /* K6 */
    MOCK_NONE, /* K7 */
};

typedef struct {
    uint8_t key[MOCK_SLOTS][AES_128_KEY_SIZE];
    uint8_t loaded[MOCK_SLOTS];
    int     ops; /* Operations run with a slot key */
} MockEngine;

static MockEngine _mock;

/* Test data */
static uint8_t _portKey[AES_128_KEY_SIZE];
static uint8_t _keyA[AES_128_KEY_SIZE];
static uint8_t _keyB[AES_128_KEY_SIZE];
static uint8_t _keyC[AES_128_KEY_SIZE];
static uint8_t _key256[AES_256_KEY_SIZE];
static uint8_t _msg[TEST_MSG_SZ];
static uint8_t _iv[AES_BLOCK_SIZE];
static uint8_t _aad[20];

/* Slot named by a key reference (the server keyId, big-endian), or -1 */
static int _MockRefSlot(const byte* ref, word32 refSz)
{
    whKeyId keyId;

    if ((ref == NULL) || (refSz != WH_HWKEYSTORE_REF_SIZE)) {
        return -1;
    }
    keyId = (whKeyId)(((whKeyId)ref[0] << 8) | ref[1]);
    if (!WH_KEYID_ISHW(keyId) || (WH_KEYID_ID(keyId) >= MOCK_SLOTS) ||
        (_mockRole[WH_KEYID_ID(keyId)] == MOCK_NONE)) {
        return -1;
    }
    return (int)WH_KEYID_ID(keyId);
}

/* Slot of a key set up by reference. A key wolfCrypt holds itself runs in
 * software. A reference to a slot with no key fails, since software has no
 * copy of it */
static int _MockKeySlot(const unsigned char* id, int idLen, int* slot)
{
    if (idLen <= 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    *slot = _MockRefSlot(id, (word32)idLen);
    if ((*slot < 0) || (_mock.loaded[*slot] == 0)) {
        return WC_HW_E;
    }
    return 0;
}

static int _MockKeystore(wc_CryptoInfo* info)
{
    int slot;

    switch (info->keystore.type) {
        case WC_KEYSTORE_IMPORT_PLAIN:
            slot = _MockRefSlot(info->keystore.op.importPlain.keyRef,
                                info->keystore.op.importPlain.keyRefSz);
            /* Only the loadable slots, and only AES-128 keys */
            if ((slot < 0) || (_mockRole[slot] != MOCK_LOAD) ||
                ((info->keystore.op.importPlain.keyType !=
                  WC_KEYSTORE_KEY_AES) &&
                 (info->keystore.op.importPlain.keyType !=
                  WC_KEYSTORE_KEY_CMAC)) ||
                (info->keystore.op.importPlain.keySz != AES_128_KEY_SIZE)) {
                return BAD_FUNC_ARG;
            }
            memcpy(_mock.key[slot], info->keystore.op.importPlain.key,
                   AES_128_KEY_SIZE);
            _mock.loaded[slot] = 1;
            return 0;

        case WC_KEYSTORE_DELETE:
            slot = _MockRefSlot(info->keystore.op.deleteKey.keyRef,
                                info->keystore.op.deleteKey.keyRefSz);
            if ((slot < 0) || (_mockRole[slot] != MOCK_LOAD)) {
                return BAD_FUNC_ARG;
            }
            wh_Utils_ForceZero(_mock.key[slot], AES_128_KEY_SIZE);
            _mock.loaded[slot] = 0;
            return 0;

        case WC_KEYSTORE_GET_INFO:
            slot = _MockRefSlot(info->keystore.op.getInfo.keyRef,
                                info->keystore.op.getInfo.keyRefSz);
            if (slot < 0) {
                return BAD_FUNC_ARG;
            }
            if (info->keystore.op.getInfo.keyType != NULL) {
                *info->keystore.op.getInfo.keyType = _mock.loaded[slot]
                                                         ? WC_KEYSTORE_KEY_AES
                                                         : WC_KEYSTORE_KEY_NONE;
            }
            if (info->keystore.op.getInfo.keyBits != NULL) {
                *info->keystore.op.getInfo.keyBits =
                    _mock.loaded[slot] ? 128 : 0;
            }
            if (info->keystore.op.getInfo.attrs != NULL) {
                *info->keystore.op.getInfo.attrs = 0;
            }
            return 0;

        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

static int _MockCipher(wc_CryptoInfo* info)
{
    Aes  sw[1];
    Aes* aes;
    int  slot;
    int  ret;

    switch (info->cipher.type) {
        case WC_CIPHER_AES_ECB:
            aes = info->cipher.aesecb.aes;
            break;
        case WC_CIPHER_AES_CBC:
            aes = info->cipher.aescbc.aes;
            break;
        case WC_CIPHER_AES_CTR:
            aes = info->cipher.aesctr.aes;
            break;
        case WC_CIPHER_AES_GCM:
            aes = (info->cipher.enc != 0) ? info->cipher.aesgcm_enc.aes
                                          : info->cipher.aesgcm_dec.aes;
            break;
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

    ret = _MockKeySlot(aes->id, aes->idLen, &slot);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesInit(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        switch (info->cipher.type) {
            case WC_CIPHER_AES_ECB:
                ret = wc_AesSetKey(sw, _mock.key[slot], AES_128_KEY_SIZE, NULL,
                                   (info->cipher.enc != 0) ? AES_ENCRYPTION
                                                           : AES_DECRYPTION);
                if ((ret == 0) && (info->cipher.enc != 0)) {
                    ret = wc_AesEcbEncrypt(sw, info->cipher.aesecb.out,
                                           info->cipher.aesecb.in,
                                           info->cipher.aesecb.sz);
                }
                else if (ret == 0) {
                    ret = wc_AesEcbDecrypt(sw, info->cipher.aesecb.out,
                                           info->cipher.aesecb.in,
                                           info->cipher.aesecb.sz);
                }
                break;

            case WC_CIPHER_AES_CBC:
                ret = wc_AesSetKey(sw, _mock.key[slot], AES_128_KEY_SIZE,
                                   (const byte*)aes->reg,
                                   (info->cipher.enc != 0) ? AES_ENCRYPTION
                                                           : AES_DECRYPTION);
                if ((ret == 0) && (info->cipher.enc != 0)) {
                    ret = wc_AesCbcEncrypt(sw, info->cipher.aescbc.out,
                                           info->cipher.aescbc.in,
                                           info->cipher.aescbc.sz);
                }
                else if (ret == 0) {
                    ret = wc_AesCbcDecrypt(sw, info->cipher.aescbc.out,
                                           info->cipher.aescbc.in,
                                           info->cipher.aescbc.sz);
                }
                /* Hand back the chaining value */
                memcpy(aes->reg, sw->reg, AES_BLOCK_SIZE);
                break;

            case WC_CIPHER_AES_CTR:
                ret = wc_AesSetKey(sw, _mock.key[slot], AES_128_KEY_SIZE,
                                   (const byte*)aes->reg, AES_ENCRYPTION);
                if (ret == 0) {
                    /* Continue from the caller's counter and unused
                     * keystream, and hand back the new state */
                    memcpy(sw->tmp, aes->tmp, AES_BLOCK_SIZE);
                    sw->left = aes->left;
                    ret      = wc_AesCtrEncrypt(sw, info->cipher.aesctr.out,
                                                info->cipher.aesctr.in,
                                                info->cipher.aesctr.sz);
                    memcpy(aes->reg, sw->reg, AES_BLOCK_SIZE);
                    memcpy(aes->tmp, sw->tmp, AES_BLOCK_SIZE);
                    aes->left = sw->left;
                }
                break;

            case WC_CIPHER_AES_GCM:
                ret = wc_AesGcmSetKey(sw, _mock.key[slot], AES_128_KEY_SIZE);
                if ((ret == 0) && (info->cipher.enc != 0)) {
                    wc_CryptoCb_AesAuthEnc* e = &info->cipher.aesgcm_enc;
                    ret = wc_AesGcmEncrypt(sw, e->out, e->in, e->sz, e->iv,
                                           e->ivSz, e->authTag, e->authTagSz,
                                           e->authIn, e->authInSz);
                }
                else if (ret == 0) {
                    wc_CryptoCb_AesAuthDec* d = &info->cipher.aesgcm_dec;
                    ret = wc_AesGcmDecrypt(sw, d->out, d->in, d->sz, d->iv,
                                           d->ivSz, d->authTag, d->authTagSz,
                                           d->authIn, d->authInSz);
                }
                break;

            default:
                break;
        }
        wc_AesFree(sw);
    }
    wh_Utils_ForceZero(sw, sizeof(sw));

    if (ret == 0) {
        _mock.ops++;
    }
    return ret;
}

static int _MockCmac(wc_CryptoInfo* info)
{
    Cmac* cmac = info->cmac.cmac;
    Cmac  sw[1];
    int   slot;
    int   ret;

    /* Key bytes passed in are a software key */
    if (info->cmac.key != NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    ret = _MockKeySlot(cmac->id, cmac->idLen, &slot);
    if (ret != 0) {
        return ret;
    }
    /* Init has nothing to set up: the running state lives in cmac */
    if ((info->cmac.in == NULL) && (info->cmac.out == NULL)) {
        return 0;
    }

    /* Run the step on a software copy keyed from the slot */
    ret = wc_InitCmac_ex(sw, _mock.key[slot], AES_128_KEY_SIZE, WC_CMAC_AES,
                         NULL, NULL, INVALID_DEVID);
    if (ret == 0) {
        memcpy(sw->buffer, cmac->buffer, sizeof(sw->buffer));
        memcpy(sw->digest, cmac->digest, sizeof(sw->digest));
        sw->bufferSz = cmac->bufferSz;
        sw->totalSz  = cmac->totalSz;

        if (info->cmac.in != NULL) {
            ret = wc_CmacUpdate(sw, info->cmac.in, info->cmac.inSz);
        }
        if ((ret == 0) && (info->cmac.out != NULL)) {
            ret = wc_CmacFinalNoFree(sw, info->cmac.out, info->cmac.outSz);
        }

        memcpy(cmac->buffer, sw->buffer, sizeof(cmac->buffer));
        memcpy(cmac->digest, sw->digest, sizeof(cmac->digest));
        cmac->bufferSz = sw->bufferSz;
        cmac->totalSz  = sw->totalSz;
        (void)wc_CmacFree(sw);
    }
    wh_Utils_ForceZero(sw, sizeof(sw));

    if (ret == 0) {
        _mock.ops++;
    }
    return ret;
}

static int _MockCryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    switch (info->algo_type) {
        case WC_ALGO_TYPE_KEYSTORE:
            return _MockKeystore(info);
        case WC_ALGO_TYPE_CIPHER:
            return _MockCipher(info);
        case WC_ALGO_TYPE_CMAC:
            return _MockCmac(info);
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

/* Boot the mock engine: empty every slot, load the port key into K2 and record
 * it with the hardware keystore. owner is the client that may use it, or 0
 * for every client, and flags the usage it allows */
static int _MockBoot(whHwKeystoreContext* hwKeystore, uint16_t owner,
                     whNvmFlags flags)
{
    memset(&_mock, 0, sizeof(_mock));
    memcpy(_mock.key[MOCK_PORT_SLOT], _portKey, sizeof(_portKey));
    _mock.loaded[MOCK_PORT_SLOT] = 1;

    return wh_HwKeystore_Register(
        hwKeystore, WH_MAKE_KEYID(WH_KEYTYPE_HW, owner, MOCK_PORT_SLOT), flags,
        AES_128_KEY_SIZE);
}

/* ------------------------------------------------------------------------
 * Client/server setup
 * ------------------------------------------------------------------------ */

/* One client and the server it talks to */
typedef struct {
    whServerContext                     server[1];
    whClientContext                     client[1];
    whServerCryptoContext               crypto[1];
    uint8_t                             reqBuf[BUFFER_SIZE];
    uint8_t                             respBuf[BUFFER_SIZE];
    whTransportMemConfig                tmcf[1];
    whTransportServerCb                 tscb[1];
    whTransportMemServerContext         tmsc[1];
    whCommServerConfig                  cs_conf[1];
    whTransportClientCb                 tccb[1];
    whTransportMemAutopollClientContext tmcc[1];
    whCommClientConfig                  cc_conf[1];
    whClientConfig                      c_conf[1];
    whServerConfig                      s_conf[1];
} TestPair;

typedef struct {
    TestPair pair[2];
    /* Shared by both servers */
    whNvmContext        nvm[1];
    whHwKeystoreContext hwKeystore[1];
    whHwKeystoreConfig  hwks_conf[1];
    whFlashRamsimCtx    fc[1];
    whFlashRamsimCfg    fc_conf[1];
    whFlashCb           fcb[1];
    whNvmFlashConfig    nf_conf[1];
    whNvmFlashContext   nfc[1];
    whNvmCb             nfcb[1];
    whNvmConfig         n_conf[1];
} TestCtx;

static TestCtx _testCtx;
static uint8_t _flashMemory[FLASH_RAM_SIZE];

static void _Pattern(uint8_t* buf, uint32_t sz, uint8_t seed)
{
    uint32_t i;

    for (i = 0; i < sz; i++) {
        buf[i] = (uint8_t)(seed ^ (i * 0x1D));
    }
}

static int _SetupPair(TestCtx* t, TestPair* p, uint16_t clientId,
                      int clientDevId, uint16_t serverId)
{
    uint32_t outClientId = 0;
    uint32_t outServerId = 0;

    p->tmcf[0] = (whTransportMemConfig){
        .req       = (whTransportMemCsr*)p->reqBuf,
        .req_size  = sizeof(p->reqBuf),
        .resp      = (whTransportMemCsr*)p->respBuf,
        .resp_size = sizeof(p->respBuf),
    };
    p->tscb[0]    = (whTransportServerCb)WH_TRANSPORT_MEM_SERVER_CB;
    p->cs_conf[0] = (whCommServerConfig){
        .transport_cb      = p->tscb,
        .transport_context = (void*)p->tmsc,
        .transport_config  = (void*)p->tmcf,
        .server_id         = serverId,
    };
    p->tccb[0]      = (whTransportClientCb)WH_TRANSPORT_MEM_AUTOPOLL_CLIENT_CB;
    p->tmcc->server = p->server;
    p->cc_conf[0]   = (whCommClientConfig){
          .transport_cb      = p->tccb,
          .transport_context = (void*)p->tmcc,
          .transport_config  = (void*)p->tmcf,
          .client_id         = clientId,
    };
    p->c_conf[0] = (whClientConfig){
        .comm  = p->cc_conf,
        .devId = clientDevId,
    };
    p->s_conf[0] = (whServerConfig){
        .comm_config = p->cs_conf,
        .nvm         = t->nvm,
        .crypto      = p->crypto,
        .devId       = MOCK_DEVID,
        .hwKeystore  = t->hwKeystore,
    };

    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(p->crypto->rng, NULL, INVALID_DEVID));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(p->server, p->s_conf));
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_SetConnected(p->server, WH_COMM_CONNECTED));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(p->client, p->c_conf));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInit(p->client, &outClientId, &outServerId));
    WH_TEST_ASSERT_RETURN(outClientId == clientId);
    return WH_ERROR_OK;
}

static int _Setup(TestCtx* t)
{
    memset(t, 0, sizeof(*t));
    memset(_flashMemory, 0, sizeof(_flashMemory));

    _Pattern(_portKey, sizeof(_portKey), 0x2B);
    _Pattern(_keyA, sizeof(_keyA), 0xA5);
    _Pattern(_keyB, sizeof(_keyB), 0x5A);
    _Pattern(_keyC, sizeof(_keyC), 0xC3);
    _Pattern(_key256, sizeof(_key256), 0x77);
    _Pattern(_msg, sizeof(_msg), 0x11);
    _Pattern(_iv, sizeof(_iv), 0xE0);
    _Pattern(_aad, sizeof(_aad), 0x42);

    t->fc_conf[0] = (whFlashRamsimCfg){
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_SECTOR_SIZE,
        .pageSize   = FLASH_PAGE_SIZE,
        .erasedByte = ~(uint8_t)0,
        .memory     = _flashMemory,
    };
    t->fcb[0]     = (whFlashCb)WH_FLASH_RAMSIM_CB;
    t->nf_conf[0] = (whNvmFlashConfig){
        .cb      = t->fcb,
        .context = t->fc,
        .config  = t->fc_conf,
    };
    t->nfcb[0]   = (whNvmCb)WH_NVM_FLASH_CB;
    t->n_conf[0] = (whNvmConfig){
        .cb      = t->nfcb,
        .context = t->nfc,
        .config  = t->nf_conf,
    };
    t->hwks_conf[0] = (whHwKeystoreConfig){
        .cb = NULL,
    };

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(
        wc_CryptoCb_RegisterDevice(MOCK_DEVID, _MockCryptoCb, NULL));
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(t->nvm, t->n_conf));
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(t->hwKeystore, t->hwks_conf));
    WH_TEST_RETURN_ON_FAIL(
        _MockBoot(t->hwKeystore, WH_KEYUSER_GLOBAL, USAGE_AES_CMAC));
    WH_TEST_RETURN_ON_FAIL(
        _SetupPair(t, &t->pair[0], CLIENT1_ID, CLIENT1_DEVID, 201));
    WH_TEST_RETURN_ON_FAIL(
        _SetupPair(t, &t->pair[1], CLIENT2_ID, CLIENT2_DEVID, 202));
    return WH_ERROR_OK;
}

static void _Cleanup(TestCtx* t)
{
    int i;

    for (i = 0; i < 2; i++) {
        (void)wh_Client_Cleanup(t->pair[i].client);
        (void)wh_Server_Cleanup(t->pair[i].server);
        (void)wc_FreeRng(t->pair[i].crypto->rng);
    }
    (void)wh_HwKeystore_Cleanup(t->hwKeystore);
    (void)wh_Nvm_Cleanup(t->nvm);
    wc_CryptoCb_UnRegisterDevice(MOCK_DEVID);
    (void)wolfCrypt_Cleanup();
    wh_Utils_ForceZero(&_mock, sizeof(_mock));
}

/* Simulate an HSM reset: the slots and the hardware keystore start empty and
 * the port registers its key again, this time for owner with flags */
static int _Reboot(TestCtx* t, uint16_t owner, whNvmFlags flags)
{
    (void)wh_HwKeystore_Cleanup(t->hwKeystore);
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(t->hwKeystore, t->hwks_conf));
    return _MockBoot(t->hwKeystore, owner, flags);
}

/* ------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------ */

/* Cache an AES key in the client's keystore. *inout_id 0 picks a free ID */
static int _Cache(whClientContext* c, whNvmFlags flags, const uint8_t* key,
                  uint16_t keySz, whKeyId* inout_id)
{
    uint8_t  label[WH_NVM_LABEL_LEN] = "hwkey source";
    uint16_t id                      = *inout_id;
    int      ret;

    ret = wh_Client_KeyCache(c, flags, label, sizeof(label), (uint8_t*)key,
                             keySz, &id);
    if (ret == WH_ERROR_OK) {
        *inout_id = id;
    }
    return ret;
}

static int _Load(whClientContext* c, whKeyId hwId, whKeyId srcId,
                 whKeyId* outHwId)
{
    return wh_Client_HwKeystoreLoadFromKeystore(c, hwId, srcId, outHwId);
}

/* Check what GetInfo reports for a hardware key */
static int _CheckInfo(whClientContext* c, int id, int loaded, whNvmFlags flags,
                      uint16_t owner)
{
    whHwKeystoreInfo info;

    memset(&info, 0xFF, sizeof(info));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreGetInfo(c, HW(id), &info));
    if (loaded) {
        WH_TEST_ASSERT_RETURN(info.keyType == WC_KEYSTORE_KEY_AES);
        WH_TEST_ASSERT_RETURN(info.keyBits == 128);
        WH_TEST_ASSERT_RETURN(info.flags == flags);
        WH_TEST_ASSERT_RETURN(info.owner == owner);
    }
    else {
        WH_TEST_ASSERT_RETURN(info.keyType == WC_KEYSTORE_KEY_NONE);
        WH_TEST_ASSERT_RETURN(info.keyBits == 0);
        WH_TEST_ASSERT_RETURN(info.flags == 0);
        WH_TEST_ASSERT_RETURN(info.owner == 0);
    }
    return WH_ERROR_OK;
}

/* Clear every key both clients loaded, and check the loadable slots are
 * empty again */
static int _ClearAll(TestCtx* t)
{
    int id;

    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClearAll(t->pair[0].client));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClearAll(t->pair[1].client));
    for (id = MOCK_LOAD_FIRST; id <= MOCK_LOAD_LAST; id++) {
        WH_TEST_RETURN_ON_FAIL(_CheckInfo(t->pair[0].client, id, 0, 0, 0));
    }
    return WH_ERROR_OK;
}

/* Expected results, from software */
typedef struct {
    uint8_t ecb[TEST_BLOCKS_SZ];
    uint8_t cbc[TEST_BLOCKS_SZ];
    uint8_t ctr[TEST_CTR_SZ];
    uint8_t gcm[TEST_GCM_SZ];
    uint8_t gcmTag[AES_BLOCK_SIZE];
    uint8_t gcm16[TEST_GCM_SZ]; /* With a 16-byte IV */
    uint8_t gcm16Tag[AES_BLOCK_SIZE];
    uint8_t cmac[AES_BLOCK_SIZE];
} Expected;

static int _SwExpected(const uint8_t* key, Expected* e)
{
    Aes    aes[1];
    word32 macSz = AES_BLOCK_SIZE;
    int    ret;

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, AES_128_KEY_SIZE, NULL, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesEcbEncrypt(aes, e->ecb, _msg, TEST_BLOCKS_SZ);
    }
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, AES_128_KEY_SIZE, _iv, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesCbcEncrypt(aes, e->cbc, _msg, TEST_BLOCKS_SZ);
    }
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, AES_128_KEY_SIZE, _iv, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesCtrEncrypt(aes, e->ctr, _msg, TEST_CTR_SZ);
    }
    if (ret == 0) {
        ret = wc_AesGcmSetKey(aes, key, AES_128_KEY_SIZE);
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(aes, e->gcm, _msg, TEST_GCM_SZ, _iv,
                               TEST_GCM_IV_SZ, e->gcmTag, AES_BLOCK_SIZE, _aad,
                               sizeof(_aad));
    }
    if (ret == 0) {
        ret =
            wc_AesGcmEncrypt(aes, e->gcm16, _msg, TEST_GCM_SZ, _iv, sizeof(_iv),
                             e->gcm16Tag, AES_BLOCK_SIZE, _aad, sizeof(_aad));
    }
    wc_AesFree(aes);
    if (ret == 0) {
        ret = wc_AesCmacGenerate(e->cmac, &macSz, _msg, TEST_CMAC_SZ, key,
                                 AES_128_KEY_SIZE);
    }
    return ret;
}

/* Fresh Aes that names keyId, with iv if not NULL */
static int _AesStart(Aes* aes, whKeyId keyId, const uint8_t* iv)
{
    int ret;

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Client_AesSetKeyId(aes, keyId);
    }
    if ((ret == 0) && (iv != NULL)) {
        ret = wc_AesSetIV(aes, iv);
    }
    return ret;
}

static int _Ecb(whClientContext* c, Aes* aes, int dma, int enc,
                const uint8_t* in, uint8_t* out, uint32_t sz)
{
#ifdef WOLFHSM_CFG_DMA
    if (dma) {
        return wh_Client_AesEcbDma(c, aes, enc, in, sz, out);
    }
#endif
    (void)dma;
    return wh_Client_AesEcb(c, aes, enc, in, sz, out);
}

static int _Cbc(whClientContext* c, Aes* aes, int dma, int enc,
                const uint8_t* in, uint8_t* out, uint32_t sz)
{
#ifdef WOLFHSM_CFG_DMA
    if (dma) {
        return wh_Client_AesCbcDma(c, aes, enc, in, sz, out);
    }
#endif
    (void)dma;
    return wh_Client_AesCbc(c, aes, enc, in, sz, out);
}

static int _Ctr(whClientContext* c, Aes* aes, int dma, int enc,
                const uint8_t* in, uint8_t* out, uint32_t sz)
{
#ifdef WOLFHSM_CFG_DMA
    if (dma) {
        return wh_Client_AesCtrDma(c, aes, enc, in, sz, out);
    }
#endif
    (void)dma;
    return wh_Client_AesCtr(c, aes, enc, in, sz, out);
}

static int _Gcm(whClientContext* c, Aes* aes, int dma, int enc,
                const uint8_t* in, uint8_t* out, uint32_t sz, uint32_t ivSz,
                const uint8_t* decTag, uint8_t* encTag)
{
#ifdef WOLFHSM_CFG_DMA
    if (dma) {
        return wh_Client_AesGcmDma(c, aes, enc, in, sz, _iv, ivSz, _aad,
                                   sizeof(_aad), decTag, encTag, AES_BLOCK_SIZE,
                                   out);
    }
#endif
    (void)dma;
    return wh_Client_AesGcm(c, aes, enc, in, sz, _iv, ivSz, _aad, sizeof(_aad),
                            decTag, encTag, AES_BLOCK_SIZE, out);
}

/* One-shot CMAC of the test message */
static int _Cmac(whClientContext* c, whKeyId keyId, int dma, uint8_t* tag)
{
    Cmac     cmac[1];
    uint32_t tagSz = AES_BLOCK_SIZE;
    int      ret;

    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, c->devId);
    if (ret == 0) {
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
    }
    if (ret == 0) {
#ifdef WOLFHSM_CFG_DMA
        if (dma) {
            ret = wh_Client_CmacDma(c, cmac, WC_CMAC_AES, NULL, 0, _msg,
                                    TEST_CMAC_SZ, tag, &tagSz);
        }
        else
#endif
        {
            ret = wh_Client_Cmac(c, cmac, WC_CMAC_AES, NULL, 0, _msg,
                                 TEST_CMAC_SZ, tag, &tagSz);
        }
    }
    (void)dma;
    (void)wc_CmacFree(cmac);
    return ret;
}

/* One CMAC update request, standard or DMA */
static int _CmacUpdate(whClientContext* c, Cmac* cmac, int dma,
                       const uint8_t* in, uint32_t sz)
{
    bool sent = false;
    int  ret;

#ifdef WOLFHSM_CFG_DMA
    if (dma) {
        ret = wh_Client_CmacDmaUpdateRequest(c, cmac, WC_CMAC_AES, NULL, 0, in,
                                             sz, &sent);
        if ((ret == 0) && sent) {
            ret = wh_Client_CmacDmaUpdateResponse(c, cmac);
        }
        return ret;
    }
#endif
    (void)dma;
    ret = wh_Client_CmacUpdateRequest(c, cmac, WC_CMAC_AES, NULL, 0, in, sz,
                                      &sent);
    if ((ret == 0) && sent) {
        ret = wh_Client_CmacUpdateResponse(c, cmac);
    }
    return ret;
}

/* CMAC final request, standard or DMA */
static int _CmacFinal(whClientContext* c, Cmac* cmac, int dma, uint8_t* tag,
                      uint32_t* tagSz)
{
    int ret;

#ifdef WOLFHSM_CFG_DMA
    if (dma) {
        ret = wh_Client_CmacDmaFinalRequest(c, cmac);
        if (ret == 0) {
            ret = wh_Client_CmacDmaFinalResponse(c, cmac, tag, tagSz);
        }
        return ret;
    }
#endif
    (void)dma;
    ret = wh_Client_CmacFinalRequest(c, cmac);
    if (ret == 0) {
        ret = wh_Client_CmacFinalResponse(c, cmac, tag, tagSz);
    }
    return ret;
}

/* CMAC of the test message over several requests, so the server picks up the
 * running state each time */
static int _CmacSteps(whClientContext* c, whKeyId keyId, int dma, uint8_t* tag)
{
    Cmac     cmac[1];
    uint32_t tagSz = AES_BLOCK_SIZE;
    int      ret;

    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, c->devId);
    if (ret == 0) {
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
    }
    if (ret == 0) {
        ret = _CmacUpdate(c, cmac, dma, _msg, 40);
    }
    if (ret == 0) {
        ret = _CmacUpdate(c, cmac, dma, _msg + 40, TEST_CMAC_SZ - 40);
    }
    if (ret == 0) {
        ret = _CmacFinal(c, cmac, dma, tag, &tagSz);
    }
    (void)wc_CmacFree(cmac);
    return ret;
}

/* AES modes for _TryAes */
enum {
    MODE_ECB = 0,
    MODE_CBC,
    MODE_CTR,
    MODE_GCM,
    MODE_COUNT,
};

/* Result of one request in mode with keyId. A GCM decrypt uses the software
 * ciphertext and tag in e, so it succeeds with the right key */
static int _TryAes(whClientContext* c, whKeyId keyId, int mode, int dma,
                   int enc, const Expected* e)
{
    Aes     aes[1];
    uint8_t out[TEST_GCM_SZ];
    uint8_t tag[AES_BLOCK_SIZE];
    int     ret;

    ret = _AesStart(aes, keyId,
                    ((mode == MODE_CBC) || (mode == MODE_CTR)) ? _iv : NULL);
    if (ret == 0) {
        switch (mode) {
            case MODE_ECB:
                ret = _Ecb(c, aes, dma, enc, _msg, out, AES_BLOCK_SIZE);
                break;
            case MODE_CBC:
                ret = _Cbc(c, aes, dma, enc, _msg, out, AES_BLOCK_SIZE);
                break;
            case MODE_CTR:
                ret = _Ctr(c, aes, dma, enc, _msg, out, AES_BLOCK_SIZE);
                break;
            case MODE_GCM:
                if (enc) {
                    ret = _Gcm(c, aes, dma, 1, _msg, out, TEST_GCM_SZ,
                               TEST_GCM_IV_SZ, NULL, tag);
                }
                else {
                    ret = _Gcm(c, aes, dma, 0, e->gcm, out, TEST_GCM_SZ,
                               TEST_GCM_IV_SZ, e->gcmTag, NULL);
                }
                break;
            default:
                ret = WH_ERROR_BADARGS;
                break;
        }
    }
    wc_AesFree(aes);
    return ret;
}

/* Result of a one-block ECB request with keyId */
static int _TryEcb(whClientContext* c, whKeyId keyId, int enc)
{
    return _TryAes(c, keyId, MODE_ECB, 0, enc, NULL);
}

/* Result of a one-shot CMAC request with keyId */
static int _TryCmac(whClientContext* c, whKeyId keyId)
{
    uint8_t tag[AES_BLOCK_SIZE];

    return _Cmac(c, keyId, 0, tag);
}

/* One-block ECB with keyId must match software with key */
static int _EcbMatches(whClientContext* c, whKeyId keyId, const uint8_t* key)
{
    Expected e;
    Aes      aes[1];
    uint8_t  out[AES_BLOCK_SIZE];

    WH_TEST_RETURN_ON_FAIL(_SwExpected(key, &e));
    WH_TEST_RETURN_ON_FAIL(_AesStart(aes, keyId, NULL));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_AesEcb(c, aes, 1, _msg, AES_BLOCK_SIZE, out));
    wc_AesFree(aes);
    WH_TEST_ASSERT_RETURN(memcmp(out, e.ecb, AES_BLOCK_SIZE) == 0);
    return WH_ERROR_OK;
}

/* The mock ran an operation since before (hardware key), or didn't (key held
 * in software) */
#define CHECK_RAN(before, hw)                           \
    WH_TEST_ASSERT_RETURN((hw) ? (_mock.ops > (before)) \
                               : (_mock.ops == (before)))

/* Run every AES mode and CMAC with keyId and compare with software results
 * for key. hw says whether the mock engine must run them */
static int _CheckModes(whClientContext* c, whKeyId keyId, const uint8_t* key,
                       int dma, int hw)
{
    Expected e;
    Aes      aes[1];
    uint8_t  out[TEST_MSG_SZ];
    uint8_t  back[TEST_MSG_SZ];
    uint8_t  tag[AES_BLOCK_SIZE];
    int      ops;

    WH_TEST_RETURN_ON_FAIL(_SwExpected(key, &e));

    /* ECB */
    ops = _mock.ops;
    WH_TEST_RETURN_ON_FAIL(_AesStart(aes, keyId, NULL));
    WH_TEST_RETURN_ON_FAIL(_Ecb(c, aes, dma, 1, _msg, out, TEST_BLOCKS_SZ));
    WH_TEST_ASSERT_RETURN(memcmp(out, e.ecb, TEST_BLOCKS_SZ) == 0);
    WH_TEST_RETURN_ON_FAIL(_Ecb(c, aes, dma, 0, out, back, TEST_BLOCKS_SZ));
    WH_TEST_ASSERT_RETURN(memcmp(back, _msg, TEST_BLOCKS_SZ) == 0);
    wc_AesFree(aes);
    CHECK_RAN(ops, hw);

    /* CBC, encrypted in two requests to check the chaining value */
    ops = _mock.ops;
    WH_TEST_RETURN_ON_FAIL(_AesStart(aes, keyId, _iv));
    WH_TEST_RETURN_ON_FAIL(_Cbc(c, aes, dma, 1, _msg, out, 32));
    WH_TEST_RETURN_ON_FAIL(
        _Cbc(c, aes, dma, 1, _msg + 32, out + 32, TEST_BLOCKS_SZ - 32));
    WH_TEST_ASSERT_RETURN(memcmp(out, e.cbc, TEST_BLOCKS_SZ) == 0);
    wc_AesFree(aes);
    WH_TEST_RETURN_ON_FAIL(_AesStart(aes, keyId, _iv));
    WH_TEST_RETURN_ON_FAIL(_Cbc(c, aes, dma, 0, out, back, TEST_BLOCKS_SZ));
    WH_TEST_ASSERT_RETURN(memcmp(back, _msg, TEST_BLOCKS_SZ) == 0);
    wc_AesFree(aes);
    CHECK_RAN(ops, hw);

    /* CTR, in two requests that split a block */
    ops = _mock.ops;
    WH_TEST_RETURN_ON_FAIL(_AesStart(aes, keyId, _iv));
    WH_TEST_RETURN_ON_FAIL(_Ctr(c, aes, dma, 1, _msg, out, 20));
    WH_TEST_RETURN_ON_FAIL(
        _Ctr(c, aes, dma, 1, _msg + 20, out + 20, TEST_CTR_SZ - 20));
    WH_TEST_ASSERT_RETURN(memcmp(out, e.ctr, TEST_CTR_SZ) == 0);
    wc_AesFree(aes);
    WH_TEST_RETURN_ON_FAIL(_AesStart(aes, keyId, _iv));
    WH_TEST_RETURN_ON_FAIL(_Ctr(c, aes, dma, 1, out, back, TEST_CTR_SZ));
    WH_TEST_ASSERT_RETURN(memcmp(back, _msg, TEST_CTR_SZ) == 0);
    wc_AesFree(aes);
    CHECK_RAN(ops, hw);

    /* GCM with a 12-byte IV, a 16-byte IV, and a bad tag */
    ops = _mock.ops;
    WH_TEST_RETURN_ON_FAIL(_AesStart(aes, keyId, NULL));
    WH_TEST_RETURN_ON_FAIL(_Gcm(c, aes, dma, 1, _msg, out, TEST_GCM_SZ,
                                TEST_GCM_IV_SZ, NULL, tag));
    WH_TEST_ASSERT_RETURN(memcmp(out, e.gcm, TEST_GCM_SZ) == 0);
    WH_TEST_ASSERT_RETURN(memcmp(tag, e.gcmTag, AES_BLOCK_SIZE) == 0);
    WH_TEST_RETURN_ON_FAIL(_Gcm(c, aes, dma, 0, out, back, TEST_GCM_SZ,
                                TEST_GCM_IV_SZ, tag, NULL));
    WH_TEST_ASSERT_RETURN(memcmp(back, _msg, TEST_GCM_SZ) == 0);
    tag[0] ^= 0x01;
    WH_TEST_ASSERT_RETURN(AES_GCM_AUTH_E == _Gcm(c, aes, dma, 0, out, back,
                                                 TEST_GCM_SZ, TEST_GCM_IV_SZ,
                                                 tag, NULL));
    WH_TEST_RETURN_ON_FAIL(
        _Gcm(c, aes, dma, 1, _msg, out, TEST_GCM_SZ, sizeof(_iv), NULL, tag));
    WH_TEST_ASSERT_RETURN(memcmp(out, e.gcm16, TEST_GCM_SZ) == 0);
    WH_TEST_ASSERT_RETURN(memcmp(tag, e.gcm16Tag, AES_BLOCK_SIZE) == 0);
    wc_AesFree(aes);
    CHECK_RAN(ops, hw);

    /* CMAC in one request, and over several */
    ops = _mock.ops;
    WH_TEST_RETURN_ON_FAIL(_Cmac(c, keyId, dma, tag));
    WH_TEST_ASSERT_RETURN(memcmp(tag, e.cmac, AES_BLOCK_SIZE) == 0);
    CHECK_RAN(ops, hw);
    ops = _mock.ops;
    memset(tag, 0, sizeof(tag));
    WH_TEST_RETURN_ON_FAIL(_CmacSteps(c, keyId, dma, tag));
    WH_TEST_ASSERT_RETURN(memcmp(tag, e.cmac, AES_BLOCK_SIZE) == 0);
    CHECK_RAN(ops, hw);

    return WH_ERROR_OK;
}

/* ------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------ */

/* GetInfo for every hardware key ID */
static int _whTest_HwKeyMap(TestCtx* t)
{
    whClientContext* c = t->pair[0].client;
    whHwKeystoreInfo info;
    int              id;

    for (id = 1; id <= MOCK_SLOTS; id++) {
        if (id == MOCK_PORT_SLOT) {
            WH_TEST_RETURN_ON_FAIL(
                _CheckInfo(c, id, 1, USAGE_AES_CMAC, WH_KEYUSER_GLOBAL));
        }
        else if ((id >= MOCK_LOAD_FIRST) && (id <= MOCK_LOAD_LAST)) {
            WH_TEST_RETURN_ON_FAIL(_CheckInfo(c, id, 0, 0, 0));
        }
        else {
            /* The port has no hardware key with this ID */
            WH_TEST_ASSERT_RETURN(
                BAD_FUNC_ARG == wh_Client_HwKeystoreGetInfo(c, HW(id), &info));
        }
    }

    /* ID 0 names no key */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_Client_HwKeystoreGetInfo(c, HW(0), &info));

    /* The split request and response */
    memset(&info, 0, sizeof(info));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_HwKeystoreGetInfoRequest(c, HW(MOCK_PORT_SLOT)));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreGetInfoResponse(c, &info));
    WH_TEST_ASSERT_RETURN(info.keyType == WC_KEYSTORE_KEY_AES);
    WH_TEST_ASSERT_RETURN(info.flags == USAGE_AES_CMAC);

    return WH_ERROR_OK;
}

/* Both clients can use the port key in K2, but neither can set or clear it */
static int _whTest_HwKeyPortKey(TestCtx* t)
{
    whClientContext* c;
    whKeyId          src;
    whKeyId          hwId;
    int              i;
    int              dma;

    for (i = 0; i < 2; i++) {
        c = t->pair[i].client;

        for (dma = 0; dma < WH_TEST_DMA_MODE_CNT; dma++) {
            WH_TEST_RETURN_ON_FAIL(
                _CheckModes(c, HW(MOCK_PORT_SLOT), _portKey, dma, 1));
        }

        src = WH_KEYID_ERASED;
        WH_TEST_RETURN_ON_FAIL(
            _Cache(c, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src));
        WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                              _Load(c, HW(MOCK_PORT_SLOT), src, &hwId));
        WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                              wh_Client_HwKeystoreClear(c, HW(MOCK_PORT_SLOT)));
        WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClearAll(c));
        WH_TEST_RETURN_ON_FAIL(_CheckInfo(c, MOCK_PORT_SLOT, 1, USAGE_AES_CMAC,
                                          WH_KEYUSER_GLOBAL));
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src));
    }

    return WH_ERROR_OK;
}

/* Load a keystore key into a hardware key and use it in every mode */
static int _whTest_HwKeyLoadAndUse(TestCtx* t)
{
    whClientContext* c   = t->pair[0].client;
    whKeyId          src = WH_KEYID_ERASED;
    whKeyId          hwId;
    Expected         e;
    Aes              aes[1];
    uint8_t          out[TEST_GCM_SZ];
    uint8_t          tag[AES_BLOCK_SIZE];
    int              dma;

    WH_TEST_RETURN_ON_FAIL(
        _Cache(c, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src));

    /* The keystore key itself runs in software */
    for (dma = 0; dma < WH_TEST_DMA_MODE_CNT; dma++) {
        WH_TEST_RETURN_ON_FAIL(_CheckModes(c, src, _keyA, dma, 0));
    }

    /* ID 0 takes the first free hardware key */
    hwId = WH_KEYID_ERASED;
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_HwKeystoreLoadFromKeystoreRequest(c, HW(0), src));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_HwKeystoreLoadFromKeystoreResponse(c, &hwId));
    WH_TEST_ASSERT_RETURN(hwId == HW(MOCK_LOAD_FIRST));
    WH_TEST_RETURN_ON_FAIL(
        _CheckInfo(c, MOCK_LOAD_FIRST, 1, USAGE_AES_CMAC, CLIENT1_ID));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(t->pair[1].client, MOCK_LOAD_FIRST, 1,
                                      USAGE_AES_CMAC, CLIENT1_ID));

    for (dma = 0; dma < WH_TEST_DMA_MODE_CNT; dma++) {
        WH_TEST_RETURN_ON_FAIL(_CheckModes(c, hwId, _keyA, dma, 1));
    }

    /* The wolfCrypt API works too: the client's crypto callback sends the
     * hardware keyId */
    WH_TEST_RETURN_ON_FAIL(_SwExpected(_keyA, &e));
    WH_TEST_RETURN_ON_FAIL(wc_AesInit(aes, NULL, c->devId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_AesSetKeyId(aes, hwId));
    WH_TEST_RETURN_ON_FAIL(wc_AesGcmEncrypt(aes, out, _msg, TEST_GCM_SZ, _iv,
                                            TEST_GCM_IV_SZ, tag, sizeof(tag),
                                            _aad, sizeof(_aad)));
    wc_AesFree(aes);
    WH_TEST_ASSERT_RETURN(memcmp(out, e.gcm, TEST_GCM_SZ) == 0);
    WH_TEST_ASSERT_RETURN(memcmp(tag, e.gcmTag, AES_BLOCK_SIZE) == 0);

    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClear(c, hwId));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c, MOCK_LOAD_FIRST, 0, 0, 0));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src));
    return WH_ERROR_OK;
}

/* Picking a free key, explicit IDs, running out, reloading, and keys that
 * belong to the other client */
static int _whTest_HwKeyAllocation(TestCtx* t)
{
    whClientContext* c1   = t->pair[0].client;
    whClientContext* c2   = t->pair[1].client;
    whKeyId          src1 = WH_KEYID_ERASED;
    whKeyId          src2 = WH_KEYID_ERASED;
    whKeyId          src3 = WH_KEYID_ERASED;
    whKeyId          hw1;
    whKeyId          hw2;
    whKeyId          tmp;

    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src1));
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c2, USAGE_AES_CMAC, _keyB, sizeof(_keyB), &src2));

    /* Each client gets the next free key */
    WH_TEST_RETURN_ON_FAIL(_Load(c1, HW(0), src1, &hw1));
    WH_TEST_ASSERT_RETURN(hw1 == HW(MOCK_LOAD_FIRST));
    WH_TEST_RETURN_ON_FAIL(_Load(c2, HW(0), src2, &hw2));
    WH_TEST_ASSERT_RETURN(hw2 == HW(MOCK_LOAD_LAST));
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c1, hw1, _keyA));
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c2, hw2, _keyB));

    /* No loadable key is left */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOSPACE == _Load(c1, HW(0), src1, &tmp));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOSPACE == _Load(c2, HW(0), src2, &tmp));

    /* A client can't use, replace or clear the other client's key */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS == _TryEcb(c2, hw1, 1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS == _TryCmac(c2, hw1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS == _TryEcb(c1, hw2, 1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS == _Load(c2, hw1, src2, &tmp));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Client_HwKeystoreClear(c2, hw1));
    WH_TEST_RETURN_ON_FAIL(
        _CheckInfo(c2, MOCK_LOAD_FIRST, 1, USAGE_AES_CMAC, CLIENT1_ID));

    /* The owner can load its key again. The copy then follows the new
     * source, so erasing the old one leaves it alone */
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, WH_NVM_FLAGS_USAGE_ENCRYPT, _keyC, sizeof(_keyC), &src3));
    WH_TEST_RETURN_ON_FAIL(_Load(c1, hw1, src3, &tmp));
    WH_TEST_ASSERT_RETURN(tmp == hw1);
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c1, hw1, _keyC));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c1, MOCK_LOAD_FIRST, 1,
                                      WH_NVM_FLAGS_USAGE_ENCRYPT, CLIENT1_ID));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyErase(c1, src1));
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c1, hw1, _keyC));

    /* ID 0 names no key, and ID 9 isn't loaded */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == _TryEcb(c1, HW(0), 1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == _TryEcb(c1, HW(9), 1));

    WH_TEST_RETURN_ON_FAIL(_ClearAll(t));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c1, src3));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c2, src2));
    return WH_ERROR_OK;
}

/* The copy keeps the source key's usage flags. Each AES request needs the
 * usage for its direction and CMAC needs sign or verify, standard and DMA */
static int _whTest_HwKeyUsage(TestCtx* t)
{
    whClientContext* c = t->pair[0].client;
    Expected         e;
    uint8_t          tag[AES_BLOCK_SIZE];
    whKeyId          src1;
    whKeyId          src2;
    whKeyId          hw1;
    whKeyId          hw2;
    whKeyId          src;
    whKeyId          hwId;
    int              mode;
    int              dma;

    WH_TEST_RETURN_ON_FAIL(_SwExpected(_keyA, &e));

    /* Encrypt only and decrypt only: each works one way in every AES mode, and
     * neither can do CMAC */
    src1 = WH_KEYID_ERASED;
    src2 = WH_KEYID_ERASED;
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c, WH_NVM_FLAGS_USAGE_ENCRYPT, _keyA, sizeof(_keyA), &src1));
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c, WH_NVM_FLAGS_USAGE_DECRYPT, _keyA, sizeof(_keyA), &src2));
    WH_TEST_RETURN_ON_FAIL(_Load(c, HW(0), src1, &hw1));
    WH_TEST_RETURN_ON_FAIL(_Load(c, HW(0), src2, &hw2));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c, WH_KEYID_ID(hw1), 1,
                                      WH_NVM_FLAGS_USAGE_ENCRYPT, CLIENT1_ID));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c, WH_KEYID_ID(hw2), 1,
                                      WH_NVM_FLAGS_USAGE_DECRYPT, CLIENT1_ID));
    for (dma = 0; dma < WH_TEST_DMA_MODE_CNT; dma++) {
        for (mode = 0; mode < MODE_COUNT; mode++) {
            WH_TEST_RETURN_ON_FAIL(_TryAes(c, hw1, mode, dma, 1, &e));
            WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                                  _TryAes(c, hw1, mode, dma, 0, &e));
            WH_TEST_RETURN_ON_FAIL(_TryAes(c, hw2, mode, dma, 0, &e));
            WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                                  _TryAes(c, hw2, mode, dma, 1, &e));
        }
        WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE == _Cmac(c, hw1, dma, tag));
        WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE == _CmacSteps(c, hw1, dma, tag));
        WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE == _Cmac(c, hw2, dma, tag));
        WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE == _CmacSteps(c, hw2, dma, tag));
    }
    WH_TEST_RETURN_ON_FAIL(_ClearAll(t));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src2));

    /* Sign only and verify only: either can do CMAC but not AES */
    src1 = WH_KEYID_ERASED;
    src2 = WH_KEYID_ERASED;
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c, WH_NVM_FLAGS_USAGE_SIGN, _keyA, sizeof(_keyA), &src1));
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c, WH_NVM_FLAGS_USAGE_VERIFY, _keyA, sizeof(_keyA), &src2));
    WH_TEST_RETURN_ON_FAIL(_Load(c, HW(0), src1, &hw1));
    WH_TEST_RETURN_ON_FAIL(_Load(c, HW(0), src2, &hw2));
    for (dma = 0; dma < WH_TEST_DMA_MODE_CNT; dma++) {
        WH_TEST_RETURN_ON_FAIL(_Cmac(c, hw1, dma, tag));
        WH_TEST_RETURN_ON_FAIL(_CmacSteps(c, hw1, dma, tag));
        WH_TEST_RETURN_ON_FAIL(_Cmac(c, hw2, dma, tag));
        WH_TEST_RETURN_ON_FAIL(_CmacSteps(c, hw2, dma, tag));
        WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                              _TryAes(c, hw1, MODE_ECB, dma, 1, &e));
        WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                              _TryAes(c, hw2, MODE_ECB, dma, 0, &e));
    }
    WH_TEST_RETURN_ON_FAIL(_ClearAll(t));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src2));

    /* A key with no usage could never be used, so it isn't loaded */
    src = WH_KEYID_ERASED;
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c, WH_NVM_FLAGS_NONE, _keyA, sizeof(_keyA), &src));
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE == _Load(c, HW(0), src, &hwId));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c, MOCK_LOAD_FIRST, 0, 0, 0));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src));

    /* A non-exportable key can be loaded: the key stays in the HSM */
    src = WH_KEYID_ERASED;
    WH_TEST_RETURN_ON_FAIL(_Cache(c,
                                  USAGE_AES_CMAC | WH_NVM_FLAGS_NONEXPORTABLE,
                                  _keyA, sizeof(_keyA), &src));
    WH_TEST_RETURN_ON_FAIL(_Load(c, HW(0), src, &hwId));
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c, hwId, _keyA));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClear(c, hwId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src));

    return WH_ERROR_OK;
}

/* Evicting the source keeps the copy. Erasing or revoking it clears every
 * copy, but only copies of that client's key */
static int _whTest_HwKeySource(TestCtx* t)
{
    whClientContext* c1 = t->pair[0].client;
    whClientContext* c2 = t->pair[1].client;
    whKeyId          src;
    whKeyId          other;
    whKeyId          hwId;

    /* Evict */
    src = WH_KEYID_ERASED;
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src));
    WH_TEST_RETURN_ON_FAIL(_Load(c1, HW(0), src, &hwId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c1, src));
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c1, hwId, _keyA));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClear(c1, hwId));

    /* Erase */
    src = WH_KEYID_ERASED;
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src));
    WH_TEST_RETURN_ON_FAIL(_Load(c1, HW(0), src, &hwId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyErase(c1, src));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c1, WH_KEYID_ID(hwId), 0, 0, 0));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == _TryEcb(c1, hwId, 1));

    /* Revoke. A revoked key has no usage, so it can't be loaded again */
    src = WH_KEYID_ERASED;
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, USAGE_AES_CMAC, _keyB, sizeof(_keyB), &src));
    WH_TEST_RETURN_ON_FAIL(_Load(c1, HW(0), src, &hwId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyRevoke(c1, src));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c1, WH_KEYID_ID(hwId), 0, 0, 0));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == _TryEcb(c1, hwId, 1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE == _Load(c1, HW(0), src, &hwId));

    /* The other client's key with the same ID is a different key */
    src   = SRC_SHARED_ID;
    other = SRC_SHARED_ID;
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src));
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c2, USAGE_AES_CMAC, _keyB, sizeof(_keyB), &other));
    WH_TEST_RETURN_ON_FAIL(_Load(c1, HW(0), src, &hwId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyErase(c2, other));
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c1, hwId, _keyA));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClear(c1, hwId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c1, src));

    return WH_ERROR_OK;
}

/* Sources and targets the server or the port refuses */
static int _whTest_HwKeyRefused(TestCtx* t)
{
    whClientContext* c      = t->pair[0].client;
    whServerContext* server = t->pair[0].server;
    whKeyId          src    = WH_KEYID_ERASED;
    whKeyId          src256 = WH_KEYID_ERASED;
    whKeyId          hwId;
    whNvmMetadata    meta[1];
    int              ret;

    WH_TEST_RETURN_ON_FAIL(
        _Cache(c, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src));

    /* Sources: a hardware key, a missing key, and no key at all */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          _Load(c, HW(0), HW(MOCK_PORT_SLOT), &hwId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          _Load(c, HW(0), SRC_MISSING_ID, &hwId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          _Load(c, HW(0), WH_KEYID_ERASED, &hwId));

    /* The port takes only AES-128 keys */
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c, USAGE_AES_CMAC, _key256, sizeof(_key256), &src256));
    WH_TEST_ASSERT_RETURN(BAD_FUNC_ARG ==
                          _Load(c, HW(MOCK_LOAD_FIRST), src256, &hwId));
    WH_TEST_ASSERT_RETURN(BAD_FUNC_ARG == _Load(c, HW(0), src256, &hwId));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c, MOCK_LOAD_FIRST, 0, 0, 0));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src256));

    /* Targets: IDs that aren't loadable hardware keys, and the port key */
    WH_TEST_ASSERT_RETURN(BAD_FUNC_ARG == _Load(c, HW(1), src, &hwId));
    WH_TEST_ASSERT_RETURN(BAD_FUNC_ARG == _Load(c, HW(5), src, &hwId));
    WH_TEST_ASSERT_RETURN(BAD_FUNC_ARG == _Load(c, HW(9), src, &hwId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          _Load(c, HW(MOCK_PORT_SLOT), src, &hwId));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c, MOCK_LOAD_FIRST, 0, 0, 0));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c, MOCK_LOAD_LAST, 0, 0, 0));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src));

    /* A trusted key is refused like for every client keystore operation. Only
     * the server can make one */
    memset(meta, 0, sizeof(meta));
    meta->id    = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, CLIENT1_ID, SRC_TRUSTED_ID);
    meta->flags = WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_TRUSTED;
    meta->len   = AES_128_KEY_SIZE;
    ret         = WH_SERVER_NVM_LOCK(server);
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_KeystoreCacheKey(server, meta, _keyA);
        (void)WH_SERVER_NVM_UNLOCK(server);
    } /* WH_SERVER_NVM_LOCK() */
    WH_TEST_RETURN_ON_FAIL(ret);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          _Load(c, HW(0), SRC_TRUSTED_ID, &hwId));
    ret = WH_SERVER_NVM_LOCK(server);
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_KeystoreEvictKey(server, meta->id);
        (void)WH_SERVER_NVM_UNLOCK(server);
    } /* WH_SERVER_NVM_LOCK() */
    WH_TEST_RETURN_ON_FAIL(ret);

    return WH_ERROR_OK;
}

/* Clear and ClearAll */
static int _whTest_HwKeyClear(TestCtx* t)
{
    whClientContext* c1   = t->pair[0].client;
    whClientContext* c2   = t->pair[1].client;
    whKeyId          src1 = WH_KEYID_ERASED;
    whKeyId          src2 = WH_KEYID_ERASED;
    whKeyId          hw1;
    whKeyId          hw2;

    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src1));
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c2, USAGE_AES_CMAC, _keyB, sizeof(_keyB), &src2));
    WH_TEST_RETURN_ON_FAIL(_Load(c1, HW(0), src1, &hw1));
    WH_TEST_RETURN_ON_FAIL(_Load(c2, HW(0), src2, &hw2));

    /* Only the owner can clear a key, nobody can clear the port key, and ID 0
     * isn't a key to clear */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Client_HwKeystoreClear(c1, hw2));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Client_HwKeystoreClear(c1, HW(MOCK_PORT_SLOT)));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_Client_HwKeystoreClear(c1, HW(9)));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_Client_HwKeystoreClearRequest(c1, HW(0)));

    /* The split request and response. The key is then gone */
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClearRequest(c1, hw1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClearResponse(c1));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c1, WH_KEYID_ID(hw1), 0, 0, 0));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == _TryEcb(c1, hw1, 1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_Client_HwKeystoreClear(c1, hw1));

    /* ClearAll clears only the caller's keys */
    WH_TEST_RETURN_ON_FAIL(_Load(c1, HW(0), src1, &hw1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClearAll(c1));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c1, WH_KEYID_ID(hw1), 0, 0, 0));
    WH_TEST_RETURN_ON_FAIL(
        _CheckInfo(c1, WH_KEYID_ID(hw2), 1, USAGE_AES_CMAC, CLIENT2_ID));
    WH_TEST_RETURN_ON_FAIL(
        _CheckInfo(c1, MOCK_PORT_SLOT, 1, USAGE_AES_CMAC, WH_KEYUSER_GLOBAL));
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c2, hw2, _keyB));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClearAll(c2));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c1, WH_KEYID_ID(hw2), 0, 0, 0));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c1, src1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c2, src2));
    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/* A key loaded with the global flag is shared: every client can use it, and
 * clearing it takes the global flag too */
static int _whTest_HwKeyShared(TestCtx* t)
{
    whClientContext* c1  = t->pair[0].client;
    whClientContext* c2  = t->pair[1].client;
    whKeyId          src = WH_KEYID_ERASED;
    whKeyId          hwId;

    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src));
    WH_TEST_RETURN_ON_FAIL(
        _Load(c1, WH_CLIENT_KEYID_MAKE_GLOBAL(HW(0)), src, &hwId));
    WH_TEST_ASSERT_RETURN(hwId ==
                          WH_CLIENT_KEYID_MAKE_GLOBAL(HW(MOCK_LOAD_FIRST)));
    WH_TEST_RETURN_ON_FAIL(
        _CheckInfo(c2, MOCK_LOAD_FIRST, 1, USAGE_AES_CMAC, WH_KEYUSER_GLOBAL));

    /* Both clients can use it, by either form of the ID */
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c1, hwId, _keyA));
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c2, hwId, _keyA));
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c2, HW(MOCK_LOAD_FIRST), _keyA));
    WH_TEST_RETURN_ON_FAIL(_TryCmac(c2, hwId));

    /* ClearAll and a clear without the global flag leave it */
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClearAll(c1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Client_HwKeystoreClear(c2, HW(MOCK_LOAD_FIRST)));
    WH_TEST_RETURN_ON_FAIL(
        _CheckInfo(c1, MOCK_LOAD_FIRST, 1, USAGE_AES_CMAC, WH_KEYUSER_GLOBAL));

    /* Any client can clear it with the global flag */
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClear(c2, hwId));
    WH_TEST_RETURN_ON_FAIL(_CheckInfo(c1, MOCK_LOAD_FIRST, 0, 0, 0));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c1, src));
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

/* If the hardware loses a key the server still records, requests fail rather
 * than run in software without the key */
static int _whTest_HwKeyNoFallback(TestCtx* t)
{
    whClientContext* c   = t->pair[0].client;
    whKeyId          src = WH_KEYID_ERASED;
    whKeyId          hwId;
    int              slot;

    WH_TEST_RETURN_ON_FAIL(
        _Cache(c, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src));
    WH_TEST_RETURN_ON_FAIL(_Load(c, HW(0), src, &hwId));
    slot = (int)WH_KEYID_ID(hwId);

    _mock.loaded[slot] = 0;
    WH_TEST_ASSERT_RETURN(WC_HW_E == _TryEcb(c, hwId, 1));
    WH_TEST_ASSERT_RETURN(WC_HW_E == _TryCmac(c, hwId));
    _mock.loaded[slot] = 1;
    WH_TEST_RETURN_ON_FAIL(_EcbMatches(c, hwId, _keyA));

    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClear(c, hwId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c, src));
    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_KEYWRAP
/* Wrapped size of an AES-128 key */
#define TEST_WRAPPED_SZ \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(whNvmMetadata) + AES_128_KEY_SIZE)

/* Wrap _keyB under kekId, then unwrap it and check the round trip */
static int _WrapRoundTrip(whClientContext* c, whKeyId kekId)
{
    whNvmMetadata meta;
    whNvmMetadata outMeta;
    uint8_t       wrapped[TEST_WRAPPED_SZ];
    uint16_t      wrappedSz = sizeof(wrapped);
    uint8_t       key[AES_128_KEY_SIZE];
    uint16_t      keySz = sizeof(key);
    int           ret;

    memset(&meta, 0, sizeof(meta));
    meta.id    = WH_CLIENT_KEYID_MAKE_WRAPPED_META(c->comm->client_id, 0x30);
    meta.len   = AES_128_KEY_SIZE;
    meta.flags = WH_NVM_FLAGS_USAGE_ENCRYPT;

    ret = wh_Client_KeyWrap(c, WC_CIPHER_AES_GCM, kekId, _keyB, sizeof(_keyB),
                            &meta, wrapped, &wrappedSz);
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_KeyUnwrapAndExport(c, WC_CIPHER_AES_GCM, kekId, wrapped,
                                           wrappedSz, &outMeta, key, &keySz);
    }
    if (ret == WH_ERROR_OK) {
        WH_TEST_ASSERT_RETURN(keySz == sizeof(_keyB));
        WH_TEST_ASSERT_RETURN(memcmp(key, _keyB, sizeof(_keyB)) == 0);
    }
    return ret;
}

/* Hardware keys as key wrap KEKs. The port key is trusted, since no client can
 * set or read it, so it also works for wrap-export and unwrap-and-cache. A
 * client-loaded key is an ordinary KEK, since the client may know its bytes.
 * Either needs WRAP usage, and a WRAP-only key is not a cipher key */
static int _whTest_HwKeyKek(TestCtx* t)
{
    whClientContext* c1       = t->pair[0].client;
    whClientContext* c2       = t->pair[1].client;
    whKeyId          src      = WH_KEYID_ERASED;
    whKeyId          plainSrc = WH_KEYID_ERASED;
    whKeyId          cachedId = WH_KEYID_ERASED;
    whKeyId          hwId;
    whNvmMetadata    meta;
    uint8_t          wrapped[TEST_WRAPPED_SZ];
    uint16_t         wrappedSz = sizeof(wrapped);
    uint8_t          data[]    = "hardware KEK data";
    uint8_t          wrappedData[WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(data)];
    uint32_t         wrappedDataSz = sizeof(wrappedData);
    uint8_t          dataOut[sizeof(data)];
    uint32_t         dataOutSz = sizeof(dataOut);
    int              ops;

    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &plainSrc));

    /* The port key as a WRAP-only KEK. The engine runs every wrap step with
     * the key in its slot */
    WH_TEST_RETURN_ON_FAIL(
        _Reboot(t, WH_KEYUSER_GLOBAL, WH_NVM_FLAGS_USAGE_WRAP));
    ops = _mock.ops;
    WH_TEST_RETURN_ON_FAIL(_WrapRoundTrip(c2, HW(MOCK_PORT_SLOT)));
    WH_TEST_ASSERT_RETURN(_mock.ops == ops + 2);

    /* It is trusted: wrap-export a server-held key, then cache it back */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapExport(
        c1, WC_CIPHER_AES_GCM, plainSrc, WH_KEYTYPE_CRYPTO, HW(MOCK_PORT_SLOT),
        wrapped, &wrappedSz));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyUnwrapAndCache(c1, WC_CIPHER_AES_GCM, HW(MOCK_PORT_SLOT),
                                    wrapped, wrappedSz, &cachedId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c1, cachedId));

    /* WRAP-only, so not a cipher key */
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE == _TryEcb(c1, HW(MOCK_PORT_SLOT), 1));

    /* The usual port key has no WRAP usage */
    WH_TEST_RETURN_ON_FAIL(_Reboot(t, WH_KEYUSER_GLOBAL, USAGE_AES_CMAC));
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                          _WrapRoundTrip(c1, HW(MOCK_PORT_SLOT)));

    /* A client-loaded WRAP key is an ordinary KEK */
    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, WH_NVM_FLAGS_USAGE_WRAP, _keyC, sizeof(_keyC), &src));
    WH_TEST_RETURN_ON_FAIL(_Load(c1, HW(0), src, &hwId));
    WH_TEST_RETURN_ON_FAIL(_WrapRoundTrip(c1, hwId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_DataWrap(c1, WC_CIPHER_AES_GCM, hwId, data,
                                              sizeof(data), wrappedData,
                                              &wrappedDataSz));
    WH_TEST_RETURN_ON_FAIL(wh_Client_DataUnwrap(c1, WC_CIPHER_AES_GCM, hwId,
                                                wrappedData, wrappedDataSz,
                                                dataOut, &dataOutSz));
    WH_TEST_ASSERT_RETURN((dataOutSz == sizeof(data)) &&
                          (memcmp(dataOut, data, sizeof(data)) == 0));

    /* Not trusted: the client may know its bytes */
    wrappedSz = sizeof(wrapped);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Client_KeyWrapExport(c1, WC_CIPHER_AES_GCM,
                                                  plainSrc, WH_KEYTYPE_CRYPTO,
                                                  hwId, wrapped, &wrappedSz));
    memset(&meta, 0, sizeof(meta));
    meta.id   = WH_CLIENT_KEYID_MAKE_WRAPPED_META(c1->comm->client_id, 0x30);
    meta.len  = AES_128_KEY_SIZE;
    wrappedSz = sizeof(wrapped);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrap(c1, WC_CIPHER_AES_GCM, hwId, _keyB,
                                             sizeof(_keyB), &meta, wrapped,
                                             &wrappedSz));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Client_KeyUnwrapAndCache(c1, WC_CIPHER_AES_GCM,
                                                      hwId, wrapped, wrappedSz,
                                                      &cachedId));

    /* WRAP-only, and only for its owner */
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE == _TryEcb(c1, hwId, 1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS == _WrapRoundTrip(c2, hwId));

    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClear(c1, hwId));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c1, src));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c1, plainSrc));
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_KEYWRAP */

/* A port key registered for one client: only that client can use it, and no
 * client can set or clear it */
static int _whTest_HwKeyPortKeyOwner(TestCtx* t)
{
    whClientContext* c1  = t->pair[0].client;
    whClientContext* c2  = t->pair[1].client;
    whKeyId          src = WH_KEYID_ERASED;
    whKeyId          hwId;

    WH_TEST_RETURN_ON_FAIL(_Reboot(t, CLIENT1_ID, USAGE_AES_CMAC));
    WH_TEST_RETURN_ON_FAIL(
        _CheckInfo(c2, MOCK_PORT_SLOT, 1, USAGE_AES_CMAC, CLIENT1_ID));

    WH_TEST_RETURN_ON_FAIL(_CheckModes(c1, HW(MOCK_PORT_SLOT), _portKey, 0, 1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          _TryEcb(c2, HW(MOCK_PORT_SLOT), 1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS == _TryCmac(c2, HW(MOCK_PORT_SLOT)));

    WH_TEST_RETURN_ON_FAIL(
        _Cache(c1, USAGE_AES_CMAC, _keyA, sizeof(_keyA), &src));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          _Load(c1, HW(MOCK_PORT_SLOT), src, &hwId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Client_HwKeystoreClear(c1, HW(MOCK_PORT_SLOT)));
    WH_TEST_RETURN_ON_FAIL(wh_Client_HwKeystoreClearAll(c1));
    WH_TEST_RETURN_ON_FAIL(
        _CheckInfo(c1, MOCK_PORT_SLOT, 1, USAGE_AES_CMAC, CLIENT1_ID));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(c1, src));

    /* Back to a shared port key */
    return _Reboot(t, WH_KEYUSER_GLOBAL, USAGE_AES_CMAC);
}

int whTest_HwKeystoreCrypto(void* ctx)
{
    TestCtx* t = &_testCtx;
    int      ret;

    (void)ctx;

    ret = _Setup(t);
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyMap(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyPortKey(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyLoadAndUse(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyAllocation(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyUsage(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeySource(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyRefused(t);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyClear(t);
    }
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyShared(t);
    }
#endif
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyNoFallback(t);
    }
#ifdef WOLFHSM_CFG_KEYWRAP
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyKek(t);
    }
#endif
    if (ret == WH_ERROR_OK) {
        ret = _whTest_HwKeyPortKeyOwner(t);
    }

    _Cleanup(t);

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER &&      \
          WOLFHSM_CFG_HWKEYSTORE_LOAD && HAVE_AES_ECB && HAVE_AES_CBC && \
          WOLFSSL_AES_COUNTER && HAVE_AESGCM && WOLFSSL_CMAC &&          \
          WOLFSSL_AES_DIRECT */
