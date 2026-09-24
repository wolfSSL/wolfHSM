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

/* Endian-translation coverage for the crypto message structs. A loopback test
 * cannot observe peers that disagree on byte order, so these call the
 * translation helpers directly with the magic of a foreign-endian peer. */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Number of chaining words a SHA-2 intermediate state carries */
#define WH_TEST_SHA2_STATE_WORDS 8

/* Magic of a peer whose byte order is the opposite of ours */
#define WH_TEST_MAGIC_FOREIGN ((uint16_t)WH_COMM_MAGIC_SWAP)
#define WH_TEST_MAGIC_LOCAL ((uint16_t)WH_COMM_MAGIC_NATIVE)

/* Fill with distinct byte values so any missed swap is visible */
static void _whTest_FillPattern(uint8_t* buf, uint32_t len, uint8_t seed)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + i);
    }
}

/* Return 1 if each word of dest is the matching word of src, byte-reversed */
static int _whTest_WordsSwapped(const uint8_t* dest, const uint8_t* src,
                                uint32_t wordSize, uint32_t words)
{
    uint32_t i;
    uint32_t j;

    for (i = 0; i < words; i++) {
        for (j = 0; j < wordSize; j++) {
            if (dest[(i * wordSize) + j] !=
                src[(i * wordSize) + (wordSize - 1u - j)]) {
                return 0;
            }
        }
    }
    return 1;
}

static int _whTest_MessageCryptoSha256Request(void)
{
    whMessageCrypto_Sha256Request src;
    whMessageCrypto_Sha256Request dest;
    whMessageCrypto_Sha256Request back;

    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));
    memset(&back, 0, sizeof(back));

    src.resumeState.hiLen = 0x01020304u;
    src.resumeState.loLen = 0x05060708u;
    src.isLastBlock       = 1;
    src.inSz              = 0x090a0b0cu;
    _whTest_FillPattern(src.resumeState.hash,
                        (uint32_t)sizeof(src.resumeState.hash), 0x10);

    /* A same-endian peer must see the message unchanged */
    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha256Request(WH_TEST_MAGIC_LOCAL, &src,
                                                &dest));
    WH_TEST_ASSERT_RETURN(memcmp(&dest, &src, sizeof(src)) == 0);

    /* A cross-endian peer swaps every chaining word. A request carries
     * intermediate state even on the last block, so isLastBlock is set here. */
    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha256Request(WH_TEST_MAGIC_FOREIGN, &src,
                                                &dest));
    WH_TEST_ASSERT_RETURN(
        _whTest_WordsSwapped(dest.resumeState.hash, src.resumeState.hash,
                             (uint32_t)sizeof(uint32_t),
                             WH_TEST_SHA2_STATE_WORDS));
    WH_TEST_ASSERT_RETURN(dest.resumeState.hiLen ==
                          wh_Translate32(WH_TEST_MAGIC_FOREIGN,
                                         src.resumeState.hiLen));

    /* Translation is its own inverse */
    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha256Request(WH_TEST_MAGIC_FOREIGN, &dest,
                                                &back));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &src, sizeof(src)) == 0);

    /* In-place translation must give the same result */
    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha256Request(WH_TEST_MAGIC_FOREIGN, &back,
                                                &back));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &dest, sizeof(src)) == 0);

    return WH_TEST_SUCCESS;
}

#if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
static int _whTest_MessageCryptoSha512Request(void)
{
    whMessageCrypto_Sha512Request src;
    whMessageCrypto_Sha512Request dest;
    whMessageCrypto_Sha512Request back;

    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));
    memset(&back, 0, sizeof(back));

    src.resumeState.hiLen    = 0x01020304u;
    src.resumeState.loLen    = 0x05060708u;
    src.resumeState.hashType = 0x090a0b0cu;
    src.isLastBlock          = 0;
    src.inSz                 = 128;
    _whTest_FillPattern(src.resumeState.hash,
                        (uint32_t)sizeof(src.resumeState.hash), 0x20);

    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha512Request(WH_TEST_MAGIC_LOCAL, &src,
                                                &dest));
    WH_TEST_ASSERT_RETURN(memcmp(&dest, &src, sizeof(src)) == 0);

    /* The SHA512 family chains 64-bit words */
    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha512Request(WH_TEST_MAGIC_FOREIGN, &src,
                                                &dest));
    WH_TEST_ASSERT_RETURN(
        _whTest_WordsSwapped(dest.resumeState.hash, src.resumeState.hash,
                             (uint32_t)sizeof(uint64_t),
                             WH_TEST_SHA2_STATE_WORDS));

    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha512Request(WH_TEST_MAGIC_FOREIGN, &dest,
                                                &back));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &src, sizeof(src)) == 0);

    return WH_TEST_SUCCESS;
}
#endif /* WOLFSSL_SHA512 || WOLFSSL_SHA384 */

static int _whTest_MessageCryptoSha2Response(void)
{
    whMessageCrypto_Sha2Response src;
    whMessageCrypto_Sha2Response dest;
    whMessageCrypto_Sha2Response back;

    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));
    memset(&back, 0, sizeof(back));

    src.hiLen    = 0x01020304u;
    src.loLen    = 0x05060708u;
    src.hashType = 0x090a0b0cu;
    _whTest_FillPattern(src.hash, (uint32_t)sizeof(src.hash), 0x30);

    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2Response_ex(
        WH_TEST_MAGIC_LOCAL, &src, &dest, (uint32_t)sizeof(uint32_t)));
    WH_TEST_ASSERT_RETURN(memcmp(&dest, &src, sizeof(src)) == 0);

    /* SHA224/256 state: the first 8 words swap, the unused tail is copied */
    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2Response_ex(
        WH_TEST_MAGIC_FOREIGN, &src, &dest, (uint32_t)sizeof(uint32_t)));
    WH_TEST_ASSERT_RETURN(_whTest_WordsSwapped(dest.hash, src.hash,
                                               (uint32_t)sizeof(uint32_t),
                                               WH_TEST_SHA2_STATE_WORDS));
    WH_TEST_ASSERT_RETURN(memcmp(&dest.hash[32], &src.hash[32], 32) == 0);
    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2Response_ex(
        WH_TEST_MAGIC_FOREIGN, &dest, &back, (uint32_t)sizeof(uint32_t)));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &src, sizeof(src)) == 0);

    /* SHA384/512 state: all 8 words are 64 bits wide */
    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2Response_ex(
        WH_TEST_MAGIC_FOREIGN, &src, &dest, (uint32_t)sizeof(uint64_t)));
    WH_TEST_ASSERT_RETURN(_whTest_WordsSwapped(dest.hash, src.hash,
                                               (uint32_t)sizeof(uint64_t),
                                               WH_TEST_SHA2_STATE_WORDS));
    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2Response_ex(
        WH_TEST_MAGIC_FOREIGN, &dest, &back, (uint32_t)sizeof(uint64_t)));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &src, sizeof(src)) == 0);

    /* A finalized digest is already in canonical order and must not move,
     * which is what the plain (non _ex) helper is for */
    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2Response_ex(
        WH_TEST_MAGIC_FOREIGN, &src, &dest, 0));
    WH_TEST_ASSERT_RETURN(memcmp(dest.hash, src.hash, sizeof(src.hash)) == 0);
    WH_TEST_ASSERT_RETURN(dest.loLen ==
                          wh_Translate32(WH_TEST_MAGIC_FOREIGN, src.loLen));

    memset(&dest, 0, sizeof(dest));
    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2Response(
        WH_TEST_MAGIC_FOREIGN, &src, &dest));
    WH_TEST_ASSERT_RETURN(memcmp(dest.hash, src.hash, sizeof(src.hash)) == 0);

    return WH_TEST_SUCCESS;
}

#if defined(WOLFHSM_CFG_DMA)
static int _whTest_MessageCryptoSha256DmaRequest(void)
{
    whMessageCrypto_Sha256DmaRequest src;
    whMessageCrypto_Sha256DmaRequest dest;
    whMessageCrypto_Sha256DmaRequest back;

    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));
    memset(&back, 0, sizeof(back));

    src.resumeState.hiLen = 0x01020304u;
    src.resumeState.loLen = 0x05060708u;
    src.input.addr        = 0x1122334455667788ull;
    src.input.sz          = 64;
    src.isLastBlock       = 0;
    src.inSz              = 0;
    _whTest_FillPattern(src.resumeState.hash,
                        (uint32_t)sizeof(src.resumeState.hash), 0x40);

    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha256DmaRequest(WH_TEST_MAGIC_LOCAL, &src,
                                                   &dest));
    WH_TEST_ASSERT_RETURN(memcmp(&dest, &src, sizeof(src)) == 0);

    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha256DmaRequest(WH_TEST_MAGIC_FOREIGN, &src,
                                                   &dest));
    WH_TEST_ASSERT_RETURN(
        _whTest_WordsSwapped(dest.resumeState.hash, src.resumeState.hash,
                             (uint32_t)sizeof(uint32_t),
                             WH_TEST_SHA2_STATE_WORDS));

    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha256DmaRequest(WH_TEST_MAGIC_FOREIGN, &dest,
                                                   &back));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &src, sizeof(src)) == 0);

    return WH_TEST_SUCCESS;
}

static int _whTest_MessageCryptoSha512DmaRequest(void)
{
    whMessageCrypto_Sha512DmaRequest src;
    whMessageCrypto_Sha512DmaRequest dest;
    whMessageCrypto_Sha512DmaRequest back;

    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));
    memset(&back, 0, sizeof(back));

    src.resumeState.hiLen    = 0x01020304u;
    src.resumeState.loLen    = 0x05060708u;
    src.resumeState.hashType = 0x090a0b0cu;
    src.input.addr           = 0x1122334455667788ull;
    src.input.sz             = 128;
    _whTest_FillPattern(src.resumeState.hash,
                        (uint32_t)sizeof(src.resumeState.hash), 0x50);

    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha512DmaRequest(WH_TEST_MAGIC_LOCAL, &src,
                                                   &dest));
    WH_TEST_ASSERT_RETURN(memcmp(&dest, &src, sizeof(src)) == 0);

    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha512DmaRequest(WH_TEST_MAGIC_FOREIGN, &src,
                                                   &dest));
    WH_TEST_ASSERT_RETURN(
        _whTest_WordsSwapped(dest.resumeState.hash, src.resumeState.hash,
                             (uint32_t)sizeof(uint64_t),
                             WH_TEST_SHA2_STATE_WORDS));

    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha512DmaRequest(WH_TEST_MAGIC_FOREIGN, &dest,
                                                   &back));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &src, sizeof(src)) == 0);

    return WH_TEST_SUCCESS;
}

static int _whTest_MessageCryptoSha2DmaResponse(void)
{
    whMessageCrypto_Sha2DmaResponse src;
    whMessageCrypto_Sha2DmaResponse dest;
    whMessageCrypto_Sha2DmaResponse back;

    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));
    memset(&back, 0, sizeof(back));

    src.hiLen                 = 0x01020304u;
    src.loLen                 = 0x05060708u;
    src.hashType              = 0x090a0b0cu;
    src.dmaAddrStatus.badAddr.addr = 0x1122334455667788ull;
    _whTest_FillPattern(src.hash, (uint32_t)sizeof(src.hash), 0x60);

    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2DmaResponse_ex(
        WH_TEST_MAGIC_FOREIGN, &src, &dest, (uint32_t)sizeof(uint32_t)));
    WH_TEST_ASSERT_RETURN(_whTest_WordsSwapped(dest.hash, src.hash,
                                               (uint32_t)sizeof(uint32_t),
                                               WH_TEST_SHA2_STATE_WORDS));
    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2DmaResponse_ex(
        WH_TEST_MAGIC_FOREIGN, &dest, &back, (uint32_t)sizeof(uint32_t)));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &src, sizeof(src)) == 0);

    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2DmaResponse_ex(
        WH_TEST_MAGIC_FOREIGN, &src, &dest, (uint32_t)sizeof(uint64_t)));
    WH_TEST_ASSERT_RETURN(_whTest_WordsSwapped(dest.hash, src.hash,
                                               (uint32_t)sizeof(uint64_t),
                                               WH_TEST_SHA2_STATE_WORDS));

    /* Final block: the digest is canonical already */
    WH_TEST_RETURN_ON_FAIL(wh_MessageCrypto_TranslateSha2DmaResponse(
        WH_TEST_MAGIC_FOREIGN, &src, &dest));
    WH_TEST_ASSERT_RETURN(memcmp(dest.hash, src.hash, sizeof(src.hash)) == 0);

    return WH_TEST_SUCCESS;
}
#endif /* WOLFHSM_CFG_DMA */

/* The SHA3 Keccak state has always been translated per word. Checking it with
 * the same helper confirms the helper agrees with known-good behavior. */
static int _whTest_MessageCryptoSha3State(void)
{
    whMessageCrypto_Sha3State src;
    whMessageCrypto_Sha3State dest;
    int                       i;

    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));

    for (i = 0; i < 25; i++) {
        src.s[i] = 0x0102030405060708ull + (uint64_t)i;
    }

    WH_TEST_RETURN_ON_FAIL(
        wh_MessageCrypto_TranslateSha3State(WH_TEST_MAGIC_FOREIGN, &src,
                                            &dest));
    WH_TEST_ASSERT_RETURN(_whTest_WordsSwapped((const uint8_t*)dest.s,
                                               (const uint8_t*)src.s,
                                               (uint32_t)sizeof(uint64_t), 25));

    return WH_TEST_SUCCESS;
}

int whTest_MessageCryptoTranslate(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing crypto message translation...\n");

    WH_TEST_RETURN_ON_FAIL(_whTest_MessageCryptoSha256Request());
#if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
    WH_TEST_RETURN_ON_FAIL(_whTest_MessageCryptoSha512Request());
#endif
    WH_TEST_RETURN_ON_FAIL(_whTest_MessageCryptoSha2Response());
#if defined(WOLFHSM_CFG_DMA)
    WH_TEST_RETURN_ON_FAIL(_whTest_MessageCryptoSha256DmaRequest());
    WH_TEST_RETURN_ON_FAIL(_whTest_MessageCryptoSha512DmaRequest());
    WH_TEST_RETURN_ON_FAIL(_whTest_MessageCryptoSha2DmaResponse());
#endif
    WH_TEST_RETURN_ON_FAIL(_whTest_MessageCryptoSha3State());

    return WH_TEST_SUCCESS;
}
