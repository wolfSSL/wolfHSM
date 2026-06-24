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
 * test-refactor/server/wh_test_server_img_mgr.c
 *
 * Server-side image manager test suite. Exercises the built-in
 * verify methods (ECC, AES-CMAC, RSA, wolfBoot) through direct
 * server API calls against the shared server context.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_SERVER_IMG_MGR) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_img_mgr.h"
#include "wolfhsm/wh_server_keystore.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifndef NO_RSA
#include "gen/wh_test_wolfboot_img_data.h"
#endif

/* Test data to be "verified" */
static const uint8_t testData[] = {
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64,
    0x21, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61,
    0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61,
    0x67, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x45, 0x43, 0x43, 0x20,
    0x73, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x20, 0x76,
    0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69};

#ifdef HAVE_ECC
/* Hardcoded ECC P256 private key for testing (DER format) */
/* ./certs/ecc-key.der, ECC */
static const unsigned char testEccPrivKey[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x45, 0xB6, 0x69, 0x02,
    0x73, 0x9C, 0x6C, 0x85, 0xA1, 0x38, 0x5B, 0x72, 0xE8, 0xE8, 0xC7,
    0xAC, 0xC4, 0x03, 0x8D, 0x53, 0x35, 0x04, 0xFA, 0x6C, 0x28, 0xDC,
    0x34, 0x8D, 0xE1, 0xA8, 0x09, 0x8C, 0xA0, 0x0A, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0xA1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0xBB, 0x33, 0xAC, 0x4C, 0x27, 0x50, 0x4A, 0xC6, 0x4A,
    0xA5, 0x04, 0xC3, 0x3C, 0xDE, 0x9F, 0x36, 0xDB, 0x72, 0x2D, 0xCE,
    0x94, 0xEA, 0x2B, 0xFA, 0xCB, 0x20, 0x09, 0x39, 0x2C, 0x16, 0xE8,
    0x61, 0x02, 0xE9, 0xAF, 0x4D, 0xD3, 0x02, 0x93, 0x9A, 0x31, 0x5B,
    0x97, 0x92, 0x21, 0x7F, 0xF0, 0xCF, 0x18, 0xDA, 0x91, 0x11, 0x02,
    0x34, 0x86, 0xE8, 0x20, 0x58, 0x33, 0x0B, 0x80, 0x34, 0x89, 0xD8};
#endif /* HAVE_ECC */

#ifdef WOLFSSL_CMAC
/* Hardcoded AES128 key for testing */
static const uint8_t testAes128Key[AES_128_KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
#endif /* WOLFSSL_CMAC */

#ifndef NO_RSA
/* Hardcoded RSA2048 private key for testing (DER format) */
static const unsigned char testRsa2048PrivKey[] = {
    0x30, 0x82, 0x04, 0xA4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
    0xC3, 0x03, 0xD1, 0x2B, 0xFE, 0x39, 0xA4, 0x32, 0x45, 0x3B, 0x53, 0xC8,
    0x84, 0x2B, 0x2A, 0x7C, 0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
    0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0, 0xBA, 0x69, 0x7B, 0xC6,
    0xC3, 0x44, 0x9E, 0xD4, 0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
    0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2, 0x1B, 0xF7, 0x8B, 0xBA,
    0xCF, 0x0D, 0xF9, 0xEF, 0xEC, 0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03, 0x47,
    0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65, 0x24, 0x69, 0xA6, 0xE8, 0x14, 0x89,
    0x5B, 0xE4, 0x34, 0xF7, 0xC5, 0xB0, 0x14, 0x93, 0xF5, 0x67, 0x7B, 0x3A,
    0x7A, 0x78, 0xE1, 0x01, 0x56, 0x56, 0x91, 0xA6, 0x13, 0x42, 0x8D, 0xD2,
    0x3C, 0x40, 0x9C, 0x4C, 0xEF, 0xD1, 0x86, 0xDF, 0x37, 0x51, 0x1B, 0x0C,
    0xA1, 0x3B, 0xF5, 0xF1, 0xA3, 0x4A, 0x35, 0xE4, 0xE1, 0xCE, 0x96, 0xDF,
    0x1B, 0x7E, 0xBF, 0x4E, 0x97, 0xD0, 0x10, 0xE8, 0xA8, 0x08, 0x30, 0x81,
    0xAF, 0x20, 0x0B, 0x43, 0x14, 0xC5, 0x74, 0x67, 0xB4, 0x32, 0x82, 0x6F,
    0x8D, 0x86, 0xC2, 0x88, 0x40, 0x99, 0x36, 0x83, 0xBA, 0x1E, 0x40, 0x72,
    0x22, 0x17, 0xD7, 0x52, 0x65, 0x24, 0x73, 0xB0, 0xCE, 0xEF, 0x19, 0xCD,
    0xAE, 0xFF, 0x78, 0x6C, 0x7B, 0xC0, 0x12, 0x03, 0xD4, 0x4E, 0x72, 0x0D,
    0x50, 0x6D, 0x3B, 0xA3, 0x3B, 0xA3, 0x99, 0x5E, 0x9D, 0xC8, 0xD9, 0x0C,
    0x85, 0xB3, 0xD9, 0x8A, 0xD9, 0x54, 0x26, 0xDB, 0x6D, 0xFA, 0xAC, 0xBB,
    0xFF, 0x25, 0x4C, 0xC4, 0xD1, 0x79, 0xF4, 0x71, 0xD3, 0x86, 0x40, 0x18,
    0x13, 0xB0, 0x63, 0xB5, 0x72, 0x4E, 0x30, 0xC4, 0x97, 0x84, 0x86, 0x2D,
    0x56, 0x2F, 0xD7, 0x15, 0xF7, 0x7F, 0xC0, 0xAE, 0xF5, 0xFC, 0x5B, 0xE5,
    0xFB, 0xA1, 0xBA, 0xD3, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
    0x01, 0x00, 0xA2, 0xE6, 0xD8, 0x5F, 0x10, 0x71, 0x64, 0x08, 0x9E, 0x2E,
    0x6D, 0xD1, 0x6D, 0x1E, 0x85, 0xD2, 0x0A, 0xB1, 0x8C, 0x47, 0xCE, 0x2C,
    0x51, 0x6A, 0xA0, 0x12, 0x9E, 0x53, 0xDE, 0x91, 0x4C, 0x1D, 0x6D, 0xEA,
    0x59, 0x7B, 0xF2, 0x77, 0xAA, 0xD9, 0xC6, 0xD9, 0x8A, 0xAB, 0xD8, 0xE1,
    0x16, 0xE4, 0x63, 0x26, 0xFF, 0xB5, 0x6C, 0x13, 0x59, 0xB8, 0xE3, 0xA5,
    0xC8, 0x72, 0x17, 0x2E, 0x0C, 0x9F, 0x6F, 0xE5, 0x59, 0x3F, 0x76, 0x6F,
    0x49, 0xB1, 0x11, 0xC2, 0x5A, 0x2E, 0x16, 0x29, 0x0D, 0xDE, 0xB7, 0x8E,
    0xDC, 0x40, 0xD5, 0xA2, 0xEE, 0xE0, 0x1E, 0xA1, 0xF4, 0xBE, 0x97, 0xDB,
    0x86, 0x63, 0x96, 0x14, 0xCD, 0x98, 0x09, 0x60, 0x2D, 0x30, 0x76, 0x9C,
    0x3C, 0xCD, 0xE6, 0x88, 0xEE, 0x47, 0x92, 0x79, 0x0B, 0x5A, 0x00, 0xE2,
    0x5E, 0x5F, 0x11, 0x7C, 0x7D, 0xF9, 0x08, 0xB7, 0x20, 0x06, 0x89, 0x2A,
    0x5D, 0xFD, 0x00, 0xAB, 0x22, 0xE1, 0xF0, 0xB3, 0xBC, 0x24, 0xA9, 0x5E,
    0x26, 0x0E, 0x1F, 0x00, 0x2D, 0xFE, 0x21, 0x9A, 0x53, 0x5B, 0x6D, 0xD3,
    0x2B, 0xAB, 0x94, 0x82, 0x68, 0x43, 0x36, 0xD8, 0xF6, 0x2F, 0xC6, 0x22,
    0xFC, 0xB5, 0x41, 0x5D, 0x0D, 0x33, 0x60, 0xEA, 0xA4, 0x7D, 0x7E, 0xE8,
    0x4B, 0x55, 0x91, 0x56, 0xD3, 0x5C, 0x57, 0x8F, 0x1F, 0x94, 0x17, 0x2F,
    0xAA, 0xDE, 0xE9, 0x9E, 0xA8, 0xF4, 0xCF, 0x8A, 0x4C, 0x8E, 0xA0, 0xE4,
    0x56, 0x73, 0xB2, 0xCF, 0x4F, 0x86, 0xC5, 0x69, 0x3C, 0xF3, 0x24, 0x20,
    0x8B, 0x5C, 0x96, 0x0C, 0xFA, 0x6B, 0x12, 0x3B, 0x9A, 0x67, 0xC1, 0xDF,
    0xC6, 0x96, 0xB2, 0xA5, 0xD5, 0x92, 0x0D, 0x9B, 0x09, 0x42, 0x68, 0x24,
    0x10, 0x45, 0xD4, 0x50, 0xE4, 0x17, 0x39, 0x48, 0xD0, 0x35, 0x8B, 0x94,
    0x6D, 0x11, 0xDE, 0x8F, 0xCA, 0x59, 0x02, 0x81, 0x81, 0x00, 0xEA, 0x24,
    0xA7, 0xF9, 0x69, 0x33, 0xE9, 0x71, 0xDC, 0x52, 0x7D, 0x88, 0x21, 0x28,
    0x2F, 0x49, 0xDE, 0xBA, 0x72, 0x16, 0xE9, 0xCC, 0x47, 0x7A, 0x88, 0x0D,
    0x94, 0x57, 0x84, 0x58, 0x16, 0x3A, 0x81, 0xB0, 0x3F, 0xA2, 0xCF, 0xA6,
    0x6C, 0x1E, 0xB0, 0x06, 0x29, 0x00, 0x8F, 0xE7, 0x77, 0x76, 0xAC, 0xDB,
    0xCA, 0xC7, 0xD9, 0x5E, 0x9B, 0x3F, 0x26, 0x90, 0x52, 0xAE, 0xFC, 0x38,
    0x90, 0x00, 0x14, 0xBB, 0xB4, 0x0F, 0x58, 0x94, 0xE7, 0x2F, 0x6A, 0x7E,
    0x1C, 0x4F, 0x41, 0x21, 0xD4, 0x31, 0x59, 0x1F, 0x4E, 0x8A, 0x1A, 0x8D,
    0xA7, 0x57, 0x6C, 0x22, 0xD8, 0xE5, 0xF4, 0x7E, 0x32, 0xA6, 0x10, 0xCB,
    0x64, 0xA5, 0x55, 0x03, 0x87, 0xA6, 0x27, 0x05, 0x8C, 0xC3, 0xD7, 0xB6,
    0x27, 0xB2, 0x4D, 0xBA, 0x30, 0xDA, 0x47, 0x8F, 0x54, 0xD3, 0x3D, 0x8B,
    0x84, 0x8D, 0x94, 0x98, 0x58, 0xA5, 0x02, 0x81, 0x81, 0x00, 0xD5, 0x38,
    0x1B, 0xC3, 0x8F, 0xC5, 0x93, 0x0C, 0x47, 0x0B, 0x6F, 0x35, 0x92, 0xC5,
    0xB0, 0x8D, 0x46, 0xC8, 0x92, 0x18, 0x8F, 0xF5, 0x80, 0x0A, 0xF7, 0xEF,
    0xA1, 0xFE, 0x80, 0xB9, 0xB5, 0x2A, 0xBA, 0xCA, 0x18, 0xB0, 0x5D, 0xA5,
    0x07, 0xD0, 0x93, 0x8D, 0xD8, 0x9C, 0x04, 0x1C, 0xD4, 0x62, 0x8E, 0xA6,
    0x26, 0x81, 0x01, 0xFF, 0xCE, 0x8A, 0x2A, 0x63, 0x34, 0x35, 0x40, 0xAA,
    0x6D, 0x80, 0xDE, 0x89, 0x23, 0x6A, 0x57, 0x4D, 0x9E, 0x6E, 0xAD, 0x93,
    0x4E, 0x56, 0x90, 0x0B, 0x6D, 0x9D, 0x73, 0x8B, 0x0C, 0xAE, 0x27, 0x3D,
    0xDE, 0x4E, 0xF0, 0xAA, 0xC5, 0x6C, 0x78, 0x67, 0x6C, 0x94, 0x52, 0x9C,
    0x37, 0x67, 0x6C, 0x2D, 0xEF, 0xBB, 0xAF, 0xDF, 0xA6, 0x90, 0x3C, 0xC4,
    0x47, 0xCF, 0x8D, 0x96, 0x9E, 0x98, 0xA9, 0xB4, 0x9F, 0xC5, 0xA6, 0x50,
    0xDC, 0xB3, 0xF0, 0xFB, 0x74, 0x17, 0x02, 0x81, 0x80, 0x5E, 0x83, 0x09,
    0x62, 0xBD, 0xBA, 0x7C, 0xA2, 0xBF, 0x42, 0x74, 0xF5, 0x7C, 0x1C, 0xD2,
    0x69, 0xC9, 0x04, 0x0D, 0x85, 0x7E, 0x3E, 0x3D, 0x24, 0x12, 0xC3, 0x18,
    0x7B, 0xF3, 0x29, 0xF3, 0x5F, 0x0E, 0x76, 0x6C, 0x59, 0x75, 0xE4, 0x41,
    0x84, 0x69, 0x9D, 0x32, 0xF3, 0xCD, 0x22, 0xAB, 0xB0, 0x35, 0xBA, 0x4A,
    0xB2, 0x3C, 0xE5, 0xD9, 0x58, 0xB6, 0x62, 0x4F, 0x5D, 0xDE, 0xE5, 0x9E,
    0x0A, 0xCA, 0x53, 0xB2, 0x2C, 0xF7, 0x9E, 0xB3, 0x6B, 0x0A, 0x5B, 0x79,
    0x65, 0xEC, 0x6E, 0x91, 0x4E, 0x92, 0x20, 0xF6, 0xFC, 0xFC, 0x16, 0xED,
    0xD3, 0x76, 0x0C, 0xE2, 0xEC, 0x7F, 0xB2, 0x69, 0x13, 0x6B, 0x78, 0x0E,
    0x5A, 0x46, 0x64, 0xB4, 0x5E, 0xB7, 0x25, 0xA0, 0x5A, 0x75, 0x3A, 0x4B,
    0xEF, 0xC7, 0x3C, 0x3E, 0xF7, 0xFD, 0x26, 0xB8, 0x20, 0xC4, 0x99, 0x0A,
    0x9A, 0x73, 0xBE, 0xC3, 0x19, 0x02, 0x81, 0x81, 0x00, 0xBA, 0x44, 0x93,
    0x14, 0xAC, 0x34, 0x19, 0x3B, 0x5F, 0x91, 0x60, 0xAC, 0xF7, 0xB4, 0xD6,
    0x81, 0x05, 0x36, 0x51, 0x53, 0x3D, 0xE8, 0x65, 0xDC, 0xAF, 0x2E, 0xDC,
    0x61, 0x3E, 0xC9, 0x7D, 0xB8, 0x7F, 0x87, 0xF0, 0x3B, 0x9B, 0x03, 0x82,
    0x29, 0x37, 0xCE, 0x72, 0x4E, 0x11, 0xD5, 0xB1, 0xC1, 0x0C, 0x07, 0xA0,
    0x99, 0x91, 0x4A, 0x8D, 0x7F, 0xEC, 0x79, 0xCF, 0xF1, 0x39, 0xB5, 0xE9,
    0x85, 0xEC, 0x62, 0xF7, 0xDA, 0x7D, 0xBC, 0x64, 0x4D, 0x22, 0x3C, 0x0E,
    0xF2, 0xD6, 0x51, 0xF5, 0x87, 0xD8, 0x99, 0xC0, 0x11, 0x20, 0x5D, 0x0F,
    0x29, 0xFD, 0x5B, 0xE2, 0xAE, 0xD9, 0x1C, 0xD9, 0x21, 0x56, 0x6D, 0xFC,
    0x84, 0xD0, 0x5F, 0xED, 0x10, 0x15, 0x1C, 0x18, 0x21, 0xE7, 0xC4, 0x3D,
    0x4B, 0xD7, 0xD0, 0x9E, 0x6A, 0x95, 0xCF, 0x22, 0xC9, 0x03, 0x7B, 0x9E,
    0xE3, 0x60, 0x01, 0xFC, 0x2F, 0x02, 0x81, 0x80, 0x11, 0xD0, 0x4B, 0xCF,
    0x1B, 0x67, 0xB9, 0x9F, 0x10, 0x75, 0x47, 0x86, 0x65, 0xAE, 0x31, 0xC2,
    0xC6, 0x30, 0xAC, 0x59, 0x06, 0x50, 0xD9, 0x0F, 0xB5, 0x70, 0x06, 0xF7,
    0xF0, 0xD3, 0xC8, 0x62, 0x7C, 0xA8, 0xDA, 0x6E, 0xF6, 0x21, 0x3F, 0xD3,
    0x7F, 0x5F, 0xEA, 0x8A, 0xAB, 0x3F, 0xD9, 0x2A, 0x5E, 0xF3, 0x51, 0xD2,
    0xC2, 0x30, 0x37, 0xE3, 0x2D, 0xA3, 0x75, 0x0D, 0x1E, 0x4D, 0x21, 0x34,
    0xD5, 0x57, 0x70, 0x5C, 0x89, 0xBF, 0x72, 0xEC, 0x4A, 0x6E, 0x68, 0xD5,
    0xCD, 0x18, 0x74, 0x33, 0x4E, 0x8C, 0x3A, 0x45, 0x8F, 0xE6, 0x96, 0x40,
    0xEB, 0x63, 0xF9, 0x19, 0x86, 0x3A, 0x51, 0xDD, 0x89, 0x4B, 0xB0, 0xF3,
    0xF9, 0x9F, 0x5D, 0x28, 0x95, 0x38, 0xBE, 0x35, 0xAB, 0xCA, 0x5C, 0xE7,
    0x93, 0x53, 0x34, 0xA1, 0x45, 0x5D, 0x13, 0x39, 0x65, 0x42, 0x46, 0xA1,
    0x9F, 0xCD, 0xF5, 0xBF};
#endif /* !NO_RSA */

/*
 * Shared signature-based verify flow used by the ECC, AES-CMAC and
 * RSA subtests. Stores the signature in NVM, caches+commits the
 * verification key, then runs the positive checks (by image, by
 * index, and verify-all) followed by a corrupted-signature negative
 * check. Leaves NVM and the key cache clean on success.
 */
static int _imgMgrRunSigVerify(whServerContext* server,
                               whServerImgMgrImg* testImage, whNvmId keyId,
                               const uint8_t* keyDer, word32 keyDerLen,
                               const char* keyLabel, whNvmId sigId,
                               const uint8_t* sig, word32 sigLen,
                               const char* sigLabel)
{
    whServerImgMgrConfig       imgMgrConfig = {0};
    whServerImgMgrContext      imgMgr       = {0};
    whServerImgMgrVerifyResult result;
    whServerImgMgrVerifyResult results[1];
    whNvmMetadata              sigMeta = {0};
    whNvmMetadata              keyMeta = {0};
    uint8_t                    corrupt[256];

    WH_TEST_ASSERT_RETURN(sigLen <= sizeof(corrupt));

    /* Store signature in NVM */
    sigMeta.id     = sigId;
    sigMeta.access = WH_NVM_ACCESS_ANY;
    sigMeta.flags  = WH_NVM_FLAGS_NONE;
    sigMeta.len    = sigLen;
    snprintf((char*)sigMeta.label, WH_NVM_LABEL_LEN, "%s", sigLabel);
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &sigMeta, sigLen, sig));

    /* Wire the image manager to the shared server */
    imgMgrConfig.images     = testImage;
    imgMgrConfig.imageCount = 1;
    imgMgrConfig.server     = server;
    WH_TEST_RETURN_ON_FAIL(wh_Server_ImgMgrInit(&imgMgr, &imgMgrConfig));

    /* Cache and commit the verification key */
    keyMeta.id     = keyId;
    keyMeta.access = WH_NVM_ACCESS_ANY;
    keyMeta.flags  = WH_NVM_FLAGS_NONE;
    keyMeta.len    = keyDerLen;
    snprintf((char*)keyMeta.label, WH_NVM_LABEL_LEN, "%s", keyLabel);
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_KeystoreCacheKey(server, &keyMeta, (uint8_t*)keyDer));
    WH_TEST_RETURN_ON_FAIL(wh_Server_KeystoreCommitKey(server, keyId));

    /* Positive: verify by image */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_ImgMgrVerifyImg(&imgMgr, testImage, &result));
    WH_TEST_ASSERT_RETURN(result.verifyMethodResult == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(result.verifyActionResult == WH_ERROR_OK);

    /* Positive: verify by index */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_ImgMgrVerifyImgIdx(&imgMgr, 0, &result));
    WH_TEST_ASSERT_RETURN(result.verifyMethodResult == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(result.verifyActionResult == WH_ERROR_OK);

    /* Positive: verify all */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_ImgMgrVerifyAll(&imgMgr, results, 1, NULL));
    WH_TEST_ASSERT_RETURN(results[0].verifyMethodResult == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(results[0].verifyActionResult == WH_ERROR_OK);

    /* Negative: corrupt the stored signature and confirm failure */
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_Read(server->nvm, sigId, 0, sigLen, corrupt));
    corrupt[0] ^= 0x01;
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &sigMeta, sigLen, corrupt));

    WH_TEST_RETURN_ON_FAIL(
        wh_Server_ImgMgrVerifyImg(&imgMgr, testImage, &result));
    /* Method must reject; the default action just relays that result */
    WH_TEST_ASSERT_RETURN(result.verifyMethodResult != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(
        result.verifyActionResult == result.verifyMethodResult);

    /* Leave NVM and key cache clean for the next suite */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &sigId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_KeystoreEraseKey(server, keyId));

    return WH_TEST_SUCCESS;
}

#ifdef HAVE_ECC
/* Sign testData with the test ECC key and export its public DER. */
static int _imgMgrEccSign(uint8_t* sig, word32* sigLen, uint8_t* pubDer,
                          word32* pubDerLen)
{
    int       ret;
    int       verifyResult = 0;
    ecc_key   eccKey;
    WC_RNG    rng;
    wc_Sha256 sha;
    uint8_t   hash[WC_SHA256_DIGEST_SIZE];
    word32    inOutIdx = 0;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return ret;
    }
    ret = wc_ecc_init(&eccKey);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_EccPrivateKeyDecode(testEccPrivKey, &inOutIdx, &eccKey,
                                 sizeof(testEccPrivKey));
    if (ret == 0) {
        ret = wc_EccPublicKeyToDer(&eccKey, pubDer, *pubDerLen, 1);
        if (ret > 0) {
            *pubDerLen = (word32)ret;
            ret        = 0;
        }
    }
    if (ret == 0) {
        ret = wc_InitSha256(&sha);
        if (ret == 0) {
            ret = wc_Sha256Update(&sha, testData, sizeof(testData));
            if (ret == 0) {
                ret = wc_Sha256Final(&sha, hash);
            }
            wc_Sha256Free(&sha);
        }
    }
    if (ret == 0) {
        ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, sigLen, &rng, &eccKey);
    }
    if (ret == 0) {
        /* Sanity check the signature directly before handing it off */
        ret = wc_ecc_verify_hash(sig, *sigLen, hash, sizeof(hash),
                                 &verifyResult, &eccKey);
        if (ret == 0 && verifyResult != 1) {
            ret = WH_ERROR_ABORTED;
        }
    }

    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
    return ret;
}

static int _whTest_ServerImgMgrEcc256(whServerContext* server)
{
    whServerImgMgrImg testImage    = {0};
    const whNvmId     keyId        = 1;
    const whNvmId     sigId        = 2;
    uint8_t           signature[ECC_MAX_SIG_SIZE];
    word32            sigLen       = sizeof(signature);
    uint8_t           pubKeyDer[ECC_BUFSIZE];
    word32            pubKeyDerLen = sizeof(pubKeyDer);

    WH_TEST_RETURN_ON_FAIL(
        _imgMgrEccSign(signature, &sigLen, pubKeyDer, &pubKeyDerLen));

    testImage.addr         = (uintptr_t)testData;
    testImage.size         = sizeof(testData);
    testImage.keyId        = keyId;
    testImage.sigNvmId     = sigId;
    testImage.verifyMethod = wh_Server_ImgMgrVerifyMethodEccWithSha256;
    testImage.verifyAction = wh_Server_ImgMgrVerifyActionDefault;

    WH_TEST_RETURN_ON_FAIL(_imgMgrRunSigVerify(
        server, &testImage, keyId, pubKeyDer, pubKeyDerLen, "TestKey", sigId,
        signature, sigLen, "TestSig"));

    WH_TEST_PRINT("IMG_MGR ECC P256 Test completed successfully!\n");
    return WH_TEST_SUCCESS;
}
#endif /* HAVE_ECC */

#ifdef WOLFSSL_CMAC
static int _whTest_ServerImgMgrAes128Cmac(whServerContext* server)
{
    int               rc;
    whServerImgMgrImg testImage = {0};
    const whNvmId     keyId     = 1;
    const whNvmId     sigId     = 2;
    Cmac              cmac;
    uint8_t           computed_cmac[AES_BLOCK_SIZE];
    word32            cmac_size = sizeof(computed_cmac);

    /* Compute the expected CMAC over the test data */
    rc = wc_InitCmac(&cmac, testAes128Key, sizeof(testAes128Key), WC_CMAC_AES,
                     NULL);
    if (rc == 0) {
        rc = wc_CmacUpdate(&cmac, testData, sizeof(testData));
    }
    if (rc == 0) {
        rc = wc_CmacFinal(&cmac, computed_cmac, &cmac_size);
    }
    WH_TEST_RETURN_ON_FAIL(rc);

    testImage.addr         = (uintptr_t)testData;
    testImage.size         = sizeof(testData);
    testImage.keyId        = keyId;
    testImage.sigNvmId     = sigId;
    testImage.verifyMethod = wh_Server_ImgMgrVerifyMethodAesCmac;
    testImage.verifyAction = wh_Server_ImgMgrVerifyActionDefault;

    WH_TEST_RETURN_ON_FAIL(_imgMgrRunSigVerify(
        server, &testImage, keyId, testAes128Key, sizeof(testAes128Key),
        "TestAes128Key", sigId, computed_cmac, cmac_size, "TestCmacSig"));

    WH_TEST_PRINT("IMG_MGR AES128 CMAC Test completed successfully!\n");
    return WH_TEST_SUCCESS;
}
#endif /* WOLFSSL_CMAC */

#ifndef NO_RSA
/* Sign testData with the test RSA key and export its public DER. */
static int _imgMgrRsaSign(uint8_t* sig, word32* sigLen, uint8_t* pubDer,
                          word32* pubDerLen)
{
    int       ret;
    RsaKey    rsaKey;
    WC_RNG    rng;
    wc_Sha256 sha;
    uint8_t   hash[WC_SHA256_DIGEST_SIZE];
    uint8_t   decrypted[256];
    word32    decryptedLen = sizeof(decrypted);
    word32    inOutIdx     = 0;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return ret;
    }
    ret = wc_InitRsaKey(&rsaKey, NULL);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_RsaPrivateKeyDecode(testRsa2048PrivKey, &inOutIdx, &rsaKey,
                                 sizeof(testRsa2048PrivKey));
    if (ret == 0) {
        ret = wc_RsaKeyToPublicDer(&rsaKey, pubDer, *pubDerLen);
        if (ret > 0) {
            *pubDerLen = (word32)ret;
            ret        = 0;
        }
    }
    if (ret == 0) {
        ret = wc_InitSha256(&sha);
        if (ret == 0) {
            ret = wc_Sha256Update(&sha, testData, sizeof(testData));
            if (ret == 0) {
                ret = wc_Sha256Final(&sha, hash);
            }
            wc_Sha256Free(&sha);
        }
    }
    if (ret == 0) {
        ret = wc_RsaSSL_Sign(hash, sizeof(hash), sig, *sigLen, &rsaKey, &rng);
        if (ret > 0) {
            *sigLen = (word32)ret;
            ret     = 0;
        }
    }
    if (ret == 0) {
        /* Sanity check the signature directly before handing it off */
        ret = wc_RsaSSL_Verify(sig, *sigLen, decrypted, decryptedLen, &rsaKey);
        if (ret > 0) {
            decryptedLen = (word32)ret;
            if (decryptedLen != sizeof(hash) ||
                XMEMCMP(decrypted, hash, sizeof(hash)) != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                ret = 0;
            }
        }
    }

    wc_FreeRsaKey(&rsaKey);
    wc_FreeRng(&rng);
    return ret;
}

static int _whTest_ServerImgMgrRsa2048(whServerContext* server)
{
    whServerImgMgrImg testImage    = {0};
    const whNvmId     keyId        = 1;
    const whNvmId     sigId        = 2;
    uint8_t           signature[256]; /* raw RSA signature is the key size */
    word32            sigLen       = sizeof(signature);
    uint8_t           pubKeyDer[512];
    word32            pubKeyDerLen = sizeof(pubKeyDer);

    WH_TEST_RETURN_ON_FAIL(
        _imgMgrRsaSign(signature, &sigLen, pubKeyDer, &pubKeyDerLen));

    testImage.addr         = (uintptr_t)testData;
    testImage.size         = sizeof(testData);
    testImage.keyId        = keyId;
    testImage.sigNvmId     = sigId;
    testImage.verifyMethod = wh_Server_ImgMgrVerifyMethodRsaSslWithSha256;
    testImage.verifyAction = wh_Server_ImgMgrVerifyActionDefault;

    WH_TEST_RETURN_ON_FAIL(_imgMgrRunSigVerify(
        server, &testImage, keyId, pubKeyDer, pubKeyDerLen, "TestRsaKey", sigId,
        signature, sigLen, "TestRsaSig"));

    WH_TEST_PRINT("IMG_MGR RSA2048 Test completed successfully!\n");
    return WH_TEST_SUCCESS;
}

static int _whTest_ServerImgMgrWolfBootRsa4096(whServerContext* server)
{
    whServerImgMgrConfig       imgMgrConfig = {0};
    whServerImgMgrContext      imgMgr       = {0};
    whServerImgMgrImg          testImage    = {0};
    const whNvmId              keyId        = 1;
    whServerImgMgrVerifyResult result;
    whNvmMetadata              keyMeta = {0};
    uint8_t                    corrupt_fw[sizeof(wolfboot_test_firmware)];
    whServerImgMgrImg          corruptImage;

    testImage.addr    = (uintptr_t)wolfboot_test_firmware;
    testImage.size    = sizeof(wolfboot_test_firmware);
    testImage.hdrAddr = (uintptr_t)wolfboot_test_header;
    testImage.hdrSize = sizeof(wolfboot_test_header);
    testImage.keyId   = keyId;
    testImage.imgType = WH_IMG_MGR_IMG_TYPE_WOLFBOOT;
    testImage.verifyMethod =
        wh_Server_ImgMgrVerifyMethodWolfBootRsa4096WithSha256;
    testImage.verifyAction = wh_Server_ImgMgrVerifyActionDefault;

    imgMgrConfig.images     = &testImage;
    imgMgrConfig.imageCount = 1;
    imgMgrConfig.server     = server;
    WH_TEST_RETURN_ON_FAIL(wh_Server_ImgMgrInit(&imgMgr, &imgMgrConfig));

    /* Cache and commit the wolfBoot public key */
    keyMeta.id     = keyId;
    keyMeta.access = WH_NVM_ACCESS_ANY;
    keyMeta.flags  = WH_NVM_FLAGS_NONE;
    keyMeta.len    = sizeof(wolfboot_test_pubkey_der);
    snprintf((char*)keyMeta.label, WH_NVM_LABEL_LEN, "WBPubKey");
    WH_TEST_RETURN_ON_FAIL(wh_Server_KeystoreCacheKey(
        server, &keyMeta, (uint8_t*)wolfboot_test_pubkey_der));
    WH_TEST_RETURN_ON_FAIL(wh_Server_KeystoreCommitKey(server, keyId));

    /* Positive: verify wolfBoot image with correct key */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_ImgMgrVerifyImg(&imgMgr, &testImage, &result));
    WH_TEST_ASSERT_RETURN(result.verifyMethodResult == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(result.verifyActionResult == WH_ERROR_OK);

    /* Negative: flip a bit in a firmware copy and confirm failure */
    corruptImage = testImage;
    memcpy(corrupt_fw, wolfboot_test_firmware, sizeof(corrupt_fw));
    corrupt_fw[0] ^= 0x01;
    corruptImage.addr = (uintptr_t)corrupt_fw;
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_ImgMgrVerifyImg(&imgMgr, &corruptImage, &result));
    WH_TEST_ASSERT_RETURN(result.verifyMethodResult != WH_ERROR_OK);

    /* Leave the key cache clean for the next suite */
    WH_TEST_RETURN_ON_FAIL(wh_Server_KeystoreEraseKey(server, keyId));

    WH_TEST_PRINT("IMG_MGR wolfBoot RSA4096 Test completed successfully!\n");
    return WH_TEST_SUCCESS;
}

#ifdef WOLFHSM_CFG_CERTIFICATE_MANAGER
static int _whTest_ServerImgMgrWolfBootCertChainRsa4096(whServerContext* server)
{
    whServerImgMgrConfig       imgMgrConfig = {0};
    whServerImgMgrContext      imgMgr       = {0};
    whServerImgMgrImg          testImage    = {0};
    const whNvmId              rootCaNvmId  = 10;
    whServerImgMgrVerifyResult result;
    whNvmMetadata              rootCaMeta = {0};
    uint8_t                    corrupt_fw[sizeof(wolfboot_test_firmware)];
    whServerImgMgrImg          corruptImage;

    /* Store the root CA cert in NVM */
    rootCaMeta.id     = rootCaNvmId;
    rootCaMeta.access = WH_NVM_ACCESS_ANY;
    rootCaMeta.flags  = WH_NVM_FLAGS_NONE;
    rootCaMeta.len    = sizeof(wolfboot_test_root_ca_cert_der);
    snprintf((char*)rootCaMeta.label, WH_NVM_LABEL_LEN, "RootCA");
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &rootCaMeta,
                         sizeof(wolfboot_test_root_ca_cert_der),
                         wolfboot_test_root_ca_cert_der));

    testImage.addr     = (uintptr_t)wolfboot_test_firmware;
    testImage.size     = sizeof(wolfboot_test_firmware);
    testImage.hdrAddr  = (uintptr_t)wolfboot_test_cert_chain_header;
    testImage.hdrSize  = sizeof(wolfboot_test_cert_chain_header);
    testImage.sigNvmId = rootCaNvmId;
    testImage.imgType  = WH_IMG_MGR_IMG_TYPE_WOLFBOOT_CERT;
    testImage.verifyMethod =
        wh_Server_ImgMgrVerifyMethodWolfBootCertChainRsa4096WithSha256;
    testImage.verifyAction = wh_Server_ImgMgrVerifyActionDefault;

    imgMgrConfig.images     = &testImage;
    imgMgrConfig.imageCount = 1;
    imgMgrConfig.server     = server;
    WH_TEST_RETURN_ON_FAIL(wh_Server_ImgMgrInit(&imgMgr, &imgMgrConfig));

    /* Positive: verify wolfBoot image against the cert chain */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_ImgMgrVerifyImg(&imgMgr, &testImage, &result));
    WH_TEST_ASSERT_RETURN(result.verifyMethodResult == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(result.verifyActionResult == WH_ERROR_OK);

    /* Negative: flip a bit in a firmware copy and confirm failure */
    corruptImage = testImage;
    memcpy(corrupt_fw, wolfboot_test_firmware, sizeof(corrupt_fw));
    corrupt_fw[0] ^= 0x01;
    corruptImage.addr = (uintptr_t)corrupt_fw;
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_ImgMgrVerifyImg(&imgMgr, &corruptImage, &result));
    WH_TEST_ASSERT_RETURN(result.verifyMethodResult != WH_ERROR_OK);

    /* Leave NVM clean for the next suite */
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_DestroyObjects(server->nvm, 1, &rootCaNvmId));

    WH_TEST_PRINT(
        "IMG_MGR wolfBoot Cert Chain RSA4096 Test completed successfully!\n");
    return WH_TEST_SUCCESS;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER */
#endif /* !NO_RSA */

int whTest_ServerImgMgr(whServerContext* server)
{
#ifdef HAVE_ECC
    WH_TEST_RETURN_ON_FAIL(_whTest_ServerImgMgrEcc256(server));
#endif
#ifdef WOLFSSL_CMAC
    WH_TEST_RETURN_ON_FAIL(_whTest_ServerImgMgrAes128Cmac(server));
#endif
#ifndef NO_RSA
    WH_TEST_RETURN_ON_FAIL(_whTest_ServerImgMgrRsa2048(server));
    WH_TEST_RETURN_ON_FAIL(_whTest_ServerImgMgrWolfBootRsa4096(server));
#ifdef WOLFHSM_CFG_CERTIFICATE_MANAGER
    WH_TEST_RETURN_ON_FAIL(_whTest_ServerImgMgrWolfBootCertChainRsa4096(server));
#endif
#endif
    return WH_TEST_SUCCESS;
}

#endif /* WOLFHSM_CFG_SERVER_IMG_MGR && WOLFHSM_CFG_ENABLE_SERVER &&
          !WOLFHSM_CFG_NO_CRYPTO */
