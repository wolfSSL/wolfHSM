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
 * test/wh_test_server_img_mgr.c
 *
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_SERVER_IMG_MGR) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_img_mgr.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#endif /* WOLFHSM_CFG_NO_CRYPTO */

#include "wh_test_common.h"

#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */
#define FLASH_SECTOR_SIZE (128 * 1024) /* 128KB */
#define FLASH_PAGE_SIZE (8) /* 8B */

/* Test data to be "verified" */
static const uint8_t testData[] = {
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64,
    0x21, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61,
    0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61,
    0x67, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x45, 0x43, 0x43, 0x20,
    0x73, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x20, 0x76,
    0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69};

#ifndef WOLFHSM_CFG_NO_CRYPTO

#ifdef HAVE_ECC
/* Hardcoded ECC P256 private key for testing (DER format) */
/* ecc */
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
/* This is a 2048-bit RSA private key generated for testing purposes */
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

#ifdef HAVE_ECC
static int whTest_ServerImgMgrServerCfgEcc256(whServerConfig* serverCfg)
{
    int                   ret             = 0;
    whServerContext       server[1]       = {0};
    whServerImgMgrConfig  imgMgrConfig    = {0};
    whServerImgMgrContext imgMgr          = {0};
    whServerImgMgrImg     testImage       = {0};
    const whNvmId         testEccKeyId    = 1;
    const whNvmId         testEccSigNvmId = 2;

    /* ECC key and signature variables */
    ecc_key   eccKey;
    WC_RNG    rng;
    wc_Sha256 sha;
    uint8_t   hash[WC_SHA256_DIGEST_SIZE];
    uint8_t   signature[ECC_MAX_SIG_SIZE];
    word32    sigLen = sizeof(signature);
    uint8_t   pubKeyDer[ECC_BUFSIZE];
    word32    pubKeyDerLen = sizeof(pubKeyDer);

    /* NVM metadata for signature */
    whNvmMetadata sigMeta = {0};

    /* Initialize wolfCrypt */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize RNG: %d\n", ret);
        return ret;
    }

    ret = wc_ecc_init(&eccKey);
    if (ret != 0) {
        printf("Failed to initialize ECC key: %d\n", ret);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Generate or import the test ECC key */
    word32 inOutIdx = 0;
    ret             = wc_EccPrivateKeyDecode(testEccPrivKey, &inOutIdx, &eccKey,
                                             sizeof(testEccPrivKey));
    if (ret != 0) {
        printf("Failed to decode ECC private key: %d\n", ret);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Export public key in DER format so we can store it in NVM */
    ret = wc_EccPublicKeyToDer(&eccKey, pubKeyDer, pubKeyDerLen, 1);
    if (ret <= 0) {
        printf("Failed to export public key to DER: %d\n", ret);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }
    pubKeyDerLen = (word32)ret;

    /* Hash the test data */
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("Failed to initialize SHA256: %d\n", ret);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_Sha256Update(&sha, testData, sizeof(testData));
    if (ret != 0) {
        printf("Failed to update SHA256: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_Sha256Final(&sha, hash);
    if (ret != 0) {
        printf("Failed to finalize SHA256: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Sign the hash */
    ret =
        wc_ecc_sign_hash(hash, sizeof(hash), signature, &sigLen, &rng, &eccKey);
    if (ret != 0) {
        printf("Failed to sign hash: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Verify the signature directly to ensure it's correct */
    int verifyResult = 0;
    ret              = wc_ecc_verify_hash(signature, sigLen, hash, sizeof(hash),
                                          &verifyResult, &eccKey);
    if (ret != 0 || verifyResult != 1) {
        printf("Direct signature verification failed: ret=%d, result=%d\n", ret,
               verifyResult);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Store signature in NVM */
    sigMeta.id     = testEccSigNvmId;
    sigMeta.access = WH_NVM_ACCESS_ANY;
    sigMeta.flags  = WH_NVM_FLAGS_NONE;
    sigMeta.len    = sigLen;
    snprintf((char*)sigMeta.label, WH_NVM_LABEL_LEN, "TestSig");

    ret = wh_Nvm_AddObject(serverCfg->nvm, &sigMeta, sigLen, signature);
    if (ret != WH_ERROR_OK) {
        printf("Failed to add signature to NVM: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Set up image manager config */
    testImage.addr         = (uintptr_t)testData;
    testImage.size         = sizeof(testData);
    testImage.keyId        = testEccKeyId;
    testImage.sigNvmId     = testEccSigNvmId;
    testImage.verifyMethod = wh_Server_ImgMgrVerifyMethodEccWithSha256;
    testImage.verifyAction = wh_Server_ImgMgrVerifyActionDefault;

    imgMgrConfig.images     = &testImage;
    imgMgrConfig.imageCount = 1;
    imgMgrConfig.server     = server;

    /* Initialize server */
    ret = wh_Server_Init(server, serverCfg);
    if (ret != WH_ERROR_OK) {
        printf("Failed to initialize server: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Initialize the image manager to work with the server */
    ret = wh_Server_ImgMgrInit(&imgMgr, &imgMgrConfig);
    if (ret != WH_ERROR_OK) {
        printf("Failed to initialize image manager: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Cache the public key in the keystore */
    whNvmMetadata keyMeta = {0};
    keyMeta.id            = testEccKeyId;
    keyMeta.access        = WH_NVM_ACCESS_ANY;
    keyMeta.flags         = WH_NVM_FLAGS_NONE;
    keyMeta.len           = pubKeyDerLen;
    snprintf((char*)keyMeta.label, WH_NVM_LABEL_LEN, "TestKey");

    ret = wh_Server_KeystoreCacheKey(server, &keyMeta, pubKeyDer);
    if (ret != WH_ERROR_OK) {
        printf("Failed to cache key in keystore: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Commit the key to NVM */
    ret = wh_Server_KeystoreCommitKey(server, testEccKeyId);
    if (ret != WH_ERROR_OK) {
        printf("Failed to commit key to NVM: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Test image verification */
    whServerImgMgrVerifyResult result;
    ret = wh_Server_ImgMgrVerifyImg(&imgMgr, &testImage, &result);
    if (ret != WH_ERROR_OK) {
        printf("Image verification failed: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Check verify method result */
    if (result.verifyMethodResult != WH_ERROR_OK) {
        printf("ECC verify method failed: %d\n", result.verifyMethodResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return result.verifyMethodResult;
    }

    /* Check verify action result */
    if (result.verifyActionResult != WH_ERROR_OK) {
        printf("ECC verify action failed: %d\n", result.verifyActionResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return result.verifyActionResult;
    }

    /* Test verify by index */
    ret = wh_Server_ImgMgrVerifyImgIdx(&imgMgr, 0, &result);
    if (ret != WH_ERROR_OK) {
        printf("Image verification by index failed: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Check verify method result */
    if (result.verifyMethodResult != WH_ERROR_OK) {
        printf("ECC verify method by index failed: %d\n",
               result.verifyMethodResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return result.verifyMethodResult;
    }

    /* Check verify action result */
    if (result.verifyActionResult != WH_ERROR_OK) {
        printf("ECC verify action by index failed: %d\n",
               result.verifyActionResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return result.verifyActionResult;
    }

    /* Test verify all */
    whServerImgMgrVerifyResult results[1];
    ret = wh_Server_ImgMgrVerifyAll(&imgMgr, results, 1, NULL);
    if (ret != WH_ERROR_OK) {
        printf("Verify all images failed: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Check verify method result for all images */
    if (results[0].verifyMethodResult != WH_ERROR_OK) {
        printf("ECC verify method for all images failed: %d\n",
               results[0].verifyMethodResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return results[0].verifyMethodResult;
    }

    /* Check verify action result for all images */
    if (results[0].verifyActionResult != WH_ERROR_OK) {
        printf("ECC verify action for all images failed: %d\n",
               results[0].verifyActionResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return results[0].verifyActionResult;
    }

    /* Negative test: corrupt signature and verify failure */

    /* Read current signature from NVM */
    uint8_t corruptedSig[128];
    ret = wh_Nvm_Read(serverCfg->nvm, testEccSigNvmId, 0, sigLen, corruptedSig);
    if (ret != WH_ERROR_OK) {
        printf("Failed to read signature for negative test: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Corrupt the signature by flipping the first bit */
    corruptedSig[0] ^= 0x01;

    /* Write corrupted signature back to NVM */
    ret = wh_Nvm_AddObject(serverCfg->nvm, &sigMeta, sigLen, corruptedSig);
    if (ret != WH_ERROR_OK) {
        printf("Failed to write corrupted signature: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Test that the image does not verify with the corrupted signature */
    ret = wh_Server_ImgMgrVerifyImg(&imgMgr, &testImage, &result);
    if (ret != WH_ERROR_OK) {
        printf("ERROR: ECC image verification with corrupted signature failed: "
               "%d\n",
               ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Verify method result should not be OK */
    if (result.verifyMethodResult == WH_ERROR_OK) {
        printf("ECC verify method with corrupted signature failed: %d\n",
               result.verifyMethodResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return WH_ERROR_ABORTED;
    }

    /* Verify action result should just be the verify method result */
    if (result.verifyActionResult != result.verifyMethodResult) {
        printf("ECC verify action with corrupted signature failed: %d\n",
               result.verifyActionResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return WH_ERROR_ABORTED;
    }

    /* Delete the signature object to leave NVM in clean state */
    ret = wh_Nvm_DestroyObjects(serverCfg->nvm, 1, &testEccSigNvmId);
    if (ret != WH_ERROR_OK) {
        printf("Failed to delete RSA signature object: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Cleanup */
    wh_Server_Cleanup(server);
    wc_Sha256Free(&sha);
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);

    printf("IMG_MGR ECC P256 Test completed successfully!\n");
    return 0;
}
#endif /* HAVE_ECC */

#ifdef WOLFSSL_CMAC
static int whTest_ServerImgMgrServerCfgAes128Cmac(whServerConfig* serverCfg)
{
    int                   ret                 = 0;
    whServerContext       server[1]           = {0};
    whServerImgMgrConfig  imgMgrConfig        = {0};
    whServerImgMgrContext imgMgr              = {0};
    whServerImgMgrImg     testImage           = {0};
    const whNvmId         testAesCmacKeyId    = 1;
    const whNvmId         testAesCmacSigNvmId = 2;

    /* CMAC variables */
    Cmac    cmac;
    uint8_t computed_cmac[AES_BLOCK_SIZE];
    word32  cmac_size = sizeof(computed_cmac);

    /* NVM metadata for signature */
    whNvmMetadata sigMeta = {0};

    /* Initialize CMAC and compute the expected signature */
    ret = wc_InitCmac(&cmac, testAes128Key, sizeof(testAes128Key), WC_CMAC_AES,
                      NULL);
    if (ret != 0) {
        printf("Failed to initialize CMAC: %d\n", ret);
        return ret;
    }

    ret = wc_CmacUpdate(&cmac, testData, sizeof(testData));
    if (ret != 0) {
        printf("Failed to update CMAC: %d\n", ret);
        return ret;
    }

    ret = wc_CmacFinal(&cmac, computed_cmac, &cmac_size);
    if (ret != 0) {
        printf("Failed to finalize CMAC: %d\n", ret);
        return ret;
    }

    /* Store signature in NVM */
    sigMeta.id     = testAesCmacSigNvmId;
    sigMeta.access = WH_NVM_ACCESS_ANY;
    sigMeta.flags  = WH_NVM_FLAGS_NONE;
    sigMeta.len    = cmac_size;
    snprintf((char*)sigMeta.label, WH_NVM_LABEL_LEN, "TestCmacSig");

    ret = wh_Nvm_AddObject(serverCfg->nvm, &sigMeta, cmac_size, computed_cmac);
    if (ret != WH_ERROR_OK) {
        printf("Failed to add CMAC signature to NVM: %d\n", ret);
        return ret;
    }

    /* Set up image manager config */
    testImage.addr         = (uintptr_t)testData;
    testImage.size         = sizeof(testData);
    testImage.keyId        = testAesCmacKeyId;
    testImage.sigNvmId     = testAesCmacSigNvmId;
    testImage.verifyMethod = wh_Server_ImgMgrVerifyMethodAesCmac;
    testImage.verifyAction = wh_Server_ImgMgrVerifyActionDefault;

    imgMgrConfig.images     = &testImage;
    imgMgrConfig.imageCount = 1;
    imgMgrConfig.server     = server;

    /* Initialize server */
    ret = wh_Server_Init(server, serverCfg);
    if (ret != WH_ERROR_OK) {
        printf("Failed to initialize server: %d\n", ret);
        return ret;
    }

    /* Initialize the image manager to work with the server */
    ret = wh_Server_ImgMgrInit(&imgMgr, &imgMgrConfig);
    if (ret != WH_ERROR_OK) {
        printf("Failed to initialize image manager: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Cache the AES128 key in the keystore */
    whNvmMetadata keyMeta = {0};
    keyMeta.id            = testAesCmacKeyId;
    keyMeta.access        = WH_NVM_ACCESS_ANY;
    keyMeta.flags         = WH_NVM_FLAGS_NONE;
    keyMeta.len           = sizeof(testAes128Key);
    snprintf((char*)keyMeta.label, WH_NVM_LABEL_LEN, "TestAes128Key");

    ret = wh_Server_KeystoreCacheKey(server, &keyMeta, (uint8_t*)testAes128Key);
    if (ret != WH_ERROR_OK) {
        printf("Failed to cache AES128 key in keystore: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Commit the key to NVM */
    ret = wh_Server_KeystoreCommitKey(server, testAesCmacKeyId);
    if (ret != WH_ERROR_OK) {
        printf("Failed to commit AES128 key to NVM: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Test image verification */
    whServerImgMgrVerifyResult result;
    ret = wh_Server_ImgMgrVerifyImg(&imgMgr, &testImage, &result);
    if (ret != WH_ERROR_OK) {
        printf("CMAC image verification failed: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Check verify method result */
    if (result.verifyMethodResult != WH_ERROR_OK) {
        printf("CMAC verify method failed: %d\n", result.verifyMethodResult);
        wh_Server_Cleanup(server);
        return result.verifyMethodResult;
    }

    /* Check verify action result */
    if (result.verifyActionResult != WH_ERROR_OK) {
        printf("CMAC verify action failed: %d\n", result.verifyActionResult);
        wh_Server_Cleanup(server);
        return result.verifyActionResult;
    }

    /* Test verify by index */
    ret = wh_Server_ImgMgrVerifyImgIdx(&imgMgr, 0, &result);
    if (ret != WH_ERROR_OK) {
        printf("CMAC image verification by index failed: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Check verify method result */
    if (result.verifyMethodResult != WH_ERROR_OK) {
        printf("CMAC verify method by index failed: %d\n",
               result.verifyMethodResult);
        wh_Server_Cleanup(server);
        return result.verifyMethodResult;
    }

    /* Check verify action result */
    if (result.verifyActionResult != WH_ERROR_OK) {
        printf("CMAC verify action by index failed: %d\n",
               result.verifyActionResult);
        wh_Server_Cleanup(server);
        return result.verifyActionResult;
    }

    /* Test verify all */
    whServerImgMgrVerifyResult results[1];
    ret = wh_Server_ImgMgrVerifyAll(&imgMgr, results, 1, NULL);
    if (ret != WH_ERROR_OK) {
        printf("CMAC verify all images failed: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Check verify method result for all images */
    if (results[0].verifyMethodResult != WH_ERROR_OK) {
        printf("CMAC verify method for all images failed: %d\n",
               results[0].verifyMethodResult);
        wh_Server_Cleanup(server);
        return results[0].verifyMethodResult;
    }

    /* Check verify action result for all images */
    if (results[0].verifyActionResult != WH_ERROR_OK) {
        printf("CMAC verify action for all images failed: %d\n",
               results[0].verifyActionResult);
        wh_Server_Cleanup(server);
        return results[0].verifyActionResult;
    }

    /* Negative test: corrupt signature and verify failure */

    /* Read current signature from NVM */
    uint8_t corruptedCmac[AES_BLOCK_SIZE];
    ret = wh_Nvm_Read(serverCfg->nvm, testAesCmacSigNvmId, 0, cmac_size,
                      corruptedCmac);
    if (ret != WH_ERROR_OK) {
        printf("Failed to read CMAC signature for negative test: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Corrupt the signature by flipping the first bit */
    corruptedCmac[0] ^= 0x01;

    /* Write corrupted signature back to NVM */
    ret = wh_Nvm_AddObject(serverCfg->nvm, &sigMeta, cmac_size, corruptedCmac);
    if (ret != WH_ERROR_OK) {
        printf("Failed to write corrupted CMAC signature: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Test that the image does not verify with the corrupted signature */
    ret = wh_Server_ImgMgrVerifyImg(&imgMgr, &testImage, &result);
    if (ret != WH_ERROR_OK) {
        printf("ERROR: CMAC image verification with corrupted signature "
               "failed: %d\n",
               ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Verify method result should not be OK */
    if (result.verifyMethodResult == WH_ERROR_OK) {
        printf("CMAC verify method with corrupted signature failed: %d\n",
               result.verifyMethodResult);
        wh_Server_Cleanup(server);
        return WH_ERROR_ABORTED;
    }

    /* Verify action result should just be the verify method result */
    if (result.verifyActionResult != result.verifyMethodResult) {
        printf("CMAC verify action with corrupted signature failed: %d\n",
               result.verifyActionResult);
        wh_Server_Cleanup(server);
        return WH_ERROR_ABORTED;
    }

    /* Delete the signature object to leave NVM in clean state */
    ret = wh_Nvm_DestroyObjects(serverCfg->nvm, 1, &testAesCmacSigNvmId);
    if (ret != WH_ERROR_OK) {
        printf("Failed to delete CMAC signature object: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Cleanup */
    wh_Server_Cleanup(server);

    printf("IMG_MGR AES128 CMAC Test completed successfully!\n");
    return 0;
}
#endif /* WOLFSSL_CMAC */

#ifndef NO_RSA
static int whTest_ServerImgMgrServerCfgRsa2048(whServerConfig* serverCfg)
{
    int                   ret             = 0;
    whServerContext       server[1]       = {0};
    whServerImgMgrConfig  imgMgrConfig    = {0};
    whServerImgMgrContext imgMgr          = {0};
    whServerImgMgrImg     testImage       = {0};
    const whNvmId         testRsaKeyId    = 1;
    const whNvmId         testRsaSigNvmId = 2;

    /* RSA key and signature variables */
    RsaKey    rsaKey;
    WC_RNG    rng;
    wc_Sha256 sha;
    uint8_t   hash[WC_SHA256_DIGEST_SIZE];
    uint8_t   signature[256]; /* raw RSA SSL signatures are just the key size */
    word32    sigLen = sizeof(signature);
    uint8_t   pubKeyDer[512]; /* conservative size for DER encoding */
    word32    pubKeyDerLen = sizeof(pubKeyDer);

    /* NVM metadata for signature */
    whNvmMetadata sigMeta = {0};

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize RNG: %d\n", ret);
        return ret;
    }

    ret = wc_InitRsaKey(&rsaKey, NULL);
    if (ret != 0) {
        printf("Failed to initialize RSA key: %d\n", ret);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Import the test RSA private key */
    word32 inOutIdx = 0;
    ret = wc_RsaPrivateKeyDecode(testRsa2048PrivKey, &inOutIdx, &rsaKey,
                                 sizeof(testRsa2048PrivKey));
    if (ret != 0) {
        printf("Failed to decode RSA private key: %d\n", ret);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Export public key in DER format so we can store it in NVM */
    ret = wc_RsaKeyToPublicDer(&rsaKey, pubKeyDer, pubKeyDerLen);
    if (ret <= 0) {
        printf("Failed to export public key to DER: %d\n", ret);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }
    pubKeyDerLen = (word32)ret;

    /* Hash the test data */
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("Failed to initialize SHA256: %d\n", ret);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_Sha256Update(&sha, testData, sizeof(testData));
    if (ret != 0) {
        printf("Failed to update SHA256: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_Sha256Final(&sha, hash);
    if (ret != 0) {
        printf("Failed to finalize SHA256: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Sign the hash using RSA SSL */
    ret = wc_RsaSSL_Sign(hash, sizeof(hash), signature, sigLen, &rsaKey, &rng);
    if (ret <= 0) {
        printf("Failed to sign hash: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }
    sigLen = (word32)ret;

    /* Verify the signature directly to ensure it's correct */
    uint8_t decrypted[256];
    word32  decryptedLen = sizeof(decrypted);
    ret = wc_RsaSSL_Verify(signature, sigLen, decrypted, decryptedLen, &rsaKey);
    if (ret <= 0) {
        printf("Direct signature verification failed: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }
    decryptedLen = (word32)ret;

    if (decryptedLen != sizeof(hash) ||
        XMEMCMP(decrypted, hash, sizeof(hash)) != 0) {
        printf("Direct signature verification failed: hash mismatch\n");
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return -1;
    }

    /* Store signature in NVM */
    sigMeta.id     = testRsaSigNvmId;
    sigMeta.access = WH_NVM_ACCESS_ANY;
    sigMeta.flags  = WH_NVM_FLAGS_NONE;
    sigMeta.len    = sigLen;
    snprintf((char*)sigMeta.label, WH_NVM_LABEL_LEN, "TestRsaSig");

    ret = wh_Nvm_AddObject(serverCfg->nvm, &sigMeta, sigLen, signature);
    if (ret != WH_ERROR_OK) {
        printf("Failed to add RSA signature to NVM: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Set up image manager config */
    testImage.addr         = (uintptr_t)testData;
    testImage.size         = sizeof(testData);
    testImage.keyId        = testRsaKeyId;
    testImage.sigNvmId     = testRsaSigNvmId;
    testImage.verifyMethod = wh_Server_ImgMgrVerifyMethodRsaSslWithSha256;
    testImage.verifyAction = wh_Server_ImgMgrVerifyActionDefault;

    imgMgrConfig.images     = &testImage;
    imgMgrConfig.imageCount = 1;
    imgMgrConfig.server     = server;

    /* Initialize server */
    ret = wh_Server_Init(server, serverCfg);
    if (ret != WH_ERROR_OK) {
        printf("Failed to initialize server: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Initialize the image manager to work with the server */
    ret = wh_Server_ImgMgrInit(&imgMgr, &imgMgrConfig);
    if (ret != WH_ERROR_OK) {
        printf("Failed to initialize image manager: %d\n", ret);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Cache the public key in the keystore */
    whNvmMetadata keyMeta = {0};
    keyMeta.id            = testRsaKeyId;
    keyMeta.access        = WH_NVM_ACCESS_ANY;
    keyMeta.flags         = WH_NVM_FLAGS_NONE;
    keyMeta.len           = pubKeyDerLen;
    snprintf((char*)keyMeta.label, WH_NVM_LABEL_LEN, "TestRsaKey");

    ret = wh_Server_KeystoreCacheKey(server, &keyMeta, pubKeyDer);
    if (ret != WH_ERROR_OK) {
        printf("Failed to cache RSA key in keystore: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Commit the key to NVM */
    ret = wh_Server_KeystoreCommitKey(server, testRsaKeyId);
    if (ret != WH_ERROR_OK) {
        printf("Failed to commit RSA key to NVM: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Test image verification */
    whServerImgMgrVerifyResult result;
    ret = wh_Server_ImgMgrVerifyImg(&imgMgr, &testImage, &result);
    if (ret != WH_ERROR_OK) {
        printf("RSA image verification failed: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Check verify method result */
    if (result.verifyMethodResult != WH_ERROR_OK) {
        printf("RSA verify method failed: %d\n", result.verifyMethodResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return result.verifyMethodResult;
    }

    /* Check verify action result */
    if (result.verifyActionResult != WH_ERROR_OK) {
        printf("RSA verify action failed: %d\n", result.verifyActionResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return result.verifyActionResult;
    }

    /* Test verify by index */
    ret = wh_Server_ImgMgrVerifyImgIdx(&imgMgr, 0, &result);
    if (ret != WH_ERROR_OK) {
        printf("RSA image verification by index failed: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Check verify method result */
    if (result.verifyMethodResult != WH_ERROR_OK) {
        printf("RSA verify method by index failed: %d\n",
               result.verifyMethodResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return result.verifyMethodResult;
    }

    /* Check verify action result */
    if (result.verifyActionResult != WH_ERROR_OK) {
        printf("RSA verify action by index failed: %d\n",
               result.verifyActionResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return result.verifyActionResult;
    }

    /* Test verify all */
    whServerImgMgrVerifyResult results[1];
    ret = wh_Server_ImgMgrVerifyAll(&imgMgr, results, 1, NULL);
    if (ret != WH_ERROR_OK) {
        printf("RSA verify all images failed: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Check verify method result for all images */
    if (results[0].verifyMethodResult != WH_ERROR_OK) {
        printf("RSA verify method for all images failed: %d\n",
               results[0].verifyMethodResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return results[0].verifyMethodResult;
    }

    /* Check verify action result for all images */
    if (results[0].verifyActionResult != WH_ERROR_OK) {
        printf("RSA verify action for all images failed: %d\n",
               results[0].verifyActionResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return results[0].verifyActionResult;
    }

    /* Negative test: corrupt signature and verify failure */

    /* Read current signature from NVM */
    uint8_t corruptedRsaSig[256];
    ret = wh_Nvm_Read(serverCfg->nvm, testRsaSigNvmId, 0, sigLen,
                      corruptedRsaSig);
    if (ret != WH_ERROR_OK) {
        printf("Failed to read RSA signature for negative test: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Corrupt the signature by flipping the first bit */
    corruptedRsaSig[0] ^= 0x01;

    /* Write corrupted signature back to NVM */
    ret = wh_Nvm_AddObject(serverCfg->nvm, &sigMeta, sigLen, corruptedRsaSig);
    if (ret != WH_ERROR_OK) {
        printf("Failed to write corrupted RSA signature: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Test that the image does not verify with the corrupted signature */
    ret = wh_Server_ImgMgrVerifyImg(&imgMgr, &testImage, &result);
    if (ret != WH_ERROR_OK) {
        printf("ERROR: RSA image verification with corrupted signature failed: "
               "%d\n",
               ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Verify method result should not be OK */
    if (result.verifyMethodResult == WH_ERROR_OK) {
        printf("RSA verify method with corrupted signature failed: %d\n",
               result.verifyMethodResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return WH_ERROR_ABORTED;
    }

    /* Verify action result should just be the verify method result */
    if (result.verifyActionResult != result.verifyMethodResult) {
        printf("RSA verify action with corrupted signature failed: %d\n",
               result.verifyActionResult);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return WH_ERROR_ABORTED;
    }

    /* Delete the signature object to leave NVM in clean state */
    ret = wh_Nvm_DestroyObjects(serverCfg->nvm, 1, &testRsaSigNvmId);
    if (ret != WH_ERROR_OK) {
        printf("Failed to delete RSA signature object: %d\n", ret);
        wh_Server_Cleanup(server);
        wc_Sha256Free(&sha);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Cleanup */
    wh_Server_Cleanup(server);
    wc_Sha256Free(&sha);
    wc_FreeRsaKey(&rsaKey);
    wc_FreeRng(&rng);

    printf("IMG_MGR RSA2048 Test completed successfully!\n");
    return 0;
}
#endif /* !NO_RSA */

int whTest_ServerImgMgr(void)
{
    int            rc          = 0;
    const uint32_t BUFFER_SIZE = 1024;

    /* Transport memory configuration */
    uint8_t              req[BUFFER_SIZE];
    uint8_t              resp[BUFFER_SIZE];
    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
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

    /* RamSim Flash state and configuration */
    uint8_t memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,    /* 1MB Flash */
        .sectorSize = FLASH_SECTOR_SIZE, /* 128KB Sector Size */
        .pageSize   = FLASH_PAGE_SIZE,   /* 8B Page Size */
        .erasedByte = ~(uint8_t)0,
        .memory     = memory,
    }};
    const whFlashCb  fcb[1]     = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};

    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {{0}};

    whServerCryptoContext crypto[1] = {{
        .devId = INVALID_DEVID,
    }};

    whServerDmaConfig dma_config = {
        .cb               = NULL, /* Disable DMA callback for test */
        .dmaAddrAllowList = NULL};

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .dmaConfig   = &dma_config,
    }};

    /* Initialize NVM */
    rc = wh_Nvm_Init(nvm, n_conf);
    if (rc != 0) {
        printf("Failed to initialize NVM: %d\n", rc);
        return rc;
    }

    /* Run image manager server config tests for each built-in verify method */

#ifdef HAVE_ECC
    /* ECC P256 verify method */
    rc = whTest_ServerImgMgrServerCfgEcc256(s_conf);
    if (rc != 0) {
        printf("ECC P256 image manager server config tests failed: %d\n", rc);
        wh_Nvm_Cleanup(nvm);
        return rc;
    }
#endif /* HAVE_ECC */

#ifdef WOLFSSL_CMAC
    /* AES128 CMAC verify method */
    rc = whTest_ServerImgMgrServerCfgAes128Cmac(s_conf);
    if (rc != 0) {
        printf("AES128 CMAC image manager server config tests failed: %d\n",
               rc);
        wh_Nvm_Cleanup(nvm);
        return rc;
    }
#endif /* WOLFSSL_CMAC */

#ifndef NO_RSA
    /* RSA2048 verify method */
    rc = whTest_ServerImgMgrServerCfgRsa2048(s_conf);
    if (rc != 0) {
        printf("RSA2048 image manager server config tests failed: %d\n", rc);
        wh_Nvm_Cleanup(nvm);
        return rc;
    }
#endif /* !NO_RSA */

    /* Cleanup NVM */
    wh_Nvm_Cleanup(nvm);

    return rc;
}

#endif /* WOLFHSM_CFG_NO_CRYPTO */
#endif /* WOLFHSM_CFG_SERVER_IMG_MGR && WOLFHSM_CFG_ENABLE_SERVER &&
          !WOLFHSM_CFG_NO_CRYPTO */
