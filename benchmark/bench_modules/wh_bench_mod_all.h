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
#ifndef WH_BENCH_MOD_ALL_H_
#define WH_BENCH_MOD_ALL_H_

#include "wh_bench_mod.h"

/* Echo benchmark module prototypes (wh_bench_mod_echo.c) */
int wh_Bench_Mod_Echo(whClientContext* client, whBenchOpContext* benchCtx,
                      int id, void* params);

/*
 * AES benchmark module prototypes (wh_bench_mod_aes.c)
 */
int wh_Bench_Mod_Aes128CTREncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes128CTRDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);
int wh_Bench_Mod_Aes128ECBEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes128ECBDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes128CBCEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes128CBCEncryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params);

int wh_Bench_Mod_Aes128CBCDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes128CBCDecryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params);

int wh_Bench_Mod_Aes128GCMEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes128GCMDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes128GCMEncryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params);

int wh_Bench_Mod_Aes128GCMDecryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params);

int wh_Bench_Mod_Aes256CTREncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes256CTRDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes256ECBEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes256ECBDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes256CBCEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes256CBCEncryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params);

int wh_Bench_Mod_Aes256CBCDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes256CBCDecryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params);

int wh_Bench_Mod_Aes256GCMEncrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes256GCMDecrypt(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Aes256GCMEncryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params);

int wh_Bench_Mod_Aes256GCMDecryptDma(whClientContext*  client,
                                     whBenchOpContext* ctx, int id,
                                     void* params);

/*
 * CMAC benchmark module prototypes (wh_bench_mod_cmac.c)
 */
int wh_Bench_Mod_CmacAes128(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params);

int wh_Bench_Mod_CmacAes128Dma(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_CmacAes256(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params);

int wh_Bench_Mod_CmacAes256Dma(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

/*
 * RNG benchmark module prototypes (wh_bench_mod_rng.c)
 */
int wh_Bench_Mod_Rng(whClientContext* client, whBenchOpContext* ctx, int id,
                     void* params);

/*
 * SHA2 benchmark module prototypes (wh_bench_mod_sha2.c)
 */
int wh_Bench_Mod_Sha256(whClientContext* client, whBenchOpContext* ctx, int id,
                        void* params);

int wh_Bench_Mod_Sha256Dma(whClientContext* client, whBenchOpContext* ctx,
                           int id, void* params);
int wh_Bench_Mod_Sha224(whClientContext* client, whBenchOpContext* ctx, int id,
                        void* params);

int wh_Bench_Mod_Sha224Dma(whClientContext* client, whBenchOpContext* ctx,
                           int id, void* params);
int wh_Bench_Mod_Sha384(whClientContext* client, whBenchOpContext* ctx, int id,
                        void* params);

int wh_Bench_Mod_Sha384Dma(whClientContext* client, whBenchOpContext* ctx,
                           int id, void* params);
int wh_Bench_Mod_Sha512(whClientContext* client, whBenchOpContext* ctx, int id,
                        void* params);

int wh_Bench_Mod_Sha512Dma(whClientContext* client, whBenchOpContext* ctx,
                           int id, void* params);
/*
 * SHA3 benchmark module prototypes (wh_bench_mod_sha3.c)
 */
int wh_Bench_Mod_Sha3256(whClientContext* client, whBenchOpContext* ctx, int id,
                         void* params);

int wh_Bench_Mod_Sha3256Dma(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params);

/*
 * HMAC benchmark module prototypes (wh_bench_mod_hmac.c)
 */
int wh_Bench_Mod_HmacSha256(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params);

int wh_Bench_Mod_HmacSha256Dma(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_HmacSha3256(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params);

int wh_Bench_Mod_HmacSha3256Dma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params);

/*
 * HKDF benchmark module prototypes (wh_bench_mod_hkdf.c)
 */
int wh_Bench_Mod_HkdfSha256(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params);

/*
 * ECC benchmark module prototypes (wh_bench_mod_ecc.c)
 */
int wh_Bench_Mod_EccP256Sign(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params);

int wh_Bench_Mod_EccP256SignDma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params);

int wh_Bench_Mod_EccP256Verify(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_EccP256VerifyDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_EccP256KeyGen(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_EccP256Ecdh(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params);

/*
 * RSA benchmark module prototypes (wh_bench_mod_rsa.c)
 */
int wh_Bench_Mod_Rsa2048PubEncrypt(whClientContext*  client,
                                   whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Rsa2048PubEncryptDma(whClientContext*  client,
                                      whBenchOpContext* ctx, int id,
                                      void* params);

int wh_Bench_Mod_Rsa2048PrvDecrypt(whClientContext*  client,
                                   whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Rsa2048PrvDecryptDma(whClientContext*  client,
                                      whBenchOpContext* ctx, int id,
                                      void* params);

int wh_Bench_Mod_Rsa2048Sign(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params);

int wh_Bench_Mod_Rsa2048SignDma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params);

int wh_Bench_Mod_Rsa2048Verify(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_Rsa2048VerifyDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Rsa2048KeyGen(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_Rsa2048KeyGenDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Rsa4096PubEncrypt(whClientContext*  client,
                                   whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Rsa4096PubEncryptDma(whClientContext*  client,
                                      whBenchOpContext* ctx, int id,
                                      void* params);

int wh_Bench_Mod_Rsa4096PrvDecrypt(whClientContext*  client,
                                   whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Rsa4096PrvDecryptDma(whClientContext*  client,
                                      whBenchOpContext* ctx, int id,
                                      void* params);

int wh_Bench_Mod_Rsa4096Sign(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params);

int wh_Bench_Mod_Rsa4096SignDma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params);

int wh_Bench_Mod_Rsa4096Verify(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_Rsa4096VerifyDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Rsa4096KeyGen(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_Rsa4096KeyGenDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);


/*
 * Curve25519 benchmark module prototypes (wh_bench_mod_curve25519.c)
 */
int wh_Bench_Mod_Curve25519KeyGen(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_Curve25519SharedSecret(whClientContext*  client,
                                        whBenchOpContext* ctx, int id,
                                        void* params);

/*
 * ML-DSA benchmark module prototypes (wh_bench_mod_mldsa.c)
 */
/* ML-DSA with security level 44 */
int wh_Bench_Mod_MlDsa44Sign(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params);

int wh_Bench_Mod_MlDsa44SignDma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params);

int wh_Bench_Mod_MlDsa44Verify(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_MlDsa44VerifyDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_MlDsa44KeyGen(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_MlDsa44KeyGenDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

/* ML-DSA with security level 65 */
int wh_Bench_Mod_MlDsa65Sign(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params);

int wh_Bench_Mod_MlDsa65SignDma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params);

int wh_Bench_Mod_MlDsa65Verify(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_MlDsa65VerifyDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_MlDsa65KeyGen(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_MlDsa65KeyGenDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

/* ML-DSA with security level 87 */
int wh_Bench_Mod_MlDsa87Sign(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params);

int wh_Bench_Mod_MlDsa87SignDma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params);

int wh_Bench_Mod_MlDsa87Verify(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_MlDsa87VerifyDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

int wh_Bench_Mod_MlDsa87KeyGen(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params);

int wh_Bench_Mod_MlDsa87KeyGenDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params);

#endif /* WH_BENCH_MOD_ALL_H_ */
