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
 * wolfhsm/wh_client_she.h
 *
 * Client API for the AUTOSAR SHE (Secure Hardware Extension) subsystem.
 *
 * This header declares the client-side interface to the optional wolfHSM SHE
 * extension, which is compiled only when WOLFHSM_CFG_SHE_EXTENSION is defined.
 * The API maps one-to-one onto the AUTOSAR SHE command set (CMD_SECURE_BOOT,
 * CMD_LOAD_KEY, CMD_RND, ...): each spec command is exposed as a
 * wh_Client_She* function that marshals the request to the wolfHSM server,
 * which implements the spec-compliant SHE behavior on top of the wolfHSM
 * keystore, NVM, and crypto infrastructure.
 *
 * AUTOSAR SHE defines a small, fixed-function security module for automotive
 * ECUs: a set of 128-bit AES key slots with fixed roles, an encrypted key
 * update protocol (the M1-M5 messages), a CMAC-based secure boot measurement,
 * a deterministic PRNG, and an 8-bit status register (SREG). See the AUTOSAR
 * "Specification of Secure Hardware Extensions" for the authoritative command
 * and protocol definitions.
 *
 * SHE key slots have fixed roles (defined in wolfhsm/wh_she_common.h):
 *   ID 0      SECRET_KEY      master secret consumed by the PRNG derivation
 *   ID 1      MASTER_ECU_KEY  ECU identity / key-update authorization key
 *   ID 2      BOOT_MAC_KEY    key used to CMAC the bootloader at secure boot
 *   ID 3      BOOT_MAC        expected bootloader CMAC compared at secure boot
 *   ID 4-13   user key slots  general-purpose keys
 *   ID 14     RAM_KEY         volatile slot, lost on power cycle
 *   ID 15     PRNG_SEED       persistent PRNG seed state
 *
 * Client SHE commands return WH_SHE_ERC_NO_ERROR (defined to WH_ERROR_OK,
 * i.e. 0) on success. On a SHE protocol failure they return one of the
 * WH_SHE_ERC_* status codes from wolfhsm/wh_error.h. On a transport or argument
 * failure they return a negative wolfHSM error code such as WH_ERROR_BADARGS.
 *
 */

#ifndef WOLFHSM_WH_CLIENT_SHE_H_
#define WOLFHSM_WH_CLIENT_SHE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION

/* System libraries */
#include <stdint.h>


#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"

/** SHE provisioning and identity functions */

/**
 * @brief Pre-programs a SHE key directly into NVM, bypassing the key update
 * protocol.
 *
 * This is a wolfHSM-specific provisioning helper that has no equivalent in the
 * AUTOSAR SHE command set. It writes @p key straight into the SHE NVM slot
 * @p keyId with an update counter of zero, skipping the encrypted M1-M5
 * CMD_LOAD_KEY protocol. It is intended for the initial provisioning of a
 * blank device (for example installing the MASTER_ECU_KEY or BOOT_MAC at
 * production) before any key-update authorization key exists; subsequent
 * in-field updates should use the spec-compliant wh_Client_SheLoadKey(). The
 * key is scoped to the calling client via the keyId USER field.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to write (0-15, e.g. WH_SHE_MASTER_ECU_KEY_ID).
 * @param[in] flags SHE key protection flags to store with the key
 *                  (WH_SHE_FLAG_WRITE_PROTECT, WH_SHE_FLAG_BOOT_PROTECT, etc.).
 * @param[in] key Pointer to the key material to store.
 * @param[in] keySz Length of the key material in bytes (WH_SHE_KEY_SZ, 16).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_ShePreProgramKey(whClientContext* c, whNvmId keyId,
    whNvmFlags flags, uint8_t* key, whNvmSize keySz);

/**
 * @brief Destroys a pre-programmed SHE key (wolfHSM-specific).
 *
 * Removes the SHE key in slot @p keyId from the calling client's NVM
 * namespace. Like wh_Client_ShePreProgramKey(), this is a provisioning helper
 * with no AUTOSAR SHE equivalent, since the spec treats SHE keys as fixed
 * hardware slots.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to destroy (0-15).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheDestroyKey(whClientContext* c, whNvmId keyId);

/**
 * @brief Sends a request to set the ECU UID (wolfHSM-specific).
 *
 * Sends a request carrying the 15-byte unique identifier. This
 * command has no AUTOSAR SHE equivalent: the spec assumes the UID is fused in
 * hardware, but a software SHE module must be told its UID. The server rejects
 * most SHE commands until the UID has been set, and the key update protocol
 * binds the M1/M4 messages against this value.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] uid Pointer to the UID bytes to install.
 * @param[in] uidSz Length of @p uid; must be at least WH_SHE_UID_SZ (15).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheSetUidRequest(whClientContext* c, uint8_t* uid,
    uint32_t uidSz);

/**
 * @brief Receives the response to a set UID request.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheSetUidResponse(whClientContext* c);

/**
 * @brief Sets the ECU UID with a blocking call (wolfHSM-specific).
 *
 * Sends a set UID request and busy-polls for the response. See
 * wh_Client_SheSetUidRequest() for why this command exists outside the AUTOSAR
 * SHE command set. The UID must be set before most other SHE commands will be
 * accepted by the server.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] uid Pointer to the UID bytes to install.
 * @param[in] uidSz Length of @p uid; must be at least WH_SHE_UID_SZ (15).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheSetUid(whClientContext* c, uint8_t* uid, uint32_t uidSz);

/** SHE secure boot functions */

/**
 * @brief Runs the SHE secure boot measurement with a blocking call
 * (CMD_SECURE_BOOT).
 *
 * Implements the AUTOSAR SHE CMD_SECURE_BOOT command by driving the
 * three-phase INIT/UPDATE/FINISH state machine in a single blocking call. The
 * server initializes a CMAC with the bootloader length, streams @p bootloader
 * into it in chunks of up to WOLFHSM_CFG_COMM_DATA_LEN (repeating the UPDATE
 * phase as needed), then finalizes the CMAC using BOOT_MAC_KEY (slot 2) and
 * compares it against the stored BOOT_MAC (slot 3). The outcome is reported
 * through the status register: a match sets WH_SHE_SREG_BOOT_OK while a
 * mismatch leaves it clear; either way WH_SHE_SREG_BOOT_FINISHED is set. Until
 * secure boot succeeds the server refuses most non-boot SHE commands.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] bootloader Pointer to the bootloader image to measure.
 * @param[in] bootloaderLen Length of the bootloader image in bytes.
 * @return int Returns 0 on success, or a negative error code on failure. A
 * boot measurement mismatch is reported via the status register
 * (wh_Client_SheGetStatus), not as an error return.
 */
int wh_Client_SheSecureBoot(whClientContext* c, uint8_t* bootloader,
    uint32_t bootloaderLen);

/** SHE status functions */

/**
 * @brief Sends a request to read the SHE status register (CMD_GET_STATUS).
 *
 * Sends an AUTOSAR SHE CMD_GET_STATUS request. This is a
 * zero-length message.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheGetStatusRequest(whClientContext* c);

/**
 * @brief Receives the SHE status register response (CMD_GET_STATUS).
 *
 * Consumes a CMD_GET_STATUS response and writes the 8-bit status register
 * (SREG) to @p sreg. The SREG bits are defined in wolfhsm/wh_she_common.h
 * (WH_SHE_SREG_SECURE_BOOT, WH_SHE_SREG_BOOT_FINISHED, WH_SHE_SREG_BOOT_OK,
 * WH_SHE_SREG_RND_INIT, ...).
 *
 * @param[in] c Pointer to the client context.
 * @param[out] sreg Pointer to a byte that receives the status register value.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheGetStatusResponse(whClientContext* c, uint8_t* sreg);

/**
 * @brief Reads the SHE status register with a blocking call (CMD_GET_STATUS).
 *
 * Sends a CMD_GET_STATUS request and busy-polls for the response, writing the
 * 8-bit status register (SREG) to @p sreg. See wolfhsm/wh_she_common.h for the
 * SREG bit definitions.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] sreg Pointer to a byte that receives the status register value.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheGetStatus(whClientContext* c, uint8_t* sreg);

/** SHE key management functions */

/**
 * @brief Sends an encrypted key update request (CMD_LOAD_KEY).
 *
 * Sends the three AUTOSAR SHE key update messages. M1, M2, and M3
 * encode the target slot, authorization key, new key, update counter, and
 * protection flags, encrypted and CMAC-protected under keys derived from the
 * authorization key using the spec's Miyaguchi-Preneel construction.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] messageOne M1: WH_SHE_M1_SZ (16) bytes - UID, key ID, auth ID.
 * @param[in] messageTwo M2: WH_SHE_M2_SZ (32) bytes - encrypted counter, flags,
 *                       and the new key.
 * @param[in] messageThree M3: WH_SHE_M3_SZ (16) bytes - CMAC over M1|M2.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheLoadKeyRequest(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree);

/**
 * @brief Receives the encrypted key update response (CMD_LOAD_KEY).
 *
 * Consumes the M4 and M5 verification messages the server returns after
 * storing the new key. M4 proves the new key and counter were stored, and M5
 * is a CMAC over M4; both are derived from the newly loaded key so the client
 * can confirm the update was applied correctly.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] messageFour M4: WH_SHE_M4_SZ (32) bytes - proof of storage.
 * @param[out] messageFive M5: WH_SHE_M5_SZ (16) bytes - CMAC over M4.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure (e.g.
 * WH_SHE_ERC_KEY_UPDATE_ERROR, WH_SHE_ERC_WRITE_PROTECTED).
 */
int wh_Client_SheLoadKeyResponse(whClientContext* c, uint8_t* messageFour,
    uint8_t* messageFive);

/**
 * @brief Performs an encrypted SHE key update with a blocking call
 * (CMD_LOAD_KEY).
 *
 * Sends the M1/M2/M3 key update messages and busy-polls for the M4/M5
 * verification response. This is the AUTOSAR SHE protocol for installing or
 * updating any key slot other than RAM_KEY: the server derives the
 * authorization keys, verifies M3, decrypts M2, enforces the strictly
 * increasing update counter and the WRITE_PROTECT / UID / WILDCARD
 * constraints, stores the new key, and returns M4/M5. Use
 * wh_Client_SheLoadPlainKey() to load the volatile RAM_KEY in plaintext.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] messageOne M1: WH_SHE_M1_SZ (16) bytes.
 * @param[in] messageTwo M2: WH_SHE_M2_SZ (32) bytes.
 * @param[in] messageThree M3: WH_SHE_M3_SZ (16) bytes.
 * @param[out] messageFour M4: WH_SHE_M4_SZ (32) bytes.
 * @param[out] messageFive M5: WH_SHE_M5_SZ (16) bytes.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheLoadKey(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree, uint8_t* messageFour,
    uint8_t* messageFive);

/**
 * @brief Sends a request to load the RAM key in plaintext (CMD_LOAD_PLAIN_KEY).
 *
 * Sends an AUTOSAR SHE CMD_LOAD_PLAIN_KEY request, which installs
 * a plaintext key directly into the volatile RAM_KEY slot (ID 14) without the
 * encrypted M1-M5 protocol. RAM_KEY lives only in the server key cache and is
 * lost on power cycle.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] key Pointer to the plaintext key material.
 * @param[in] keySz Length of @p key; must be at least WH_SHE_KEY_SZ (16).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheLoadPlainKeyRequest(whClientContext* c, uint8_t* key,
    uint32_t keySz);

/**
 * @brief Receives the response to a load plain key request
 * (CMD_LOAD_PLAIN_KEY).
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheLoadPlainKeyResponse(whClientContext* c);

/**
 * @brief Loads the RAM key in plaintext with a blocking call
 * (CMD_LOAD_PLAIN_KEY).
 *
 * Sends a CMD_LOAD_PLAIN_KEY request and busy-polls for the response,
 * installing @p key into the volatile RAM_KEY slot (ID 14), which is lost on
 * power cycle.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] key Pointer to the plaintext key material.
 * @param[in] keySz Length of @p key; must be at least WH_SHE_KEY_SZ (16).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheLoadPlainKey(whClientContext* c, uint8_t* key, uint32_t keySz);

/**
 * @brief Sends a request to export the RAM key (CMD_EXPORT_RAM_KEY).
 *
 * Sends an AUTOSAR SHE CMD_EXPORT_RAM_KEY request. This is a
 * zero-length message.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheExportRamKeyRequest(whClientContext* c);

/**
 * @brief Receives the exported RAM key as an M1-M5 blob (CMD_EXPORT_RAM_KEY).
 *
 * Consumes the CMD_EXPORT_RAM_KEY response, which returns the current RAM_KEY
 * (ID 14) packaged as the five key update messages bound to the
 * MASTER_ECU_KEY. The resulting M1-M5 blob can be transferred to a peer SHE
 * module and installed there via the CMD_LOAD_KEY protocol.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] messageOne M1: WH_SHE_M1_SZ (16) bytes.
 * @param[out] messageTwo M2: WH_SHE_M2_SZ (32) bytes.
 * @param[out] messageThree M3: WH_SHE_M3_SZ (16) bytes.
 * @param[out] messageFour M4: WH_SHE_M4_SZ (32) bytes.
 * @param[out] messageFive M5: WH_SHE_M5_SZ (16) bytes.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheExportRamKeyResponse(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree, uint8_t* messageFour,
    uint8_t* messageFive);

/**
 * @brief Exports the RAM key as an M1-M5 blob with a blocking call
 * (CMD_EXPORT_RAM_KEY).
 *
 * Sends a CMD_EXPORT_RAM_KEY request and busy-polls for the response. The
 * RAM_KEY is returned as the five key update messages (M1-M5) bound to the
 * MASTER_ECU_KEY, suitable for loading into a peer with wh_Client_SheLoadKey().
 *
 * @param[in] c Pointer to the client context.
 * @param[out] messageOne M1: WH_SHE_M1_SZ (16) bytes.
 * @param[out] messageTwo M2: WH_SHE_M2_SZ (32) bytes.
 * @param[out] messageThree M3: WH_SHE_M3_SZ (16) bytes.
 * @param[out] messageFour M4: WH_SHE_M4_SZ (32) bytes.
 * @param[out] messageFive M5: WH_SHE_M5_SZ (16) bytes.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheExportRamKey(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree, uint8_t* messageFour,
    uint8_t* messageFive);

/** SHE PRNG functions */

/**
 * @brief Sends a request to initialize the SHE PRNG (CMD_INIT_RNG).
 *
 * Sends an AUTOSAR SHE CMD_INIT_RNG request. This is a
 * zero-length message.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheInitRndRequest(whClientContext* c);

/**
 * @brief Receives the response to a PRNG initialization request
 * (CMD_INIT_RNG).
 *
 * On success the server has derived the PRNG key and state from SECRET_KEY and
 * PRNG_SEED, advanced and persisted the seed, and set WH_SHE_SREG_RND_INIT in
 * the status register.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheInitRndResponse(whClientContext* c);

/**
 * @brief Initializes the SHE PRNG with a blocking call (CMD_INIT_RNG).
 *
 * Sends a CMD_INIT_RNG request and busy-polls for the response. The
 * deterministic PRNG must be initialized with this command before
 * wh_Client_SheRnd() can draw random data.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheInitRnd(whClientContext* c);

/**
 * @brief Sends a request to draw random bytes from the SHE PRNG (CMD_RND).
 *
 * Sends an AUTOSAR SHE CMD_RND request. This is a zero-length
 * message. The PRNG must have been initialized with wh_Client_SheInitRnd().
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheRndRequest(whClientContext* c);

/**
 * @brief Receives random bytes from the SHE PRNG (CMD_RND).
 *
 * Consumes a CMD_RND response and copies the generated random block into
 * @p out. SHE produces exactly WH_SHE_KEY_SZ (16) bytes per call.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out Buffer that receives the random bytes.
 * @param[in,out] outSz On input, the size of @p out (must be at least
 *                      WH_SHE_KEY_SZ); on output, the number of bytes written
 *                      (WH_SHE_KEY_SZ).
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheRndResponse(whClientContext* c, uint8_t* out, uint32_t* outSz);

/**
 * @brief Draws random bytes from the SHE PRNG with a blocking call (CMD_RND).
 *
 * Sends a CMD_RND request and busy-polls for the response, copying
 * WH_SHE_KEY_SZ (16) bytes of PRNG output into @p out. wh_Client_SheInitRnd()
 * must have been called first.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out Buffer that receives the random bytes.
 * @param[in,out] outSz On input, the size of @p out (must be at least
 *                      WH_SHE_KEY_SZ); on output, the number of bytes written.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheRnd(whClientContext* c, uint8_t* out, uint32_t* outSz);

/**
 * @brief Sends a request to reseed the SHE PRNG (CMD_EXTEND_SEED).
 *
 * Sends an AUTOSAR SHE CMD_EXTEND_SEED request, mixing
 * caller-supplied entropy into the PRNG state.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] entropy Pointer to the additional entropy to mix in.
 * @param[in] entropySz Length of @p entropy; must equal WH_SHE_KEY_SZ (16).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheExtendSeedRequest(whClientContext* c, uint8_t* entropy,
    uint32_t entropySz);

/**
 * @brief Receives the response to a PRNG reseed request (CMD_EXTEND_SEED).
 *
 * On success the server has folded the supplied entropy into the PRNG state
 * and written the updated PRNG_SEED back to NVM so the reseed survives reboots.
 *
 * @param[in] c Pointer to the client context.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheExtendSeedResponse(whClientContext* c);

/**
 * @brief Reseeds the SHE PRNG with a blocking call (CMD_EXTEND_SEED).
 *
 * Sends a CMD_EXTEND_SEED request and busy-polls for the response, mixing
 * WH_SHE_KEY_SZ (16) bytes of caller-supplied entropy into the PRNG state and
 * persisting the updated seed.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] entropy Pointer to the additional entropy to mix in.
 * @param[in] entropySz Length of @p entropy; must equal WH_SHE_KEY_SZ (16).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheExtendSeed(whClientContext* c, uint8_t* entropy,
    uint32_t entropySz);

/** SHE cipher functions */

/**
 * @brief Sends an AES-ECB encryption request (CMD_ENC_ECB).
 *
 * Sends an AUTOSAR SHE CMD_ENC_ECB request to encrypt @p in under
 * the key in slot @p keyId.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to encrypt with.
 * @param[in] in Pointer to the plaintext.
 * @param[in] sz Length of the plaintext in bytes; must be at least
 *               WH_SHE_KEY_SZ (16) and fit within WOLFHSM_CFG_COMM_DATA_LEN.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheEncEcbRequest(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint32_t sz);

/**
 * @brief Receives the AES-ECB ciphertext (CMD_ENC_ECB).
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out Buffer that receives the ciphertext.
 * @param[in] sz Size of @p out; must be at least the input size.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheEncEcbResponse(whClientContext* c, uint8_t* out, uint32_t sz);

/**
 * @brief Encrypts data with AES-ECB using a blocking call (CMD_ENC_ECB).
 *
 * Sends a CMD_ENC_ECB request and busy-polls for the response, encrypting
 * @p in under the key in slot @p keyId and writing the ciphertext to @p out.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to encrypt with.
 * @param[in] in Pointer to the plaintext.
 * @param[out] out Buffer that receives the ciphertext (at least @p sz bytes).
 * @param[in] sz Length of the data in bytes; must be at least WH_SHE_KEY_SZ.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheEncEcb(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint8_t* out, uint32_t sz);

/**
 * @brief Sends an AES-CBC encryption request (CMD_ENC_CBC).
 *
 * Sends an AUTOSAR SHE CMD_ENC_CBC request to encrypt @p in under
 * the key in slot @p keyId using the supplied initialization vector.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to encrypt with.
 * @param[in] iv Pointer to the initialization vector.
 * @param[in] ivSz Length of @p iv; must be at least WH_SHE_KEY_SZ (16).
 * @param[in] in Pointer to the plaintext.
 * @param[in] sz Length of the plaintext in bytes; must be at least
 *               WH_SHE_KEY_SZ (16) and fit within WOLFHSM_CFG_COMM_DATA_LEN.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheEncCbcRequest(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint32_t sz);

/**
 * @brief Receives the AES-CBC ciphertext (CMD_ENC_CBC).
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out Buffer that receives the ciphertext.
 * @param[in] sz Size of @p out; must be at least the input size.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheEncCbcResponse(whClientContext* c, uint8_t* out, uint32_t sz);

/**
 * @brief Encrypts data with AES-CBC using a blocking call (CMD_ENC_CBC).
 *
 * Sends a CMD_ENC_CBC request and busy-polls for the response, encrypting
 * @p in under the key in slot @p keyId with the supplied @p iv.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to encrypt with.
 * @param[in] iv Pointer to the initialization vector.
 * @param[in] ivSz Length of @p iv; must be at least WH_SHE_KEY_SZ (16).
 * @param[in] in Pointer to the plaintext.
 * @param[out] out Buffer that receives the ciphertext (at least @p sz bytes).
 * @param[in] sz Length of the data in bytes; must be at least WH_SHE_KEY_SZ.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheEncCbc(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint8_t* out, uint32_t sz);

/**
 * @brief Sends an AES-ECB decryption request (CMD_DEC_ECB).
 *
 * Sends an AUTOSAR SHE CMD_DEC_ECB request to decrypt @p in under
 * the key in slot @p keyId.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to decrypt with.
 * @param[in] in Pointer to the ciphertext.
 * @param[in] sz Length of the ciphertext in bytes; must be at least
 *               WH_SHE_KEY_SZ (16) and fit within WOLFHSM_CFG_COMM_DATA_LEN.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheDecEcbRequest(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint32_t sz);

/**
 * @brief Receives the AES-ECB plaintext (CMD_DEC_ECB).
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out Buffer that receives the plaintext.
 * @param[in] sz Size of @p out; must be at least the input size.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheDecEcbResponse(whClientContext* c, uint8_t* out, uint32_t sz);

/**
 * @brief Decrypts data with AES-ECB using a blocking call (CMD_DEC_ECB).
 *
 * Sends a CMD_DEC_ECB request and busy-polls for the response, decrypting
 * @p in under the key in slot @p keyId and writing the plaintext to @p out.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to decrypt with.
 * @param[in] in Pointer to the ciphertext.
 * @param[out] out Buffer that receives the plaintext (at least @p sz bytes).
 * @param[in] sz Length of the data in bytes; must be at least WH_SHE_KEY_SZ.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheDecEcb(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint8_t* out, uint32_t sz);

/**
 * @brief Sends an AES-CBC decryption request (CMD_DEC_CBC).
 *
 * Sends an AUTOSAR SHE CMD_DEC_CBC request to decrypt @p in under
 * the key in slot @p keyId using the supplied initialization vector.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to decrypt with.
 * @param[in] iv Pointer to the initialization vector.
 * @param[in] ivSz Length of @p iv; must be at least WH_SHE_KEY_SZ (16).
 * @param[in] in Pointer to the ciphertext.
 * @param[in] sz Length of the ciphertext in bytes; must be at least
 *               WH_SHE_KEY_SZ (16) and fit within WOLFHSM_CFG_COMM_DATA_LEN.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheDecCbcRequest(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint32_t sz);

/**
 * @brief Receives the AES-CBC plaintext (CMD_DEC_CBC).
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out Buffer that receives the plaintext.
 * @param[in] sz Size of @p out; must be at least the input size.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheDecCbcResponse(whClientContext* c, uint8_t* out, uint32_t sz);

/**
 * @brief Decrypts data with AES-CBC using a blocking call (CMD_DEC_CBC).
 *
 * Sends a CMD_DEC_CBC request and busy-polls for the response, decrypting
 * @p in under the key in slot @p keyId with the supplied @p iv.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to decrypt with.
 * @param[in] iv Pointer to the initialization vector.
 * @param[in] ivSz Length of @p iv; must be at least WH_SHE_KEY_SZ (16).
 * @param[in] in Pointer to the ciphertext.
 * @param[out] out Buffer that receives the plaintext (at least @p sz bytes).
 * @param[in] sz Length of the data in bytes; must be at least WH_SHE_KEY_SZ.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheDecCbc(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint8_t* out, uint32_t sz);

/** SHE MAC functions */

/**
 * @brief Sends a CMAC generation request (CMD_GENERATE_MAC).
 *
 * Sends an AUTOSAR SHE CMD_GENERATE_MAC request to compute a CMAC
 * over @p in using the key in slot @p keyId.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to MAC with.
 * @param[in] in Pointer to the message to authenticate.
 * @param[in] sz Length of the message in bytes; must be at least WH_SHE_KEY_SZ
 *               (16) and fit within WOLFHSM_CFG_COMM_DATA_LEN.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheGenerateMacRequest(whClientContext* c, uint8_t keyId,
    uint8_t* in, uint32_t sz);

/**
 * @brief Receives the generated CMAC (CMD_GENERATE_MAC).
 *
 * @param[in] c Pointer to the client context.
 * @param[out] out Buffer that receives the WH_SHE_KEY_SZ (16) byte CMAC.
 * @param[in] sz Size of @p out; must be at least WH_SHE_KEY_SZ (16).
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheGenerateMacResponse(whClientContext* c, uint8_t* out,
    uint32_t sz);

/**
 * @brief Generates a CMAC with a blocking call (CMD_GENERATE_MAC).
 *
 * Sends a CMD_GENERATE_MAC request and busy-polls for the response, computing
 * a CMAC over @p in under the key in slot @p keyId and writing the 16-byte tag
 * to @p out.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to MAC with.
 * @param[in] in Pointer to the message to authenticate.
 * @param[in] inSz Length of the message in bytes; must be at least
 *                 WH_SHE_KEY_SZ (16).
 * @param[out] out Buffer that receives the CMAC.
 * @param[in] outSz Size of @p out; must be at least WH_SHE_KEY_SZ (16).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheGenerateMac(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint32_t inSz, uint8_t* out, uint32_t outSz);

/**
 * @brief Sends a CMAC verification request (CMD_VERIFY_MAC).
 *
 * Sends an AUTOSAR SHE CMD_VERIFY_MAC request to verify @p mac
 * against a freshly computed CMAC of @p message using the key in slot @p keyId.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to verify with.
 * @param[in] message Pointer to the message that was authenticated.
 * @param[in] messageLen Length of @p message; must be at least WH_SHE_KEY_SZ
 *                       (16). The message plus MAC must fit within
 *                       WOLFHSM_CFG_COMM_DATA_LEN.
 * @param[in] mac Pointer to the CMAC to verify.
 * @param[in] macLen Length of @p mac; must be at least WH_SHE_KEY_SZ (16).
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheVerifyMacRequest(whClientContext* c, uint8_t keyId,
    uint8_t* message, uint32_t messageLen, uint8_t* mac, uint32_t macLen);

/**
 * @brief Receives the CMAC verification result (CMD_VERIFY_MAC).
 *
 * Consumes a CMD_VERIFY_MAC response and reports whether the MAC matched
 * through @p outStatus. Per the SHE spec a verification mismatch is a normal
 * result rather than an error: the function still returns success and signals
 * the mismatch via @p outStatus.
 *
 * @param[in] c Pointer to the client context.
 * @param[out] outStatus Set to 0 if the MAC verified successfully, or 1 if it
 *                       did not match.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if no response is
 * available yet, or a negative error code on failure.
 */
int wh_Client_SheVerifyMacResponse(whClientContext* c, uint8_t* outStatus);

/**
 * @brief Verifies a CMAC with a blocking call (CMD_VERIFY_MAC).
 *
 * Sends a CMD_VERIFY_MAC request and busy-polls for the response, verifying
 * @p mac against a CMAC of @p message under the key in slot @p keyId. A
 * verification mismatch is reported through @p outStatus, not as an error
 * return.
 *
 * @param[in] c Pointer to the client context.
 * @param[in] keyId SHE key slot to verify with.
 * @param[in] message Pointer to the message that was authenticated.
 * @param[in] messageLen Length of @p message; must be at least WH_SHE_KEY_SZ.
 * @param[in] mac Pointer to the CMAC to verify.
 * @param[in] macLen Length of @p mac; must be at least WH_SHE_KEY_SZ (16).
 * @param[out] outStatus Set to 0 if the MAC verified successfully, or 1 if it
 *                       did not match.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_SheVerifyMac(whClientContext* c, uint8_t keyId, uint8_t* message,
    uint32_t messageLen, uint8_t* mac, uint32_t macLen, uint8_t* outStatus);

#endif /* WOLFHSM_CFG_SHE_EXTENSION */

#endif /* !WOLFHSM_WH_CLIENT_SHE_H_ */
