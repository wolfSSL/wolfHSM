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
 * test/wh_test_pkcs11.c
 *
 * PKCS#11 integration test: forks wh_server_uds, connects via
 * p11-kit-client.so (dlopen), exercises key generation and signing.
 *
 * Test sequence:
 *  1. fork+exec the wh_server_uds daemon on a temp socket
 *  2. dlopen p11-kit-client.so, get C_GetFunctionList
 *  3. C_Initialize -> CKR_OK
 *  4. C_InitToken (set SO PIN)
 *  5. Open R/W session, login as SO, C_InitPIN (set user PIN), logout
 *  6. Login as user
 *  7. C_GenerateKeyPair (EC prime256v1)
 *  8. C_FindObjectsInit/C_FindObjects/C_FindObjectsFinal -> finds both keys
 *  9. C_SignInit + C_Sign (ECDSA, 32-byte digest)
 * 10. Cross-validate: verify signature with wolfCrypt wc_ecc_verify_hash
 *     (independent oracle)
 * 11. C_GenerateRandom(32) twice -> outputs differ and are non-zero
 * 12. C_DestroyObject, C_CloseSession, C_Finalize
 * 13. Kill daemon
 *
 * Sign oracle is wolfCrypt wc_ecc_verify_hash — never C_Verify — so the test
 * proves round-trip correctness against an independent implementation.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_TEST_PKCS11)

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>   /* NULL */
#include <stdint.h>   /* uint8_t */
#include <stdio.h>    /* fprintf, snprintf */
#include <stdlib.h>   /* getenv, exit */
#include <string.h>   /* memset, memcmp */
#include <unistd.h>   /* fork, exec, unlink */
#include <time.h>     /* nanosleep */
#include <sys/stat.h> /* stat */
#include <sys/types.h>
#include <sys/wait.h> /* waitpid */
#include <dlfcn.h>    /* dlopen, dlsym, dlclose */
#include <signal.h>   /* kill */
#include <pthread.h>  /* unused but commonly pulled in with POSIX */

/* p11-kit PKCS#11 types */
#include <p11-kit/pkcs11.h>

/* wolfCrypt: used as independent oracle for signature verification */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn_public.h"  /* wc_EccPublicKeyDecode */

#include "wolfhsm/wh_error.h"
#include "wh_test_common.h"
#include "wh_test_pkcs11.h"

/* ── Tunable constants ───────────────────────────────────────────────────── */

/* p11-kit-client.so: first path that exists is used */
#define WH_TEST_PKCS11_P11KIT_SO_PATH \
    "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so"

/* Default daemon binary, relative to the repo root */
#define WH_TEST_PKCS11_DAEMON_DEFAULT \
    "examples/posix/wh_server_uds/Build/wh_server_uds"

/* wolfPKCS11's PKCS#11 slot ID (not the pkcs11-tool list index) */
#define WH_TEST_PKCS11_SLOT_ID  ((CK_SLOT_ID)1)

/* PINs used during the test */
#define WH_TEST_PKCS11_SO_PIN   "87654321"
#define WH_TEST_PKCS11_USER_PIN "12345678"

/* Maximum time to wait for the daemon socket to appear (10 × 200 ms = 2 s) */
#define WH_TEST_PKCS11_SOCK_RETRIES   10
/* 200 ms expressed as nanoseconds for nanosleep */
#define WH_TEST_PKCS11_SOCK_WAIT_NS   200000000L

/* ── Helpers ──────────────────────────────────────────────────────────────── */

/* CK_FUNCTION_LIST pointer obtained from p11-kit-client.so */
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);

/*
 * Locate the daemon binary.  Resolution order:
 *  1. WH_TEST_PKCS11_DAEMON_PATH compile-time define
 *  2. WH_TEST_PKCS11_DAEMON_PATH environment variable
 *  3. Default relative path (works when cwd = repo root)
 */
static const char* pkcs11_daemon_path(void)
{
#ifdef WH_TEST_PKCS11_DAEMON_PATH
    return WH_TEST_PKCS11_DAEMON_PATH;
#else
    const char* env = getenv("WH_TEST_PKCS11_DAEMON_PATH");
    if (env != NULL && env[0] != '\0') {
        return env;
    }
    return WH_TEST_PKCS11_DAEMON_DEFAULT;
#endif
}

/* Returns 1 if the socket at path exists as a socket file, 0 otherwise */
static int sock_exists(const char* path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISSOCK(st.st_mode)) ? 1 : 0;
}

/* ── Test implementation ──────────────────────────────────────────────────── */

int whTest_Pkcs11(void)
{
    int    ret    = WH_ERROR_OK;
    pid_t  daemon_pid = -1;
    void*  dl_handle  = NULL;
    char   sock_path[128];
    char   env_val[256];

    CK_FUNCTION_LIST_PTR fns    = NULL;
    CK_SESSION_HANDLE    session = CK_INVALID_HANDLE;

    CK_OBJECT_HANDLE priv_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub_handle  = CK_INVALID_HANDLE;

    /* ── 1. Locate daemon binary ── */
    const char* daemon_bin = pkcs11_daemon_path();
    {
        struct stat st;
        if (stat(daemon_bin, &st) != 0) {
            WH_ERROR_PRINT("[PKCS11] daemon binary not found at %s\n"
                           "  Set WH_TEST_PKCS11_DAEMON_PATH or build with "
                           "  'make -C examples/posix/wh_server_uds'\n",
                           daemon_bin);
            return WH_ERROR_ABORTED;
        }
    }

    /* ── 2. Choose a unique socket path ── */
    snprintf(sock_path, sizeof(sock_path),
             "/tmp/wolfhsm-pkcs11-test-%d.sock", (int)getpid());
    (void)unlink(sock_path);  /* remove stale socket from a prior crash */

    /* ── 3. Fork+exec the daemon ── */
    daemon_pid = fork();
    if (daemon_pid < 0) {
        WH_ERROR_PRINT("[PKCS11] fork failed\n");
        return WH_ERROR_ABORTED;
    }
    if (daemon_pid == 0) {
        /* Child: set socket path and exec daemon */
        if (setenv("WH_UDS_PATH", sock_path, 1) != 0) {
            _exit(1);
        }
        execl(daemon_bin, daemon_bin, (char*)NULL);
        _exit(1);  /* exec failed */
    }

    /* Parent: wait up to 2 s for the daemon socket to appear */
    {
        int i;
        for (i = 0; i < WH_TEST_PKCS11_SOCK_RETRIES; i++) {
            struct timespec ts;
            ts.tv_sec  = 0;
            ts.tv_nsec = WH_TEST_PKCS11_SOCK_WAIT_NS;
            nanosleep(&ts, NULL);
            if (sock_exists(sock_path)) {
                break;
            }
        }
        if (!sock_exists(sock_path)) {
            WH_ERROR_PRINT("[PKCS11] daemon socket did not appear within 2s\n");
            ret = WH_ERROR_ABORTED;
            goto cleanup_daemon;
        }
    }

    /* ── 4. Set P11_KIT_SERVER_ADDRESS for p11-kit-client.so ── */
    snprintf(env_val, sizeof(env_val), "unix:path=%s", sock_path);
    if (setenv("P11_KIT_SERVER_ADDRESS", env_val, 1) != 0) {
        WH_ERROR_PRINT("[PKCS11] setenv P11_KIT_SERVER_ADDRESS failed\n");
        ret = WH_ERROR_ABORTED;
        goto cleanup_daemon;
    }

    /* ── 5. dlopen p11-kit-client.so ── */
    dl_handle = dlopen(WH_TEST_PKCS11_P11KIT_SO_PATH, RTLD_NOW | RTLD_LOCAL);
    if (dl_handle == NULL) {
        WH_ERROR_PRINT("[PKCS11] dlopen %s failed: %s\n",
                       WH_TEST_PKCS11_P11KIT_SO_PATH, dlerror());
        ret = WH_ERROR_ABORTED;
        goto cleanup_daemon;
    }

    {
        CK_C_GetFunctionList get_fn_list =
            (CK_C_GetFunctionList)dlsym(dl_handle, "C_GetFunctionList");
        if (get_fn_list == NULL) {
            WH_ERROR_PRINT("[PKCS11] dlsym C_GetFunctionList failed: %s\n",
                           dlerror());
            ret = WH_ERROR_ABORTED;
            goto cleanup_dl;
        }
        if (get_fn_list(&fns) != CKR_OK || fns == NULL) {
            WH_ERROR_PRINT("[PKCS11] C_GetFunctionList failed\n");
            ret = WH_ERROR_ABORTED;
            goto cleanup_dl;
        }
    }

    /* ── 6. C_Initialize ── */
    {
        CK_RV rv = fns->C_Initialize(NULL);
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_Initialize: 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_dl;
        }
    }

    /* ── 7. C_InitToken: set SO PIN on slot 1 ── */
    {
        CK_UTF8CHAR so_pin[]  = WH_TEST_PKCS11_SO_PIN;
        CK_UTF8CHAR label[32];
        CK_RV rv;

        memset(label, ' ', sizeof(label));
        memcpy(label, "wolfHSM-pkcs11-test", 19);

        rv = fns->C_InitToken(WH_TEST_PKCS11_SLOT_ID,
                              so_pin, (CK_ULONG)(sizeof(so_pin) - 1),
                              label);
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_InitToken: 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_pkcs11;
        }
    }
    WH_TEST_PRINT("  whTest_Pkcs11: C_InitToken OK\n");

    /* ── 8. Open R/W session, login as SO, set user PIN, logout ── */
    {
        CK_FLAGS  flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        CK_UTF8CHAR so_pin[]   = WH_TEST_PKCS11_SO_PIN;
        CK_UTF8CHAR user_pin[] = WH_TEST_PKCS11_USER_PIN;
        CK_RV rv;

        rv = fns->C_OpenSession(WH_TEST_PKCS11_SLOT_ID, flags,
                                NULL, NULL, &session);
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_OpenSession: 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_pkcs11;
        }

        rv = fns->C_Login(session, CKU_SO,
                          so_pin, (CK_ULONG)(sizeof(so_pin) - 1));
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_Login (SO): 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }

        rv = fns->C_InitPIN(session,
                            user_pin, (CK_ULONG)(sizeof(user_pin) - 1));
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_InitPIN: 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }

        rv = fns->C_Logout(session);
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_Logout (SO): 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }
    }

    /* ── 9. Login as user ── */
    {
        CK_UTF8CHAR user_pin[] = WH_TEST_PKCS11_USER_PIN;
        CK_RV rv = fns->C_Login(session, CKU_USER,
                                user_pin, (CK_ULONG)(sizeof(user_pin) - 1));
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_Login (user): 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }
    }
    WH_TEST_PRINT("  whTest_Pkcs11: C_Login (user) OK\n");

    /* ── 10. C_GenerateKeyPair: EC prime256v1 ── */
    {
        /* DER encoding of OID 1.2.840.10045.3.1.7 (prime256v1) */
        static const CK_BYTE ec_params[] = {
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
        };

        CK_BBOOL     ck_true  = CK_TRUE;
        CK_BBOOL     ck_false = CK_FALSE;
        CK_KEY_TYPE  key_type = CKK_EC;
        CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
        CK_OBJECT_CLASS pub_class  = CKO_PUBLIC_KEY;
        CK_UTF8CHAR  label[]  = "wh-test-ec-key";

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_CLASS,     &pub_class,  sizeof(pub_class)  },
            { CKA_KEY_TYPE,  &key_type,   sizeof(key_type)   },
            { CKA_EC_PARAMS, (CK_VOID_PTR)ec_params,
                             sizeof(ec_params)               },
            { CKA_LABEL,     label,       sizeof(label) - 1  },
            { CKA_VERIFY,    &ck_true,    sizeof(ck_true)    },
            { CKA_TOKEN,     &ck_true,    sizeof(ck_true)    },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_CLASS,     &priv_class, sizeof(priv_class) },
            { CKA_KEY_TYPE,  &key_type,   sizeof(key_type)   },
            { CKA_LABEL,     label,       sizeof(label) - 1  },
            { CKA_SIGN,      &ck_true,    sizeof(ck_true)    },
            { CKA_SENSITIVE, &ck_true,    sizeof(ck_true)    },
            { CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)   },
            { CKA_TOKEN,     &ck_true,    sizeof(ck_true)    },
        };
        CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
        CK_RV rv;

        rv = fns->C_GenerateKeyPair(session, &mech,
                                    pub_tmpl,
                                    sizeof(pub_tmpl) / sizeof(pub_tmpl[0]),
                                    priv_tmpl,
                                    sizeof(priv_tmpl) / sizeof(priv_tmpl[0]),
                                    &pub_handle, &priv_handle);
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_GenerateKeyPair: 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }
    }
    WH_TEST_PRINT("  whTest_Pkcs11: C_GenerateKeyPair (EC P-256) OK\n");

    /* ── 11. C_FindObjects: must find both keys ── */
    {
        CK_UTF8CHAR  label[]  = "wh-test-ec-key";
        CK_ATTRIBUTE find_tmpl[] = {
            { CKA_LABEL, label, sizeof(label) - 1 },
        };
        CK_OBJECT_HANDLE found[8];
        CK_ULONG         found_cnt = 0;
        CK_RV rv;

        rv = fns->C_FindObjectsInit(session, find_tmpl,
                                    sizeof(find_tmpl) / sizeof(find_tmpl[0]));
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_FindObjectsInit: 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }

        rv = fns->C_FindObjects(session, found,
                                sizeof(found) / sizeof(found[0]), &found_cnt);
        (void)fns->C_FindObjectsFinal(session);

        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_FindObjects: 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }
        /* Expect exactly 2: one public, one private */
        if (found_cnt != 2) {
            WH_ERROR_PRINT("[PKCS11] C_FindObjects: expected 2, got %lu\n",
                           (unsigned long)found_cnt);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }
    }
    WH_TEST_PRINT("  whTest_Pkcs11: C_FindObjects OK (2 objects)\n");

    /* ── 12. C_Sign (ECDSA) + independent wolfCrypt verify ── */
    {
        /*
         * Digest: a fixed 32-byte value representing the hash of some message.
         * This is fed to C_Sign as the pre-hashed input for CKM_ECDSA.
         */
        static const CK_BYTE digest[32] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        };

        /* Buffer for DER signature: P-256 ECDSA is at most 72 bytes */
        CK_BYTE   sig[128];
        CK_ULONG  sig_len = sizeof(sig);
        CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
        CK_RV rv;

        rv = fns->C_SignInit(session, &mech, priv_handle);
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_SignInit: 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }

        rv = fns->C_Sign(session,
                         (CK_BYTE_PTR)(uintptr_t)digest, sizeof(digest),
                         sig, &sig_len);
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_Sign: 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }

        WH_TEST_PRINT("  whTest_Pkcs11: C_Sign OK (%lu bytes)\n",
                      (unsigned long)sig_len);

        /*
         * Independent verification using wolfCrypt wc_ecc_verify_hash.
         *
         * We need the public key material (EC_POINT) from the token to
         * construct a wolfCrypt ecc_key.  Retrieve CKA_EC_POINT from the
         * public key object.
         */
        {
            CK_BYTE   ec_point_buf[256];
            CK_ULONG  ec_point_len = sizeof(ec_point_buf);
            CK_ATTRIBUTE point_attr = {
                CKA_EC_POINT, ec_point_buf, ec_point_len
            };
            ecc_key  wc_key;
            int      verified = 0;
            int      wc_ret;

            rv = fns->C_GetAttributeValue(session, pub_handle,
                                          &point_attr, 1);
            if (rv != CKR_OK) {
                WH_ERROR_PRINT("[PKCS11] C_GetAttributeValue(EC_POINT): "
                               "0x%08lX\n", (unsigned long)rv);
                ret = WH_ERROR_ABORTED;
                goto cleanup_session;
            }
            ec_point_len = point_attr.ulValueLen;

            /*
             * ec_point_buf holds a DER-encoded ECPoint:
             *   04 || 04 || x (32 bytes) || y (32 bytes)
             * The outer DER wrapping is OCTET STRING.  We need to import the
             * raw EC_POINT bytes into wolfCrypt.
             *
             * CKA_EC_POINT is an OCTET STRING wrapping an uncompressed point:
             *   tag(0x04) len raw_point
             * where raw_point = 0x04 || x || y for uncompressed P-256.
             *
             * wc_ecc_import_point_der decodes the DER-wrapped point.
             */
            wc_ret = wc_ecc_init(&wc_key);
            if (wc_ret != 0) {
                WH_ERROR_PRINT("[PKCS11] wc_ecc_init: %d\n", wc_ret);
                ret = WH_ERROR_ABORTED;
                goto cleanup_session;
            }

            /*
             * CKA_EC_POINT returns a DER OCTET STRING wrapping the
             * uncompressed point: 04 41 04 <x_32> <y_32> (67 bytes for
             * P-256). Skip the 2-byte OCTET STRING header to get the raw
             * x9.63 uncompressed point (65 bytes) for wc_ecc_import_x963_ex.
             */
            if (ec_point_len < 3 || ec_point_buf[0] != 0x04) {
                WH_ERROR_PRINT("[PKCS11] unexpected EC_POINT format "
                               "(len=%lu)\n",
                               (unsigned long)ec_point_len);
                wc_ecc_free(&wc_key);
                ret = WH_ERROR_ABORTED;
                goto cleanup_session;
            }
            wc_ret = wc_ecc_import_x963_ex(ec_point_buf + 2,
                                            (word32)(ec_point_len - 2),
                                            &wc_key, ECC_SECP256R1);
            if (wc_ret != 0) {
                WH_ERROR_PRINT("[PKCS11] wc_ecc_import_x963_ex: %d "
                               "(point_len=%lu)\n",
                               wc_ret, (unsigned long)ec_point_len);
                wc_ecc_free(&wc_key);
                ret = WH_ERROR_ABORTED;
                goto cleanup_session;
            }

            /*
             * CKM_ECDSA signature format is raw (r || s), 32+32 = 64 bytes.
             * wolfCrypt wc_ecc_verify_hash expects DER-encoded signature.
             * Convert r||s → DER using wc_ecc_rs_raw_to_sig.
             */
            {
                byte der_sig[128];
                word32 der_sig_len = sizeof(der_sig);

                if (sig_len != 64) {
                    WH_ERROR_PRINT("[PKCS11] unexpected CKM_ECDSA sig_len=%lu "
                                   "(expected 64)\n",
                                   (unsigned long)sig_len);
                    wc_ecc_free(&wc_key);
                    ret = WH_ERROR_ABORTED;
                    goto cleanup_session;
                }

                wc_ret = wc_ecc_rs_raw_to_sig(sig,        32,
                                               sig + 32,   32,
                                               der_sig, &der_sig_len);
                if (wc_ret != 0) {
                    WH_ERROR_PRINT("[PKCS11] wc_ecc_rs_raw_to_sig: %d\n",
                                   wc_ret);
                    wc_ecc_free(&wc_key);
                    ret = WH_ERROR_ABORTED;
                    goto cleanup_session;
                }

                /* Independent oracle: verify with wolfCrypt */
                wc_ret = wc_ecc_verify_hash(der_sig, der_sig_len,
                                            digest, sizeof(digest),
                                            &verified, &wc_key);
                if (wc_ret != 0 || !verified) {
                    WH_ERROR_PRINT("[PKCS11] wc_ecc_verify_hash: ret=%d "
                                   "verified=%d\n", wc_ret, verified);
                    wc_ecc_free(&wc_key);
                    ret = WH_ERROR_ABORTED;
                    goto cleanup_session;
                }
            }

            wc_ecc_free(&wc_key);
            WH_TEST_PRINT("  whTest_Pkcs11: wolfCrypt verify OK\n");
        }
    }

    /* ── 13. C_GenerateRandom: two 32-byte outputs must differ ── */
    {
        CK_BYTE rand1[32];
        CK_BYTE rand2[32];
        CK_RV rv;

        memset(rand1, 0, sizeof(rand1));
        memset(rand2, 0, sizeof(rand2));

        rv = fns->C_GenerateRandom(session, rand1, sizeof(rand1));
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_GenerateRandom (1): 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }

        rv = fns->C_GenerateRandom(session, rand2, sizeof(rand2));
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_GenerateRandom (2): 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }

        /* The two outputs must differ (astronomically unlikely to collide) */
        if (memcmp(rand1, rand2, sizeof(rand1)) == 0) {
            WH_ERROR_PRINT("[PKCS11] C_GenerateRandom: both outputs identical\n");
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }

        /* Neither output should be all-zeros */
        {
            static const CK_BYTE zeros[32] = {0};
            if (memcmp(rand1, zeros, sizeof(zeros)) == 0 ||
                    memcmp(rand2, zeros, sizeof(zeros)) == 0) {
                WH_ERROR_PRINT("[PKCS11] C_GenerateRandom: all-zero output\n");
                ret = WH_ERROR_ABORTED;
                goto cleanup_session;
            }
        }
    }
    WH_TEST_PRINT("  whTest_Pkcs11: C_GenerateRandom OK\n");

    /* ── 14. Destroy the generated keys ── */
    {
        CK_RV rv;
        rv = fns->C_DestroyObject(session, priv_handle);
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_DestroyObject (priv): 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }
        rv = fns->C_DestroyObject(session, pub_handle);
        if (rv != CKR_OK) {
            WH_ERROR_PRINT("[PKCS11] C_DestroyObject (pub): 0x%08lX\n",
                           (unsigned long)rv);
            ret = WH_ERROR_ABORTED;
            goto cleanup_session;
        }
        priv_handle = CK_INVALID_HANDLE;
        pub_handle  = CK_INVALID_HANDLE;
    }
    WH_TEST_PRINT("  whTest_Pkcs11: C_DestroyObject OK\n");

    /* ── Cleanup ── */
cleanup_session:
    if (session != CK_INVALID_HANDLE) {
        (void)fns->C_Logout(session);
        (void)fns->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
    }

cleanup_pkcs11:
    if (fns != NULL) {
        (void)fns->C_Finalize(NULL);
        fns = NULL;
    }

cleanup_dl:
    if (dl_handle != NULL) {
        dlclose(dl_handle);
        dl_handle = NULL;
    }

cleanup_daemon:
    if (daemon_pid > 0) {
        kill(daemon_pid, SIGTERM);
        waitpid(daemon_pid, NULL, 0);
        daemon_pid = -1;
    }
    unlink(sock_path);
    unsetenv("P11_KIT_SERVER_ADDRESS");

    if (ret == WH_ERROR_OK) {
        WH_TEST_PRINT("  whTest_Pkcs11: all tests PASSED\n");
    }
    else {
        WH_ERROR_PRINT("[PKCS11] test FAILED (ret=%d)\n", ret);
    }
    return ret;
}

#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_TEST_PKCS11 */
