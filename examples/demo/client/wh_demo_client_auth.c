/*
 * Auth Manager demo client
 *
 * The session ID is associated with the client_id on the server side,
 * so subsequent operations from this client will be authorized based on
 * the authenticated session.
 */

#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_auth.h"

#include "wh_demo_client_auth.h"
#include "wh_demo_client_crypto.h"

static int wh_DemoClient_AuthPin(whClientContext* clientContext)
{
    int              rc        = 0;
    int32_t          serverRc  = 0;
    const uint8_t    pin[]     = "1234"; /* demo PIN */
    const uint8_t    badPin[]  = "4321"; 
    whUserId         userId    = WH_USER_ID_INVALID;
    whAuthPermissions out_permissions;
    int32_t out_rc;

    /* give permissions for everything */
    memset(&out_permissions, 0xFF, sizeof(whAuthPermissions));

    if (clientContext == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* ============================================================
     * Step 1: Attempt crypto operation without authentication
     * ============================================================ */
    whUserId adminUserId = WH_USER_ID_INVALID;
    /* login as the admin and add a new user  */
    rc = wh_Client_AuthLogin(clientContext,
            WH_AUTH_METHOD_PIN,
            "admin",
            "1234", 4,
            &serverRc,
            &adminUserId);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to login as admin: %d\n", rc);
        return rc;
    }
    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error logging in as admin: %d\n", (int)serverRc);
        return (int)serverRc;
    }

    memset(&out_permissions, 0, sizeof(whAuthPermissions));
    rc = wh_Client_AuthUserAdd(clientContext, "demo", out_permissions,
            WH_AUTH_METHOD_PIN, pin, (uint16_t)(sizeof(pin) - 1),
            &out_rc, &userId);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to add user: %d\n", rc);
        return rc;
    }

    rc = wh_Client_AuthLogout(clientContext, adminUserId, &serverRc);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to logout user: %d\n", rc);
        return rc;
    }

    /* ============================================================
     * Step 2: Authenticate user
     * ============================================================ */
    rc = wh_Client_AuthLogin(clientContext,
        WH_AUTH_METHOD_PIN,
        "demo",
        badPin,
        (uint16_t)(sizeof(badPin) - 1),
        &serverRc,
        &userId);

    if (rc == WH_ERROR_OK && serverRc != WH_AUTH_LOGIN_FAILED) {
        printf("[AUTH-DEMO] Failed to not login with bad pin: %d, serverRc=%d\n", rc, serverRc);
        return rc;
    }

    rc = wh_Client_AuthLogin(clientContext,
                                    WH_AUTH_METHOD_PIN,
                                    "demo",
                                    pin,
                                    (uint16_t)(sizeof(pin) - 1),
                                    &serverRc,
                                    &userId);

    if (rc == WH_ERROR_NOTIMPL) {
        printf("[AUTH-DEMO] wh_Client_AuthAuthenticate() not implemented yet.\n");
        printf("[AUTH-DEMO] This demo currently serves as a control-flow sketch.\n");
        return rc;
    }

    if (rc != 0) {
        printf("[AUTH-DEMO] Client-side error rc=%d while sending auth request.\n", rc);
        return rc;
    }

    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side auth failed, rc=%d.\n", (int)serverRc);
        return (int)serverRc;
    }

    /* ============================================================
     * Step 3: Update user credentials
     * ============================================================ */
    const uint8_t newPin[] = "5678"; /* new PIN */

    rc = wh_Client_AuthUserSetCredentials(clientContext, userId,
            WH_AUTH_METHOD_PIN,
            pin, (uint16_t)(sizeof(pin) - 1),  /* current credentials */
            newPin, (uint16_t)(sizeof(newPin) - 1),  /* new credentials */
            &out_rc);

    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to update credentials: %d\n", rc);
        return rc;
    }

    if (out_rc != 0) {
        printf("[AUTH-DEMO] Server-side error updating credentials: %d\n", (int)out_rc);
        return (int)out_rc;
    }

    /* logout the user */
    rc = wh_Client_AuthLogout(clientContext, userId, &serverRc);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to logout user: %d\n", rc);
        return rc;
    }

    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error logging out user: %d\n", (int)serverRc);
        return (int)serverRc;
    }

    /* Verify old PIN no longer works */
    rc = wh_Client_AuthLogin(clientContext,
            WH_AUTH_METHOD_PIN,
            "demo",
            pin,
            (uint16_t)(sizeof(pin) - 1),
            &serverRc,
            &userId);

    if (rc == 0 && serverRc == 0) {
        printf("[AUTH-DEMO] Old PIN still works (unexpected)\n");
    }

    /* Verify new PIN works */
    rc = wh_Client_AuthLogin(clientContext,
            WH_AUTH_METHOD_PIN,
            "demo",
            newPin,
            (uint16_t)(sizeof(newPin) - 1),
            &serverRc,
            &userId);

    if (rc != 0) {
        printf("[AUTH-DEMO] Client-side error with new PIN: %d\n", rc);
        return rc;
    }

    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error with new PIN: %d\n", (int)serverRc);
        return (int)serverRc;
    }

    rc = wh_Client_AuthLogout(clientContext, userId, &serverRc);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to logout user: %d\n", rc);
        return rc;
    }
    return rc;
}

#include "../../test/wh_test_cert_data.h"
static int wh_DemoClient_AuthCertificate(whClientContext* clientContext)
{
    int              rc        = 0;
    int32_t          serverRc  = 0;
    whUserId         userId    = WH_USER_ID_INVALID;
    whUserId         adminUserId = WH_USER_ID_INVALID;
    whAuthPermissions out_permissions;
    int32_t out_rc;

    /* Include test certificates - prefer wolfssl/certs_test.h if available,
     * otherwise use test certificates from wh_test_cert_data.h */
    const unsigned char* ca_cert;
    uint16_t ca_cert_len;
    const unsigned char* server_cert;
    uint16_t server_cert_len;

    /* Use INTERMEDIATE_A_CERT as the CA since it directly signs LEAF_A_CERT
     * The chain is: ROOT_A_CERT -> INTERMEDIATE_A_CERT -> LEAF_A_CERT */
    ca_cert = INTERMEDIATE_A_CERT;
    ca_cert_len = (uint16_t)INTERMEDIATE_A_CERT_len;
    server_cert = LEAF_A_CERT;
    server_cert_len = (uint16_t)LEAF_A_CERT_len;

    memset(&out_permissions, 0, sizeof(whAuthPermissions));

    if (clientContext == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* ============================================================
     * Step 1: Add user with CA certificate as credentials
     * ============================================================ */

    /* login as the admin and add a new user  */
    rc = wh_Client_AuthLogin(clientContext,
            WH_AUTH_METHOD_PIN,
            "admin",
            "1234", 4,
            &serverRc,
            &adminUserId);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to login as admin: %d\n", rc);
        return rc;
    }
    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error logging in as admin: %d\n", (int)serverRc);
        return (int)serverRc;
    }

    rc = wh_Client_AuthUserAdd(clientContext, "certuser", out_permissions,
            WH_AUTH_METHOD_CERTIFICATE, ca_cert, ca_cert_len,
            &out_rc, &userId);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to add user: %d\n", rc);
        return rc;
    }
    if (out_rc != 0) {
        printf("[AUTH-DEMO] Server-side error adding user: %d\n", (int)out_rc);
        return (int)out_rc;
    }

    rc = wh_Client_AuthLogout(clientContext, adminUserId, &serverRc);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to logout user: %d\n", rc);
        return rc;
    }

    /* ============================================================
     * Step 2: Authenticate user with server certificate
     * ============================================================ */
    rc = wh_Client_AuthLogin(clientContext,
            WH_AUTH_METHOD_CERTIFICATE,
            "certuser",
            server_cert,
            server_cert_len,
            &serverRc,
            &userId);

    if (rc == WH_ERROR_NOTIMPL) {
        printf("[AUTH-DEMO] wh_Client_AuthLogin() not implemented for certificates.\n");
        return rc;
    }

    if (rc != 0) {
        printf("[AUTH-DEMO] Client-side error rc=%d while sending auth request.\n", rc);
        return rc;
    }

    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side auth failed, rc=%d.\n", (int)serverRc);
        return (int)serverRc;
    }

    /* Try doing a crypto operation, with permissions all 0 this should fail */
    rc = wh_DemoClient_CryptoAesCbc(clientContext);
    if (rc == 0 || rc == WH_ERROR_OK) {
        /* found success when should have failed */
        printf("[AUTH-DEMO] Crypto operation should have failed\n");
        return -1;
    }

    rc = wh_Client_AuthLogout(clientContext, userId, &serverRc);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to logout user: %d\n", rc);
        return rc;
    }
    return rc;
}

static int wh_DemoClient_AuthUserDelete(whClientContext* clientContext)
{
    int              rc        = 0;
    int32_t          serverRc  = 0;
    whUserId         userId    = WH_USER_ID_INVALID;
    whUserId         adminUserId = WH_USER_ID_INVALID;
    whAuthPermissions permissions;

    rc = wh_Client_AuthLogin(clientContext,
            WH_AUTH_METHOD_PIN,
            "admin",
            "1234", 4,
            &serverRc,
            &adminUserId);
    if (rc != 0) {
        return rc;
    }
    if (serverRc != 0) {
        return (int)serverRc;
    }

    rc = wh_Client_AuthUserGet(clientContext, "certuser", &serverRc, &userId, &permissions);
    if (rc != 0) {
        return rc;
    }
    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error %d while getting user: %d\n", (int)serverRc, userId);
        return (int)serverRc;
    }

    rc = wh_Client_AuthUserDelete(clientContext, userId, &serverRc);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to delete user: %d\n", rc);
        return rc;
    }
    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error deleting user: %d\n", (int)serverRc);
        return (int)serverRc;
    }

    rc = wh_Client_AuthLogout(clientContext, adminUserId, &serverRc);
    if (rc != 0) {
        return rc;
    }
    if (serverRc != 0) {
        return (int)serverRc;
    }

    return rc;
}


static int wh_DemoClient_AuthUserSetPermissions(whClientContext* clientContext)
{
    int              rc        = 0;
    int32_t          serverRc  = 0;
    whUserId         userId    = WH_USER_ID_INVALID;
    whUserId         adminUserId = WH_USER_ID_INVALID;
    whAuthPermissions permissions;

    rc = wh_Client_AuthLogin(clientContext,
            WH_AUTH_METHOD_PIN,
            "admin",
            "1234", 4,
            &serverRc,
            &adminUserId);
    if (rc != 0) {
        return rc;
    }
    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error %d while logging in as admin: %d\n", (int)serverRc, adminUserId);
        return (int)serverRc;
    }

    rc = wh_Client_AuthUserGet(clientContext, "demo", &serverRc, &userId, &permissions);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to get user: %d\n", rc);
        return rc;
    }
    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error %d while getting user: %d\n", (int)serverRc, userId);
        return (int)serverRc;
    }

    /* Set up key IDs: allow access to key 1 for encrypt and key 2 for decrypt */
    permissions.keyIdCount = 2;
    permissions.keyIds[0] = 1; /* encrypt key */
    permissions.keyIds[1] = 2; /* decrypt key */

    rc = wh_Client_AuthUserSetPermissions(clientContext, userId, permissions, &serverRc);
    if (rc != 0) {
        printf("[AUTH-DEMO] Failed to set permissions: %d\n", rc);
        return rc;
    }
    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error %d while setting permissions for user: %d\n", (int)serverRc, userId);
        return (int)serverRc;
    }


    rc = wh_Client_AuthUserGet(clientContext, "demo", &serverRc, &userId, &permissions);
    if (rc != 0) {
        return rc;
    }
    if (serverRc != 0) {
        printf("[AUTH-DEMO] Server-side error %d while getting user: %d\n", (int)serverRc, userId);
        return (int)serverRc;
    }

    rc = wh_Client_AuthLogout(clientContext, adminUserId, &serverRc);
    if (rc != 0) {
        return rc;
    }
    if (serverRc != 0) {
        return (int)serverRc;
    }

    return rc;
}


int wh_DemoClient_Auth(whClientContext* clientContext)
{
    int              rc        = 0;

    printf("[AUTH-DEMO] Starting authentication demo...\n");
    rc = wh_DemoClient_AuthCertificate(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_AuthPin(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_AuthUserDelete(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_AuthUserSetPermissions(clientContext);
    if (rc != 0) {
        return rc;
    }
    printf("[AUTH-DEMO] Authentication demo completed.\n");
    return rc;
}
