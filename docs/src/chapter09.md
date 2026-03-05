# Authentication Manager

The wolfHSM Authentication Manager is a transport-agnostic component that provides authentication (PIN and certificate verification), session management, and authorization for wolfHSM operations. It is configured via a callback structure (`whAuthCb`) and can use the default in-memory implementation in `wh_auth_base.c`, or a custom backend that implements the same interface.

## Table of Contents

- [Enabling and Configuring the Authentication Manager](#enabling-and-configuring-the-authentication-manager)
- [WH_AUTH_* Macro Helpers](#wh_auth_-macro-helpers)
- [Default User Database (wh_auth_base.c)](#default-user-database-wh_auth_basec)
- [Admin vs Non-Admin Users and Restrictions](#admin-vs-non-admin-users-and-restrictions)
- [Auth Message Group and Actions](#auth-message-group-and-actions)
- [Authorization Callbacks (Override)](#authorization-callbacks-override)
- [Error Codes](#error-codes)
- [Thread Safety and Locking](#thread-safety-and-locking)

## Enabling and Configuring the Authentication Manager

### Build-time

The Authentication Manager feature is off by default. To enable it, define `WOLFHSM_CFG_ENABLE_AUTHENTICATION` when building wolfHSM (e.g., in `wh_config.h` or via compiler flags). Without this macro, auth-related code is excluded from the build and auth requests return `WH_AUTH_NOT_ENABLED`.

### Building examples with auth

The POSIX server, POSIX client, and test Makefiles support an authentication-capable build via `AUTH=1`. Pass `AUTH=1` to `make` when building these targets:

```bash
# From the examples/posix/wh_posix_server or wh_posix_client directory
make AUTH=1

# From the test directory
make AUTH=1

# From the top-level directory (exports AUTH to subdirectories)
make AUTH=1 examples
```

The auth demo client (`wh_demo_client_auth.c`) and related examples require this build to function.

### Runtime configuration

Even when auth is compiled in, the server must have an auth context configured. The auth context is set via `whServerConfig.auth` and stored in `server->auth`. If `server->auth == NULL`, no authentication is attempted:

- Auth group requests (LOGIN, USER_ADD, USER_DELETE, etc.) return `WH_AUTH_NOT_ENABLED`
- Authorization checks for other message groups (NVM, key, crypto, etc.) are skipped entirely

The server will process requests without requiring login. To enable authentication, the application must initialize an auth context and pass it in the server configuration.

## WH_AUTH_* Macro Helpers

The following macros in `wolfhsm/wh_auth.h` simplify setting and checking permissions in a `whAuthPermissions` structure:

| Macro | Purpose |
|-------|---------|
| `WH_AUTH_IS_ADMIN(permissions)` | Returns non-zero if admin flag is set |
| `WH_AUTH_SET_IS_ADMIN(permissions, value)` | Sets admin flag (0 = non-admin, non-zero = admin) |
| `WH_AUTH_ACTION_TO_WORD_AND_BITMASK(action, wordIdx, bitMask)` | Internal: maps action (0-255) to word index and bitmask |
| `WH_AUTH_SET_ALLOWED_GROUP(permissions, group)` | Enables a message group and allows all actions in that group |
| `WH_AUTH_SET_ALLOWED_ACTION(permissions, group, action)` | Enables group and only the specified action bit |
| `WH_AUTH_CLEAR_ALLOWED_GROUP(permissions, group)` | Disables group and clears all action bits |
| `WH_AUTH_CLEAR_ALLOWED_ACTION(permissions, group, action)` | Clears permission for a specific action |

Related constants:

- `WH_AUTH_MAX_KEY_IDS` (2): Maximum number of key IDs a user can have access to
- `WH_AUTH_ACTIONS_PER_GROUP` (256): Support for up to 256 actions per group
- `WH_AUTH_ACTION_WORDS`: Number of `uint32_t` words used for the action bit array per group

Example: creating a non-admin user with permission to add users but not perform other auth operations:

```c
#include "wolfhsm/wh_auth.h"
#include "wolfhsm/wh_message.h"

whAuthPermissions perms;

memset(&perms, 0, sizeof(perms));
WH_AUTH_SET_ALLOWED_ACTION(perms, WH_MESSAGE_GROUP_AUTH,
                           WH_MESSAGE_AUTH_ACTION_USER_ADD);
WH_AUTH_SET_IS_ADMIN(perms, 0);
perms.keyIdCount = 0;

/* Use perms when adding the user via wh_Auth_UserAdd or in UserAdd request */
```

## Default User Database (wh_auth_base.c)

The in-memory implementation in `src/wh_auth_base.c` provides a simple user database suitable for development and testing. It can be used as the auth backend by registering the `wh_Auth_Base*` callbacks in `whAuthCb`.

### Storage

- Static array of `whAuthBase_User` structures (max 5 users by default via `WH_AUTH_BASE_MAX_USERS`)
- Each entry holds `whAuthUser`, authentication method, and credentials (max 2048 bytes via `WH_AUTH_BASE_MAX_CREDENTIALS_LEN`)

### Init and Cleanup

- `wh_Auth_BaseInit` zeros the user array
- `wh_Auth_BaseCleanup` force-zeros sensitive data in memory

### Login

- `wh_Auth_BaseLogin` supports:
  - `WH_AUTH_METHOD_PIN`: Credentials are SHA256-hashed when crypto is enabled; stored as plain copy when `WOLFHSM_CFG_NO_CRYPTO` is defined
  - `WH_AUTH_METHOD_CERTIFICATE`: When `WOLFHSM_CFG_CERTIFICATE_MANAGER` is defined

### Operations

- `wh_Auth_BaseUserAdd`, `wh_Auth_BaseUserDelete`, `wh_Auth_BaseUserSetPermissions`, `wh_Auth_BaseUserGet`, `wh_Auth_BaseUserSetCredentials`

### Lookup

- `wh_Auth_BaseFindUser` looks up users by username
- User IDs are 1-based (0 reserved for `WH_USER_ID_INVALID`)

### Usernames

The default user database does not support multiple users with the same username. Duplicate usernames are rejected in `wh_Auth_BaseUserAdd` with `WH_ERROR_BADARGS`.

### Example: seeding a default admin user

The POSIX server example in `examples/posix/wh_posix_server/wh_posix_server_cfg.c` seeds a default admin user at configuration time:

```c
/* Add an admin user with permissions for everything */
memset(&permissions, 0xFF, sizeof(whAuthPermissions));
permissions.keyIdCount = 0;
for (i = 0; i < WH_AUTH_MAX_KEY_IDS; i++) {
    permissions.keyIds[i] = 0;
}
rc = wh_Auth_BaseUserAdd(&auth_ctx, "admin", &out_user_id, permissions,
                         WH_AUTH_METHOD_PIN, "1234", 4);
```

## Admin vs Non-Admin Users and Restrictions

### Admin users

- Identified by `WH_AUTH_IS_ADMIN(permissions)` returning non-zero (stored in `groupPermissions[WH_NUMBER_OF_GROUPS]`)
- Can add users (including other admins), delete users, set permissions, and set credentials for any user
- Can log out other users (in addition to themselves)

### Non-admin users

- Identified by `WH_AUTH_SET_IS_ADMIN(permissions, 0)` or admin flag cleared
- **Key restriction**: Cannot add a user with admin permissions. If a non-admin attempts to add a user whose permissions include the admin flag, the operation fails with `WH_AUTH_PERMISSION_ERROR` (-2301). This is enforced in `wh_Auth_UserAdd` in `src/wh_auth.c` before the backend callback is invoked.
- Cannot delete users (enforced in `wh_Auth_BaseUserDelete`: only admin may delete)
- Cannot set permissions for other users (enforced in `wh_Auth_BaseUserSetPermissions`: only admin may change permissions)
- Can log out only themselves (enforced in `wh_Auth_BaseLogout`: non-admin cannot log out another user)
- Can add non-admin users if they have `WH_MESSAGE_AUTH_ACTION_USER_ADD` in the auth group

Example: a non-admin user with user-add permission can add other non-admin users but will fail when attempting to add an admin:

```c
/* Create non-admin with only USER_ADD permission */
whAuthPermissions nonadmin_perms;
memset(&nonadmin_perms, 0, sizeof(nonadmin_perms));
WH_AUTH_SET_ALLOWED_ACTION(nonadmin_perms, WH_MESSAGE_GROUP_AUTH,
                           WH_MESSAGE_AUTH_ACTION_USER_ADD);
WH_AUTH_SET_IS_ADMIN(nonadmin_perms, 0);

/* After logging in as this user: adding a non-admin succeeds,
 * but adding a user with admin permissions (e.g. memset(&perms, 0xFF, ...))
 * returns WH_AUTH_PERMISSION_ERROR. */
```

## Auth Message Group and Actions

The auth message group is `WH_MESSAGE_GROUP_AUTH` (0x0D00). Available actions in `wolfhsm/wh_message.h`:

- `WH_MESSAGE_AUTH_ACTION_LOGIN`
- `WH_MESSAGE_AUTH_ACTION_LOGOUT`
- `WH_MESSAGE_AUTH_ACTION_USER_ADD`
- `WH_MESSAGE_AUTH_ACTION_USER_DELETE`
- `WH_MESSAGE_AUTH_ACTION_USER_GET`
- `WH_MESSAGE_AUTH_ACTION_USER_SET_PERMISSIONS`
- `WH_MESSAGE_AUTH_ACTION_USER_SET_CREDENTIALS`

Unauthenticated users can only perform LOGIN and communications (comm) operations. Logout is always allowed for logged-in users. All other auth actions require the corresponding permission bits to be set in the user's permissions for the auth group.

## Authorization Callbacks (Override)

The `whAuthCb` structure defines optional callbacks that allow the auth backend to override default authorization results:

### CheckRequestAuthorization

Allows the auth backend to override the default authorization result for a given group and action. After the Auth Manager computes the default result (allowed or denied based on the user's permissions), if this callback is set, it is invoked with the preliminary result. The callback may change the result (e.g., grant access that would otherwise be denied, or deny access that would otherwise be allowed).

The callback is invoked from `wh_Auth_CheckRequestAuthorization` in `src/wh_auth.c`. Parameters: context, preliminary err, user_id, group, action. Returns the final authorization result.

### CheckKeyAuthorization

Placeholder for checking whether a user is authorized to use a specific key ID. This callback is defined in the interface but wolfHSM currently does not invoke it before key use; it is a TODO for future integration. When implemented, it would allow the backend to override key-access decisions (e.g., based on the user's `keyIds` array in permissions).

## Error Codes

Auth-related error codes in `wolfhsm/wh_error.h`:

| Code | Value | Description |
|------|-------|-------------|
| `WH_AUTH_LOGIN_FAILED` | -2300 | User login attempt failed |
| `WH_AUTH_PERMISSION_ERROR` | -2301 | User attempted an action not allowed |
| `WH_AUTH_NOT_ENABLED` | -2302 | Server does not have auth feature |

## Thread Safety and Locking

### Conditional compilation

When `WOLFHSM_CFG_THREADSAFE` is defined, the Auth Manager uses a lock (`whLock`) stored in `whAuthContext` to serialize auth operations. When undefined, locking is disabled and `WH_AUTH_LOCK`/`WH_AUTH_UNLOCK` expand to no-ops (return `WH_ERROR_OK`).

### Lock acquisition

All public Auth Manager API functions in `src/wh_auth.c` acquire the lock via `WH_AUTH_LOCK` at entry and release via `WH_AUTH_UNLOCK` before return. Callbacks (Login, Logout, UserAdd, etc.) are invoked while holding the lock.

### Base implementation

The default user database in `wh_auth_base.c` uses a static global users array. When `WOLFHSM_CFG_THREADSAFE` is defined, this array is protected by the auth context lock; locking is performed by the `wh_Auth_*` wrapper functions, not by the base implementation itself.

### Configuration

`whAuthConfig` includes an optional `lockConfig` (of type `whLockConfig`) when `WOLFHSM_CFG_THREADSAFE` is defined; this is passed to `wh_Lock_Init` during `wh_Auth_Init`. Custom backends that maintain shared state must either rely on this lock or implement their own synchronization.
