# wolfHSM API reference

## Key Revocation

### wh_Client_KeyRevokeRequest

Send a key revocation request to the server (non-blocking).

This function prepares and sends a revoke request for the specified key ID. It
returns after the request is sent; use `wh_Client_KeyRevokeResponse()` to
retrieve the result.

Parameters:

- `c`: Client context.
- `keyId`: Key ID to revoke.

Return values:

- `WH_ERROR_OK` on successful request send.
- A negative error code on failure.

Error codes:

- `WH_ERROR_BADARGS` if `c` is NULL or `keyId` is invalid.
- Propagates comm layer errors on send failure.

### wh_Client_KeyRevokeResponse

Receive a key revocation response.

This function polls for the revoke response and returns `WH_ERROR_NOTREADY`
until the server reply is available.

Parameters:

- `c`: Client context.

Return values:

- `WH_ERROR_OK` on success.
- `WH_ERROR_NOTREADY` if the response has not arrived.
- A negative error code on failure.

Error codes:

- `WH_ERROR_BADARGS` if `c` is NULL.
- Server error codes such as `WH_ERROR_NOTFOUND`.

### wh_Client_KeyRevoke

Revoke a key using a blocking request/response.

This helper sends a revoke request and waits for the response.

Parameters:

- `c`: Client context.
- `keyId`: Key ID to revoke.

Return values:

- `WH_ERROR_OK` on success.
- A negative error code on failure.

Error codes:

- Any error code returned by `wh_Client_KeyRevokeRequest()` or
  `wh_Client_KeyRevokeResponse()`.

### wh_Server_KeystoreRevokeKey

Revoke a key by updating its metadata.

This server-side function marks a key as non-modifiable and clears all usage
flags. If the key exists in NVM, the metadata update is committed so the revoke
state persists.

Parameters:

- `server`: Server context.
- `keyId`: Key ID to revoke.

Return values:

- `WH_ERROR_OK` on success.
- A negative error code on failure.

Error codes:

- `WH_ERROR_BADARGS` if parameters are invalid.
- `WH_ERROR_NOTFOUND` if the key is missing.
- Propagates NVM/storage errors (for example `WH_ERROR_NOSPACE`).

## NVM Access and Flag Controls

### whNvmFlags

Policy flags for NVM objects and keys.

Flags include `WH_NVM_FLAGS_NONMODIFIABLE`, `WH_NVM_FLAGS_NONDESTROYABLE`,
`WH_NVM_FLAGS_NONEXPORTABLE`, and the usage policy flags `WH_NVM_FLAGS_USAGE_*`.
If no usage flags are set, the key is not permitted for cryptographic use.

### wh_Nvm_AddObjectChecked

Add an NVM object with policy enforcement.

This function applies NVM policy checks (for example non-modifiable objects)
before writing the object.

Parameters:

- `context`: NVM context.
- `meta`: Metadata describing the object.
- `data_len`: Length of object data.
- `data`: Object data buffer.

Return values:

- `WH_ERROR_OK` on success.
- A negative error code on failure.

Error codes:

- `WH_ERROR_BADARGS` if parameters are invalid.
- `WH_ERROR_ACCESS` if the object is non-modifiable.
- Propagates backend errors (for example `WH_ERROR_NOSPACE`).

### wh_Nvm_ReadChecked

Read an NVM object with policy enforcement.

This function applies NVM policy checks (for example non-exportable objects)
before reading the object data.

Parameters:

- `context`: NVM context.
- `id`: Object ID to read.
- `offset`: Byte offset into the object.
- `data_len`: Length of data to read.
- `data`: Output buffer.

Return values:

- `WH_ERROR_OK` on success.
- A negative error code on failure.

Error codes:

- `WH_ERROR_BADARGS` if parameters are invalid.
- `WH_ERROR_ACCESS` if the object is non-exportable.
- `WH_ERROR_NOTFOUND` if the object does not exist.

### wh_Nvm_DestroyObjectsChecked

Destroy NVM objects with policy enforcement.

This function applies NVM policy checks (for example non-destroyable objects)
before erasing the objects.

Parameters:

- `context`: NVM context.
- `list_count`: Number of IDs in the list.
- `id_list`: Array of object IDs to destroy.

Return values:

- `WH_ERROR_OK` on success.
- A negative error code on failure.

Error codes:

- `WH_ERROR_BADARGS` if parameters are invalid.
- `WH_ERROR_ACCESS` if any object is non-destroyable or non-modifiable.
- `WH_ERROR_NOTFOUND` if a listed object is missing.
