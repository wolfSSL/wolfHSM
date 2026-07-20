# whnvmtool

## Overview

`whnvmtool` is a utility for creating Non-Volatile Memory (NVM) images for wolfHSM. It allows users to create NVM images with predefined objects and keys, which can be used for provisioning a wolfHSM device. The tool creates an NVM image and loads it with objects and keys specified by the user in a configuration file. The generated image can then be loaded into device memory, or used for to initialize an instance of a `whNvmFlash` provider.

## Supported NVM Providers

Currently, `whnvmtool` only supports the `whNvmFlash` provider.

## Usage

```
./whnvmtool [--test] [--image[=<file>]] [--size <size>] [--invert-erased-byte] <config-file>
```

where:

- `--image[=<file>]`: Specifies the output NVM image file. If not provided, defaults to `whNvmImage.bin`.
- `--size <size>`: Sets the partition size for the NVM image. Can be specified in decimal or hexadecimal (with '0x' prefix).
- `--invert-erased-byte`: Inverts the erased byte value (default is 0xFF, this option changes it to 0x00).
- `--test`: Enables test mode. In this mode, the tool generates an intermediate file (`nvm_metadata.txt`) containing comma separated metadata ID/file path pairs, associating each object ID with the file path containing the object's original data. This option is used by the `whnvmtool` tests to verify the contents of the generated NVM image, and is not required for normal operation.

## Configuration File Schema

The configuration file follows a specific schema for defining objects and keys to be stored in the NVM image. Each line in the file represents either an object or a key entry. The schema also supports comments and empty lines for readability. Comments use the `#` character, and all text after the `#` on a line is ignored. There are no multi-line comments.

### Object Entry Format

Lines beginning with `obj` define objects to be stored in the NVM image. The format of an object entry is as follows:

```
obj <metaDataId> <access> <flags> <label> <file>
```

where:

- `<metaDataId>`: Unsigned 16-bit integer (1-65535) representing the object metadata ID. Note that 0 is an invalid metadata ID.
- `<access>`: Unsigned 16-bit integer (0-65535) representing the access permissions.
- `<flags>`: Unsigned 16-bit integer (0-65535) representing object flags.
- `<label>`: Label string enclosed in double quotes, maximum 24 characters.
- `<file>`: Valid file path to a file containing the object's data. Data will be read from this file and stored in the NVM object.

### Key Entry Format

Lines beginning with `key` define keys (a special case of NVM objects)to be stored in the NVM image. The format of a key entry is as follows:

```
key <clientId> <keyId> <access> <flags> <label> <file>
```

where:

- `<clientId>`: Unsigned integer (0-15) representing the client ID the key belongs to (the keyId USER field is 4 bits). Use 0 to place the key in the global namespace shared by all clients, referenced by clients with `WH_CLIENT_KEYID_MAKE_GLOBAL()` (requires the server to be built with `WOLFHSM_CFG_GLOBAL_KEYS`, otherwise the key is unreachable).
- `<keyId>`: Unsigned integer (1-255) representing the key ID (the keyId ID field is 8 bits). Note that 0 is an invalid key ID.
- `<access>`: Unsigned 16-bit integer (0-65535) representing access permissions.
- `<flags>`: Unsigned 16-bit integer (0-65535) representing key flags.
- `<label>`: Label string enclosed in double quotes, maximum 24 characters.
- `<file>`: Valid file path to a file containing the key's data. Data will be read from this file and stored in the NVM key.

### SHE Key Entry Format

Lines beginning with `she` define AUTOSAR SHE key slots. SHE keys are stored like other keys, but their NVM id carries the SHE key type and their label holds the slot's SHE metadata rather than a string. The format of a SHE entry is as follows:

```
she <clientId> <sheSlot> <counter> <flags> <file>
```

where:

- `<clientId>`: Unsigned integer (0-15) selecting the SHE key namespace. Use the ID the client connects with for per-client SHE slots, or 0 for the global namespace (required when the server is built with `WOLFHSM_CFG_SHE_GLOBAL_KEYS`).
- `<sheSlot>`: SHE slot number (0-15): 0 = `SECRET_KEY`, 1 = `MASTER_ECU_KEY`, 2 = `BOOT_MAC_KEY`, 3 = `BOOT_MAC`, 4-13 = user keys, 14 = `RAM_KEY`, 15 = `PRNG_SEED`. Slot 14 is rejected: the spec defines `RAM_KEY` as volatile, so it is never stored in NVM.
- `<counter>`: Initial value of the slot's 28-bit update counter (0-0x0FFFFFFF). Use 0 for fresh provisioning; subsequent `CMD_LOAD_KEY` updates must present a strictly larger counter.
- `<flags>`: SHE protection flags (0-0x1F): 0x01 = write-protect, 0x02 = boot-protect, 0x04 = debugger-protection, 0x08 = key-usage (CMAC key instead of encryption key), 0x10 = wildcard. See the `WH_SHE_FLAG_*` definitions in `wolfhsm/wh_she_common.h`.
- `<file>`: Valid file path to a file containing exactly 16 bytes of key material.

SHE entries take no `<label>` field: the counter and protection flags are packed into the first eight bytes of the object label (the `wh_She_Meta2Label()` encoding), which is where the server's SHE command handlers read them. The NVM access and flags metadata fields are set to 0, matching runtime SHE provisioning via `wh_Client_ShePreProgramKey()`.


### Provisioning a Trusted Key-Encryption Key (KEK)

The keystore `wrap-export` and `unwrap-and-cache` operations require a **trusted KEK** — one the client can neither read nor set. On a system without a hardware keystore, this is a software key carrying the server-only `WH_NVM_FLAGS_TRUSTED` flag (bit 12). The server strips that flag from every client request, so the only way to set it is to write it directly into an NVM image with this tool (or via trusted server-internal boot code).

To provision such a KEK, give a `key` entry the flag value `0x1205`, which is `WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_USAGE_WRAP` (`0x1000 | 0x0004 | 0x0001 | 0x0200`). The `WH_NVM_FLAGS_TRUSTED` bit alone already makes the key unreadable, immutable, and KEK-only through the client API; the remaining bits make that intent explicit. Use `clientId` 0 to place the KEK in the global namespace if clients reference it with the global flag (requires `WOLFHSM_CFG_GLOBAL_KEYS`), or a specific `clientId` to scope it to one client.

```
# A trusted software KEK for wrap-export / unwrap-and-cache (global namespace)
key 0 0x20 0xFFFF 0x1205 "Export KEK" path/to/kek.bin
```

The KEK material file must be exactly the key size used to wrap (e.g. 32 bytes for AES-256) and must be kept secret from clients.

### Provisioning SHE Keys

Use `she` entries to provision AUTOSAR SHE key slots. By default SHE slots are per-client, so provision them with the `clientId` each client connects with:

```
# Client 1's MASTER_ECU_KEY: counter 0, write-protected
she 1 1 0 0x01 path/to/master_ecu_key.bin
```

When the server is built with `WOLFHSM_CFG_SHE_GLOBAL_KEYS`, all SHE slots live in the global namespace instead, so their `she` entries must use `clientId` 0:

```
# Shared SECRET_KEY and MASTER_ECU_KEY for a global-SHE server
she 0 0 0 0x00 path/to/secret_key.bin
she 0 1 0 0x00 path/to/master_ecu_key.bin
```

A per-client SHE image built for a default server will not be found by a global-SHE server (the USER fields differ) and vice-versa; migrate existing per-client SHE keys by re-provisioning at `clientId` 0, or move them at runtime with `wrap-export`/`unwrap-and-cache`, which normalizes a SHE blob into the global namespace.

### General Schema Rules and Restrictions

1. Each entry must be on a separate line.
2. Fields must be separated by single spaces.
3. The `<label>` field must be enclosed in double quotes and cannot contain newlines.
4. Comments can be added using the `#` character. Anything after `#` on a line is ignored.
5. Empty lines and lines containing only whitespace or comments are ignored.
6. `<id>`, `<client_id>`, `<key_id>`, `<sheSlot>`, `<counter>`, `<access>`, and `<flags>` can be specified in decimal or hexadecimal (with '0x' prefix).
7. File paths must be valid and accessible, and are not quoted.


### Example Configuration File

```
# This is a comment
obj 1 0xFFFF 0x0000 "My Object" path/to/object.bin # This is a trailing comment
key 1 1 0x0001 0x0000 "My Key" path/to/key.bin
she 1 4 0 0x00 path/to/she_key.bin
```

## Generated NVM Image

The generated NVM image is a binary file that can be used to initialize an instance of `whNvmFlash` or loaded directly into device memory at a device-specific address. In order for a generated NVM image to be compatible with a wolfHSM server implementation, the following must be true:

1. `whnvmtool` must be compiled against the same version of wolfHSM as the server, and be compiled to use the same value of `WOLFHSM_CFG_NVM_OBJECT_COUNT`
2. The partition size specified for the NVM image must match that of the server's `whNvmFlash` provider
3. If using a real flash implementation, the binary NVM image must be programmed to the correct address

### Generating a Hex File

Users may find it useful to generate a hex file to program the NVM image into device memory. This can be accomplished by using the `objcopy` utility to convert the generated NVM image to a hex file, making sure to specify the correct offset into the image for the start of the NVM partition. For example:

```
objcopy -I binary -O ihex --change-address <offset> <input-file> <output-file>
```

where:

- `<offset>` is the offset to the base address that will be applied to the generated hex file. Without this option, the offset is 0x0, so automated programming tools will attempt to load the hex file starting at address 0x0, which is likely not the desired behavior. The `<offset>` parameter should correspond to the base address of the NVM partition used by wolfHSM in the device's address space.
- `<input-file>` is the NVM image file generated by `whnvmtool`
- `<output-file>` is the name of the output hex file

## Testing

Tests for `whnvmtool` can be run by invoking `make check` or `make test`. This will perform the following steps:

1. Invoke `whnvmtool` to generate an NVM image using an example configuration file, using the `--test` option to export the ID/data file pairs to a file
2. Run the negative test script `test/test_invalid_input.sh`, which verifies that invalid configuration files (out-of-range clientId, keyId, SHE slot, counter, or flags, or the volatile `RAM_KEY` slot) and bad key files (wrong size or missing) cause the tool to exit with an error instead of producing an incomplete image
3. Build and run a test program `test/test_whnvmtool.c`, which loads the generated NVM image and verifies the contents of the objects and keys using the exported ID/data file pairs. The compatibility of the generated image is verified by loading the image into two `whNvmFlash` providers: the POSIX port file-based NVM flash file simulator (`port/posix/posix_flash_file.c`) and the RAM-based NVM flash simulator (`src/wh_flash_ramsim.c`).
