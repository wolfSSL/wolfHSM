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

- `<clientId>`: Unsigned 8-bit integer (0-255) representing the client ID the key belongs to.
- `<keyId>`: Unsigned 16-bit integer (1-65535) representing the key ID. Note that 0 is an invalid key ID.
- `<access>`: Unsigned 16-bit integer (0-65535) representing access permissions.
- `<flags>`: Unsigned 16-bit integer (0-65535) representing key flags.
- `<label>`: Label string enclosed in double quotes, maximum 24 characters.
- `<file>`: Valid file path to a file containing the key's data. Data will be read from this file and stored in the NVM key.


### General Schema Rules and Restrictions

1. Each entry must be on a separate line.
2. Fields must be separated by single spaces.
3. The `<label>` field must be enclosed in double quotes and cannot contain newlines.
4. Comments can be added using the `#` character. Anything after `#` on a line is ignored.
5. Empty lines and lines containing only whitespace or comments are ignored.
6. `<id>`, `<client_id>`, `<key_id>`, `<access>`, and `<flags>` can be specified in decimal or hexadecimal (with '0x' prefix).
7. File paths must be valid and accessible.


### Example Configuration File

```
# This is a comment
obj 1 0xFFFF 0x0000 "My Object" "path/to/object.bin" # This is a trailing comment
key 1 1 0x0001 0x0000 "My Key" "path/to/key.bin"
```

## Generated NVM Image

The generated NVM image is a binary file that can be used to initialize an instance of `whNvmFlash` or loaded directly into device memory at a device-specific address. In order for a generated NVM image to be compatible with a wolfHSM server implemenation, the following must be true:

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
2. Build and run a test program `test/test_whnvmtool.c`, which loads the generated NVM image and verifies the contents of the objects and keys using the exported ID/data file pairs. The compatibility of the generated image is verified by loading the image into two `whNvmFlash` providers: the POSIX port file-based NVM flash file simulator (`port/posix/posix_flash_file.c`) and the RAM-based NVM flash simulator (`src/wh_flash_ramsim.c`).
