# examples

This directory contains examples code demonstrating how to use various wolfHSM features. The examples provided are split between port-agnostic demo code, and port-specific server/client applications that use the aforementioned demo code.

- `demo/`: port-agnostic demonstration code (`demo/`). This code is intended to be used as a reference for how to use wolfHSM features, and are organized by high-level wolfHSM feature.
- `port/`: Example server and client applications for each port. These applications initialize the server and client context and then run the demo code.

## Current Examples
Currently, the only public example for wolfHSM uses the POSIX simulator. If you are interested in examples for NDA-restricted hardware platforms, please contact us at support@wolfssl.com.

### Posix TCP server and client
This example spawns a wolfHSM client and server, both in their own thread, and runs the client-side unit tests against the server.

### Posix SHM server and client
This example spawns a wolfHSM client and server, both in their own thread, and runs the client-side unit tests against the server.

### Building
To build the client and the server examples, wolfHSM must be configured and built along side wolfSSL.

In the Makefile for both the server and client in `examples/posix/tcp/wh_<client or server>_tcp/` under important directories is as follows :
```
# Important directories
BUILD_DIR = ./Build
WOLFHSM_DIR = $(CURDIR)/../../../../wolfHSM

WOLFSSL_DIR ?= $(CURDIR)/../../../../wolfssl
```

Set the `WOLFHSM_DIR` and `WOLFSSL_DIR` variables to point to your local installation of wolfHSM and wolfSSL. Now the client and server demo application can be built.

### Building wh_server_tcp
`cd` into `examples/posix/tcp/wh_server_tcp` and run `make`. Once completed, the output server executable `wh_server_tcp.elf` will be located in the `Build` directory.

### Building wh_client_tcp
`cd` into `examples/posix/tcp/wh_client_tcp` and run `make`. Once completed, the output server executable `wh_client_tcp.elf` will be located in the `Build` directory.

### Executables
Run `examples/posix/tcp/wh_server_tcp/Build/wh_server_tcp.elf` to launch the server. In a separate shell, run `examples/posix/tcp/wh_client_tcp/Build/wh_client_tcp.elf` to launch the client.

### Initializing server NVM
The server example supports two methods for initializing its Non-Volatile Memory (NVM) with cryptographic keys and objects.

#### Choosing a specific transport to use
With POSIX builds there is multiple transport types available. They can be used with the --type flag.
The types of transports are:

- shm : Using shared memory
- tcp : Using TCP connections
- dma : Builds off of shm and adds in a common buffer that is accessed by offsets passed between the client and server

```
./wh_server_posix.elf --type shm
```

#### Loading a single key
To load a single key with a specific keyId, use the `--key` and `--id` arguments:

```
./wh_server_tcp.elf --key /path/to/key.der --id <keyId>
```

You can also specify a client ID with the `--client` argument (default is 12):

```
./wh_server_tcp.elf --key /path/to/key.der --id <keyId> --client <clientId>
```

#### Using an NVM initialization file
For more complex scenarios requiring multiple keys or objects, use the `--nvminit` argument to specify a configuration file:

```
./wh_server_tcp.elf --nvminit /path/to/nvminit.conf
```

The NVM initialization file allows you to define multiple keys and objects to be loaded into the server's NVM. The file format is as follows:

```
# Keys are defined as: key <clientId> <keyId> <access> <flags> <label> <filePath>
key 1 0x01 0x0000 0x0000 "Example Key 1" /path/to/key1.der
key 2 0x02 0x0000 0x0000 "Example Key 2" /path/to/key2.der

# Objects are defined as: obj <id> <access> <flags> <label> <filePath>
obj 0x1000 0x0000 0x0000 "Example Object" /path/to/object.bin
```

Each entry defines:
- For keys: clientId, keyId, access permissions, flags, label, and file path
- For objects: object ID, access permissions, flags, label, and file path

Numbers can be specified in decimal or hexadecimal (prefixed with 0x) format. For more information on nvminit files see the [whnvmtool documentation](https://github.com/wolfSSL/wolfHSM/blob/main/tools/whnvmtool/README.md)

### Results
After all steps are you complete you should see the following outputs.

Server output :

```
Waiting for connection...
Successful connection!
Server disconnected
```

Client output :

```
Client connecting to server...
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client disconnected
```
