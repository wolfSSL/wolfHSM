# Generic Examples

Generic client and server entry points that use the `wh_Port_*` abstraction API
defined in `wolfhsm/wh_port.h`. These examples are platform-independent and
rely on a port implementation (e.g. `port/posix/`) to provide the concrete
transport, NVM, and crypto configuration.

## Files

- `wh_generic_client.c` - Client entry point. Optionally runs wolfHSM tests and
  benchmarks, then connects to the server and executes echo requests.
- `wh_generic_server.c` - Server entry point. Listens for client connections and
  handles request messages in a polling loop.

## Building

These files are not built directly. Each port provides its own Makefile that
compiles the generic examples together with the port-specific `wh_Port_*`
implementation. For example:

```
cd port/posix
make
```
