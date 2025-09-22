# POSIX Examples

There are a couple of different ways POSIX can be used for transport.

- tcp
- shm (Shared memory)
- dma (Shared memory pass by offset into DMA area making use of wolfSSL static memory feature)

Each of these methods has its own source file wh_posix_transport_<type>.c that contains
the unique example configuration for setting each up. This is a function for
configuration of server and a function for configuration for use with a client.

Sub directories contain the server and client logic. wh_server_posix and
wh_client_posix. Selecting which type of transport to use in the client/server
can be done by using the -t flag. i.e `./client -type shm`.
