# POSIX Examples

There are a couple of different ways POSIX can be used for transport.

- tcp
- shm (Shared memory)
- dma (Shared memory pass by offset into DMA area making use of wolfSSL static memory feature)

Each of these methods has its setup function in wh_posix_[server|client]_cfg.c
that contains the unique example configuration for setting each up.

Sub directories contain the server and client logic. wh_posix_server and
wh_posix_client. Selecting which type of transport to use in the client/server
can be done by using the -t flag. i.e `./client -type shm`.
