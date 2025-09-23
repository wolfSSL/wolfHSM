#ifndef WH_POSIX_CLIENT_CFG_H
#define WH_POSIX_CLIENT_CFG_H

int wh_PosixClient_ExampleShmDmaConfig(void* c_conf);
int wh_PosixClient_ExampleShmConfig(void* c_conf);
int wh_PosixClient_ExampleTcpConfig(void* c_conf);
int wh_PosixClient_ExampleSetupDmaMemory(void* ctx, void* c_conf);
#endif /* WH_POSIX_CLIENT_CFG_H */