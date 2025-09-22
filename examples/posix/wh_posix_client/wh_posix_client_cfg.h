#ifndef WH_POSIX_CLIENT_CFG_H
#define WH_POSIX_CLIENT_CFG_H

int wh_PosixClient_ExampleDMAConfig(void* c_conf);
int wh_PosixClient_ExampleSHMConfig(void* c_conf);
int wh_PosixClient_ExampleTCPConfig(void* c_conf);
int wh_PosixClient_ExampleSetupDmaMemory(void* ctx, void* c_conf);
#endif /* WH_POSIX_CLIENT_CFG_H */