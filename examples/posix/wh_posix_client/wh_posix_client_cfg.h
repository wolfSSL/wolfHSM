#ifndef WH_POSIX_CLIENT_CFG_H
#define WH_POSIX_CLIENT_CFG_H

int Client_ExampleDMAConfig(void* c_conf);
int Client_ExampleSHMConfig(void* c_conf);
int Client_ExampleTCPConfig(void* c_conf);
int Client_ExampleSetupDmaMemory(void* ctx, void* c_conf);
#endif /* WH_POSIX_CLIENT_CFG_H */