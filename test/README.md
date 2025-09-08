# Testing

wolfHSM unit tests need to be portable and platform-agnostic (e.g. no system dependencies) such that they are able to run on a bare-metal system.
One notable exception is for tests that use the POSIX API (sockets, pthreads, etc.), which must be conditionally compiled in with the `WOLFHSM_CFG_TEST_POSIX` preprocessor macro.
wolfHSM unit tests are designed to provide test coverage of the wolfHSM library, rather than the underlying wolfCrypt library. You can run the wolfCrypt test suite as a wolfHSM client (where all relevant crypto is offloaded to the server) as an extra step in the wolfHSM test suite when building the tests with the `TESTWOLFCRYPT=1` makefile option, or by defining the `WOLFHSM_CFG_TEST_WOLFCRYPTTEST` configuration macro.

##  Running Tests
Tests for each module should be defined in their own source file and export their API in a corresponding header. Tests are run by the main test driver in `wh_test.c`.
Embedded systems that wish to only compile and run a subset of the tests should be able to pick and choose individual tests from their respective files and run them
without needing to run the entire test suite.

To build and run the tests in a default configuration on a POSIX host system, simply run:

```
make
make run
```

This will build and run all tests, including the POSIX tests with output similar to:
```
$ make run
./Build/wh_test.elf
Enter unit tests
Testing RAM-based flash simulator...
Testing NVM flash with RAM sim...
--Adding 3 new objects
--Overwrite an existing object
--Overwrite an existing object again 
--Overwrite an existing object with new data
--Reclaim space
--Read IDs after reclaim
--Destroy 1 object
--Destroy 3 objects
--Done
Testing NVM flash with POSIX file sim...
--Adding 3 new objects
--Overwrite an existing object
--Overwrite an existing object again 
--Overwrite an existing object with new data
--Reclaim space
--Read IDs after reclaim
--Destroy 1 object
--Destroy 3 objects
--Done
Testing Server Certificate with RAM sim...
Testing comms: mem...
Testing comms: (pthread) mem...
Testing comms: (pthread) tcp...
Testing comms: (pthread) posix mem...
Testing client/server sequential: mem...
Server Info: 
 - Version:01.01.01
 - Build:12345678
 - cfg_comm_data_len:5120
 - cfg_nvm_object_count:30
 - cfg_server_keycache_count:9
 - cfg_server_keycache_bufsize:300
 - cfg_server_keycache_bigcount:2
 - cfg_server_keycache_bigbufsize:5120
 - cfg_server_customcb_count:6
 - cfg_server_dmaaddr_count:8
 - debug_state:1
 - boot_state:2
 - lifecycle_state:3
 - nvm_state:4
Testing client/server: (pthread) mem...
Testing non-exportable NVM object access protection...
Non-exportable NVM object read correctly denied
Exportable NVM object read succeeded
NON-EXPORTABLE NVM ACCESS TEST SUCCESS
Testing client/server: (pthread) POSIX shared memory ...
Testing non-exportable NVM object access protection...
Non-exportable NVM object read correctly denied
Exportable NVM object read succeeded
NON-EXPORTABLE NVM ACCESS TEST SUCCESS
Testing crypto: (pthread) mem...
RNG SUCCESS
KEY CACHE/EXPORT SUCCESS
KEY CACHE USER EXCLUSION SUCCESS
KEY CACHE EVICT SUCCESS
KEY COMMIT/ERASE SUCCESS
KEY CROSS-CACHE EVICTION AND REPLACEMENT SUCCESS
Testing non-exportable keystore enforcement...
Non-exportable key export correctly denied
Exportable key export succeeded
NON-EXPORTABLE KEYSTORE TEST SUCCESS
AES CBC SUCCESS
AES GCM SUCCESS
CMAC DEVID=0x5748534D SUCCESS
RSA SUCCESS
ECDH SUCCESS
ECC SIGN/VERIFY SUCCESS
CURVE25519 SUCCESS
SHA256 DEVID=0x5748534D SUCCESS
ML-DSA DEVID=0x5748534D SUCCESS
IMG_MGR ECC P256 Test completed successfully!
IMG_MGR AES128 CMAC Test completed successfully!
IMG_MGR RSA2048 Test completed successfully!
```
