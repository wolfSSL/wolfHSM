#ifndef WH_TEST_NVM_FLASH_H_
#define WH_TEST_NVM_FLASH_H_

#include "wolfhsm/wh_nvm_flash.h"

/*
 * Runs all the NVM flash tests using a RAM-based flash memory simulator, and
 * optionally using a POSIX file simulator if WH_CFG_TEST_POSIX is defined.
 * Returns 0 on success, and a non-zero error code on failure
 */
int whTest_NvmFlash(void);

/*
 * Runs NVM flash tests on a custom NVM flash configuration. Useful to test your
 * NVM HAL implementation
 * Returns 0 on success, and a non-zero error code on failure
 */
int whTest_NvmFlashCfg(whNvmFlashConfig* cfg);

#endif /* WH_TEST_NVM_FLASH_H_ */
