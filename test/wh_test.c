#include <assert.h>
#include <string.h>

#include "wh_test_common.h"

/* Individual unit test drivers */
#include "wh_test_comm.h"
#include "wh_test_nvm_flash.h"


/* Default test args */


int whTest_Unit(void)
{
    /* Comm tests */
    WH_TEST_ASSERT(0 == whTest_Comm());
    WH_TEST_ASSERT(0 == whTest_NvmFlash());

    return 0;
}


#if !defined(WH_CFG_TEST_UNIT_NO_MAIN)

int main(void)
{
    return whTest_Unit();
}

#endif
