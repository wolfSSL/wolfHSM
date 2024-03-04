#ifndef WH_TEST_COMMON_H_
#define WH_TEST_COMMON_H_

#include <assert.h>
#include <stdio.h>


#define WH_TEST_FAIL (-1)
#define WH_TEST_SUCCESS (0)

/* Helper macro to print a message with caller source file info */
#define WH_DEBUG_PRINT(fmt, ...) \
    printf("[%s:%d]: " fmt, __func__, __LINE__, ##__VA_ARGS__)

/* Helper macro to print a message, prefixed by ERROR, along with caller source
 * file info */
#define WH_ERROR_PRINT(fmt, ...) \
    printf("ERROR [%s:%d]: " fmt, __func__, __LINE__, ##__VA_ARGS__)

/*
 * Helper macro for test error propagation
 * Evaluates the "call" argument, and if not equal to zero, displays the
 * stringified call argument along with caller source file info and
 * causes the calling function to return the value of "call"
 */
#define WH_TEST_RETURN_ON_FAIL(call)                 \
    do {                                             \
        int ret = (call);                            \
        if (ret != 0) {                              \
            WH_ERROR_PRINT(#call ": ret=%d\n", ret); \
            return ret;                              \
        }                                            \
    } while (0)


/*
 * Helper macro for test error propagation
 * Mimics "assert" semantics by evaluating the "statement" argument, and if not
 * true, displays the stringified argument along with caller source file info
 * and causes the calling function to return the value of WH_TEST_FAIL
 */
#define WH_TEST_ASSERT_RETURN(statement)                 \
    do {                                                 \
        if (!(statement)) {                              \
            WH_ERROR_PRINT("(" #statement ") failed\n"); \
            return WH_TEST_FAIL;                         \
        }                                                \
    } while (0)


#define WH_TEST_ASSERT(condition) assert((condition))

/*
 * Helper macro for test error propagation
 * Wraps stdlib assert() with a custom error message
 */
#define WH_TEST_ASSERT_MSG(condition, message, ...)                        \
    do {                                                                   \
        if (!(condition)) {                                                \
            printf("\n\n***TEST FAILURE***\nin %s:%s():%d: " message "\n", \
                   __FILE__, __func__, __LINE__, ##__VA_ARGS__);           \
            assert(condition);                                             \
        }                                                                  \
    } while (0)


#endif /* WH_TEST_COMMON_H_ */
