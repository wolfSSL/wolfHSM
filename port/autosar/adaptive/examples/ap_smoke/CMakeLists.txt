# Build the Adaptive CryptoProvider smoke binary.
#
# Usage (from port/autosar/adaptive/examples/ap_smoke/):
#   cmake -S . -B build -DWOLFHSM_DIR=../../../../.. -DWOLFSSL_DIR=/path/to/wolfssl
#   cmake --build build
#
# Run alongside examples/posix/wh_posix_server (TCP, default port 23456):
#   ./build/ap_smoke

cmake_minimum_required(VERSION 3.13)
project(ap_smoke CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

if(NOT DEFINED WOLFHSM_DIR)
    set(WOLFHSM_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../..)
endif()
if(NOT DEFINED WOLFSSL_DIR)
    set(WOLFSSL_DIR ${WOLFHSM_DIR}/../wolfssl)
endif()
# Normalize to absolute paths anchored at this example's source dir. A
# relative -DWOLFHSM_DIR is meant relative to where cmake was invoked
# (here), but CMake resolves relative include dirs against each target's
# own source dir — so the inherited value would point at the wrong place
# inside the add_subdirectory()'d adaptive library. Resolving now makes
# the paths unambiguous everywhere they're inherited.
get_filename_component(WOLFHSM_DIR "${WOLFHSM_DIR}" ABSOLUTE
                       BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
get_filename_component(WOLFSSL_DIR "${WOLFSSL_DIR}" ABSOLUTE
                       BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(WOLFHSM_CONFIG_DIR ${WOLFHSM_DIR}/port/autosar/common/config)

# Pull in the Adaptive library.
add_subdirectory(${WOLFHSM_DIR}/port/autosar/adaptive
                 ${CMAKE_BINARY_DIR}/wolfhsm_ara_crypto)

# Glob the wolfHSM client + wolfSSL sources we need at link time.
file(GLOB WOLFHSM_SRC      ${WOLFHSM_DIR}/src/*.c)
file(GLOB WOLFHSM_POSIX    ${WOLFHSM_DIR}/port/posix/*.c)
file(GLOB WOLFCRYPT_SRC    ${WOLFSSL_DIR}/wolfcrypt/src/*.c)
file(GLOB WOLFSSL_SRC      ${WOLFSSL_DIR}/src/*.c)

add_executable(ap_smoke
    ap_smoke.cpp
    ${WOLFHSM_SRC}
    ${WOLFHSM_POSIX}
    ${WOLFCRYPT_SRC}
    ${WOLFSSL_SRC}
)

target_compile_definitions(ap_smoke PRIVATE
    _POSIX_C_SOURCE=200809L
    WOLFHSM_CFG
    WOLFSSL_USER_SETTINGS
    WC_USE_DEVID=0x5748534D
)
target_include_directories(ap_smoke PRIVATE
    ${WOLFHSM_DIR}
    ${WOLFSSL_DIR}
    ${WOLFHSM_CONFIG_DIR}
)
target_link_libraries(ap_smoke PRIVATE wolfhsm_ara_crypto pthread m)
