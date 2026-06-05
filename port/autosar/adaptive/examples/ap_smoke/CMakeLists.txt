# Adaptive CryptoProvider smoke test, run against wh_posix_server

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
get_filename_component(WOLFHSM_DIR "${WOLFHSM_DIR}" ABSOLUTE
                       BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
get_filename_component(WOLFSSL_DIR "${WOLFSSL_DIR}" ABSOLUTE
                       BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(WOLFHSM_CONFIG_DIR ${WOLFHSM_DIR}/port/autosar/common/config)

add_subdirectory(${WOLFHSM_DIR}/port/autosar/adaptive
                 ${CMAKE_BINARY_DIR}/wolfhsm_ara_crypto)

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
